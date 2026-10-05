# Two-server DUORAM adaptation

## Start the application

Install Node.js 20.19+ or 22.12+ and npm, then run:

```sh
npm ci
npm run demo
```

Open **http://127.0.0.1:5173**. This starts server A on port 4101, server B on port 4102, and the React interface on port 5173. Wait for preprocessing to become ready, then read or write a bit at an index from **0 to 65535**. Multiple browser clients can connect; server A serializes operations.

The database starts as **65,536 zero bits (`2^16`)**. A write replaces the addressed bit and preserves every other cell. Stop with **Ctrl+C**. Restarting both servers resets the in-memory database and preprocessing. This startup command runs the local demo over loopback HTTP.

## Sharing and protocol phases

There are exactly two server parties and no trusted dealer. Database values, indices and inserted values use XOR shares:

```text
D[i] = D_A[i] XOR D_B[i]
alpha = alpha_A XOR alpha_B
newBit = newBit_A XOR newBit_B
```

The browser sends each server only its own input shares and combines read-result shares. XOR operations on secret shares are local; multiplication of two secret bits requires MPC. The servers perform the following preprocessing before receiving the actual client index or value. At startup A prepares one item and replenishes it after each operation; an operation waits if no item is ready.

## Preprocessing MPCs and primitives

### 1. Base oblivious transfer: Chou-Orlandi-style OT

**Purpose:** establish the seeds needed for OT extension, once per paired server lifetime, in both directions.

In a 1-out-of-2 oblivious transfer, a sender supplies two messages and a receiver privately chooses one. The receiver obtains its selected message; the sender does not learn the choice. The implementation uses Diffie-Hellman operations in the 3072-bit MODP-15 subgroup, validates public group elements, and hashes the shared group element and transcript with SHA-256. Each extension direction starts with 128 base OTs.

Reference: Tung Chou and Claudio Orlandi, [*The Simplest Protocol for Oblivious Transfer*](https://eprint.iacr.org/2015/267). This implementation targets passive security; it does not claim the stronger composition guarantees retracted in the corrected paper.

### 2. OT extension: IKNP-style extension

**Purpose:** obtain many bit OTs from the small base-OT setup, for triple generation and private retrieval key selection.

The implementation expands 128 seed rows, exchanges masked rows, and hashes transposed columns to mask the two message alternatives. Row streams use AES-128-CTR with HMAC-SHA256-derived keys bound to the row and a fresh batch identifier. Column hashes use SHA-256. Base material is reused, while each extension batch uses fresh randomness.

Reference: Yuval Ishai, Joe Kilian, Kobbi Nissim and Erez Petrank, [*Extending Oblivious Transfers Efficiently*](https://csaws.cs.technion.ac.il/~erez/Papers/IsKiNiPe-Crypto03.pdf), CRYPTO 2003. The row-key derivation and encodings are implementation choices.

### 3. OT-generated Boolean multiplication triples

**Purpose:** prepare random shared products without revealing either party's shares or using a dealer.

Each server samples fresh random shares of vectors `a` and `b`. Two-direction OT multiplication generates shares of:

```text
c = a AND b
```

For each multiplication, server `p` offers OT messages `mask_p` and `mask_p XOR a_p`; the peer chooses using its share of `b`. The selected output masks a cross term. Combining both directions with local products produces XOR shares of `c`, including both cross terms.

At depth 16, each DPF receives **2,048 triples** in one batched multiplication: 128 triples per tree level. These OTs multiply random triple inputs, not the DPF's actual operands. This is a direct Boolean multiplication construction from OT, using the OT protocols above.

### 4. Beaver multiplication inside joint DPF generation

**Purpose:** multiply actual secret DPF operands using the prepared triples.

For secret-shared bits `x` and `y`, the servers consume one triple and exchange shares of masked differences. They reconstruct only `d` and `e`:

```text
d = x XOR a
e = y XOR b
z_p = c_p XOR (d AND b_p) XOR (e AND a_p)
```

Server A additionally XORs `d AND e` into its output. Thus `z_A XOR z_B = x AND y`. Each triple is consumed before the exchange and cannot be reused; failures discard the affected preprocessing.

Reference: Donald Beaver, [*Efficient Multiparty Protocols Using Circuit Randomization*](https://link.springer.com/chapter/10.1007/3-540-46766-1_34), CRYPTO 1991. Here the multiplication operates on Boolean XOR shares.

### 5. Joint random DPF generation and AES expansion

**Purpose:** prepare compact keys whose evaluated flag arrays reconstruct a point function at a hidden random address.

Each server samples its own random 16-bit address `r_p`. Joint generation uses these as shares of `r = r_A XOR r_B`. At each tree level, servers expand their seeds locally, reduce child seeds and controls, consume 128 Beaver triples to compute a seed correction share, and exchange correction contributions. They retain their private roots and common correction words. Evaluated flags satisfy:

```text
flags_A[i] XOR flags_B[i] = 1 if i == r, otherwise 0
```

Expansion uses fixed-key AES-128 Davies-Meyer: set an input seed's reserved bit to the branch, compute `AES_K(input) XOR input`, extract its low bit as the child control, and clear that bit in the child seed. Root blocks occupy 128 bits, including 127 random seed bits and a reserved public control bit. Tree layers are expanded in batches. Corrected leaf labels, flags and their XOR reductions are retained for online shifting and updates.

References: Boyle, Gilboa and Ishai, [*Function Secret Sharing: Improvements and Extensions*](https://eprint.iacr.org/2018/707), for the seed/control DPF construction; [*DUORAM*](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf), Appendix C, for joint generation through tree reductions. The concrete fixed-key AES expansion requires its own PRG assumptions.

### 6. OT-selected keys for symmetric private retrieval

**Purpose:** let each server privately retrieve one masked bit from the peer during the online phase.

In each direction, the serving server creates 16 pairs of independent 128-bit keys. Through OT extension, the querying server selects one key from each pair using the bits of its private random address `r_p`. This transfers 2,048 key bits per direction. The serving server derives a one-bit pad for every position by hashing its index, preprocessing context and concatenated corresponding keys with SHA-256. The querying server can derive the pad for its selected position.

Reference: Moni Naor and Benny Pinkas, [*Oblivious Transfer and Polynomial Evaluation*](https://dl.acm.org/doi/10.1145/301250.301312), STOC 1999, for combining small OTs with encrypted-record retrieval. This implementation uses a concatenated-key hash under a random-oracle assumption and downloads the full encrypted array; it is an adaptation of that strategy.

## Online phase

### 1. Consume preprocessing and shift the random point

The browser supplies fresh shares of the actual index. Both servers consume the prepared item once and exchange:

```text
delta_p = alpha_p XOR r_p
shift = delta_A XOR delta_B
```

They locally XOR-permute their DPF flags and labels by `shift`. The reconstructed point moves from `r_A XOR r_B` to `alpha`. No index is reconstructed and no new DPF is generated online. The offsets rely on fresh random addresses and single-use preprocessing.

### 2. Read using masked symmetric retrieval

Each server samples a fresh mask bit `m_p` and creates an encrypted response over all positions `j`:

```text
C_p[j] = D_p[j XOR alpha_p XOR delta_peer] XOR m_p XOR pad_p[j]
```

The peer decrypts only its random query position using its selected pad. The index arithmetic selects the actual addressed cell. Querying server `p` obtains:

```text
selected_p = D_peer[alpha] XOR m_peer
readShare_p = selected_p XOR m_p
readShare_A XOR readShare_B = D[alpha]
```

The browser receives and combines the output shares. The DPF flags also provide a shared validity bit for configurations with padded addresses. Online reads use local scans and masked exchanges; **there are no online OT batches or secret AND multiplications**.

This follows the masked two-party read structure of [DUORAM, section 5](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf), with XOR address permutations and the encrypted-download retrieval backend described above.

### 3. Write through read-modify-update

A write first performs the same private read. Each server computes `deltaValue_p = readShare_p XOR newBit_p`. It embeds that delta share in byte one's low bit and exchanges a deferred value-DPF correction:

```text
F_p = XOR_i labels_p[i] XOR embed(deltaValue_p)
F = F_A XOR F_B
update_p[i] = valuebit(labels_p[i]) XOR (flags_p[i] AND valuebit(F))
D'_p[i] = D_p[i] XOR update_p[i]
```

`valuebit` projects byte one's low bit; byte zero's low bit is reserved for DPF controls and cannot mask a value. Since `F` is public, multiplying its projected bit by a private flag is local. The reconstructed update is `oldBit XOR newBit` at the target and zero elsewhere. Both servers stage their changes before commit. No additional multiplication triples are consumed online.

The deferred correction follows the value-DPF update approach in [DUORAM](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf). The read-modify-update step converts an overwrite into a shared delta without opening the old value.

## Differences from DUORAM

- **Retrieval bandwidth:** reads download full encrypted arrays instead of using SPIRAL-based symmetric PIR. Each server sends 8,192 response bytes at the default size, or 16 KiB total before encoding and other messages; online read communication is therefore O(N).
- **Address arithmetic:** indices use XOR sharing and XOR permutations rather than additive shares and cyclic shifts. XOR sharing of database cells is supported by the paper.
- **Records and preprocessing:** this application stores binary cells and prepares a DPF even for a pure read. The paper's two-party reads use SPIR, with DPFs used for updates.
- **Implementation assurance:** the OT, triples and DPF code is handwritten Node.js targeting one passive, non-colluding server. It is a research adaptation, not an audited reproduction of the complete paper protocol.

Reference: [Vadapalli, Schoenmakers and Goldberg, *DUORAM: A Practically Efficient Oblivious RAM*](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf), USENIX Security 2023.
