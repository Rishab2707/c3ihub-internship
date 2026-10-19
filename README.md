# DUORAM text-block demo

## Start the application

Install Node.js 20.19+ or 22.12+ and npm, then run:

```sh
npm ci
npm run demo
```

Open **http://127.0.0.1:5173**. The launcher starts database servers A/B on ports 4101/4102, the online helper on 4103, and React on 5173. Wait for preprocessing, choose a slot, then use **Read text** or **Write once**. Multiple browsers can connect; server A serializes their operations.

The default database has **1,024 slots**, numbered **0-1023**. Each slot contains **1,024 bits (128 bytes)**:

| Bytes | Contents |
| --- | --- |
| 0 | Occupied marker: 0 for never written, 1 for written |
| 1 | ASCII text length, 0-126 |
| 2-127 | Up to 126 ASCII characters, followed by zero padding |

Empty strings are allowed and occupy a slot permanently. Spaces, newlines and ASCII NUL characters round-trip using the explicit length. Unicode outside ASCII is rejected by the browser. The frontend reports a refused write without replacing the existing text.

To change the slot count in PowerShell before starting:

```powershell
$env:DB_SIZE = '2048'
npm run demo
```

All three backend processes must use the same slot count: a power of two from 2 to 16,384. Block length is fixed by `shared/block-format.js`; changing it requires updating the length format and multiplication batch limits as appropriate. The database starts empty and is held in memory. Stop with **Ctrl+C**; restart all three processes together to reset it. Restart an older running demo after this update.

The **DPF preprocessing** button selects **Third-party triples** (default) or **OT based triples** for both DPF generation and the write-once gate. Switching preserves stored posts and discards unused old-mode preprocessing. The helper remains online in both modes.

This demo hides indices and contents under the one-passive-corrupted-party, no-collusion model. It does **not** hide browser IP addresses, connection timing, or other network identity metadata. Anonymous posting needs a separate transport design. The complete handwritten cryptographic composition has not been independently audited; the local launcher explicitly enables the research prototype on loopback HTTP.

## Sharing and stored state

The browser encodes text into a fixed-length block and samples fresh, uniformly random XOR shares of the entire block, including its header and padding. It also XOR-shares the index. A receives only its shares; B receives only its shares. Read outputs and write-acceptance bits are reconstructed in the browser.

```text
D = D_A XOR D_B
alpha = alpha_A XOR alpha_B
A stores: D_A, B_A, cached_A = D_B XOR B_B
B stores: D_B, B_B, cached_B = D_A XOR B_A
Helper stores: B_A, B_B
```

Database shares, blinds and cached blinded shares are flat byte arrays, with 128 consecutive bytes per slot. They start at public zero. No full database or flag vector is sent during an online access. The helper receives neither index shares nor client value shares. Each server authenticates to it with a separate credential. Remote transport configuration requires HTTPS.

## Preprocessing MPCs and primitives

### Base OT and OT extension

In OT mode only, the database servers establish reusable OT contexts once per paired process lifetime. Chou-Orlandi-style base OT uses the 3072-bit MODP-15 subgroup and a SHA-256 transcript-bound mask, with 128 base OTs in each direction.

IKNP-style extension expands 128 seed rows using AES-128-CTR with HMAC-SHA256-derived row keys and fresh batch identifiers. SHA-256 hashes of transposed columns mask bit-OT alternatives. Actual DPF and write-gate operands are not supplied to these offline OT batches.

References: Chou and Orlandi, [The Simplest Protocol for Oblivious Transfer](https://eprint.iacr.org/2015/267); Ishai, Kilian, Nissim and Petrank, [Extending Oblivious Transfers Efficiently](https://csaws.cs.technion.ac.il/~erez/Papers/IsKiNiPe-Crypto03.pdf). This implementation targets passive security.

### Du-Atallah multiplication correlations

Both modes generate the same random correlations:

```text
Z_A = (X_A AND Y_B) XOR T
Z_B = (X_B AND Y_A) XOR T
```

Dealer mode samples them at the helper and delivers each party only its assigned share. OT mode generates the cross terms between A/B using two-direction OT and fresh masks.

For actual XOR-shared operands x and y, each server consumes fresh correlations and exchanges masked local operands:

```text
u_p = x_p XOR X_p
v_p = y_p XOR Y_p
product_p = (x_p AND (y_p XOR v_peer))
            XOR (Y_p AND u_peer) XOR Z_p
```

The outputs XOR to x AND y. The helper does not receive these exchanges. Correlations are consumed once and erased after use.

Reference: [DUORAM, Appendix A](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf), including its dealer and OT constructions and reference to Du and Atallah's protocols.

### Three random DPFs and final leaf expansion

A/B jointly generate three independent DPF components at the same random XOR-shared address: **Read**, **Blind0** and **Blind1**. The tree protocol uses one private 128-bit multiplication batch per level and exchanges seed/control corrections. Keys contain a private root and logarithmically many correction words.

Tree expansion uses fixed-key AES-128 Davies-Meyer: branch-labelled input, AES output XOR input, with a separate extracted control bit. Root blocks have 127 random bits and one reserved public control bit.

**Final output conversion:** every corrected 128-bit leaf seed becomes an AES-128-CTR key. Encrypting 128 zero bytes with the fixed, domain-labelled IV `DUORAM-LEAF-v14` (zero-padded to 16 bytes) produces a **1,024-bit pseudorandom block**. This is separate from tree expansion and does not increase seed entropy. Equal off-target leaf seeds produce equal blocks; their XOR therefore vanishes away from the selected slot. Deferred corrections cancel the target's masks and insert the desired block delta.

Each component retains its flags, expanded blocks and the XOR reduction of those blocks. The helper receives only A's Blind0 key and B's Blind1 key and evaluates them locally. It receives neither Read key nor both keys of any component.

At the default depth 10, three DPFs consume **3,840 Boolean correlations**. A separate **1,024-correlation batch** is reserved for the write-once gate, for **4,864 per prepared access**. Reads discard the unused gate batch. Both batches follow the selected preprocessing mode.

References: Boyle, Gilboa and Ishai, [Function Secret Sharing: Improvements and Extensions](https://eprint.iacr.org/2018/707); [DUORAM, section 4 and Appendix C](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf). The block output conversion and web wire format are implementation choices.

## Online reads

### Read procedure

1. In the browser, enter a slot index and click **Read text**. The text input is ignored for a read.
2. `run('access')` in `src/main.jsx` generates a session ID, a private result token and fresh XOR shares of the index. It submits B's input to `POST /api/share`, then A's input to `POST /api/access`.
3. In `server/server.js`, A queues the operation through `enqueueClientOperation()` and starts `runCoordinatorOperation()`. It checks B's process lifetime and consumes a fresh prepared item through `takePreprocessing()`, waiting for preprocessing if necessary.
4. A starts B through `/internal/op/run`. Both servers call `runPartyOperation()` and then `runSharedBlockOperation()` in `server/crypto/operation.js`. They exchange masked offsets, shift the prepared evaluations and request helper cancellation blocks as described below.
5. Each server scans its own database share, blind and cached blinded peer share to compute a 128-byte read share and a validity share. A waits for B through `/internal/op/wait` and returns its output to the browser. B stores its output for retrieval.
6. The browser's `readServerShare()` retrieves B's output from `GET /api/result/<sessionId>` using the private result token. The browser XORs the validity shares and the full block shares, then decodes the occupied marker, length and ASCII text. A never-written slot is shown as empty; a written empty string is shown separately.

A starts replenishing preprocessing for the next access in the background. The current read consumes its prepared item once and discards the unused write-gate correlations. The separate `/api/status` polling updates UI readiness and is not a read-protocol step.

### Masked shift and local computation

Each access consumes fresh preprocessing. A/B exchange masked offsets:

```text
offset_p = alpha_p XOR r_p
shift = offset_A XOR offset_B
```

The prepared vectors are locally permuted with `i XOR shift`. The helper receives only public operation identifiers, the masked shift and the blind version. It computes block cancellation shares using its blind arrays and assigned flags, masked by the same fresh random **128-byte block** rho.

The database servers calculate, bytewise:

```text
read_A = dot(D_A XOR cached_A, flags_A_Read)
         XOR dot(B_A, flags_A_Blind1 XOR flags_A_Read) XOR gamma_A
read_B = dot(D_B XOR cached_B, flags_B_Read)
         XOR dot(B_B, flags_B_Blind0 XOR flags_B_Read) XOR gamma_B
```

Here a flag selects an entire block; dot XOR-reduces the selected bytes. The browser combines the 128-byte output shares, checks the shared validity bit and decodes the occupied marker, length and ASCII payload. B's output requires the private, per-request result token supplied only to B.

A prepared read performs no online OT or shared multiplication. It scans local arrays without changing the database or blinds.

## Online write-once update and blind refresh

### Write procedure

1. In the browser, enter a slot index and up to **126 ASCII characters**, then click **Write once**. An empty string is valid. `encodeTextBlock()` in `shared/block-format.js` creates the 128-byte block with its occupied marker, length and zero padding.
2. `run('insert')` in `src/main.jsx` creates fresh XOR shares of the index and the entire block. It sends B's shares and private result token to `POST /api/share`, then A's shares to `POST /api/insert`. Each server receives only its own shares.
3. A serializes the operation with other clients and reserves fresh preprocessing. Both servers run the same private read procedure to obtain shares of the old block, then evaluate the secret write-once gate described below. Neither server reconstructs the old text or occupied bit.
4. Each server forms three 1,024-bit correction contributions from its expanded-leaf reductions and its conditional delta share. A/B exchange contributions and combine them into three final corrections. They locally stage the database, blind and cached-copy updates; the helper receives only the two blind corrections and stages its own blind updates.
5. A commits the helper and B before applying its own staged state. This coordination is in `runCoordinatorOperation()` in `server/server.js`. The same path runs for accepted and refused writes; an occupied slot receives a zero reconstructed delta and keeps its original contents.
6. The browser retrieves B's result with `readServerShare()`, checks the validity bit and XORs the acceptance shares. On success it displays the submitted text and **clears the text input**. On refusal or failure it displays the error and **preserves the text input**. Two clients competing for the same empty slot cannot both succeed because A serializes the occupied check and update.

A also starts preparing the next access in the background. Writes do not send plaintext text, reconstructed occupancy or a full database array between servers.

### Secret conditional delta

A write first privately reads the old block. Its occupied bit remains XOR-shared. The servers compute:

```text
accepted = NOT old.occupied
delta = accepted AND (oldBlock XOR requestedBlock)
```

The second equation uses **1,024 parallel Boolean multiplications in one online round**, consuming the separate preprocessed correlations. The occupied marker in the requested block is forced to 1 by the protocol. The browser receives acceptance shares; no server reconstructs the acceptance bit.

If already occupied, the reconstructed delta is zero. The same update and commit path runs regardless of acceptance, so rejection does not expose occupancy through a separate server-side branch. Even an occupied empty string cannot be overwritten.

### Final corrections and local refresh

For each DPF component k (Read, Blind0 and Blind1), `expandedLeaf_k,p[i]` is the **1,024-bit output** of the final leaf PRG. Its XOR reduction was stored during preprocessing. Each party computes a correction contribution from that reduction and its 1,024-bit delta share:

```text
F_k,p = XOR_i expandedLeaf_k,p[i] XOR delta_p
F_k = F_k,A XOR F_k,B
u_k,p[i] = expandedLeaf_k,p[i] XOR (flag_k,p[i] * F_k)
```

Each `F_k,p` and combined `F_k` is **1,024 bits (128 bytes)**. There are three final corrections, totalling **3,072 bits (384 bytes)** before wire encoding. These block corrections are distinct from the DPF tree's **128-bit seed correction words** and separate control bits. Multiplication by a public one-bit flag selects either the entire correction block or an all-zero block and requires no additional MPC.

Each pair u reconstructs the same point update. Servers locally update:

```text
A: D_A ^= u_Read,A
   B_A ^= u_Blind0,A
   cached_A ^= u_Read,A XOR u_Blind1,A
B: D_B ^= u_Read,B
   B_B ^= u_Blind1,B
   cached_B ^= u_Read,B XOR u_Blind0,B
```

Only the two blind-component corrections go to the helper; it refreshes its own blind copies locally. All states are staged before commit. Ambiguous commit failures close the runtime gate and require restarting all three processes. Server A serializes clients, making the occupied check and update atomic for cooperating servers.

Reference: [DUORAM, UPDATE and REFRESHBLINDS](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf). The secret conditional write-once gate is an application extension.

For N slots and B bytes per block, local scans and full expanded storage cost O(NB). Online read communication is O(8B + log N) payload bits; writes add O(8B) masked multiplication bits and O(B) correction bytes. No online database-sized transfer is needed.

## Differences from DUORAM

- Indices are XOR-shared with XOR permutations instead of additive indices and cyclic shifts.
- Cells are fixed 1,024-bit XOR-shared blocks with a text header and AES-CTR leaf output conversion, rather than the default arithmetic words.
- Writes are conditional, immutable-slot inserts. This adds an online multiplication round beyond the underlying read-modify-update protocol.
- Browser clients reconstruct results; operations and preprocessing are serialized using a small replenished pool.
- The helper participates online in both modes. OT-based preprocessing does not turn this into the paper's two-party CSPIR construction.
- This is an in-memory demo with passive-security assumptions, without independent proof of the complete composition or network anonymity.

Reference: Vadapalli, Henry and Goldberg, [DUORAM: A Bandwidth-Efficient Distributed ORAM for 2- and 3-Party Computation](https://www.usenix.org/system/files/usenixsecurity23-vadapalli.pdf), USENIX Security 2023.
