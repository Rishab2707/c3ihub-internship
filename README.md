# Two-server DUORAM adaptation

Node.js backend, React browser client, and a configurable binary database of 65,536 cells (2^16). Database values, requested indices and inserted bits are XOR-shared between servers A and B. The browser generates shares; the two servers preprocess random cryptographic DPFs and shift them online.

The supplied C++ reference is **three-party** DUORAM for packed genomic words. This version adapts its joint leafless DPF generation and deferred value corrections to two parties and binary cells, and uses the paper's two-party masked CSPIR read structure. The CSPIR backend is an encrypted full-array download with OT-selected keys, **not SPIRAL**: it has linear communication. See [the read protocol](docs/two-party-read.md) and [reference mapping](docs/cpp-reference-mapping.md).

## Local web demo

Requires Node.js 20.19+ or 22.12+ and npm.

```sh
npm ci
npm run demo
```

Open http://127.0.0.1:5173. Multiple tabs or browsers can read and replace bits at indices 0–65535. On startup A prepares one random query with B, including one-time base-OT setup. A replenishes the pool after each operation. A request waits if preprocessing is unfinished; later requests reuse base material with fresh extension batches. Concurrent requests are serialized by server A.

`npm run demo` starts exactly two server processes plus Vite, generates a fresh shared peer token, and binds all listeners to loopback. It explicitly uses HTTP and the dummy-data test override. It does not enable the production validation gate. Stop with Ctrl+C; restart both servers together to reset the all-zero database. No data is persisted.

To change the size later, set `DB_SIZE` before starting. Supported lengths are 1–1,000,000; indices use the next power-of-two domain. Padded indices have no backing cell and cannot change the database.

## Focused validation

```sh
npm run test:crypto
npm run build
```

The three retained checks cover DPF generation/evaluation, online shifting and deferred value corrections, default disabled routes, and concurrent read/replacement flows through both server processes on 65,536 cells. The integration checks preservation of other cells, one-use preprocessing, absence of online AND messages for reads/updates, TLS trust, ambiguous commits and one-sided restarts. There are no helper-by-helper tests. Temporary HTTPS certificates require the OpenSSL CLI; set `DUORAM_TEST_OPENSSL` if it is not on PATH. The browser interface has build evidence; automated browser execution is not claimed.

## Protocol

- Browser CSPRNG generates fresh index and value XOR shares and a request identifier.
- B receives its shares directly. A receives its shares and coordinates the operation with B.
- The browser sends a fresh result token only to B. B requires it to retrieve the result share; the public session ID known to A does not authorize retrieval.
- Offline, each server chooses a private random address. OT prepares a symmetric private query and a batch of random XOR-shared multiplication triples. Joint DPF generation uses the random addresses, tree reductions, one-use triple multiplications and 128-bit seeds. It receives no browser index or database values. At the default size, 2,048 triples are prepared before generating each DPF and consumed as 128 per level.
- Online, the servers consume the prepared item once, exchange masked address offsets, and XOR-permute its DPF leaves. Freshly masked and encrypted CSPIR responses provide the old bit as two private output shares; there is no full-domain online MPC product. The browser combines the two result shares.
- Replacement privately reads the old bit, derives a shared XOR delta, exchanges the deferred DPF value correction, and applies local corrected leaf values. Both servers stage their database shares before commit.
- Uncertain write commits and changed peer process identities close the runtime gate. Restart both processes to discard and reset their in-memory state.

The backend cryptography is handwritten JavaScript using Node built-ins: Chou–Orlandi-style base OT in a 3072-bit subgroup, IKNP-style OT extension, fixed-key AES-128 Davies–Meyer DPF expansion matching `cpp-implementation/prg.cpp`, and OT-generated Boolean Beaver triples. DPF child controls are extracted and cleared before seed corrections; binary updates project a remaining seed bit. HMAC-SHA256 remains in the OT row-key derivation. Direct two-direction OT multiplication generates the random triples; actual DPF operands are multiplied by consuming those triples and opening only masked differences. No external npm cryptography package or helper server is used. These are cryptographic constructions, but passing correctness checks does not establish their security.

AES DPF keys use version 3 and wire protocol `duoram-preprocessed-cspir-triples-aes-bit-v11`. Earlier HMAC keys are rejected. Restart both servers together after upgrading; preprocessing and database shares are in memory and are reset on restart. See [the AES expansion notes](docs/aes-dpf-expansion.md).

## Security and deployment

The intended model is one passive, non-colluding server and trusted browsers with separately protected connections to A and B. Active server attacks, timing resistance and persistent crash recovery are not established. This adaptation has linear local work and encrypted-download read communication; it does not claim SPIRAL's bandwidth efficiency, constant online communication, or complete paper protocol equivalence. At the default size each server sends an 8,192-byte encrypted response, before base64/JSON overhead.

`PROTOCOL_VALIDATED` is currently false. Normal `npm run dev` starts servers with operations disabled until security validation is completed. Independent review is recommended, rather than a user-imposed prerequisite. See [protocol review](docs/protocol-review.md), [OT security argument](docs/ot-security-argument.md), [generation-view argument](docs/dpf-privacy-argument.md), and [completion audit](docs/completion-audit.md).

For configured server launches, use `DUORAM_HOST`, `DUORAM_PORT_A/B`, `DUORAM_PEER_URL` and a common `DUORAM_PEER_TOKEN` of 64 hexadecimal characters. Configure `DUORAM_TLS_KEY_PATH`, `DUORAM_TLS_CERT_PATH` and `DUORAM_TLS_CA_PATH` together for HTTPS; the peer client verifies the configured CA. Non-loopback listeners require TLS. Set `DUORAM_ALLOWED_ORIGINS` for browser origins, and `VITE_DUORAM_SERVER_A/B` for browser endpoints. Remote browser endpoints require HTTPS. Configuring these values alone does not override the validation gate.
