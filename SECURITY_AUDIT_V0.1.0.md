# @lethenymous/sdk v0.1.0 Security Audit

Status: initial candidate audit
Audit date: 2026-09-28
Candidate: `@lethenymous/sdk` `0.1.0`
Scope: the TypeScript SDK, its local Rust production-prover integration, production proving-key handling, package boundary, and SDK-facing RPC/wallet state handling.

This document is the initial audit report. It was written before any remediation. The findings below describe the candidate baseline, not a post-fix state. The remediation and re-audit sections are intentionally pending.

The frozen on-chain program, circuits, production PK/VK bytes, and SBF were not modified as part of this audit.

## Executive Summary

The SDK does not provide an identified direct path for a malicious RPC, recipient, relayer, or malformed local input to bypass the deployed program's proof, nullifier, account, or token authorization checks. Valid proof inputs and transaction account metas are bound on chain. Private Send is an alias of the audited arbitrary-recipient unshield path, and the recipient is included in the unshield public statement and checked by the token-account authority constraints.

The candidate is nevertheless blocked from release. The most important SDK findings are:

- `buildAndSend` ignores `confirmTransaction().value.err`, so failed transactions can be reported as successful and the wallet can mark notes spent or save nonexistent output notes.
- The production prover executable is caller-selected and not authenticated. It receives plaintext witness files, inherited environment variables, and all witness secrets. A substituted executable can exfiltrate spend material.
- The default note store is volatile, private-swap outputs have no encrypted recovery payload, and there is no complete chain recovery path.
- The witness provider is fail-closed for many incomplete-history cases, but does not authenticate the program that emitted `Program data` logs and trusts a single RPC for both tree state and history.
- Private-swap and quote math omit the on-chain LP-claim reserve floor, causing avoidable transaction failure near reserve boundaries.
- The source and built package are not included in the current git commit or release manifest, so the candidate cannot currently be reproduced from the audited release provenance.

The current release status is `BLOCKED`.

## Phase A: Candidate Freeze

### Repository identity

- Repository remote: `https://github.com/emyrinj/zkcpamm.git`
- Working repository: `/Users/emirilhan/Desktop/Crypto/zkCPMM`
- Branch: `release/zkcpmm-v1`
- Current git commit: `4a37c918f5b980967da468399e7f25f4b76e5115`
- Short commit: `4a37c91`
- Commit subject: `Organize audited release archive`
- Commit date: `2026-09-22T23:46:18+03:00`
- Program ID: `ZkCP47fAJJREdXNKSBvTsgJAuLoTKepgk6opmqsHobm`

The SDK is not tracked at this commit. `git ls-files lethenymous-sdk` returned no paths. The working-tree status includes:

```text
?? docs/PRIVATE_SEND_UNSHIELD_SECURITY_AUDIT.md
?? lethenymous-sdk/
```

The `lethenymous-sdk/` entry includes the candidate `src`, generated `dist`, package metadata, tests, E2E harness, and an unignored local `node_modules` tree. These are the uncommitted SDK/E2E-development changes being audited. The unrelated untracked `docs/PRIVATE_SEND_UNSHIELD_SECURITY_AUDIT.md` is not part of the SDK candidate. There is no tracked SDK diff to compare with `HEAD`; the complete SDK directory is an uncommitted addition.

The local production prover binary is also ignored by the repository rule `audit/tooling/**/target/` and is not release-tracked.

### Relevant candidate tree

```text
lethenymous-sdk/
  package.json
  package-lock.json
  README.md
  LICENSE
  tsconfig.json
  src/
    accounts.ts
    client.ts
    crypto.ts
    encoding.ts
    index.ts
    instructions.ts
    math.ts
    merkle.ts
    pda.ts
    prover.ts
    types.ts
    wallet.ts
    witness.ts
  dist/                         generated package payload
    *.js and *.d.ts
  tests/
    negative.test.mjs
    parity.test.mjs
  e2e/run.mjs
  node_modules/                 local, not packaged
```

The SDK package deliberately does not include the source tree, tests, E2E harness, Rust prover, PKs, VKs, or SBF.

### SDK package and dependency versions

`package.json` declares version `0.1.0`, ESM package type, Node `>=20`, and the following direct runtime dependencies:

| Dependency | Lockfile version | Role |
| --- | ---: | --- |
| `@noble/ciphers` | `1.3.0` | note AEAD |
| `@noble/hashes` | `1.8.0` | HKDF/hash helpers |
| `@solana/spl-token` | `0.4.15` | token accounts and ATA instructions |
| `@solana/web3.js` | `1.99.0` | RPC and transactions |
| `poseidon-lite` | `0.3.0` | commitment/nullifier/Merkle hashing |

The installed development versions are `typescript 5.9.3` and `@types/node 26.6.2` under the declared caret ranges. Relevant runtime transitive versions are `@solana/buffer-layout-utils 0.3.0`, `bigint-buffer 1.1.5`, `jayson 4.3.0`, `stream-json 1.9.1`, and `uuid 8.3.2`.

Environment observed during the audit:

| Tool | Version |
| --- | --- |
| Node.js | `v25.2.1` |
| npm | `11.6.2` |
| Rust | `1.95.0` |
| Cargo | `1.95.0` |
| Anchor CLI | `1.0.2` |
| Anchor framework in program Cargo manifests | `0.32.1` |
| Solana CLI | `3.1.10` |
| Solana program/dev dependencies | `2.3.x` family as pinned by the program lockfile |

The SDK has no Anchor npm dependency. Anchor is relevant to the source-derived instruction parity audit only.

### Program, circuit, and production artifact identity

The frozen program declares the program ID above in `programs/zkcpmm/src/lib.rs:13`. The release manifest records the same ID and SBF hash:

- SBF: `target/deploy/zkcpmm.so`
- SBF SHA-256: `8aa9037a2c31995d82d688069a06d85b0915771630a04f0043755a0dd9f5f6d6`
- SBF size: `797584` bytes
- Circuit version: `1`
- Private swap public inputs: `22` fields, `704` bytes
- Unshield public inputs: `10` fields, `320` bytes
- Groth16 proof size: `256` bytes
- Token program: `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`

Production PK/VK hashes observed and cross-checked against `artifacts/production-groth16-v1/manifest.json` and `release/manifest.json`:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `private_swap_pk.production.bin` | `2829872` | `26f9aaa5ff0924bc5c1d4a6fc618f70147d4f8b6d76acdfca3eabbd704cf51f5` |
| `private_swap_vk.production.bin` | `968` | `879889c529af83fa54fba4f0b97152ebcb1b356342ab258b52e317534f18422a` |
| `private_swap_vk.production.hex` | `3840` | `530f9cfc549cf42b3ccc5b678dcbf469db8e4749343c7b8ddcd1b5a178872a1a` |
| `unshield_pk.production.bin` | `1409808` | `156b0759e8819cb529c59249fbef6e075651655c8f8361f97616a8a1fc981563` |
| `unshield_vk.production.bin` | `584` | `886fe37ae9f9054b7f4cc45a740967bb13e0fc796aedbab4a36ee5e02f2486b6` |
| `unshield_vk.production.hex` | `2304` | `5ab829c0ab0dd0fbe3ed345a5e84c8753d8ef834ab44e2dc9693f5ba127cd1ec` |

The production setup is explicitly documented as a single-party trusted setup (`artifacts/production-groth16-v1/manifest.json:23`). The toxic-waste assumption is an existing protocol/artifact trust assumption, not an SDK implementation change, and is not counted as an SDK finding here.

### Prover tooling

The configured production tool is the Rust binary built from `audit/tooling/production-prover/src/main.rs`, package version `0.1.0`, with `ark-groth16 0.4.0`, `ark-bn254 0.4.0`, `ark-serialize 0.4.2`, `shielded-core`, and `zkcpmm-zk` path dependencies. The E2E/default README path is:

```text
audit/tooling/production-prover/target/debug/production-prover
```

The binary existed locally and had:

SHA-256: 540c34ab3eddfbad77e0daa8857bcd4c3fd10b936dcf3ed6801e26b49c1353d2
size:    7694992 bytes
```

This binary is ignored and its hash is not checked by `ProductionProver`.

### Current npm package contents

`npm pack --dry-run --json` and an actual pack to an audit-only temporary directory produced:

- Filename: `lethenymous-sdk-0.1.0.tgz`
- Packed size: `15994` bytes
- Unpacked size: `64073` bytes
- Entry count: `29`
- SHA-1 shasum: `dfa93aaf86bab13b2ea0e1ed6ba11b800d57be54`
- Integrity: `sha512-yuTthYkzGuNp6Sc8KsiOGFMKSM9o1kjIjxZjxm57B4vbxrGhjh0jsAuSU3AhhvdkJzBRFOOqUmjU3k0CWT68yQ==`

The 29 entries are `package.json`, `README.md`, `LICENSE`, and the JavaScript/declaration pairs for `accounts`, `client`, `crypto`, `encoding`, `index`, `instructions`, `math`, `merkle`, `pda`, `prover`, `types`, `wallet`, and `witness` under `dist/`. The tarball contains no source, tests, E2E harness, `node_modules`, `.env`, keypair, PK/VK, proof, witness, audit, Rust, or local binary files. The only public export is `.` with an ESM import target and declaration target.

An external temporary consumer installed the packed tarball without monorepo resolution. ESM import, program ID/PDA use, and `swapOutput` worked. The package exposes declarations in the advertised `types` path. It is ESM-only; a CommonJS `require` path is not exported. The README's prover paths are repository-relative and are not present in the package, so an external developer cannot use those instructions without separately acquiring repository artifacts.

### Baseline verification

- `npm test`: 8 passed, 0 failed.
- `npm run typecheck`: passed.
- `cargo test --manifest-path audit/tooling/production-prover/Cargo.toml --locked --no-run`: passed, with one unused-import warning.
- The previously confirmed Devnet flows are accepted as supplied baseline evidence: Shield, Private Swap, Unshield, Private Send, and Private Swap -> Private Send.
- The requested full flow `Shield A -> Private Swap A->B -> Private Swap B->A -> Unshield A` had not been rerun at the time this initial report was written. Its prior failure was fixture funding before submission, not treated as a protocol failure.

## Phase B: Threat Model

### Trust boundaries

```text
Application
    |
    v
@lethenymous/sdk
    |-- RPC Connection -------------------- untrusted transport/state oracle
    |-- NoteStore ------------------------- application-controlled local state
    |-- MerkleWitnessProvider ------------- RPC history plus tree-state source
    |-- ProductionProver ------------------ local executable and PK paths
    |-- production PK artifacts ----------- local files authenticated by hash
    `-- Solana transaction submission ----- relayer/RPC delivery and status
```

The SDK also handles the wallet adapter and recipient-provided public keys. The wallet signer is assumed to protect the payer key. A malicious recipient is allowed to see the recipient, amount, asset, timing, and received token balance for an unshield or Private Send.

### Threat actors and modeled failures

| Actor or condition | What is trusted | What is not trusted | Expected consequence if controls hold |
| --- | --- | --- | --- |
| Honest user/application | Its seed, signer, intentional parameters | SDK local state can still be stale or lost | No unauthorized spend; failures are explicit |
| Malicious or incomplete RPC | Transport availability only | Reads, history completeness, balances, reserves, tree data, status | Proof/account checks reject false state; omission should fail closed |
| Stale RPC | Nothing about freshness | Confirmed versus finalized account/history alignment | Operation may fail or be delayed, not authorize a false proof |
| Faulty relayer/submitter | Signed bytes are unmodified only | Delivery, ordering, censorship, retry/status reporting | Transaction can be dropped or duplicated; nullifier protects consensus |
| Malicious recipient | Its own token account and ability to receive | None of the sender's spend authorization | It cannot redirect a valid proof to another recipient account |
| Malformed artifact path or substituted PK | Files are present and readable | File content, path identity, race after hashing | Wrong PK should fail proof; local executable is a separate high-risk trust assumption |
| Substituted prover | None unless externally authenticated | All child behavior and output | Must be treated as able to read all witness secrets |
| Concurrent application calls | JavaScript execution is single-threaded per wallet object | Multiple wallet objects/processes/stores | Per-object lock helps one instance; shared state requires atomic reservation |
| Crash, timeout, drop, or fork | Nothing about local completion | Confirmation and finality before durable note update | Note state must remain recoverable and retryable |
| Malformed on-chain event/history | Finalized ledger is canonical | RPC reconstruction and log source | Missing or contradictory history must not produce a witness |
| Dependency/supply-chain compromise | Package lock and reviewed code | Transitive parser/native code and configured binary | No secret should reach an unauthenticated component |

### Protocol-enforced versus SDK-enforced security

The frozen program and circuits enforce the security properties that the SDK cannot replace:

- Fixed embedded Groth16 VKs, proof length, input count, and canonical field checks.
- Commitment recomputation during shield.
- Nullifier derivation and one-time spent-nullifier PDAs.
- Accepted Merkle root and generation/sequence checks.
- Exact public-input reconstruction inside unshield/private swap.
- Pool, custody, vault, mint, token-program, and recipient token-account constraints.
- The recipient is a public input; the recipient token accounts must be owned by that recipient. The recipient is not required to sign.
- Private Send is exactly an unshield instruction, not a second protocol primitive.

The SDK is responsible for safe local behavior and transaction assembly:

- Keeping spend material out of avoidable logs and process arguments.
- Selecting and reserving notes without races.
- Persisting and recovering note randomness and spent state.
- Reconstructing a witness from complete, authenticated-enough history.
- Binding returned prover public inputs to local values.
- Authenticating production artifacts and the prover executable.
- Using exact arithmetic and matching the frozen CPMM.
- Handling ATA preparation, LUTs, compute limits, and confirmation semantics.

The audit found SDK correctness, availability, privacy, and provenance defects. It did not find an SDK construction that bypasses the on-chain authorization checks and moves funds without a valid user-controlled note/proof and signer.

## Findings

### F-01 - HIGH - Confirmation errors are ignored and local note state is committed on failed execution

Classification: `CORRECTNESS BUG` with high availability and local-funds-state impact.

Affected files/functions:

- `lethenymous-sdk/src/client.ts:8`, `Lethenymous.buildAndSend`
- `lethenymous-sdk/src/wallet.ts:27-30`, `ShieldedWallet.shield`, `unshield`, and `privateSwap`

Security invariant: a note may become spent or a new note may be recorded only after the submitted transaction is confirmed at the selected finality and `value.err` is absent. A signature by itself, or a confirmation response containing an execution error, is not success.

Preconditions: an operation reaches `confirmTransaction` and the RPC returns `{ value: { err: ... } }`, or returns a non-final confirmed result that later forks out. The same condition occurs when simulation/preflight succeeds but runtime execution fails.

Attack/failure path:

1. The SDK sends a shield, unshield, or private swap.
2. `confirmTransaction` resolves, but its `value.err` is non-null, or the confirmed transaction is later removed by a fork.
3. `buildAndSend` ignores the error and returns the signature.
4. `shield` saves a note for a deposit that did not occur, or `unshield`/`privateSwap` marks the input spent and saves output notes for a transaction that did not occur.

Impact: local balance can contain phantom notes, real notes can become locally unavailable, and retries can submit unnecessary duplicate nullifier transactions. If a timeout occurs after the transaction actually landed, the catch path releases the note and a retry can submit the same nullifier. Consensus rejects the duplicate, but both application attempts can appear failed and local state remains ambiguous. This does not bypass on-chain authorization or steal funds directly; it can strand or misrepresent funds in the local wallet.

Exploitability: high for a faulty, malicious, or inconsistent RPC and ordinary runtime failures. No attacker needs the spend secret.

Reproducibility: deterministic. A mocked `confirmTransaction` returning `value.err = { InstructionError: [0, "custom"] }` caused `buildAndSend` to return the signature. The source has no check of `confirmation.value.err`.

Evidence: `client.ts:8` awaits `confirmTransaction` and immediately returns `signature`. `wallet.ts:28` calls `markSpent` after that return, and `wallet.ts:30` saves change/output notes after that return.

Recommended remediation, not performed: inspect and reject `value.err`; require the documented commitment, preferably finalized for shielded note state; expose an explicit unknown/dropped result for ambiguous submission; reconcile local state against finalized signatures and events before retrying.

Protocol/on-chain changes required: No.

### F-02 - HIGH - Production prover executable is configurable but not authenticated

Classification: `SECURITY VULNERABILITY` at the local supply-chain/process trust boundary.

Affected files/functions:

- `lethenymous-sdk/src/prover.ts:18-29`, `ProductionProverConfig` and `run`
- `lethenymous-sdk/e2e/run.mjs:30-35`, `E2E_PROVER_BIN`
- `audit/tooling/production-prover/src/main.rs:129-169`

Security invariant: a component that receives spend secrets, note randomness, Merkle siblings, and proving witnesses must be authenticated as the intended production prover, or the user must explicitly accept that component as fully trusted.

Preconditions: an attacker or compromised installation can control `executablePath`, the local binary, the package's runtime environment, or the configuration supplied by an application.

Attack/failure path:

1. The SDK accepts an arbitrary executable path and calls `spawn` without a hash, signature, owner/mode check, or trusted-directory check.
2. The child receives the plaintext request path, both PK paths through environment variables, and the inherited process environment.
3. The request file contains spend secrets, randomness, roots, siblings, amounts, commitments, and recipient data.
4. A substituted binary can copy those values, exfiltrate them, or generate unauthorized proofs for notes it can reconstruct. It can also return plausible-length output or deliberately deny service.

Impact: spend secret and note randomness disclosure can enable future note spending and destroys the intended local-prover privacy boundary. A malicious executable can also learn `E2E_SEED_HEX` and other inherited environment variables. The frozen on-chain verifier still rejects malformed or mismatched proofs, but it cannot distinguish a valid proof made by an attacker who obtained the user's witness material.

Exploitability: medium to high for a compromised binary distribution, writable path, malicious application configuration, or local same-user attacker. This is not an RPC-only attack and is a trust assumption if the application deliberately supplies its own prover.

Reproducibility: direct source inspection. The local binary exists at the README/default path but has no SDK-checked identity. Its observed SHA-256 is recorded in Phase A only; it is not enforced.

Evidence: `spawn(executable, ...)` at `prover.ts:29`; `ProductionProverConfig.executablePath` is a free string at `:19`; E2E allows `E2E_PROVER_BIN`; `main.rs` reads all witness tokens and secrets before proving.

Recommended remediation, not performed: ship or install a versioned prover with an authenticated distribution mechanism; pin an expected executable digest/signature or require an explicit trusted binary policy; avoid inheriting the full environment; document the binary as a security-critical component. Do not treat PK hashes as prover-binary authentication.

Protocol/on-chain changes required: No.

### F-03 - MEDIUM - Prover witness IPC uses plaintext temporary files and has unbounded process/resource behavior

Classification: `SECURITY VULNERABILITY` for local secret exposure and `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/prover.ts:2-5,29-35,40-41`
- `audit/tooling/production-prover/src/main.rs:31-34,177-193`

Security invariant: sensitive witness material should be transported only through a private channel with bounded lifetime, bounded resource use, and deterministic cleanup. A prover failure must not leave an application indefinitely blocked with secrets on disk.

Preconditions: any private operation invokes `ProductionProver`; the process or child crashes, hangs, emits excessive output, or the host has another same-user observer.

Attack/failure path:

1. TypeScript writes `tokens.join(" ")` to `request.txt` in a temporary directory.
2. The file is mode `0600`, and `mkdtemp` normally creates a private directory, which is a positive control.
3. Cleanup occurs only in `finally` after the child exits. There is no timeout, cancellation, child kill, or bounded stderr/stdout handling.
4. `stdout` is piped but never consumed, so a child that writes enough stdout can block. `stderr` is accumulated without a limit and is included in a thrown error. Output files are read without a size bound before the length check.
5. A process crash, parent termination, or hung child can leave request material and output files behind and retain the witness indefinitely.

Impact: local same-user exposure of spend secrets and note plaintext, indefinite operation denial, memory exhaustion, and possible event-loop/process blocking. The current Rust prover does not intentionally log secrets, and sensitive tokens are not placed directly in argv. The transport is still weaker than private stdin/IPC and the thrown stderr path can propagate arbitrary child output.

Exploitability: medium. A malicious configured prover is covered separately by F-02; this finding also occurs through a faulty or merely hung binary.

Reproducibility: source inspection. No timeout or output cap exists in `run`; `rm` is reachable only after process close.

Evidence: `writeFile(request, tokens.join(" "), { mode: 0o600 })` at `prover.ts:34`; `spawn` with `stdio: ["ignore", "pipe", "pipe"]` and unbounded `stderr += b` at `:29`; Rust uses unbounded `fs::read_to_string` at `main.rs:182`.

Recommended remediation, not performed: use private stdin or a carefully permissioned IPC channel; if files remain necessary, use a private directory, bounded input/output, timeout, kill/cleanup on abort and process exit, and explicit crash recovery. Do not include raw child stderr in errors without redaction and a size cap. Avoid inherited environment variables and zeroize temporary buffers where practical.

Protocol/on-chain changes required: No.

### F-04 - HIGH - Default note state is volatile and shielded output recovery is incomplete

Classification: `AVAILABILITY / ROBUSTNESS` with high custody-state impact.

Affected files/functions:

- `lethenymous-sdk/src/client.ts:16`, `Lethenymous.shieldedWallet`
- `lethenymous-sdk/src/wallet.ts:9-20,27,30`
- `lethenymous-sdk/src/witness.ts:16-17,33`
- `lethenymous-sdk/src/crypto.ts:6,12-13`
- `shielded-core/src/lib.rs:10,430-482` for the existing envelope compatibility boundary

Security invariant: after a successful shielded operation, the owner must be able to recover note amount, pool, asset, owner material, and randomness after restart or a crash. A note inserted on chain must not become permanently inaccessible merely because the process-local map was lost.

Preconditions: the application uses the default `InMemoryNoteStore`, restarts, crashes between submission and `saveNote`, loses custom store state, or receives a private-swap output whose local record was not durably committed.

Attack/failure path:

1. `shieldedWallet` defaults to a fresh `InMemoryNoteStore`.
2. The witness provider parses shield events but discards the encrypted payload and exposes no scan/decrypt/recovery API.
3. A private swap emits only commitments and indexes on chain; `wallet.ts:30` saves change/output notes locally without `encryptedPayload`.
4. `keyHierarchy` derives spend/view keys but not note randomness, so the randomness for a private-swap output cannot be reconstructed from the seed.
5. On restart or a crash, the local note is unavailable even though custody was transferred on chain.

There is also an envelope-version mismatch: SDK `encryptNote` writes outer version `1` while `shielded-core::decrypt_note` requires `PROTOCOL_VERSION = 2`. The frozen on-chain shield handler currently requires outer version `1`, so the SDK shield can succeed on chain but the current core decryptor rejects the persisted payload.

Impact: funds can be stranded from the user's SDK wallet state, with no supported recovery path. This is not unauthorized movement and does not alter the on-chain custody balance; it is a release-blocking recovery failure.

Exploitability: high under ordinary crash/restart/storage loss; no adversarial RPC is needed.

Reproducibility: direct source inspection. Constructing a default wallet creates a new empty map; `privateSwap` saves output notes without an encrypted payload. The version bytes are visible at `crypto.ts:12-13` and `shielded-core/src/lib.rs:10,461`.

Recommended remediation, not performed: require an application-supplied persistent, encrypted, integrity-protected NoteStore for production use; persist a journal covering reservation, submission, finality, and spent/output transitions; implement finalized chain scanning and authenticated decryption for shield events; define a deliberate envelope version compatible with the frozen on-chain format; include recoverable encrypted payloads or a documented derivation/recovery design for swap outputs.

Protocol/on-chain changes required: No for storage and recovery architecture. The envelope compatibility decision must respect the frozen on-chain version; changing the deployed program is out of scope.

### F-05 - MEDIUM - NoteStore lacks ownership isolation and atomic reservation semantics

Classification: `CORRECTNESS BUG` and `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/types.ts:15,19`
- `lethenymous-sdk/src/wallet.ts:9-13,20,24-25`

Security invariant: a note store must atomically reserve a specific note for one wallet operation, reject conflicting duplicate commitments, preserve spent state, and isolate notes belonging to different wallet identities.

Preconditions: multiple `ShieldedWallet` instances share a store, multiple processes use a persistent store, a custom store returns stale snapshots, or a custom store fails during an asynchronous write.

Attack/failure path:

1. The only NoteStore operations are `getNotes`, `saveNote`, and `markSpent`; there is no compare-and-set reservation, unlock, transaction journal, owner namespace, or duplicate validation.
2. The lock is a private in-memory `Set` on one wallet object. Two wallet instances can select the same note and submit the same nullifier concurrently.
3. The on-chain nullifier prevents both spends from succeeding, but a timeout/error can leave both local attempts ambiguous. A failed `markSpent` or `saveNote` can produce partial state.
4. `InMemoryNoteStore.saveNote` silently overwrites an existing commitment, `markSpent` silently ignores an unknown commitment, and `getNotes` exposes mutable note objects. `addNote` deliberately discards the save promise and any error.
5. Selection does not check `note.ownerCommitment` against the wallet owner commitment. A shared store can therefore expose another wallet's note plaintext and attempt an invalid proof; the proof still binds the wallet's own secret, so this is not an authorization bypass.

Impact: duplicate-spend submissions, cross-wallet local confidentiality exposure when a store is shared, lost updates, and inconsistent recovery. The current one-instance JavaScript lock makes the exact same-wallet `Promise.all` case safe for the ordinary in-memory implementation because the lock check and insertion are synchronous after each await. That protection does not extend across wallet objects or processes.

Exploitability: medium in applications that share a store or run concurrent workers; low for the default single-instance map.

Reproducibility: source inspection. `locked` is declared at `wallet.ts:18`, while store methods have no reservation operation. The default map overwrites by commitment at `wallet.ts:12`.

Recommended remediation, not performed: define an atomic reservation/state-machine interface, namespace records by wallet identity and pool/asset, reject commitment conflicts, clone/validate records, make writes awaitable, and persist an operation journal. Document that a future persistent store must be encrypted and authenticated.

Protocol/on-chain changes required: No.

### F-06 - MEDIUM - Merkle history accepts forged event logs from unrelated programs and incompletely validates event metadata

Classification: `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/witness.ts:15-18,27-35`
- `lethenymous-sdk/src/witness.ts:39-42`

Security invariant: a witness provider must include only successful append events emitted by the configured zkCPMM program for the configured pool, in canonical transaction/log order, and must return a witness only when it agrees with a trusted on-chain root and generation.

Preconditions: an RPC or unrelated program can cause a transaction mentioning the public tree address to contain a forged Anchor event-shaped `Program data` log; or RPC supplies inconsistent transaction metadata.

Attack/failure path:

1. `getSignaturesForAddress` identifies any finalized transaction that mentions the tree PDA.
2. The provider scans every `Program data: ` log in that transaction and calls `readEvent` without checking the emitting instruction/program ID or `tx.meta.err`.
3. A malicious program can emit a valid-looking `ShieldedNoteAppended` or `PrivateSwapped` payload with a forged index/commitment/generation. The map silently overwrites duplicate index keys.
4. The count/max-index check and requested path check usually detect the poison and fail closed. The current root check prevents a forged path from being useful for a valid on-chain proof, but it does not prevent wallet-wide denial of service.

Impact: availability loss, excessive history scanning, and possible inconsistent local diagnostics. A malicious event cannot cause unauthorized movement because the on-chain program recomputes the accepted root/public statement and verifies the proof. The provider also ignores event asset/sequence metadata rather than validating it.

Exploitability: medium for denial of service by an actor able to submit transactions referencing the tree; lower if the tree account is not practically usable by unrelated programs.

Reproducibility: static. There is no `programId` comparison against transaction instruction accounts or log invocation context at `witness.ts:33`. Malformed data is caught and ignored, which is a positive fail-closed behavior when it causes the subsequent count check to fail.

Recommended remediation, not performed: authenticate the event source by inspecting the transaction message/instruction stack as supported by the RPC response; reject failed transactions; validate exact event lengths, asset, index, generation, sequence, and per-transaction ordering; detect duplicate signatures/indexes rather than overwriting. Keep the independent count and root checks.

Protocol/on-chain changes required: No.

### F-07 - MEDIUM - RPC state, history, and confirmation commitments are inconsistent and not independently authenticated

Classification: `AVAILABILITY / ROBUSTNESS` with conditional user-authorized economic impact.

Affected files/functions:

- `lethenymous-sdk/src/client.ts:3-8,13-15`
- `lethenymous-sdk/src/witness.ts:23-42`
- `lethenymous-sdk/e2e/run.mjs:25,40-43`

Security invariant: values used to quote, prove, assemble, and declare success should come from a consistent finalized view, and an RPC response must not be treated as an authorization oracle.

Preconditions: malicious, stale, incomplete, or inconsistent RPC; a connection whose default commitment is `confirmed`; an app immediately spends after a confirmed shield; or an app automatically uses an RPC-derived quote as `minAmountOut`.

Attack/failure path:

1. `getPool`, `getShieldedState`, `getTree`, `getReserves`, and ATA/account reads use the connection default commitment, while witness history and LUT reads explicitly request `finalized`.
2. A tree append can be visible in account state but absent from finalized history, causing witness failure. Reserves or `swapNonce` can change after the read, causing a private proof to be rejected on chain.
3. An RPC can return fake pool/token balances or fake status. A fake reserve can mislead an application that blindly uses `quote`; a fake status can trigger F-01 local-state corruption.
4. A fake tree/root/history pair can produce a locally coherent witness, but the frozen program rejects it if it does not match actual accepted root state.

Impact: availability failure, stale quotes, and application-level economic loss only when the caller treats an unauthenticated quote as an authorization decision. No direct authorization bypass or fund theft was found. The RPC learns public wallet/pool query metadata and operation timing.

Exploitability: high for an RPC operator as a denial-of-service actor; conditional for user-authorized economic impact. A single RPC endpoint cannot cryptographically prove the canonical Solana state to this SDK.

Reproducibility: direct source inspection. `client.ts:3-7` omits explicit commitment; `client.ts:8` confirms at `confirmed`; `witness.ts:29,33` uses finalized history and transactions.

Recommended remediation, not performed: use explicit finalized reads for shielded state transitions or expose the finality tradeoff clearly; re-read and bind reserve/nonce state immediately before proving; treat quotes as advisory and require caller-chosen slippage; consider multiple RPCs or a verified ledger/indexer for a stronger witness trust model; fix F-01 independently.

Protocol/on-chain changes required: No.

### F-08 - MEDIUM - SDK CPMM output omits the frozen program's LP-claim reserve floor

Classification: `CORRECTNESS BUG` and `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/math.ts:3-5`
- `lethenymous-sdk/src/client.ts:13`
- `lethenymous-sdk/src/wallet.ts:30`
- Frozen reference: `programs/zkcpmm/src/math/cpmm.rs:144-162`

Security invariant: an SDK quote and private-swap public statement must equal the on-chain `swap_output_preserving_lp_claims` result, including the `MINIMUM_LIQUIDITY` reserve floor.

Preconditions: a pool is near the minimum reserve needed to preserve positive locked/provider LP claims.

Attack/failure path:

1. The SDK calls ordinary `swapOutput` and does not pass LP supply or `MINIMUM_LIQUIDITY`.
2. It produces an amount-out that would leave the depleted reserve below the on-chain floor.
3. Public swap or private swap is submitted/proved with that amount and the program rejects it at its LP-floor check.

Impact: quotes can be wrong and private operations can waste prover time and fail. There is no direct loss or unauthorized transfer because the program rejects the invalid amount before completing the swap.

Exploitability: deterministic pool-state condition; no malicious actor is required.

Reproducibility: the Rust floor is at `cpmm.rs:155-160`; SDK `math.ts:5` has no equivalent. The targeted boundary example with total LP `1002`, locked LP `1000`, and remaining output reserve at the floor demonstrates a mismatch between ordinary output and the program's rejection condition.

Recommended remediation, not performed: implement the exact frozen floor in SDK quote/private-swap math and add boundary/property tests against the Rust reference.

Protocol/on-chain changes required: No.

### F-09 - MEDIUM - Default legacy transaction path cannot serialize unshield/Private Send transactions

Classification: `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/client.ts:8`
- `lethenymous-sdk/src/wallet.ts:28-29`
- `lethenymous-sdk/src/types.ts:7`

Security invariant: every supported operation should either compile into a valid transaction or fail before signing, without silently relying on an undocumented external LUT configuration.

Preconditions: `lookupTables` is omitted, as it is by the default `Lethenymous` constructor, and the application calls unshield or its `privateSend` alias.

Attack/failure path:

1. `buildAndSend` selects a legacy `Transaction` whenever `lookupTables.length === 0`.
2. The unshield instruction includes the proof and 320-byte public-input vector plus the recipient, custody, nullifier, and system accounts.
3. Serialization exceeds Solana's legacy 1232-byte packet limit before the transaction is submitted.

Impact: default unshield/Private Send is unavailable. An application configured with the known v0 LUT can work, as demonstrated by the supplied E2E flows. This is not a security bypass.

Exploitability: deterministic configuration/operation condition; a malicious LUT is not required.

Reproducibility: constructing a representative legacy unshield transaction with the SDK codec produced `Transaction too large: 1417 > 1232` with distinct account keys. The exact size varies with account-key deduplication, but it remains over the limit for the normal account set.

Recommended remediation, not performed: make a size-safe v0/LUT path the documented/default private-operation path, or fail early with a clear requirement for a specific validated LUT. Add a size regression test.

Protocol/on-chain changes required: No.

### F-10 - MEDIUM - Public `programId` configuration is ignored by PDAs and instruction builders

Classification: `CORRECTNESS BUG` and `DEVELOPER UX` with availability impact.

Affected files/functions:

- `lethenymous-sdk/src/types.ts:7`
- `lethenymous-sdk/src/client.ts:2,4-6`
- `lethenymous-sdk/src/pda.ts:2,5-15`
- `lethenymous-sdk/src/instructions.ts:1,3-11`

Security invariant: all account derivations, reads, witness tree addresses, and instruction program IDs must bind to the configured deployment identity.

Preconditions: an application supplies a non-default `ClientConfig.programId`.

Attack/failure path:

1. `Lethenymous` stores the configured ID.
2. `pda` and `ix` continue to use the hardcoded `PROGRAM_ID` from `encoding.ts`.
3. Reads derive default-program accounts and transactions target the default program even though the caller selected another deployment.

Impact: custom deployments fail or can cause a caller to sign a transaction for an unintended program/account set. The default frozen program ID is correct, and this bug does not bypass authorization on either program.

Exploitability: deterministic custom-configuration condition.

Reproducibility: source inspection. No builder receives `this.programId`; E2E works only because its configured ID equals the hardcoded ID.

Recommended remediation, not performed: thread a validated program ID through every PDA and instruction builder, or remove the public configuration option and make the fixed deployment explicit. Add a non-default-ID parity test.

Protocol/on-chain changes required: No.

### F-11 - LOW - Proving-key identity is only conditionally hard-bound and is subject to path TOCTOU

Classification: `SECURITY CONTROL GAP` and `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/prover.ts:18-28,30-34`
- `artifacts/production-groth16-v1/manifest.json:28-34`

Security invariant: the private-swap and unshield proving keys must be authenticated to the expected production artifacts, remain the same object used for proving, and be bound to the intended circuit/version.

Preconditions: application configuration is mutable or attacker-controlled, or an attacker can replace a file between `sha256(path)` and the Rust prover reopening the path.

Attack/failure path:

1. `ProductionProverConfig` accepts both PK paths and expected hashes as arbitrary strings.
2. The SDK hashes only the selected path before creating the request and spawning the child.
3. The Rust prover later reopens the path from `PRODUCTION_PRIVATE_PK` or `PRODUCTION_UNSHIELD_PK`.
4. A path can be replaced between those operations, or a caller can supply a different expected hash. A wrong circuit PK normally yields a proof rejected by the embedded VK, but the result is still denial of service/provenance failure.

Impact: hash checking is useful against ordinary pre-existing file corruption when the caller passes the published constants, but it does not authenticate path identity, atomic file identity, circuit manifest, or the executable. No valid proof for the frozen VK was shown to result from a wrong PK.

Exploitability: low to medium and primarily local. This is not a remote fund-theft path under the frozen VK.

Reproducibility: source inspection. `PRODUCTION_ARTIFACT_SHA256` contains the correct current PK hashes, and verification occurs before proving, but the constructor does not require those constants and the Rust process reopens paths.

Recommended remediation, not performed: bind the production artifact manifest/version and expected hashes in the SDK configuration, reject arbitrary expected hashes for the production mode, use immutable/open file handles or an equivalent TOCTOU-resistant design, validate exact artifact lengths, and keep PK identity checks separate from executable authentication.

Protocol/on-chain changes required: No.

### F-12 - LOW - Production VK verification script rejects the manifest's valid unshield VK length

Classification: `CORRECTNESS BUG` in release tooling and `DEVELOPER UX`.

Affected files/functions:

- `scripts/verify_vk.sh:8-9`
- `artifacts/production-groth16-v1/manifest.json:33-34`
- `programs/zkcpmm/src/shielded_verifier.rs:13-15`

Security invariant: the release verification gate must agree with the artifact manifest and the verifier's embedded expected representation.

Preconditions: a production build runs `scripts/build-production.sh`, which invokes `scripts/verify_vk.sh`.

Attack/failure path: the script expects `unshield_vk.production.hex` to be `4608` bytes, while the manifest, file, and embedded verifier expect `2304` bytes. The script exits nonzero before production build/tests complete.

Impact: release automation is blocked or operators may bypass a security gate. This does not change runtime SDK PK handling or authorize a bad proof.

Exploitability: deterministic local/release condition.

Reproducibility: `wc -c` returned `2304`; `./scripts/verify_vk.sh` failed at the `4608` assertion.

Recommended remediation, not performed: reconcile the script with the frozen manifest or explicitly document why a different representation is expected, then rerun the gate. Do not silently bypass it.

Protocol/on-chain changes required: No.

### F-13 - LOW - Low-level encoders accept lossy JavaScript numbers and reduce noncanonical fields

Classification: `CORRECTNESS BUG` and `DEVELOPER UX`.

Affected files/functions:

- `lethenymous-sdk/src/encoding.ts:13,16,23`
- `lethenymous-sdk/src/prover.ts:12-16`
- `lethenymous-sdk/src/pda.ts:5,16`

Security invariant: all u64/u16/enum protocol values must be exact integers in range, and field byte values that are protocol-bound must be rejected when noncanonical rather than silently reduced.

Preconditions: a caller uses low-level exported helpers with a JavaScript `number`, fraction, unsafe integer, or a 32-byte field at or above the BN254 modulus.

Attack/failure path:

1. `u64` accepts `bigint | number`, so a number already rounded by IEEE-754 is converted to BigInt after loss of precision.
2. `enumByte` checks only bounds; `Buffer.from([1.5])` becomes `01`. `u16` similarly accepted `1.5` and encoded `0100` in the observed Node runtime.
3. `encodeUnshieldPublicInputs` and private-swap encoding apply modulo reduction through `field` to roots, nullifiers, and commitments. The on-chain unshield/private-swap instruction compares raw values and requires canonical fields.

Impact: a caller can construct bytes different from the intended amount/direction, or receive a transaction that deterministically fails because public inputs use reduced values while instruction arguments use raw values. The typed high-level amount APIs use bigint, and the frozen program rejects malformed values; no direct unauthorized movement was found.

Exploitability: low and primarily caller-misuse. The documented README says amounts are bigint, but the exported low-level APIs permit the unsafe forms.

Reproducibility: targeted probe returned `u64(Number.MAX_SAFE_INTEGER + 1) = 0000000000002000`, `u16(1.5) = 0100`, and `enumByte(1.5) = 01`.

Recommended remediation, not performed: accept bigint for all protocol integers, validate safe integer/integer/range at API boundaries, reject noncanonical field values, and add mutation tests for every public-input field.

Protocol/on-chain changes required: No.

### F-14 - LOW - ATA helpers reject valid off-curve recipients and do not validate an existing account before skipping creation

Classification: `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/wallet.ts:26`
- `lethenymous-sdk/src/client.ts:11,14-15`

Security invariant: recipient ATA preparation must support every recipient authority accepted by the frozen instruction and must fail closed when an existing address has the wrong owner or mint.

Preconditions: recipient is a valid off-curve PDA, or the canonical ATA address is pre-existing but malformed.

Attack/failure path:

1. `getAssociatedTokenAddressSync` is called without `allowOwnerOffCurve`.
2. A PDA recipient fails locally even though the unshield instruction does not require the recipient to sign and can bind an off-curve authority through token-account constraints.
3. If account info exists, `ensureRecipientAtas` skips creation without decoding and validating owner/mint. The later on-chain instruction rejects a malformed account.

Impact: valid recipient operations fail; malformed pre-existing accounts cause confusing failures. Account constraints prevent redirection of funds.

Exploitability: low, requiring a particular recipient/account configuration.

Reproducibility: direct source inspection; the default SPL helper rejects off-curve owners.

Recommended remediation, not performed: explicitly support or intentionally reject off-curve recipients in the public API; decode existing accounts and verify canonical ATA, mint, owner, and token program before deciding preparation is complete.

Protocol/on-chain changes required: No.

### F-15 - LOW - `removeLiquidity` does not prepare destination ATAs

Classification: `AVAILABILITY / ROBUSTNESS` and `DEVELOPER UX`.

Affected files/functions:

- `lethenymous-sdk/src/client.ts:12`
- `lethenymous-sdk/src/instructions.ts:8`

Security invariant: a supported high-level liquidity operation should either create its user's destination token accounts idempotently or clearly require them before submission.

Preconditions: a provider has no existing token A/B ATA when calling `removeLiquidity`.

Attack/failure path: the helper derives destination ATAs and submits only `remove_liquidity`; the on-chain token transfers fail because the destination accounts do not exist.

Impact: withdrawal helper unavailable for a common first-time user case. No funds are transferred by a failed atomic transaction.

Exploitability: deterministic user-state condition.

Reproducibility: compare `client.ts:11` and `:12`; add-liquidity creates three idempotent accounts while remove-liquidity creates none.

Recommended remediation, not performed: prepare the two destination ATAs idempotently in a separate transaction or document the precondition.

Protocol/on-chain changes required: No.

### F-16 - LOW - LUT configuration is not validated beyond account availability

Classification: `AVAILABILITY / ROBUSTNESS`.

Affected files/functions:

- `lethenymous-sdk/src/types.ts:7`
- `lethenymous-sdk/src/client.ts:8`

Security invariant: a configured address lookup table must be the intended active table and must not create account-index or signer confusion.

Preconditions: caller supplies a stale, deactivated, wrong, or malicious LUT public key.

Attack/failure path:

1. The SDK fetches the table at finalized commitment and checks only that it is non-null.
2. It compiles a v0 message with the table and requires a versioned transaction signer.
3. A wrong table normally leaves required addresses static or makes compilation/execution fail; a stale/deactivated table can make the transaction fail. The lookup table cannot replace an instruction's explicit `PublicKey` with a different key; semantic accounts are not silently altered by table contents.

Impact: operation failure, excess static accounts, or confusing signer/size behavior. No fund theft or authorization bypass was found.

Exploitability: low and configuration-dependent.

Reproducibility: source inspection. `client.ts:8` checks table presence/length but not activation/deactivation state or expected address set.

Recommended remediation, not performed: validate table identity, activation, expected addresses, writable/read-only usage, and signer constraints; fail closed when contents differ from the expected deployment configuration.

Protocol/on-chain changes required: No.

### F-17 - INFORMATIONAL - SDK candidate source and generated package are outside release provenance

Classification: `DEVELOPER UX` and release-integrity risk.

Affected files/functions:

- Untracked `lethenymous-sdk/` working-tree directory
- `release/manifest.json:5-7`
- `scripts/build-production.sh:7-10`

Security invariant: the audited source, generated package, dependency lock, and published tarball must be reproducible and attributable to a recorded candidate commit.

Preconditions: the SDK is published or reviewed from the current working tree without first committing/attesting it.

Attack/failure path: the release manifest and dirty-worktree guard cover the existing protocol archive, but no SDK source/dist hash or commit is recorded. Any untracked change to the SDK can change the package without the program release guard detecting it.

Impact: audit scope cannot be reproduced from `HEAD`; package consumers and reviewers cannot establish that the published tarball is the audited artifact. This is a release blocker despite the informational runtime classification.

Exploitability: high as a release-process/provenance weakness; not a runtime attack against a correctly packaged tarball.

Reproducibility: `git ls-files lethenymous-sdk` returned no paths and `git status` showed the whole directory untracked.

Recommended remediation, not performed: commit or otherwise attest the exact SDK source, generated `dist`, lockfile, package tarball hash, and audit report; extend release checks to include SDK provenance. Do not create a tag or publish during this audit.

Protocol/on-chain changes required: No.

### F-18 - LOW - Production dependency audit reports nine advisories with no compatible automatic fix

Classification: `SUPPLY-CHAIN RISK` and `AVAILABILITY / ROBUSTNESS`; actual SDK impact is lower than several npm severity labels.

Affected package: the production dependency graph in `lethenymous-sdk/package-lock.json`.

Security invariant: production dependencies must not expose reachable parsers/native helpers with known memory-safety or denial-of-service advisories without an accepted risk decision.

Preconditions: a consumer installs the package with the current lock-resolved production graph and receives adversarial RPC/account data or invokes affected transitive code.

Audit result: `npm audit --omit=dev --json` reported 9 findings: 3 high, 6 moderate, 0 critical. The exact findings are:

| Package and installed version | npm severity and issue | Dependency chain | Fixed version/status | Runtime reachability and actual SDK risk |
| --- | --- | --- | --- | --- |
| `@solana/buffer-layout-utils 0.3.0` | High via `bigint-buffer` and web3 | `@solana/spl-token -> @solana/buffer-layout-utils` | npm proposes `@solana/spl-token 0.1.8`, semver-major and not a normal upgrade | Token account decoding reaches this package through `getAccount`; fixed-width u64 layouts limit the demonstrated exploit to possible parser/availability risk. |
| `@solana/spl-token 0.4.15` | High through buffer-layout-utils, group, metadata, web3 | Direct SDK dependency | npm proposes `0.1.8`, semver-major/downgrade-like and incompatible with the SDK API surface | Directly used for ATA and token account operations. No fund-theft path demonstrated. |
| `@solana/spl-token-group 0.0.7` | Moderate via web3 | `@solana/spl-token -> @solana/spl-token-group -> @solana/web3.js` | Same proposed `@solana/spl-token 0.1.8` major change | Not directly imported by SDK code; transitive supply-chain surface. |
| `@solana/spl-token-metadata 0.1.6` | Moderate via web3 | `@solana/spl-token -> @solana/spl-token-metadata -> @solana/web3.js` | Same proposed `@solana/spl-token 0.1.8` major change | Not directly imported by SDK code; no demonstrated reachable exploit. |
| `@solana/web3.js 1.99.0` | Moderate through `jayson` | Direct SDK dependency -> `jayson 4.3.0` | npm proposes `@solana/web3.js 0.0.3`, semver-major and not a viable modern fix | Core RPC/transaction path is reachable. Advisory consequence is primarily parser/client availability; no authorization bypass found. |
| `bigint-buffer 1.1.5` | High, buffer overflow in `toBigIntLE`, range `<=1.1.5` | `@solana/spl-token -> @solana/buffer-layout-utils -> bigint-buffer` | No patched release reported; npm suggests changing SPL Token | Native/fallback conversion is used by fixed-width layouts. No direct SDK call with attacker-controlled arbitrary width was found. Treat as a supply-chain/DoS risk. |
| `jayson 4.3.0` | Moderate through `stream-json` and `uuid` | `@solana/web3.js -> jayson` | `jayson 5.0.0` removes the vulnerable dependency path, but web3 1.x requires the 4.x line | Web3 RPC client reaches jayson. A compatible upgrade is not available without a web3/API change. |
| `stream-json 1.9.1` | Moderate O(depth^2) nested-input DoS, vulnerable `<=3.4.0` | `jayson -> stream-json` | Fixed at `3.5.0` or through jayson 5.0.0; not selected by current web3 | Jayson uses it for server/stream parsing; the SDK's observed HTTP client path uses ordinary response parsing. No direct SDK server path. |
| `uuid 8.3.2` | Moderate missing bounds checks in v3/v5/v6, vulnerable `<11.1.1` | `jayson -> uuid` | `uuid >=11.1.1` or jayson 5.0.0; current jayson uses `uuid.v4` | The observed jayson request-ID path calls v4, not the vulnerable v3/v5/v6 APIs. No demonstrated exploit in SDK use. |

The findings are runtime dependencies, not dev-only dependencies. The current actual risk is primarily denial of service and supply-chain exposure under malicious RPC/native/parser inputs, not unauthorized token movement. No force upgrade was performed.

Recommended remediation, not performed: obtain a compatible patched Solana dependency line or document/mitigate the residual risk; test affected RPC/account decoding with adversarial data; do not apply npm's proposed major/downgrade changes automatically.

Protocol/on-chain changes required: No.

### F-19 - INFORMATIONAL - Stale internal IDL and external setup documentation can mislead consumers

Classification: `DEVELOPER UX` and release documentation risk.

Affected files/functions:

- `target/idl/zkcpmm.json:2` and `target/types/zkcpmm.ts:8` in the repository archive
- `lethenymous-sdk/README.md:30-56`

Evidence: the generated internal IDL uses the obsolete `ZkCpMm111...` address and contains stale instruction/state details, while the SDK source-derived codecs use the current program ID. The package README references undeclared `keypair`, `poolAddress`, and `swapOutput` variables and repository-relative prover/PK paths that are absent from the npm tarball.

Impact: consumers can assemble invalid calls or believe the packaged npm artifact includes production proving infrastructure. This is not a protocol or authorization vulnerability.

Exploitability: low; primarily accidental misuse.

Recommended remediation, not performed: regenerate/retire the stale internal IDL, correct the README example, and explain how an external consumer obtains and authenticates the local prover and PKs.

Protocol/on-chain changes required: No.

## Non-Findings and Control Results

### Secret handling

The production SDK source contains no `console.log` of spend secrets, view keys, randomness, note plaintext, witnesses, or proofs. The E2E harness logs public program/pool/payer/recipient identifiers and flow results, not the seed value. The Rust production prover does not intentionally log the witness. The SDK does not serialize sensitive values into JSON automatically.

Sensitive values do appear in these places:

- `ShieldedWallet.spendSecret`, `viewKey`, and note randomness are held as ordinary mutable `Uint8Array` values in process memory.
- `ProductionProver` writes witness material, including spend secret and randomness, to a mode-`0600` temporary request file.
- The child inherits `process.env`; the E2E seed is an environment variable and is therefore visible to a substituted child.
- A custom NoteStore can persist plaintext `Note` fields unless the application encrypts it.
- Child stderr is included in thrown errors without redaction or a bound. A malicious child can put arbitrary sensitive data into that output.

Sensitive witness values are not passed directly as process arguments. The process arguments contain only the circuit name and temporary file paths. `spawn` is used without shell interpolation, so attacker-controlled values are not shell-expanded. This removes the direct OS process-list exposure identified for argv, but does not remove temporary-file or unauthenticated-child exposure.

### Randomness

No production SDK use of `Math.random`, timestamp-based randomness, or predictable counters was found. `cryptoRandom` uses `globalThis.crypto.getRandomValues` and throws if secure randomness is unavailable. Shield randomness, private-swap change/output randomness, and AEAD nonces are generated independently. The Rust prover uses `rand::rngs::OsRng` for Groth16 proof randomness. `Math.random` occurrences were limited to an unused transitive `bignumber.js` random helper, not an SDK call site.

The deterministic HKDF key hierarchy is intentional seed derivation, not nonce generation. Concurrent calls on one wallet receive independent randomness; the local note reservation limitations are covered by F-05.

### Public-input parity

The TypeScript builders match the frozen Rust statements for canonical values.

Unshield encodes exactly 10 fields in this order:

```text
domain, pool_hi, pool_lo, asset_hi, asset_lo,
root, nullifier, amount, recipient_hi, recipient_lo
```

Private swap encodes exactly 22 fields in this order:

```text
domain, pool_hi, pool_lo, asset_in_hi, asset_in_lo,
asset_out_hi, asset_out_lo, root, root_sequence, generation,
nullifier, reserve_in, reserve_out, fee_bps, amount_in,
amount_out, change_amount, change_commitment, output_commitment,
direction, protocol_version, swap_nonce
```

Both expected lengths are enforced by the package tests (`320` and `704` bytes), and `ShieldedWallet` compares returned prover public inputs against its own encoding before building a private transaction. Canonical values use the same big-endian field encoding and 16-byte public-key limbs as Rust. Noncanonical modulo behavior is F-13.

### Instruction and account parity

The source-derived instruction codecs match the current Rust account ordering and discriminator calculations for the supported instructions: initialize pool, initialize shielded state, add/remove liquidity, public swap, shield, unshield, and private swap. The prior E2E-sensitive `shielded_state`, private-swap remaining accounts, and unshield recipient/spent/system accounts are present in the expected positions and flags. The recipient is read-only and is not a signer; the SDK payer signs.

The hardcoded program identity defect is F-10. Direct `initializeShieldedState` without a supplied state uses zero default mint keys (`instructions.ts:5`) and fails on chain; the high-level client supplies the pool mints. This is a low-level misuse variant of the same configuration/correctness class, not a separate authorization finding.

### Private Send and recipient binding

`privateSend` is exactly `return this.unshield(input)` at `wallet.ts:29`. The proof public inputs bind `recipient`, and the instruction passes the same recipient plus ATAs derived from that recipient. The frozen program checks each selected recipient token account's mint and authority and does not require the recipient to sign. `note owner != payer != recipient` is therefore supported for on-curve recipients. Off-curve helper behavior is F-14.

### ATA, LUT, and compute-budget controls

Idempotent ATA creation is separated from proof transactions in `ensureRecipientAtas`; payer behavior and a race where another transaction creates the ATA are safe for a correct ATA because the instruction is idempotent. A wrong pre-existing account fails closed on chain. The missing validation/off-curve limitations are F-14 and F-15.

LUT compilation uses explicit instruction public keys. A wrong table cannot substitute a different semantic account; it causes static keys, compilation failure, or execution failure. Validation gaps are F-16.

Private swap requests `1,400,000` compute units and unshield/private send requests `500,000`. Devnet evidence measured approximately `1,198,924` and `351,728` CU. The SDK sets no compute-unit price and exposes no priority-fee override, so malformed user configuration cannot cause an unexpectedly large priority fee through these helpers. The values are within the u32 compute-budget instruction range.

### Malicious RPC consequences

| RPC behavior | Funds/authorization | Availability | Privacy |
| --- | --- | --- | --- |
| Fake pool/reserve/token balance | Cannot change on-chain account constraints; may cause a user-authorized public swap to use a bad caller-selected quote | Quote/proof failure or wrong advisory quote | RPC sees queries |
| Omitted/reordered/missing event | Cannot make a false proof pass the program | Provider should fail; current count/root checks usually do | Scanning pattern visible |
| Fake tree/root/history | Cannot pass actual on-chain accepted-root/proof checks | Witness or transaction failure | RPC learns pool/history queries |
| Fake confirmation or ignored execution error | Does not change chain state | Can corrupt local note state through F-01 | Timing/status metadata exposed |
| Stale confirmed account versus finalized history | No authorization bypass | Proof/history mismatch and retry burden | RPC sees operation timing |
| Mutated submitted bytes | Wallet signature invalidates mutation | Submission failure | No additional secret disclosure |

### Transaction retries and forks

There is no explicit SDK retry loop. A dropped/expired transaction normally causes `sendRawTransaction` or `confirmTransaction` to reject, and unshield/private-swap catch blocks release the in-memory lock. If the transaction actually landed but the client timed out, a retry can submit the same nullifier; the chain rejects the duplicate, but local state cannot identify which attempt won. If a transaction is only confirmed and later reorged, the SDK has already updated local state. These are covered by F-01 and F-05. Nullifiers protect consensus correctness, not local recovery.

### Privacy boundary

The SDK does not claim anonymity. RPC sees pool, payer, transactions, commitments, nullifiers, timing, public amounts/assets as applicable, and unshield recipients. The local prover is not remote, and no witness is sent to an RPC. Additional leakage comes from sequential finalized-history scans, per-transaction RPC requests, retries, and local note identifiers. The unauthenticated local prover and plaintext temporary file are the material additional secret-leak paths, covered by F-02/F-03.

## Dependency and Package Conclusions

The packed tarball is clean and exports only the documented package entry point, but the package depends on nine production-advisory-affected transitive nodes and does not bundle the prover/PK material needed for private operations. External import worked from a clean temporary project and did not depend on monorepo resolution. Package readiness is still blocked by the runtime findings, provenance gap, and unresolved dependency risk.

## Initial Required Summary

```text
CRITICAL: 0
HIGH: 3
MEDIUM: 7
LOW: 7
INFORMATIONAL: 2
```

1. Can the current SDK cause unauthorized movement of funds?

No direct path was found. The SDK can submit malformed, stale, duplicate, or failed-state transactions, but the frozen program enforces proof/public-input/account/nullifier/token authorization. A compromised local prover that exfiltrates spend material can enable later unauthorized proof generation; this is the F-02 local trust-boundary risk, not an RPC or instruction bypass.

2. Can malicious RPC responses compromise authorization, or only availability/state reconstruction?

For the audited paths, malicious RPC can cause availability failures, stale/fake quotes, misleading status, and local state corruption. It cannot make a false root/proof or recipient account pass the frozen on-chain checks. User-authorized economic loss remains possible if an application blindly treats an RPC quote as an authorization decision.

3. Can secrets leak through the prover subprocess?

Yes, if the configured executable is malicious or compromised. Secrets are not in argv, but plaintext request files, inherited environment variables, and unbounded stderr/output handling expose them to the child and potentially to local observers. The binary itself is not authenticated.

4. Can local note state become inconsistent after timeout/crash/retry?

Yes. Confirmation errors are ignored, confirmed state is not finalized, writes are not journaled, and restart loses the default store. A timeout after landing can result in duplicate retry attempts and an apparently unspent local note; a reported execution error can mark a note spent or create phantom outputs.

5. Is Merkle reconstruction fail-closed?

Partially. Missing history, malformed events, wrong counts, and paths that do not match the RPC-supplied current root generally fail closed. It is not a complete malicious-RPC fail-closed boundary because it does not authenticate the event-emitting program, does not reject every failed transaction based on transaction metadata, and trusts the same RPC for the root and history. The remaining consequence observed is denial of service, not a demonstrated valid false spend.

6. Is Private Send recipient binding preserved by the SDK?

Yes for supported on-curve recipients. It is exactly unshield; recipient is bound in the public inputs and instruction, ATAs are derived from that recipient, and recipient is not incorrectly made a signer. Off-curve recipient support is an availability limitation.

7. Are production proving keys safely authenticated?

Partially. The published PK hashes are correct, the selected PK is hashed before proving, and private/unshield selection is distinct. However, expected hashes and paths are caller-configurable, the path is reopened after hashing, and there is no manifest/circuit-version or atomic file-identity check. Wrong keys should fail against the embedded VK rather than authorize funds.

8. Is the prover executable itself authenticated?

No. `ProductionProver` accepts an arbitrary executable path and does not verify a digest, signature, owner, or trusted installation source.

9. Are there unsafe JS Number conversions?

Yes in exported low-level encoders and PDA/enum inputs. High-level token amounts are bigint, but `u64`, `u16`, and `enumByte` accept numbers and can round or truncate them. Public-input field helpers also reduce noncanonical values instead of rejecting them.

10. Are any npm audit findings realistically exploitable?

The nine production findings are real dependency advisories, but no direct fund-theft path was demonstrated. The most plausible SDK impact is parser/native-code denial of service under adversarial RPC/account data or supply-chain exposure. Several vulnerable functions are not used by the observed SDK path, and npm's proposed fixes are incompatible major changes or a nonsensical old Solana version. They still require an explicit release risk decision.

11. Is the current package safe to publish as v0.1.0?

No. The package tarball is clean and imports externally, but failed-transaction state handling, unauthenticated secret-bearing prover execution, non-recoverable note state, partial witness trust, provenance, and dependency findings block publication.

12. Which findings MUST be fixed before npm publication?

At minimum: F-01, F-02, F-04, F-06, F-08, F-09, F-10, and F-17. F-03, F-05, F-07, F-11, F-12, F-13, F-14, F-15, F-16, F-18, and F-19 require remediation, an explicit documented risk acceptance, or removal of the affected public promise before publication. No forced dependency upgrade is recommended without compatibility testing.

## Initial Release Classification

`BLOCKED`

Reason: the candidate has three high-severity findings, multiple medium correctness/availability findings affecting supported private operations, an unauthenticated secret-bearing prover boundary, no durable note recovery, an uncommitted/unattested SDK candidate, and a failing production VK release gate. No release tag or npm publication was performed.

## Remediation and Re-Audit

No remediation was performed before this report. The missing full lifecycle regression and any future remediation must occur after this initial report and be recorded in a separate dated section or follow-up report that preserves the findings above as the initial baseline.

### Post-report lifecycle regression attempt

The regression was attempted after this initial report was completed. The current shell has no isolated E2E fixture configuration: `E2E_POOL`, `E2E_BOB_KEYPAIR`, and `E2E_SEED_HEX` are absent, and no LUT was configured. The E2E harness correctly refuses to run without an isolated pool and Bob keypair. No secret values were printed or reconstructed from the workspace, and no Devnet transaction was submitted. The full lifecycle therefore remains pending due to unavailable funded fixture credentials, not a new protocol result.

Pending post-report work:

- Rerun the fully funded `Shield A -> Private Swap A->B -> Private Swap B->A -> Unshield A` Devnet flow.
- Decide and implement only approved remediations without modifying the frozen program, circuits, production PK/VK bytes, or SBF.
- Re-run the findings-specific tests, package audit, packed external consumer test, and all E2E flows.
- Record residual risk and a final `READY FOR REMEDIATION`, `READY FOR RELEASE`, or `BLOCKED` classification after re-audit.
