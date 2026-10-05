# Lethenymous SDK v0.1.0 Remediation Record

This record documents remediation performed after the preserved initial audit:

`lethenymous-sdk/SECURITY_AUDIT_V0.1.0.md`

The initial report and all original finding text remain unchanged. No on-chain
zkCPMM semantics, Groth16 circuit, production PK/VK bytes, or frozen SBF were
modified.

## Remediation Summary

- F-01: transaction outcome state machine and finalized error handling implemented.
- F-02: production prover executable authentication implemented.
- F-03: witness IPC moved to bounded private stdin with timeout and cleanup.
- F-04: persistent encrypted journal, restart reconciliation, and shield recovery implemented.
- F-05: atomic note reservation, ownership isolation, duplicate rejection, and awaited mutations implemented.
- F-06: finalized program-authenticated event replay and duplicate/history validation implemented.
- F-07: explicit finalized reads and operation reconciliation implemented; single-RPC availability remains documented.
- F-08: exact frozen LP-claim reserve-floor math implemented.
- F-09: private proof operations require validated v0/LUT configuration before proving.
- F-10: configured program ID is threaded through PDA, instruction, account, and witness paths.
- F-11: PK identity is compiled into the SDK and independently validated inside the prover process.
- F-12: VK gate now reads hashes and sizes from the canonical production manifest.
- F-13: protocol integer and BN254 field encoders reject lossy/noncanonical inputs.
- F-14: ATA derivation and existing-account validation are explicit and off-curve-aware.
- F-15: remove-liquidity prepares destination ATAs idempotently.
- F-16: LUT existence, activation, authority, expected contents, and slot usability are validated when configured.
- F-17: release provenance metadata and authenticated prover/checkpoint manifests were added; the SDK source will be bound to the candidate source commit in the release manifest.
- F-18: dependency audit was rerun; no compatible safe upgrade exists without an incompatible Solana-stack change.
- F-19: package documentation was corrected and explicitly identifies source-derived codecs instead of a generated IDL.
- Additional pre-release review: the frozen TreeState account length, ambiguous submission path, journal crash ordering, event-time root replay, and spent-note recovery were corrected before re-audit closure.

## Finding Records

### F-01 - Transaction success and note-state correctness

**Status:** `CLOSED` for the identified correctness defect.

**Changes:**

- `src/client.ts` now exposes `buildAndSendOutcome` with `finalized-success`, `finalized-failed`, and `unknown` outcomes.
- Confirmation always uses an explicit finalized commitment and rejects non-null `confirmation.value.err`.
- Timeout reconciliation checks signature status, finalized transaction metadata, and block-height expiry.
- A signed transaction's primary signature is derived before submission; acknowledgement errors remain `unknown` instead of releasing a note.
- Reconciliation RPC failures remain `unknown` rather than entering failure cleanup.
- `TransactionFailedError`, `TransactionUnknownError`, and `LookupTableRequiredError` provide typed failure boundaries.
- Wallet note mutations occur only after finalized success. Unknown outcomes leave the input submitted/reserved and journaled.
- `ShieldedWallet.reconcilePending` reconciles signatures and requires a matching authenticated program event before committing journal state.

**Tests:** `remediation.test.mjs` covers finalized execution error, timeout without finality, timeout after finality, acknowledgement loss with a derived signature, RPC reconciliation failure, and blockhash expiry. The persistent journal tests cover reservation and submitted-state recovery.

**Residual:** A single RPC remains an availability trust boundary; this is documented under F-07 and is not an authorization bypass.

### F-02 - Production prover executable authentication

**Status:** `CLOSED` for the arbitrary-executable finding.

**Changes:**

- `src/prover.ts` pins the target-specific executable SHA-256 and exact version `production-prover 0.2.0 ipc-v1`.
- The SDK resolves the real path, requires a regular non-group/other-writable file, checks the digest, and verifies `--version` before every proof.
- The production configuration no longer accepts caller-supplied expected PK hashes.
- `release/production-prover-manifest.json` records the authenticated `darwin-arm64` release binary digest and size.
- Custom implementations remain outside `ProductionProver` through the explicit `Prover` interface and are not presented as authenticated production provers.

**Tests:** malformed/legacy prover invocation is rejected before processing witness material; executable policy rejects an unauthenticated path.

**Residual:** Other operating-system targets fail closed until their authenticated release-manifest entry exists.

### F-03 - Plaintext witness-file IPC and unbounded process behavior

**Status:** `CLOSED` for the identified IPC/resource defects.

**Changes:**

- TypeScript sends a bounded LF-delimited `zkcpmm-prover-ipc-v1` request over private stdin.
- No request/output files, argv witness secrets, PK environment variables, or inherited application environment are used.
- Rust accepts only `--stdin-v1`, validates UTF-8, framing, token count, hex, integers, Merkle bounds, and request size.
- Rust emits one bounded binary response frame containing exact proof/public-input lengths.
- TypeScript bounds stdout, stderr, request size, proof timeout, and version probing.
- Timeout/output overflow kills the child and returns a fixed non-secret error.
- Rust validates PK file size before bounded reading and writes no output files.
- Devnet and program proof fixtures were migrated to the same stdin/frame protocol.

**Tests:** legacy file IPC, malformed framing, bounded output behavior, and non-secret errors are covered by `remediation.test.mjs`; Rust and fixture tooling compile with the new interface.

### F-04 - Volatile note state and incomplete shield recovery

**Status:** `MITIGATED`; no unresolved HIGH under the documented production storage model.

**Changes:**

- `Lethenymous.shieldedWallet` refuses to silently create an in-memory production store.
- `EncryptedFileNoteStore` provides an encrypted/authenticated append-only journal with an exclusive writer lock, crash-tolerant final-frame handling, atomic note transitions, operation records, backup export, and backup import.
- Storage keys use a dedicated HKDF branch and are not the view key.
- Notes are cloned, owner-scoped, commitment-validated, and stateful.
- Shielded operation intents persist sensitive preimages before proving; signed transaction bytes and signatures are journaled before confirmation.
- Private input reservation and operation intent are persisted by one journal event; restart recovery derives a signature from prepared signed bytes when necessary.
- Finalized shield events can be scanned, authenticated, decrypted using the frozen outer-version-1 envelope, checked against the owner, and reconstructed into notes.
- Finalized `Unshielded` and `PrivateSwapped` events are scanned for nullifiers so recovered shield notes are marked spent instead of reintroduced as available.
- `shielded-core` and the frozen on-chain program were not changed. SDK recovery explicitly supports the deployed outer payload version.

**Tests:** encrypted journal restart, atomic reserve-plus-begin, idempotent spend recovery, reservation, competing reservation, encrypted backup contents, and frozen outer-version-1 authenticated decryption are covered.

**Accepted residual risk:** Loss of the seed plus the journal/backups remains unrecoverable. Existing private-swap outputs created with random output randomness cannot be recovered from chain data alone because the frozen event does not contain that randomness. Durable journal/backup custody is therefore a production precondition and is documented in the README.

### F-05 - NoteStore ownership and reservation semantics

**Status:** `CLOSED` for the identified store defects.

**Changes:**

- Note stores now expose atomic `reserveNote`, `markSubmitted`, `markSpent`, and `releaseReservation` operations.
- Journaled stores expose atomic `reserveNoteAndBegin`, preventing an input reservation from existing without its operation intent.
- Notes are namespaced by owner commitment through store validation and wallet filtering.
- Conflicting duplicate commitments are rejected.
- Unknown or invalid state transitions fail instead of being ignored.
- Wallet-local `Set` locking is no longer authoritative; the store transition is authoritative.
- Mutations are awaited and returned notes are cloned.
- `InMemoryNoteStore` remains available only when explicitly constructed for tests/demos.

**Tests:** state transitions and competing reservations are covered by existing negative tests and `remediation.test.mjs`.

### F-06 - Merkle event provenance and history validation

**Status:** `CLOSED` for the identified event-authentication and replay defects.

**Changes:**

- `RpcMerkleWitnessProvider` requires finalized successful transactions.
- It authenticates `Program data` logs to the configured program invocation and requires the configured tree in the program instruction account set.
- Known events are decoded with exact lengths and field validation.
- Asset/direction/amount/field/index/generation/commitment constraints are checked.
- Duplicate signatures, conflicting indexes, noncontiguous indexes, malformed events, and incomplete history fail closed.
- Shield roots are recomputed after each append.
- Private-swap accepted input roots are checked against the finalized root ring.
- Historical private-swap roots are reconstructed by event-time sequence and checked against the root window that existed when each event executed, rather than only the current ring.
- Private-swap leaf sequence/index replay uses actual leaf indexes instead of `root_sequence + 1/+2`.
- `Unshielded` events are parsed with exact lengths and their nullifiers are exposed for recovery.
- Persistent encrypted checkpoints are keyed by full deployment identity, replay-validated, cursor-checked, atomically replaced, and reused only for finalized suffixes.
- Swap nullifiers are retained across restart, and wallet recovery independently verifies finalized spent-nullifier PDAs.
- Final replayed root, sequence, next index, and generation are compared with finalized tree state.

**Tests:** the provider implementation includes strict event parsing and independent replay/root checks. Full malicious-RPC live tests remain part of the unavailable funded Devnet E2E fixture.

### F-07 - RPC state and finality consistency

**Status:** `MITIGATED`; no unresolved Medium authorization/economic finding.

**Changes:**

- Pool, shielded state, tree, protocol config, vault, mint, ATA, LUT, and witness history reads use explicit finalized commitment.
- Private quotes use finalized reserves and finalized LP mint supply.
- Private operations refresh pool/state/reserves/supply immediately before witness/proof construction.
- Quotes remain advisory and callers provide `minAmountOut`.
- Confirmation and pending-operation reconciliation are finalized-aware.
- README documents ordinary RPC availability/privacy limitations and the absence of cryptographic canonical-ledger proof from one RPC.

**Accepted residual risk:** A malicious single RPC can still deny service or supply stale advisory data; it cannot authorize a proof or alter frozen on-chain account constraints.

### F-08 - CPMM LP-claim reserve floor

**Status:** `CLOSED`.

**Changes:**

- `swapOutputPreservingLpClaims` ports the frozen `minimum_lp_claim_reserve` and integer rounding behavior.
- `quote` and private swap use finalized LP mint supply and the exact floor.
- Ordinary `swapOutput` is no longer used for shielded swap public statements.

**Tests:** boundary tests cover exact floor acceptance/rejection; frozen Rust math tests continue to pass.

### F-09 - Legacy private transaction size

**Status:** `CLOSED` for silent doomed submission.

**Changes:**

- Unshield and private swap require a configured v0/LUT path and versioned wallet signer before proving/signing.
- Missing configuration throws `LookupTableRequiredError` before proof generation.
- Once instruction accounts are known, LUT existence, identity, activation, and deployment contents are revalidated before invoking the prover; the final signed transaction validates them again.
- E2E configuration and README document the requirement.
- Rust/SDK test launcher configuration was migrated to the new versioned private-operation path.

**Tests:** private wallet code checks readiness before invoking the prover; package tests cover the typed requirement boundary.

### F-10 - Configured program ID

**Status:** `CLOSED`.

**Changes:**

- Every PDA helper accepts the configured program ID.
- Every instruction builder accepts and uses the configured program ID.
- Client account reads validate the configured program owner and account discriminator.
- Witness tree derivation uses the configured ID.
- The default `PROGRAM_ID` remains only the default configuration.

**Tests:** non-default PDA parity is covered by `remediation.test.mjs`; existing instruction parity remains green.

### F-11 - PK identity and TOCTOU

**Status:** `CLOSED` for the identified PK substitution path.

**Changes:**

- TypeScript checks immutable compiled production PK hashes and exact file sizes.
- Rust validates the exact PK bytes it opens, with bounded reads, expected size, SHA-256, canonical deserialization, expected public-input arity, serialized VK size, and serialized VK SHA-256.
- Rust receives the PK path as argv and never reopens an independently selected environment path.
- Production expected hashes are compiled constants matching the frozen manifest.

**Tests:** PK mismatch/legacy environment behavior is covered by prover policy tests and Rust compilation; frozen artifact bytes were not changed.

### F-12 - VK release gate length mismatch

**Status:** `CLOSED`.

**Changes:**

- `scripts/verify_vk.sh` now reads SHA-256 and byte-size expectations for all four VK artifacts from `artifacts/production-groth16-v1/manifest.json`.
- The existing `unshield_vk.production.hex` size of `2304` is accepted; no VK was regenerated.

**Evidence:** `./scripts/verify_vk.sh` exits successfully with the existing artifacts.

### F-13 - Numeric and field encoding

**Status:** `CLOSED` for the identified encoder defects.

**Changes:**

- `u64` accepts only bigint values in range.
- `u16`, `u32`, and enum encoders require safe integer/range values.
- Public-input encoding rejects BN254 values at or above the modulus instead of reducing them.
- Direction and fee values are validated before encoding.

**Tests:** fractional, unsafe, overflow, and noncanonical-field cases are covered by `remediation.test.mjs`.

### F-14 - ATA recipient hardening

**Status:** `CLOSED` for the identified local ATA validation defects.

**Changes:**

- ATA derivation explicitly uses classic SPL Token and Associated Token program IDs.
- Off-curve recipients are deliberately supported for private sends.
- Existing accounts are checked for token-program ownership, mint, and authority before creation is skipped.
- High-level shield, public operations, liquidity operations, and private recipients use the common validation path.

### F-15 - remove-liquidity destination ATAs

**Status:** `CLOSED`.

**Changes:**

- `removeLiquidity` now prepares provider token A/B ATAs idempotently, matching add-liquidity behavior.

### F-16 - LUT validation

**Status:** `MITIGATED`; remaining impact is configuration-dependent availability only.

**Changes:**

- LUTs are fetched at finalized commitment.
- Existence, last-extension slot, deactivation status, optional authority, and optional exact expected address set are validated.
- Same-slot extension boundaries use `lastExtendedSlotStartIndex`; newly appended addresses cannot be treated as active at the extension slot.
- Lookup-table responses are bound to the requested table key, frozen authorities normalize to the documented `null` form, and same-slot cache misses are coalesced.
- Versioned private transactions require a configured LUT and versioned signer.
- README and E2E configuration document deployment-specific LUT requirements.

**Accepted residual risk:** A caller who supplies a table public key without an expected deployment address set can still select a wrong table, but explicit instruction keys cannot be semantically replaced by LUT contents; the result is early validation failure, size failure, or transaction failure rather than fund redirection.

### F-17 - Release provenance

**Status:** `MITIGATED`; final provenance metadata commit and funded E2E evidence remain required before release.

**Changes:**

- SDK source, tests, generated `dist`, lockfile, README, and reports are now part of the candidate working tree.
- `lethenymous-sdk/.gitignore` excludes `node_modules`, secrets, environment files, and tarballs.
- `release/production-prover-manifest.json` records protocol version, source, target, executable digest, and size.
- `release/manifest.json` references the remediation report and prover manifest and records the SDK source, lockfile, generated-dist, and npm package hashes.
- External packed-consumer import succeeded.
- `scripts/verify_sdk_release.sh` rebuilds/tests from `package-lock.json` and verifies the recorded SDK source commit, lockfile hash, generated-dist archive hash, and npm tarball SHA-256/SHA-512/size; it remains pending the candidate source commit and final hash recording.

**Remaining action:** Commit the final provenance metadata after this re-audit and complete funded E2E evidence. Do not tag or publish.

### F-18 - Dependency advisories

**Status:** `ACCEPTED RESIDUAL RISK` at LOW release severity.

**Evidence:** `npm audit --omit=dev` still reports 9 production findings: 3 high and 6 moderate, with no compatible non-breaking fix in the supported Solana dependency line. npm proposes incompatible major/downgrade changes.

**Changes:**

- The audit was rerun after remediation.
- No force upgrade or obsolete Solana downgrade was applied.
- The actual SDK reachability and impact are documented in this report and the re-audit.
- The SDK does not expose a demonstrated authorization or fund-loss path through the affected transitive parsers.

**Remaining action:** Retain the accepted risk in release notes and revisit when a compatible Solana-stack update exists.

### F-19 - Stale IDL and documentation

**Status:** `CLOSED` for the published SDK documentation issue.

**Changes:**

- README examples define their inputs and no longer reference undeclared variables.
- README explicitly states Node.js-first scope, no browser/WASM prover, external PK/prover custody, v0/LUT requirements, persistent NoteStore requirements, finalized outcomes, and public unshield metadata.
- README identifies source-derived codecs as the SDK source of truth and does not present a generated IDL as authoritative.

## Additional Pre-Release Review Corrections

The following issues were found while independently reviewing the first
remediation pass. They were fixed before this report was updated and are not
changes to the preserved initial finding text:

- `src/accounts.ts` now decodes the frozen `TreeState` payload length of `2664` bytes after the Anchor discriminator; the prior `1640` check could not read a deployed tree account.
- `src/client.ts` preserves ambiguity when signed submission acknowledgement or reconciliation fails and only treats expiry as failure when finalized RPC checks show no signature/transaction.
- `src/store.ts` initializes journals through a synced temporary file and rename, repairs only an incomplete final frame, serializes a PID lock, recovers stale locks, serializes reads under the lock, and reloads backups before releasing the lock.
- `src/wallet.ts` uses atomic reserve-plus-operation intent, derives prepared signatures during restart reconciliation, makes final state transitions idempotent, and refuses an omitted `NoteStore` at runtime.
- `src/witness.ts` replays event-time root history, authenticates finalized transaction/signature ordering, persists swap and unshield nullifiers, and fails closed on incomplete pagination.
- `src/wallet.ts` verifies finalized spent-nullifier PDA ownership, discriminator, pool, nullifier, and version before recovery marks notes spent.

These corrections are covered by the TreeState, LUT, journal restart, derived
signature, and reconciliation tests in `tests/remediation.test.mjs`.

## Frozen Artifact Check

The following were intentionally not changed:

- `programs/zkcpmm/src/**` protocol implementation
- Groth16 circuit sources
- `artifacts/production-groth16-v1/*.bin`
- `artifacts/production-groth16-v1/*_vk.production.hex`
- deployed/frozen SBF

`./scripts/verify_vk.sh` passed against the existing artifacts.

## Verification Evidence

- SDK typecheck: passed.
- SDK build: passed.
- SDK tests: 31 passed, including cold/warm/restart incremental Merkle checkpoint, pagination, cache-integrity, gap, provenance, generation, bounded-retry, and spent-nullifier account verification tests.
- Production prover tests: passed with zero test failures.
- Devnet lifecycle and program test crates: compile-checked after IPC migration.
- Packed npm consumer import: passed outside the monorepo.
- `npm audit --omit=dev`: 9 accepted residual advisories.
- SDK release provenance gate: pending candidate source commit and final package hash/size recording.
- Full frozen workspace test suite: passed with the extended timeout; the full-tree capacity test completed successfully.
- QuickNode incremental profile: cold unshield used 102 HTTP requests and 81 historical transactions; warm unshield used 19 HTTP requests and 2 historical transactions. Cold private swap used 104 HTTP requests and 85 historical transactions; warm private swap used 18 HTTP requests and 2 historical transactions. Warm operations had no 429 responses or duplicate history reads.
- Real funded QuickNode E2E: preflight passed and a serialized, bounded-rate run observed no 429 responses, but the required six-flow run stopped at Private Send because QuickNode rejected the versioned transaction with JSON-RPC `-32602` (`1233 bytes`, maximum `1232`). No six-flow or restart/recovery success verdict is claimed.

## Release Decision

`BLOCKED`

The practical HIGH/MEDIUM implementation work is complete, but `READY FOR
RELEASE` is not claimed because the final provenance metadata commit and
required real finalized funded E2E evidence are still pending. No npm
publication or tag was created.
