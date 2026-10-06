# Multi-generation Merkle support (feature branch)

**IMPLEMENTATION COMPLETE — PENDING INDEPENDENT SOURCE REVIEW AND DEVNET ADVERSARIAL VALIDATION**

These source changes require the matching generation/fee program ABI. They are
not a published SDK release or an audited deployment. Do not run this branch's
live E2E harness against the old deployed ABI expecting the new accounts to work.

## Identity and discovery

`pda.tree(pool, generation, programId?)` keeps the legacy Gen0 seeds and adds a
LE u64 generation seed for Gen1+. `pda.tree(pool, programId)` is retained as an
explicit backwards-compatible Gen0 call. Use the explicit generation parameter
for spending. `getTree(pool)` now returns the active tree, discovered through
`ShieldedState.tree`; `getActiveTree`, `getTreeAt`, and `getTreeByGeneration` expose
explicit lookup paths with owner/discriminator/pool/canonical-PDA checks.

Shield writes to the active pointer and passes the selected protocol fee vault.
Private swap derives INPUT tree from witness generation, and independently passes
the active OUTPUT tree. Unshield and Private Send derive their INPUT tree from
the witness; they do not use the active pointer as membership state. The prover
continues receiving only INPUT generation. Its IPC, public inputs, keys, proof
response format, and authenticated released executable digest are unchanged.

`ensureTreeCapacity` prepares permissionless rollover when one/two required
outputs cannot fit. It refetches finalized state, including when another caller
wins the rollover race. Unknown outcomes are not guessed into note spends.
Private swap checks capacity again after proving and journals both output notes
with the freshly observed output generation. A subsequent race can still reject
the transaction; the existing finalized/failed/unknown journal state machine
keeps reservations safe and lets callers reconcile/retry.

## Replay and migration

History is collected from the stable ShieldedState PDA, which is referenced by
shield, private swap, unshield, initialization, and rollover. Finalized signatures
are paginated chronologically with cursor/gap/duplicate checks. Direct and CPI
instructions must reference the configured program and stream account; event
logs are decoded only inside that program's invocation stack. Failed finalized
transactions are verified against RPC metadata and skipped, so failed spam
cannot become append history or permanently block reconstruction.

Replay maintains separate generation trees and pool-global spent nullifiers.
Shields may append only to the replay's active generation. Swaps validate their
input root in the input generation and append only to the event's output
generation. Both old and new PrivateSwapped layouts are decoded: the old format
infers output generation from input generation, while the new appended u64 is
read using the change flag and total event length (including the ambiguous
218-byte length). Rollover must be contiguous, canonical, at the 0/1-leaf
threshold, and match the old final root. The new tree starts empty. Replayed
frontier, counters, empties, root history, and roots are checked against finalized
accounts for every generation before returning a witness. Historical witnesses
use that generation's stable final/current root and sequence.

`getWitness(pool, commitment, generation?)` allows an explicit generation filter.
Wallet operations always pass the note's generation. A generation is local
metadata, not a change to encrypted protocol note plaintext or commitment.
Legacy notes without it deliberately normalize to `0n`. The encrypted note
journal framing/version/key derivation is preserved; optional generation is
serialized as a decimal string. Existing encrypted note and pending-operation
data is not destroyed or reinterpreted.

Checkpoint payload version is now **3**. A small pool manifest resumes the finalized
stream and points to an active base/delta chain; sealed generation snapshots are
immutable and loaded lazily. Nullifiers have a separate uncompressed direct index
and journal. No lifetime event list is retained in the pool checkpoint. v1/v2
checkpoints are authenticated as their original format and explicitly rebuilt,
not silently reinterpreted. NoteStore content is preserved. See
[CHECKPOINT_SCALABILITY.md](CHECKPOINT_SCALABILITY.md) for publication, migration,
complexity, instrumentation and validation details. Archive disk usage and orphan
garbage collection remain operational concerns. The protocol does not impose an
active-generation cutoff on old notes.

## Fee and packet size

`shieldFee(amount)` is `floor(amount * 5 / 10_000)` for u64 bigint amounts. The
wallet checks amount-plus-fee backing balance, while note amount remains exactly
amount. This never changes CPMM fee tiers or private-swap economics.

Local v0 serialized packet measurements include compute-budget instructions,
one payer signature and a static pool LUT containing pool/mints/LP/vaults/custody/
ShieldedState. Neither input nor output generation Tree PDA, spent nullifier PDA,
nor arbitrary recipient/recipient ATAs is in that LUT:

| Flow | Bytes |
|---|---:|
| private swap with change | 875 |
| private swap without change | 875 |
| unshield | 1,171 |
| private send | 1,171 |
| shield | 624 |
| rollover | 325 |

Solana's limit remains 1,232. These measurements require the stated static LUT;
they do not claim that arbitrary missing/incomplete LUTs fit. In particular,
unshield/private send have 61 bytes of headroom and must not bundle ATA creation
or unrelated instructions. No future generation is assumed preloaded.

## Local validation and remaining risks

The SDK baseline was 31 passed/1 skipped. Generation tests cover PDA compatibility,
fees, active discovery, legacy/new events, rollover parsing, wallet generation
metadata across a race, old-generation withdrawals, and packet limits. A slow
full-capacity test reconstructs all 65,535 Gen0 appends, rollover, cross-generation
swap/unshield events, and a checkpoint restart. It then fills the complete Gen1,
Gen2, and Gen3 histories and checks a Gen0 witness while Gen2 is active and a Gen1
witness while Gen4 is active. It rejects impossible continuation
without overwriting the last good checkpoint. RPC fixtures in SDK unit tests are
synthetic; real production-key proofs and SBF execution are covered separately by
the core local integration suite. No new live transaction was broadcast.

Final `npm test` inventory is 48 tests: 47 passed, zero failed, one skipped. The
skipped test expects the separate Rust executable at a monorepo-relative path;
that executable is intentionally not bundled in this standalone repository.
`npm run typecheck`, `npm run build`, and `npm pack --dry-run` passed. The package
contains 32 files (approximately 49 kB packed and 232 kB unpacked), with no proving keys,
native prover, wallets, runtime caches, or generated proofs included.

Transaction reconciliation also now checks execution errors in a finalized RPC
status before committing local spent state. This prevents an already-finalized
failed transaction from being mistaken for success during recovery.

Historical root retention does not preserve every originally captured witness:
before rollover, old roots can expire after 32 appends. Leaves/history and backups
are therefore mandatory for reconstructing the final accepted root. RPC is an
availability/authenticity trust boundary, not a receiver of spend secrets.
Nullifier-PDA state remains global and grows per spent note; no compression or
accumulator is introduced. Browser/WASM proving is not added. Existing dependency
audit findings are unchanged. Upgrade authority and single-party setup assumptions
remain external boundaries. Independent source review and devnet adversarial
validation, including larger-generation stress tests, remain outstanding.
