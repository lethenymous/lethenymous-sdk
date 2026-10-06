# Generation-scoped checkpoint remediation

**CHECKPOINT SCALABILITY REMEDIATION COMPLETE — PENDING SOURCE REVIEW**

This is an SDK-only feature-branch update. It has not been published or merged.
The core program, ABI, PDA derivation, circuits, prover IPC, production key pins,
shield-fee math, and pool-global nullifier identity are unchanged.

## Problem in v2

The v2 pool checkpoint stored all lifetime events and all generation snapshots.
Every update serialized that lifetime event list; restart replayed it from Gen0.
If H is total lifetime history, both update persistence and restart verification
were O(H), and all historical leaf sets remained resident.

## v3 architecture

The authenticated pool manifest contains only:

- chain/program/pool/stable history-stream identity;
- active generation and its base/delta-head references;
- active root, sequence and next-index summary;
- finalized history cursor;
- the head reference of the separate nullifier journal.

Generation locators have deterministic, identity-bound keys. The manifest has no
array of generations and no lifetime HistoryEvent list.

### Immutable data

At rollover, the previous generation is stored as a sealed snapshot with all its
append records and final TreeState. Its locator, blob and optional content-addressed
chunks are write-once. Identical interrupted-write retries do not rewrite them;
conflicting bytes fail closed. Future generations do not rewrite or serialize
these records. Each generation contains at most 65,536 leaves.

Active-generation base snapshots and delta segments are also immutable blobs;
only their manifest references advance. An update normally writes only its new
append records and final frontier/root metadata. After 64 delta segments, the
active generation alone is compacted into a new base snapshot. Sealed snapshots
never participate in compaction.

Large generation snapshots use identity-scoped 8 MiB chunks to fit the existing
encrypted store's per-file limit. Chunks are authenticated by the store and
integrity-bound to the generation blob. SHA-256 checks are not a replacement for
the store's authentication contract.

### Mutable data and publication

The sole mutable visibility boundary is the pool manifest. Candidate generation
blobs, sealed locators and nullifier records are written first; the manifest and
cursor publish last. Until publication, a sealed locator for the old active
generation is an orphan and is not used as historical state.

The supplied EncryptedFileNoteStore now supports atomic compare-and-swap of
authenticated checkpoint plaintext. Publication holds its existing filesystem
lock, verifies the expected manifest digest, fsyncs the file, renames it, and
fsyncs the directory. A concurrent manifest change fails closed. Custom stores
without compare-and-swap must externally serialize writers for each pool; a
read-before-write check alone cannot provide cross-process mutual exclusion.

On interruption, the last authenticated manifest still references the previous
base/delta chain and cursor. Recovery reprocesses only the finalized suffix,
validates it against chain state, accepts identical orphan writes idempotently,
and publishes the completed transition. Unknown/missing/corrupt referenced data
is never interpreted as a new empty generation.

## Lazy witness recovery

`getWitness(pool, commitment, generation)` synchronizes the finalized suffix and
then loads only the named generation's leaf set. When no suffix exists, a warm
request for a historical note does not even load active-generation leaves.
It authenticates the generation locator/blob, checks pool/generation/canonical
PDA identity, verifies append count/index continuity and commitment-to-event
bindings, reconstructs the frontier and root history, and compares the result
to the canonical finalized on-chain TreeState. A bounded two-generation cache
retains already-validated historical leaf sets; on-chain comparison is repeated.

No append may target a generation older than the replay's active generation.
Old input-root validation needs only that generation's finalized on-chain root
history, not its entire leaf set.

Let C be the fixed generation capacity and D be the finalized suffix:

- normal persistence: O(D) records; periodic compaction is O(active C);
- warm synchronization: O(D), plus active-generation loading/copying when needed;
- warm historical witness: O(requested C), independent of prior/later generations;
- memory: active leaf set plus at most two requested historical leaf sets;
- no-checkpoint cold recovery: O(H), intentionally preserved;
- optional witness calls without a generation and full shield-note recovery are
  explicitly exhaustive APIs, not the normal wallet path.

Without a configured persistent store, old serialized generation archives are
evicted from volatile memory; a requested historical tree is reconstructed from
its finalized RPC append history. Use authenticated persistent storage for warm
restart guarantees. Storage and orphan-blob garbage collection remain operational
concerns; this change does not claim bounded total archive disk usage.

## Pool-global nullifiers

Nullifiers remain uncompressed raw identifiers. Each spent identifier has an
authenticated, direct lookup record keyed by pool identity and nullifier, not
generation. The record includes finalized transaction/event provenance. A new
spend checks one record, without replaying generation history or enumerating all
nullifiers. A different event using the same identifier is rejected globally.
An identical event can retry an unpublished batch after interruption.

The manifest references immutable journal segments containing only newly committed
nullifiers. `getSpentNullifiers()` deliberately enumerates that journal and verifies
its index records; this explicit all-results operation remains O(total spends).
Normal witnesses and incremental duplicate detection do not call it. There is
no on-chain accumulator, compressed state, bitmap or changed nullifier PDA.
The deployed program remains authoritative for actual double-spend protection.

## Migration

v3 has a distinct namespace and schema. If absent, v1/v2 data is authenticated
and checked as its own format, then recovery rebuilds from finalized RPC. Its
old pool/tree cursor is not reused as a v3 cursor, and lifetime events are never
copied into v3. Invalid legacy data fails closed. Once a valid v3 manifest exists,
ordinary restart does not load legacy blobs. NoteStore content and its existing
encrypted journal format are unchanged.

## Evidence

The persistence-specific fixture uses four complete 65,535-leaf generations with
real Poseidon roots. It verifies warm Gen0 and Gen3 witnesses while Gen4 is active,
with one generation loaded per request. A single new Gen4 append processed one
transaction, serialized one leaf, wrote zero sealed checkpoints, and left every
Gen0–Gen3 plaintext checkpoint digest byte-identical. The pool manifest was
1,639 bytes. Separate cases cover corruption, generation substitution, rollover
interruption, global nullifier replay, legacy migration, active compaction and
native-store compare-and-swap.

The complete normal suite has 55 tests: 54 passed, zero failed, one external-prover
test skipped. The unchanged-capacity stress test is now separate:

```sh
npm run typecheck
npm run build
npm test
node --test tests/generations.test.mjs
node --test tests/witness.test.mjs
npm run test:stress
npm pack --dry-run
```

The stress fixture still reconstructs every append through Gen4, cross-generation
swap/withdrawal events, authenticated restart, historical witnesses and invalid
continuation. Its measured runtime was 1,332,009 ms (~22.2 minutes), versus the
previous 1,090,471 ms (~18.2 minutes). The new run overlapped the normal suite's
crypto-heavy persistence tests, so these are not controlled speed benchmarks.
Cold throughput is not the remediation's claim; the deterministic read/write
instrumentation proves the removal of lifetime-history work from warm updates.

Generation snapshot plaintext sizes in the stress run:

| Generation | Bytes |
|---|---:|
| 0 | 56,757,596 |
| 1 | 56,930,556 |
| 2 | 56,965,307 |
| 3 | 56,965,306 |

These are individual immutable generation snapshots, not a repeatedly serialized
pool-wide history. A requested full-generation validation remains crypto-heavy
but is bounded by that generation's capacity. Independent source review is still
required; no Mainnet or audited-readiness claim is made.
