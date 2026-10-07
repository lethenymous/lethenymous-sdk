# REAUD-01 — consumed recovered outputs

SDK branch: `fix/reaud-spent-output-recovery`.
Verified clean starting revisions:

- Core: `60740af1600d1cfece28028dfd2cb6f9dcaf338d`.
- SDK: `c3c2a333c429eb4c5a7bb53bfc0c1a633ff71c28`.

Core source, branch and HEAD remain untouched. This is implementation evidence
pending focused independent re-test, not an audit or deployment-readiness claim.

## Root cause

Account-only pending reconciliation proved output issuance by locating commitments
in the canonical archive, but then saved those outputs as available without
checking their own current spent-nullifier state. An old pending journal could
therefore restore a note that had already been consumed successfully.

Merkle membership is issuance evidence; it is not proof of current spendability.
The authoritative consumed identity remains `["spent", pool, nullifier]`.

## Classification and publication

Existing retained-preimage, exact generation, unique commitment, ordering,
contiguity, conservation and input-spend checks remain intact. After account
membership or authenticated event location lookup:

1. Recompute each owned note commitment from its retained pool, asset, amount,
   owner and randomness; authenticate it against the wallet's owner.
2. Derive **each output's own** nullifier using the unchanged production formula.
   Input spent-state evidence is separate and never reused for outputs.
3. Derive each canonical spent PDA and fetch the output batch at `finalized`.
   The read occurs after membership/event reads and local note loading, as late
   as practical before durable publication.
4. Classify strictly:
   - Only an actual `null` finalized response means absent/unspent.
   - A valid canonical spent record means consumed.
   - Unexpected/malformed data, incomplete/undefined responses or RPC failures
     mean unknown and leave recovery pending; no new output is published.
5. Preserve consumed state already recorded in the operation or note journal.
   An absent/stale response cannot downgrade a persisted spent note.
6. Journal output locations and classifications before publishing notes. Save
   consumed notes as `state = "spent", spent = true`; absent outputs as available
   only when all existing reconciliation checks pass. Promote a partially
   published available note to spent through the existing reservation/spend
   transitions. Existing spent/reserved/submitted records are never reset to
   available. Finalization and publication remain retryable and idempotent.

The shared internal `readCanonicalSpentStates` helper in `src/spent.ts` is reused
for input-spend validation, recovered outputs and ordinary shield-event recovery.
It computes PDA addresses itself, requests finalized batches, and requires:

- Exact response count; only `null` is absence.
- Non-executable account with configured program ownership.
- Buffer data of exactly 73 bytes.
- Exact `SpentNullifier` discriminator and version 1.
- Exact expected pool and nullifier bytes.

All returned output accounts are validated before publication begins. Historical
events can locate issuance through the optional fallback but cannot bypass
current canonical output spent validation. A valid account-only issuance path
whose spent-state read fails stays pending without consulting historical APIs.

## Independent mixed output states

Shield and one-output swaps can recover either available or consumed. Two-output
same-page and cross-page swaps independently support all four combinations:

| Change | Output |
| --- | --- |
| available | available |
| spent | available |
| available | spent |
| spent | spent |

Consumed notes remain stored with preimages, generation/index, amounts/assets and
operation metadata for history. They contribute zero spendable private balance,
reject new reservations, and ordinary unshield selection rejects them before
witness/proof generation. No deletion or NoteStore format migration is required.

## Focused tests

`tests/account-reconciliation.test.mjs`: **35/35 passes**.

- Shield available, consumed and malformed spent state.
- One-output swap available/consumed.
- All four mixed same-page and cross-page combinations.
- Original missing/duplicate commitment, wrong-generation, noncontiguous-index
  and missing-input-spend negatives.
- Wrong owner, pool, nullifier, discriminator, version, size and executable flag.
- Unexpected system-owned/prefunded state; incomplete/undefined responses.
- Transient spent-fetch failure followed by successful retry.
- Malformed second output prevents publishing either output.
- Spend occurring after membership lookup is seen by the later spent-state read.
- Partially published available output is promoted to consumed.
- Crash after spent publication, then restart with an absent/stale response:
  consumed state remains monotonic and publication stays idempotent.
- Authenticated event fallback also classifies consumed outputs and fails closed
  on malformed output spent state.

Successful account-only cases assert zero historical calls, correct persisted
generation/index/state after reopening twice, and no duplicate note. Spent cases
assert zero spendable balance, reservation rejection, two ordinary unshield
selection rejections, and zero proof calls.

## Genuine unchanged-Core SBF reproduction

SDK-side `e2e/reaud-sbf` imports the author's frozen Core test/proof helpers without
editing Core. Its own locked Cargo graph pins Anchor 0.32.1. It executes the rebuilt
unchanged Core SBF and uses the frozen production proving artifacts:

1. Shield a 6,000-unit note at index 0.
2. Persist an encrypted pending shield journal with the actual local transaction
   signature, before the note is consumed.
3. Execute a production-proof private swap of 2,000 units, issuing change and
   output at indices 1/2.
4. Persist an encrypted pending swap journal with the actual transaction signature,
   before consuming either output. Final output locations/classification are not
   written to that journal.
5. Use a canonical SDK archive witness and production unshield proof to consume
   the 4,000-unit change. Verify genuine program-owned canonical spent records
   for both the swap input and change; verify the other output's PDA is absent.
6. Reopen the original pending swap journal against current BanksClient accounts
   with all transaction/signature/event APIs forbidden.
7. Reopen the original pending shield journal against the same post-spend accounts.

Observed bridge results:

```text
swap: indices [1,2], states [spent,available], historyCalls=0, proofCalls=0
shield: index [0], state [spent], historyCalls=0, proofCalls=0
both: restartIdempotent=true
```

The consumed notes fail reservation and ordinary unshield selection; the remaining
unspent output remains available. Journals are retained from before consumption,
not reconstructed as already-spent records after the fact. The bridge runs
against real local SBF settlement, not synthetic spent-account insertion.

Rebuilt unchanged Core SBF SHA-256:
`bb70f41d59660c2f66378f7124ba068a83911746698fbab26236a1e2d447d87b`.
This matches the prior remediation artifact. Core git status stays clean.

## Complete validation

| Check | Result |
| --- | --- |
| `npm run typecheck` | pass |
| `npm run build` | pass |
| `npm test` | **96 passed / 1 skipped** |
| `node --test tests/account-reconciliation.test.mjs` | **35/35** |
| `node --test tests/pages.test.mjs` | **6/6** |
| `node --test tests/generations.test.mjs` | **14/14** |
| `npm pack --dry-run` | pass; runtime spent module included |
| `npm run test:reaud:sbf` | **1/1**, both genuine journal recoveries |
| Unchanged Core historical Gen0 unshield with Gen10 active | **1/1** |
| Unchanged Core production-VK runtime suite | **2/2** |
| Rebuild unchanged Core SBF | pass; identical hash |

The one SDK skip concerns an external production prover not bundled in the npm
package. The SBF reproduction and Core tests execute production proofs locally.
The first shared-native-target Core build hit a dependency-type mismatch; isolated
targets resolve it without source changes. A focused-suite attempt timed out
during concurrent native builds; its uncontended final run passes all 35 cases.

### Reproduce locally

Check out both frozen starting Core and this SDK branch as sibling directories
named `zkCPMM` and `lethenymous-sdk`. Build the SDK, then build unchanged Core into
an isolated `SBF_OUT` directory:

```sh
npm run typecheck
npm run build
npm test
node --test tests/account-reconciliation.test.mjs
node --test tests/pages.test.mjs
node --test tests/generations.test.mjs
npm pack --dry-run
```

From Core:

```sh
cargo build-sbf --manifest-path programs/zkcpmm/Cargo.toml --sbf-out-dir "$SBF_OUT"
RUST_LOG=error BPF_OUT_DIR="$SBF_OUT" cargo test -p zkcpmm --target-dir "$CORE_TEST_TARGET" --release --locked --test phase1_program historical_unshield_gen0_with_gen10_active_and_full_rollover -- --nocapture
cargo test -p zkcpmm --target-dir "$CORE_TEST_TARGET" --release --locked --test production_vk_runtime -- --test-threads=1
```

From SDK, with `CARGO_TARGET_DIR` unset so the reused production-prover helper
retains its standard artifact path:

```sh
RUST_LOG=error BPF_OUT_DIR="$SBF_OUT" npm run test:reaud:sbf
```

The script uses its own ignored native target; do not share native target
directories across the Core and SDK harness workspaces. The harness and lockfile
are test-only and excluded from the npm package.

## Scope and remaining boundaries

No Core source, circuit, proving/verifying key, Merkle layout, note/nullifier
formula, global nullifier identity, Program ID or journal format changes.
No deployment, live broadcast, npm publication or merge.

Classification reflects the latest obtained finalized spent-state response; it
is not a global atomic transaction with other wallet instances. A later concurrent
spend can make an available local cache stale; on-chain nullifier enforcement
remains authoritative. Accurate finalized RPC responses are part of the existing
SDK trust assumptions. Known consumed state is never downgraded locally.

Malformed/unexpected current accounts, including system-owned/prefunded empty
accounts, are unknown for recovery and leave it pending. This fix does not sweep
all previously finalized journal records or replace balance selection with a
live chain-wide scan. It fixes publication through pending account/event recovery.

REAUD-01 REMEDIATED — PENDING FOCUSED INDEPENDENT RE-TEST
