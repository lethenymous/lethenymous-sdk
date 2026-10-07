# Paged Merkle audit remediation — SDK

The subsequent SDK-only REAUD-01 correction is documented in
[REAUD_SPENT_OUTPUT_RECOVERY.md](REAUD_SPENT_OUTPUT_RECOVERY.md). Pending recovery
now checks each output's own current spent state; archive membership alone does
not establish spendability. The results below record the earlier remediation.

Branch: `fix/paged-merkle-audit-remediation`. Clean starting SDK HEAD:
`f252be93b951365faa8f7d4d13c017e859ea3b54`.
Paired core starts at `8d58a1a1423402146d3d37a7cea3797978dd33a6`.
Implementation evidence pending independent re-audit.

## Account-only pending reconciliation (AUD-03)

New shield/swap intents persist the exact expected output generation before
signing. `ShieldedWallet.reconcilePending()` first tries canonical finalized
account recovery before optional transaction/event APIs. It authenticates retained
preimages against owner/commitment/pool, checks expected generation and recorded
amounts/assets/commitments, and locates each output with the account-only provider
**without** supplying a predicted index.

Shield requires one unique match. Swap additionally requires the canonical
finalized73-byte spent-nullifier account, verifies retained input/nullifier and
change conservation, and requires two outputs as change then output at contiguous
global indices. Missing, duplicate, wrong-generation or inconsistent account
evidence fails closed and remains pending when optional history is unavailable.

Recovered indices are journaled before publication. Input consumption, note saves
and finalization are idempotent across another restart. This requires retained
preimages and the expected generation; it cannot recover lost randomness or infer
success merely from a retained signature.

Nine encrypted-store tests disable transaction/signature/event APIs: shield,
one-output swap, same-page/cross-page two-output swaps, duplicate/missing commitment,
wrong generation, noncontiguous outputs and missing spend state. Successful cases
have **zero history calls**, correct generation/index and idempotent second
restarts. Negative cases remain pending. Existing historical recovery remains
an optional path.

`e2e/local-pending-reconciliation.mjs` consumes actual production-proof SBF
settlement accounts from paired core tests. After dropping final publication and
reopening twice, shield index0 and Gen3 swap indices4095/4096 recover with history
forbidden. Its retained signature is a local placeholder; recovery authority is
canonical finalized account state and retained preimages.

## Directory v2 and bounded integrity work (AUD-02)

Directory is now **1,122 bytes/version2**, adding sixteen canonical page bumps at
1104..1119, with directory bump/version at1120/1121. Pages stay version1,597-byte
header, maximum131,669 bytes. Existing root/digest offsets are preserved. SDK checks
the bump table against canonical off-chain derivation.

Core computes page bumps at initialization/rollover and uses constant-cost swap
address validation. Append-time SHA checks the header and active256-leaf chunk,
treating sealed chunks as immutable program-owned state. SDK still verifies all
chunks and independently reconstructs all populated Poseidon page roots and the
global root against canonical TreeState. Full18-account privacy-oriented retrieval
and global depth16 membership are preserved.

Core shared initialization now tops up/allocates/assigns empty pre-funded spent
PDAs safely, retaining surplus (AUD-01). The host terminal carry is fixed at65536
(AUD-04). See core `docs/PAGED_MERKLE_AUDIT_REMEDIATION.md` for the complete
canonicality/integrity proof, profiling deltas, prefunding matrix and frozen hashes.

Directory-v1 migration is not implemented on these undeployed paired branches.
Use fresh initialization or a separately reviewed migration. No circuit/setup,
PK/VK, note/nullifier formula, public-input count or Program ID change was needed.

## Verification and priority-fee packet regression

- SDK typecheck/build: pass; full suite **70 passed,1 skipped**.
- Paged/generation/reconciliation suites: **6/14/9**, all pass.
- Package dry-run: pass.
- Core debug/release: **67 passes/3 existing ignored tests** each.
- SBF lifecycle: **31/31**; separate full-capacity paging: **1/1**.
- Production-VK runtime: **2/2**, plus lifecycle production proofs.

Actual SBF v0 transactions include both compute-budget instructions and dynamic
trees/directories/pages outside the static pool LUT. Eight deterministic ground-
address cases cover starts4095/32767/61439/65534; bumps include page246 and
nullifier243. Normal maximum: **704,189 CU**; instrumentation maximum:
**721,159 CU**. No remediated tested valid swap reaches1.4M; all meet1.30M.

All measurements include CU limit and CU price:

| Ready-ATA, single-signature v0 flow | Bytes | Headroom below1232 |
| --- | ---: | ---: |
| Shield | 775 | 457 |
| No-change swap | 953 | 279 |
| Two-output same-page swap | 953 | 279 |
| Cross-page swap | 986 | 246 |
| Cross-page/new-page swap | 986 | 246 |
| Unshield / Private Send | 1183 | 49 |
| Rollover | 410 | 822 |

Extra ATA instructions, signatures or different LUTs must still pass SDK packet
preflight. Measurements do not constitute deployment-wide bounds or readiness.

```sh
npm run typecheck
npm run build
npm test
node --test tests/pages.test.mjs tests/generations.test.mjs tests/account-reconciliation.test.mjs
npm pack --dry-run
```

The existing checkpoint suite takes over eight minutes. The SDK prover skip is
for an unbundled external executable; core tests run real production proofs.
Full-generation RPC/CPU work and durable preimage custody remain necessary.
Canonical-creation/ownership invariants must survive future program upgrades.

AUDIT REMEDIATION IMPLEMENTED — PENDING INDEPENDENT RE-AUDIT
