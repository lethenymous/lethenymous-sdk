# Lethenymous SDK v0.1.0 Focused Re-Audit

This focused re-audit follows the preserved initial report
`SECURITY_AUDIT_V0.1.0.md` and remediation record
`SECURITY_REMEDIATION_V0.1.0.md`. The initial findings were not rewritten.

## Scope and Frozen Controls

No on-chain zkCPMM semantics, Groth16 circuits, production PK bytes,
production VK bytes, or frozen SBF were changed. The existing VK gate passes
against the canonical artifact manifest.

## Finding Status

| Finding | Status | Re-audit evidence | Residual decision |
|---|---|---|---|
| F-01 | CLOSED | Finalized outcome union, `value.err` rejection, status/block-height reconciliation, wallet journal tests | None beyond ordinary single-RPC availability |
| F-02 | CLOSED | Executable realpath/digest/version policy and authenticated release manifest | Unsupported target platforms fail closed |
| F-03 | CLOSED | stdin IPC, bounded frames/streams, timeout, child kill, minimal environment, no temp witness files | None identified in reviewed path |
| F-04 | MITIGATED | Encrypted journal, operation recovery, shield event decryption, backup APIs, restart tests | Loss of seed plus backups; existing random private-swap outputs cannot be reconstructed chain-only |
| F-05 | CLOSED | Atomic reservation/CAS-style store methods, owner namespace, conflict rejection, awaited mutations | None identified in reviewed path |
| F-06 | CLOSED | Program invocation provenance, failed-transaction/signature rejection, exact event parsing, persistent checkpoint replay, canonical pagination, root/index replay | Live malicious-RPC E2E remains fixture-dependent |
| F-07 | MITIGATED | Explicit finalized reads and caller-controlled slippage | Single RPC remains an availability/privacy trust boundary |
| F-08 | CLOSED | Exact LP-floor formula and boundary tests | None identified in reviewed path |
| F-09 | CLOSED | Private proof paths require v0/LUT before proving/signing | Deployment must provide the intended LUT |
| F-10 | CLOSED | Configured program ID reaches PDAs, instructions, reads, and witness provider | None identified in reviewed path |
| F-11 | CLOSED | Same Rust process validates exact PK bytes and VK pair | None identified in reviewed path |
| F-12 | CLOSED | Manifest-derived hash/size gate passes with existing 2304-byte unshield hex | None identified in reviewed path |
| F-13 | CLOSED | Strict bigint/safe-integer and canonical-field tests | None identified in reviewed path |
| F-14 | CLOSED | Off-curve-aware ATA derivation and existing-account validation | None identified in reviewed path |
| F-15 | CLOSED | Remove-liquidity destination ATA preparation | None identified in reviewed path |
| F-16 | MITIGATED | Finalized LUT account/slot/deactivation/authority/content validation, response-key binding, and same-slot cache coalescing | Wrong unpinned deployment config remains availability-only |
| F-17 | MITIGATED | Hash-bound manifest and release gate design are in place; candidate source commit will be recorded after final SDK changes | Final provenance metadata commit and funded E2E remain required |
| F-18 | ACCEPTED RESIDUAL RISK | 9 production advisories re-audited; no compatible safe upgrade | Low supply-chain/availability risk; no demonstrated fund-loss path |
| F-19 | CLOSED | README corrected; source-derived codecs explicitly authoritative | None identified in published SDK documentation |

## Additional Review Corrections

The initial remediation pass exposed additional defects before release closure;
they were fixed and tested rather than suppressed:

- Frozen `TreeState` decoding now requires the actual `2664`-byte payload.
- Signed submission acknowledgement loss derives and journals a signature, while RPC reconciliation failures remain unknown.
- Journal initialization, stale locks, partial-frame repair, atomic reserve-plus-begin, and idempotent terminal transitions are hardened.
- Historical swap roots are checked against replayed event-time roots, and finalized unshield/private-swap nullifiers plus spent-nullifier PDA verification preserve spent-note state during shield recovery.
- Checkpoint identity, integrity, replay semantics, cursor pagination, transaction signatures, and finalized history ordering are validated before reuse.
- LUT same-slot extension boundaries are rejected until all addresses are finalized-active; returned table keys and frozen authorities are normalized and checked.

## Final Classification

The original severity counts remain part of the historical record. Re-audit
status is:

- CRITICAL: 0
- HIGH: 0 unresolved
- MEDIUM: 0 unresolved
- LOW: accepted residual risk remains for dependency advisories and limited deployment/storage conditions
- INFORMATIONAL: no open runtime issue; provenance is bound to the candidate source commit and the final metadata commit is pending

## Test Evidence

- `npm run typecheck`: passed.
- `npm run build`: passed.
- `npm test`: 31 passed, including incremental Merkle checkpoint cold/warm/restart, pagination, LUT cache, spent-nullifier account verification, and fail-closed integrity tests.
- `cargo test` for the standalone production prover: passed.
- Devnet lifecycle and program test crates: compile-checked after IPC migration.
- `./scripts/verify_vk.sh`: passed.
- `npm pack --dry-run`: passed.
- External packed-consumer import: passed.
- `npm audit --omit=dev`: 9 residual advisories documented as accepted risk.
- Full workspace tests: passed with the extended timeout, including the full-tree capacity test.
- QuickNode profile after incremental synchronization: cold unshield used 102 HTTP requests and 81 historical transactions; warm unshield used 19 HTTP requests and 2 historical transactions. Cold private swap used 104 HTTP requests and 85 historical transactions; warm private swap used 18 HTTP requests and 2 historical transactions. Warm operations had no 429 responses or duplicate history reads.
- Real funded finalized QuickNode lifecycle: preflight passed and bounded serialized RPC pacing removed 429 responses, but the required six-flow run stopped at Private Send on JSON-RPC `-32602` because the versioned transaction was `1233` bytes against a `1232`-byte maximum. No six-flow or restart/recovery success verdict is claimed.
- `scripts/verify_sdk_release.sh`: pending the candidate source commit and final provenance hashes.

## Release Decision

`BLOCKED`

The re-audit finds no unresolved High or Medium finding in the reviewed code,
but release readiness requires the final provenance metadata commit and real
on-chain evidence for Shield, Private Swap, Unshield, Private Send, routed Private Send,
and liquidity operations. No npm publication or tag was created.
