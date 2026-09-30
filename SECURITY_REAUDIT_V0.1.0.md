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
| F-06 | CLOSED | Program invocation provenance, failed-transaction rejection, exact event parsing, root/index replay | Live malicious-RPC E2E remains fixture-dependent |
| F-07 | MITIGATED | Explicit finalized reads and caller-controlled slippage | Single RPC remains an availability/privacy trust boundary |
| F-08 | CLOSED | Exact LP-floor formula and boundary tests | None identified in reviewed path |
| F-09 | CLOSED | Private proof paths require v0/LUT before proving/signing | Deployment must provide the intended LUT |
| F-10 | CLOSED | Configured program ID reaches PDAs, instructions, reads, and witness provider | None identified in reviewed path |
| F-11 | CLOSED | Same Rust process validates exact PK bytes and VK pair | None identified in reviewed path |
| F-12 | CLOSED | Manifest-derived hash/size gate passes with existing 2304-byte unshield hex | None identified in reviewed path |
| F-13 | CLOSED | Strict bigint/safe-integer and canonical-field tests | None identified in reviewed path |
| F-14 | CLOSED | Off-curve-aware ATA derivation and existing-account validation | None identified in reviewed path |
| F-15 | CLOSED | Remove-liquidity destination ATA preparation | None identified in reviewed path |
| F-16 | MITIGATED | Finalized LUT account/slot/deactivation/authority/content validation | Wrong unpinned deployment config remains availability-only |
| F-17 | MITIGATED | SDK source/dist/lock/report and prover manifest prepared; packed consumer passed | Candidate commit still required before release |
| F-18 | ACCEPTED RESIDUAL RISK | 9 production advisories re-audited; no compatible safe upgrade | Low supply-chain/availability risk; no demonstrated fund-loss path |
| F-19 | CLOSED | README corrected; source-derived codecs explicitly authoritative | None identified in published SDK documentation |

## Additional Review Corrections

The initial remediation pass exposed additional defects before release closure;
they were fixed and tested rather than suppressed:

- Frozen `TreeState` decoding now requires the actual `2664`-byte payload.
- Signed submission acknowledgement loss derives and journals a signature, while RPC reconciliation failures remain unknown.
- Journal initialization, stale locks, partial-frame repair, atomic reserve-plus-begin, and idempotent terminal transitions are hardened.
- Historical swap roots are checked against replayed event-time roots, and finalized unshield/private-swap nullifiers are used to preserve spent-note state during shield recovery.
- LUT same-slot extension boundaries are rejected until all addresses are finalized-active.

## Final Classification

The original severity counts remain part of the historical record. Re-audit
status is:

- CRITICAL: 0
- HIGH: 0 unresolved
- MEDIUM: 0 unresolved
- LOW: accepted residual risk remains for dependency advisories and limited deployment/storage conditions
- INFORMATIONAL: no open runtime issue; provenance is pending candidate commit

## Test Evidence

- `npm run typecheck`: passed.
- `npm run build`: passed.
- `npm test`: 23 passed.
- `cargo test` for the standalone production prover: passed.
- Devnet lifecycle and program test crates: compile-checked after IPC migration.
- `./scripts/verify_vk.sh`: passed.
- `npm pack --dry-run`: passed.
- External packed-consumer import: passed.
- `npm audit --omit=dev`: 9 residual advisories documented as accepted risk.
- Full workspace tests were blocked by the existing full-tree capacity test exceeding five minutes in this environment; no assertion failure was observed before timeout.
- Real funded finalized Devnet lifecycle was not executed because isolated fixture credentials were not present.
- `scripts/verify_sdk_release.sh`: added; it will be run after the candidate commit and final provenance hashes are recorded.

## Release Decision

`BLOCKED`

The re-audit finds no unresolved High or Medium finding in the reviewed code,
but release readiness requires the clean candidate commit and real on-chain
evidence for Shield, Private Swap, Unshield, Private Send, routed Private Send,
