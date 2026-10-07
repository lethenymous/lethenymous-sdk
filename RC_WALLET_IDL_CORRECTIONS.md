# Release-candidate wallet and IDL corrections

Baseline SDK: `31096aece5ceee3a8f00e0810044c38a527aad9f`.
Baseline Core: `60740af1600d1cfece28028dfd2cb6f9dcaf338d`.

## Corrected invariants

- **RC-01:** finalized success is retained in operation metadata before note
  publication. The operation remains pending until the input is durably spent
  and every output is durably published. Persistence errors do not enter the
  unsuccessful-spend release path. Account-authenticated recovery also retains
  its success evidence before publication. Restart retries are idempotent.
- **RC-02:** spend operations begin in the durable `proving` lifecycle state.
  Reservations remain exclusive throughout witness preparation and proof
  generation. Active operation IDs are shared across wallet instances in the
  process, including the prepared/submitted callback interval. Signatureless
  proving operations are never assumed abandoned by reconciliation.
- **RC-05:** `canonicalNoteState` is the single state rule used by both stores
  and wallet balance/selection. `spent === true` always means `spent`, including
  conflicting legacy encrypted records. Copies and retained operation outputs
  normalize both fields. Reservation/release cannot downgrade consumed notes;
  conflicting duplicate saves are rejected.
- **RC-06:** input release requires a finalized read of its derived canonical
  spent PDA through the existing strict `readCanonicalSpentStates` validator.
  Valid consumption spends the input; an unsuccessful operation plus explicit
  absence permits release. RPC errors, malformed accounts, or incomplete reads
  keep the operation unresolved. Known success is never downgraded by expired
  blockhash or unavailable transaction history.

## IDL parity (RC-03)

Core regenerates `idl/zkcpmm.json` with its intended Anchor 0.32.1 tooling:

```sh
anchor-0.32.1 idl build -p zkcpmm -o idl/zkcpmm.json -t target/types/zkcpmm.ts
```

The generated changes synchronize initialize-shielded-state, private-swap,
rollover-tree, shield, and the existing PageDirectory type/error metadata.
Core program logic is unchanged.

`tests/idl-parity.test.mjs` compares every supported SDK instruction builder's
discriminator, account order/address, signer and writable flags against that
generated IDL. It covers both shield assets and private swaps with/without
change and across page boundaries, using independently derived addresses.
It additionally checks handler-defined remaining accounts: shield's directory,
page and system program; private-swap's token/system programs, spent PDA and
optional second output page. PrivateSwap's unchecked payer has a handler-level
signature requirement not represented by Anchor's generated account metadata.

Two excess SDK writable flags were corrected: initialize-pool authority and
shield's shielded state. The payer signature and all handler-required remaining
accounts are preserved.

By default the parity test uses `../zkCPMM/idl/zkcpmm.json`. Standalone checkouts
can set `LETHENYMOUS_CORE_IDL`; without either, that paired-repository test skips.

## Validation

```sh
npm run typecheck
npm run build
node --test tests/rc-wallet.test.mjs tests/idl-parity.test.mjs
npm test
npm pack --dry-run
```

The focused tests interrupt finalized unshield at success metadata, input-spent
publication and operation finalization. Finalized swap tests interrupt located
output persistence, input publication, each output save and finalization, then
restart encrypted stores and verify exact notes and idempotency. Concurrent
tests pause unshield/swap inside the prover with competing same-wallet,
two-wallet and independent encrypted-store operations. Legacy consumed notes
cannot contribute to balance, be reserved, be released or be overwritten as
available. Expired-history tests use the production transaction reconciliation
method with absent historical responses and an expired blockhash.

The existing full suite covers account-only shield/swap recovery, mixed
spent/unspent outputs, one/two/cross-page outputs, paged witnesses, rollover,
checkpoint persistence and historical-API-independent recovery. Its external
prover IPC test retains its existing skip when that executable is not bundled.

Final local SDK result: **117 tests, 116 passed, 1 skipped, 0 failed,
0 cancelled**. Typecheck, build and package dry-run passed. The checked-in Core
IDL is byte-identical to a separate authoritative Anchor regeneration.

All six frozen production PK/VK hashes match Core's existing production
manifest, and Core program/circuit/artifact paths have no diff from baseline.
No deployment, circuit/setup regeneration, economics or architecture change
is part of these corrections. RC-04 is outside this work.

## Remaining operational limitation

A signatureless proving operation left behind by process termination remains
reserved: time alone cannot prove that another process stopped owning it.
Likewise unavailable/malformed canonical account evidence keeps an input
unresolved rather than available. Durable pending operations are intentionally
retained until authoritative evidence permits reconciliation.
