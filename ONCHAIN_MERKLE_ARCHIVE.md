# Account-only paged Merkle witnesses

See [PAGED_MERKLE_AUDIT_REMEDIATION.md](PAGED_MERKLE_AUDIT_REMEDIATION.md) for current
bounded on-chain SHA checks, account-only pending recovery and priority-fee
measurements. Original feature-branch measurements below are baseline evidence.

Implemented on `feature/onchain-merkle-pages`, paired with the core archive
branch. Pending independent audit and devnet validation.

## Default provider

`Lethenymous` now defaults to `OnChainPagedMerkleWitnessProvider`. It requires
only finalized account reads for membership reconstruction, with no event
history, indexer or checkpoint store. The encrypted note journal still supplies
the wallet's note preimages and pending-operation state.

```ts
const provider = new OnChainPagedMerkleWitnessProvider(connection, programId);
const witness = await provider.getWitness(
  note.pool, note.commitment, note.generation ?? 0n, note.leafIndex,
);
// witness.index is global; witness.siblings.length === 16
```

Every request fetches the canonical tree, directory and **all sixteen pages**
in one finalized `getMultipleAccountsInfo` batch. It hides which page is selected
from the request address set. A full generation requires roughly 2.1 MB of raw
page data plus RPC encoding overhead and local Poseidon reconstruction work.
The provider is Node.js-first and uses Node SHA-256 and the existing Poseidon
implementation.

It verifies account owner/executable status/discriminator, pool/tree/generation
identity, canonical PDA bumps, version, exact size/count, every header/chunk
digest, canonical commitment fields, every populated page Poseidon root, the
four-level directory root, the tree root/history entry, and the final global
depth-16 path. Missing pages are allowed only where the expected population is
zero and both the page root and digest are empty. Missing populated pages and
missing directories fail closed with `MerkleArchiveError`.

If `leafIndex` is absent, the provider scans the verified generation for one
matching commitment. Ambiguous duplicates fail closed. An explicit index must
match the commitment and be within the populated range.

## Account layouts and instruction compatibility

- Directory PDA: `["page-dir", pool, generation_le_u64]`; 1,122 bytes/version2.
- Page PDA: `["leaf-page", pool, generation_le_u64, page_index_u8]`.
- A page stores a 597-byte header followed by up to 4,096 raw commitments.
  Maximum size is 131,669 bytes; version is 1.
- Header includes sixteen SHA-256 digests, one per 256-leaf chunk. Directory
  includes sixteen header digests and sixteen Poseidon page roots.
- Membership stays 12 page siblings + 4 upper siblings = depth 16, with global
  index `page * 4096 + offset` and capacity 65,536 per generation.
- Existing tree/state layouts, Gen0/later tree seeds, historical spending,
  global nullifiers, note formulas, prover IPC, PKs/VKs, and proof inputs remain
  unchanged. No trusted setup regeneration is involved.

Initialization/rollover builders add the new directory. Shield/private-swap
builders require `ArchiveAppendContext { generation, nextIndex }` from a checked
active tree. Shield supplies directory/page/system remaining accounts. Swap
adds its directory and first page, and supplies the second page only when two
outputs cross a page boundary. `unshield` and Private Send retain their account
ABI. Refetch and rebuild after a stale output-page transaction fails atomically.

## Durable output locations

Shield and private-swap completion locates the output through the exact
finalized signature's authenticated program events. Generation and global leaf
index are saved into normal encrypted note records; private swap persists both
change and output indices. Unavailable or ambiguous location events keep the
operation unknown for `reconcilePending()`, which repeats authentication before
publishing notes or consuming the reservation. Caller-predicted indices are
never persisted as success.

The default account-only provider does not recover lost note randomness or
discover notes whose journal and backups were lost. The existing explicit
`RpcMerkleWitnessProvider` remains available for historical shield-event
discovery/checkpoint workflows. Nonempty pre-archive trees have no on-chain
commitment list; no unsafe backfill is implemented. Start the archive with fresh
program initialization.

## Executable years-offline evidence

`e2e/local-paged-witness.mjs` is invoked by the core SBF ProgramTest suite. It
stores a normal encrypted note, reopens a fresh store/provider, permits only the
18-account finalized batch, and throws if history/signature APIs are called.
Only current BanksClient accounts and ordinary note metadata enter the bridge.
The resulting 16-sibling witness feeds the real production Rust prover:

1. Gen0 private swap into Gen3 after several rollovers, crossing indices
   4095→4096 and 32767→32768.
2. Historical Gen0 unshield while Gen10 is active, with missing-index recovery.
3. Global replay rejection and unchanged historical tree account bytes.

This establishes account-only membership recovery for a wallet returning after
a long absence with its normal encrypted note state, independently of historical
RPC retention, SDK Merkle sidecars, indexers and checkpoints.

## Validation and measured costs

- `npm run typecheck` and `npm run build`: pass.
- Full normal suite: **61 passed, 1 skipped**; generation suite **14/14 passes**,
  including encrypted journal restart recovery. Six paged-provider tests pass.
- Page-provider tests cover page boundaries through index 8192, all eighteen
  requested addresses, missing/known indices, duplicates, account ownership,
  identity/discriminator/version/count/size/digest corruption, and missing pages.
- Restart test: unavailable/ambiguous finalized events leave outputs pending;
  authenticated reconciliation persists generation 4 and indices 4095/4096
  through an encrypted store reopen.
- Core final SBF suite: **28/28**. Workspace release suite: **62 passes/3 ignored**.
  Full-capacity real-Poseidon property
  passes separately. See core `docs/ONCHAIN_MERKLE_ARCHIVE.md` for frozen hashes,
  allocation internals, mutation matrix and exact reproduction commands.

Static pool LUT packet measurements (trees/directories/pages stay dynamic):

| Flow | v0 bytes | Remaining packet bytes |
| --- | ---: | ---: |
| Swap with/without change | 941 | 291 |
| Cross-page swap | 974 | 258 |
| Unshield / Private Send | 1171 | 61 |
| Shield | 723 | 509 |
| Rollover | 358 | 874 |

Final local cross-page swaps measured 1,377,445 and 1,381,948 CU under a 1.4M
budget; these have limited headroom and are not a deployment-wide maximum.
Historical unshield measured 356,337 CU. A 1/2/4096-leaf page respectively costs
5,268,720 / 5,491,440 / 917,307,120 rent-exempt lamports in ProgramTest. Pages
are funded incrementally by append payers, not allocated fully in one CPI.

```sh
npm run typecheck
npm run build
npm test
node --test tests/pages.test.mjs tests/generations.test.mjs
npm run pack:check
```

Allow more than eight minutes for the existing full checkpoint regression suite.
The package/prover skip applies when the external production prover is not
bundled; the paired core tests use the real production prover locally.

ON-CHAIN PAGED MERKLE ARCHIVE IMPLEMENTED — PENDING INDEPENDENT AUDIT AND DEVNET VALIDATION
