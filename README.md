# @lethenymous/sdk

## Release status

SDK release source: `1939d5104901c7a18a653c60893b96c416736faa` plus release-only
version metadata for `0.1.1`. The paired Core source is
`cde3018f4ab5f29c30df0442ffb2812dabfc6c8f`, deployed under Program ID
`ZkCP47fAJJREdXNKSBvTsgJAuLoTKepgk6opmqsHobm` with frozen SBF SHA-256
`bb70f41d59660c2f66378f7124ba068a83911746698fbab26236a1e2d447d87b`.

Fresh Devnet release-gate validation **passed** for Shield, production-proof
private swaps in both directions, Private Send, Unshield, replay rejection,
account-only witness recovery and spend, canonical spent-state restart, and an
organic two-output 4095→4096 cross-page swap. The full details and scope limits
are in Core's
[`release/DEVNET_VALIDATION_2026-10-07.md`](https://github.com/lethenymous/zkcpmm/blob/main/release/DEVNET_VALIDATION_2026-10-07.md).
Gen0→Gen1 rollover scale stress was not executed on Devnet; no Devnet Gen1
success is claimed. It is documented as a quantified scale-stress coverage
limitation, not a demonstrated protocol defect.

Historical v0.1.0 audit reports describe earlier implementations. The current
security and operational assumptions are summarized in the release and
remediation notes below; historical audit status is not current release
evidence.

The account-only paged witness provider and archive ABI are documented in
[ONCHAIN_MERKLE_ARCHIVE.md](ONCHAIN_MERKLE_ARCHIVE.md). Generation-aware state
and checkpoint migration are documented in
[MERKLE_GENERATIONS.md](MERKLE_GENERATIONS.md) and
[CHECKPOINT_SCALABILITY.md](CHECKPOINT_SCALABILITY.md). Wallet restart and
canonical spent-output behavior are documented in
[REAUD_SPENT_OUTPUT_RECOVERY.md](REAUD_SPENT_OUTPUT_RECOVERY.md), with
[PAGED_MERKLE_AUDIT_REMEDIATION.md](PAGED_MERKLE_AUDIT_REMEDIATION.md) covering
the paired runtime remediation.

TypeScript protocol client for the frozen Lethenymous / zkCPMM program.

## Status

This package provides source-derived codecs for the fixed deployment, PDA
derivation, account decoding, public and private instructions, exact CPMM
integer math, shielded primitives, and finalized Merkle verification. It does
not provide browser/WASM proving support.

Private operations require an authenticated local `ProductionProver`, the
production proving keys, a validated v0 address lookup table, and an encrypted
persistent `NoteStore`. The package does not bundle the prover, PKs, VKs, or
frozen SBF.

## Install and build

```bash
npm install @lethenymous/sdk
npm run build
```

The package is Node.js-first and requires Node.js 20 or newer.

## Public client

```ts
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { Lethenymous } from "@lethenymous/sdk";

const secretKey = Uint8Array.from(JSON.parse(process.env.KEYPAIR_JSON!));
const keypair = Keypair.fromSecretKey(secretKey);
const connection = new Connection(process.env.RPC_URL!, "finalized");
const wallet = {
  publicKey: keypair.publicKey,
  signTransaction: async tx => { tx.partialSign(keypair); return tx; },
  signVersionedTransaction: async tx => { tx.sign([keypair]); return tx; },
};
const sdk = new Lethenymous({ connection, wallet });
const poolAddress = new PublicKey(process.env.POOL_ADDRESS!);
const quote = await sdk.quote(poolAddress, "AToB", 1_000_000n);
```

All protocol amounts and indices are `bigint`. Quotes include the frozen
`MINIMUM_LIQUIDITY` LP-claim reserve floor. Quotes are advisory; callers must
choose their own slippage limits.

## Private operations

The prover binary must match the authenticated release identity in
`release/production-prover-manifest.json`. The SDK verifies the executable
digest and exact `production-prover 0.2.0 ipc-v1` version before every proof.
The child receives only a minimal environment and receives witness tokens over
bounded private stdin IPC; it does not receive the parent environment, wallet
seed, or RPC credentials.

The PK paths must refer to the exact production artifacts. PK identity is
verified both by the SDK and inside the Rust prover. Do not pass caller-chosen
PK hashes as production configuration.

```ts
import {
  EncryptedFileNoteStore,
  Lethenymous,
  ProductionProver,
  keyHierarchy,
  ownerCommitment,
} from "@lethenymous/sdk";

const seed = Uint8Array.from(Buffer.from(process.env.WALLET_SEED_HEX!, "hex"));
const owner = ownerCommitment(keyHierarchy(seed).spendSecret);
const store = EncryptedFileNoteStore.fromSeed("/secure/path/notes.lnsj", seed, owner);
const prover = new ProductionProver({
  executablePath: "/trusted/release/production-prover",
  privateSwapPkPath: "/trusted/artifacts/private_swap_pk.production.bin",
  unshieldPkPath: "/trusted/artifacts/unshield_pk.production.bin",
});
const shielded = sdk.shieldedWallet(seed, prover, { noteStore: store });
```

`EncryptedFileNoteStore` uses an encrypted, authenticated append-only journal
with atomic reservation and operation transitions. The file contains note
randomness and pending operation preimages, so it must be protected like the
seed. Losing both the seed and the journal/backup loses recovery material.

The default `OnChainPagedMerkleWitnessProvider` reconstructs membership from
the finalized tree, directory and all sixteen page accounts; no Merkle sidecars
or history are needed. Normal encrypted notes retain generation and global leaf
index. A missing legacy index is recovered by a unique verified commitment scan.

```ts
const witnessProvider = new OnChainPagedMerkleWitnessProvider(connection, programId);
const sdk = new Lethenymous({ connection, wallet, programId, witnessProvider });
const shielded = sdk.shieldedWallet(seed, prover, { noteStore: store });
```

The default `Lethenymous.shieldedWallet` path refuses to create a volatile
store. `InMemoryNoteStore` remains available only when explicitly supplied for
tests, demos, or ephemeral development.

After a process restart, call `reconcilePending()` before selecting notes for
new private operations. The method checks finalized transaction status and the
authenticated zkCPMM event before applying pending local state. A wallet can
also call `recoverShieldedNotes(pool)` with `RpcMerkleWitnessProvider` to scan
finalized shield events and decrypt the frozen outer-version-1 note envelope.
Recovery also verifies finalized spent-nullifier PDAs before marking a note
spent, rather than relying only on event history.
In a shared pool, envelopes that fail this wallet's view-key authentication are
foreign-wallet ciphertexts and are ignored; decryptable notes still require
commitment, owner, and spent-nullifier validation.

Use `exportBackup()` and `importBackup()` for encrypted journal backup and
restore. Backups contain note randomness and pending operation material and
must be kept under the same custody policy as the seed.

Private-swap outputs created with the current random-output design require the
durable journal or an encrypted backup for recovery. The frozen event does not
contain output randomness, so chain-only recovery of an output whose local
journal and backups are both lost is not possible without changing the wallet
protocol convention.

## Lookup tables and transaction outcomes

Unshield and private swap require a validated v0 address lookup table and a
wallet adapter implementing `signVersionedTransaction`. If the requirement is
not met, the SDK throws `LookupTableRequiredError` before proving or signing.

The fresh Devnet release-gate fixture used a validated v0 lookup table with
stable pool, shielded-state, mint, vault and token/system addresses; dynamic
archive and recipient accounts remain outside the static table. On that real
fixture, Private Send measured 1109 bytes and Unshield 1077 bytes. Both fit the
1232-byte packet limit without extra transaction instructions. Applications
must validate their own table configuration and preflight the complete signed
transaction; different account lists can change packet size.

Transactions are confirmed at finalized commitment. A confirmation response
with a non-null `value.err` is a finalized failure. Timeouts and incomplete
status are represented as an unknown/ambiguous outcome and must be reconciled;
a signature alone is not success.

## Repository and license

The public source repository is
[`lethenymous/lethenymous-sdk`](https://github.com/lethenymous/lethenymous-sdk).
`@lethenymous/sdk` is distributed under the MIT License; see `LICENSE`. The
underlying zkCPMM repository is a separate project with its own license.

The repository's extracted development-history provenance is documented in
`MIGRATION.md`.

## Security model

Spend secrets, view keys, note randomness, commitments, and proving witnesses
are sensitive. Do not log or upload them. RPC is transport/state access, not a
trusted prover. The default witness provider validates finalized canonical
account bindings and recomputed Poseidon roots. Event-based recovery additionally
requires successful events invoked by the configured zkCPMM program.

Private Send is an SDK-level use of the existing arbitrary-recipient unshield
instruction. It does not hide the recipient, amount, asset, payer, timing, or
fact of withdrawal. Public recipient and transaction metadata remain visible
on chain.
