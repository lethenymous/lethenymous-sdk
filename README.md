# @lethenymous/sdk

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

For persistent finalized Merkle reconstruction, pass the same store to
`RpcMerkleWitnessProvider` as its checkpoint store. Checkpoints are encrypted
and authenticated sidecars keyed by genesis identity, program, pool, tree, and
generation. The provider still refreshes finalized tree state and verifies the
reconstructed root before returning a witness. A custom checkpoint store must
provide equivalent authenticated, crash-safe replacement semantics.

```ts
let sdk: Lethenymous;
const witnessProvider = new RpcMerkleWitnessProvider(
  connection,
  programId,
  pool => sdk.getTree(pool),
  store,
);
sdk = new Lethenymous({ connection, wallet, programId, witnessProvider });
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

For the audited Devnet fixture, configure
`FMVUyVx6byt3dVV7nmkbXbsu5fLQPM8gTdJwN5YYL9HC` with its frozen address list
and authority, as `e2e/fixture.mjs` does. That table places the stable
shielded-state, tree, custody, mint, token-program, and system accounts in the
LUT while recipient and recipient-ATA accounts remain dynamic. The arbitrary
recipient Private Send transaction measures 1078 bytes with this table; the
older partial table `2LDxX9aeVaQhTjcDtwBqCGzA8Nm9MGGCShwnGSKzDYwy` measures
1233 bytes and must not be used for this flow.

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
trusted prover. The witness provider accepts only finalized successful events
invoked by the configured zkCPMM program and fails closed on contradictory or
incomplete history.

Private Send is an SDK-level use of the existing arbitrary-recipient unshield
instruction. It does not hide the recipient, amount, asset, payer, timing, or
fact of withdrawal. Public recipient and transaction metadata remain visible
on chain.
