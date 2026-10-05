import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { AddressLookupTableAccount, ComputeBudgetProgram, Keypair, PublicKey, SystemProgram, TransactionInstruction, TransactionMessage, VersionedTransaction } from "@solana/web3.js";
import {
  EncryptedFileNoteStore,
  Lethenymous,
  TransactionFailedError,
  TransactionUnknownError,
  decryptNotePayload,
  decodeTreeState,
  encodeNote,
  encryptNote,
  encodePrivateSwapPublicInputs,
  enumByte,
  feeBreakdown,
  keyHierarchy,
  minimumLpClaimReserve,
  noteCommitment,
  ownerCommitment,
  pda,
  PROGRAM_ID,
  swapOutput,
  swapOutputPreservingLpClaims,
  SYSTEM_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  u16,
  u64,
  unshield,
} from "../dist/index.js";

const payer = Keypair.generate();
const instruction = SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: new PublicKey(new Uint8Array(32).fill(8)), lamports: 1 });

function fakeConnection(confirm, overrides = {}) {
  return {
    getLatestBlockhash: async () => ({ blockhash: new PublicKey(new Uint8Array(32).fill(3)).toBase58(), lastValidBlockHeight: 100 }),
    sendRawTransaction: async () => "signature",
    confirmTransaction: async () => confirm,
    getSignatureStatuses: async () => ({ value: overrides.status ?? [null] }),
    getTransaction: async () => overrides.transaction ?? null,
    getBlockHeight: async () => overrides.blockHeight ?? 1,
  };
}

function sdk(connection) {
  return new Lethenymous({
    connection,
    wallet: {
      publicKey: payer.publicKey,
      signTransaction: async tx => { tx.partialSign(payer); return tx; },
    },
  });
}

test("buildAndSend rejects finalized execution errors", async () => {
  const client = sdk(fakeConnection({ value: { err: { InstructionError: [0, "custom"] } } }));
  const outcome = await client.buildAndSendOutcome([instruction]);
  assert.equal(outcome.status, "finalized-failed");
  await assert.rejects(() => client.buildAndSend([instruction]), TransactionFailedError);
});

test("confirmation timeout remains unknown when the signature is not final", async () => {
  const client = sdk(fakeConnection(undefined, { status: [ { err: null, confirmationStatus: "confirmed" } ] }));
  client.connection.confirmTransaction = async () => { throw new Error("timeout"); };
  const outcome = await client.buildAndSendOutcome([instruction]);
  assert.equal(outcome.status, "unknown");
  await assert.rejects(() => client.buildAndSend([instruction]), TransactionUnknownError);
});

test("confirmation timeout is reconciled as success when the signature finalized", async () => {
  const client = sdk(fakeConnection(undefined, { status: [ { err: null, confirmationStatus: "finalized" } ] }));
  client.connection.confirmTransaction = async () => { throw new Error("timeout after landing"); };
  const outcome = await client.buildAndSendOutcome([instruction]);
  assert.equal(outcome.status, "finalized-success");
});

test("submission callback failure is unknown and does not attempt confirmation", async () => {
  let confirmed = false;
  const client = sdk(fakeConnection({ value: { err: null } }));
  client.connection.confirmTransaction = async () => { confirmed = true; return { value: { err: null } }; };
  const outcome = await client.buildAndSendOutcome([instruction], { onSubmitted: async () => { throw new Error("journal unavailable"); } });
  assert.equal(outcome.status, "unknown");
  assert.equal(confirmed, false);
});

test("submission acknowledgement failure preserves a derived signature", async () => {
  const client = sdk(fakeConnection({ value: { err: null } }));
  client.connection.sendRawTransaction = async () => { throw new Error("RPC acknowledgement lost"); };
  const outcome = await client.buildAndSendOutcome([instruction]);
  assert.equal(outcome.status, "unknown");
  assert.equal(typeof outcome.signature, "string");
  assert(outcome.signature.length > 40);
});

test("reconciliation RPC errors remain unknown", async () => {
  const client = sdk(fakeConnection(undefined));
  client.connection.getSignatureStatuses = async () => { throw new Error("RPC unavailable"); };
  const outcome = await client.reconcileTransaction("signature");
  assert.equal(outcome.status, "unknown");
});

test("expired blockhash without a signature is classified as finalized failure", async () => {
  const client = sdk(fakeConnection(undefined, { blockHeight: 101 }));
  client.connection.confirmTransaction = async () => { throw new Error("blockhash expired"); };
  const outcome = await client.buildAndSendOutcome([instruction]);
  assert.equal(outcome.status, "finalized-failed");
});

test("encrypted note journal survives restart and hides note plaintext", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zkcpmm-note-store-"));
  try {
    const seed = new Uint8Array(32).fill(7);
    const owner = ownerCommitment(keyHierarchy(seed).spendSecret);
    const pool = new PublicKey(new Uint8Array(32).fill(1));
    const asset = new PublicKey(new Uint8Array(32).fill(2));
    const randomness = new Uint8Array(32).fill(3);
    const commitment = noteCommitment(pool, asset, 42n, owner, randomness);
    const path = join(directory, "notes.lnsj");
    const store = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    await store.saveNote({ pool, asset, amount: 42n, ownerCommitment: owner, randomness, commitment });
    const operation = new Uint8Array(32).fill(4);
    await store.reserveNote(commitment, operation, owner);
    await store.markSubmitted(commitment, operation, "signature");
    const persisted = await readFile(path);
    assert.equal(persisted.includes(Buffer.from(randomness).toString("hex")), false);
    const restarted = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    assert.equal((await restarted.getNotes())[0].state, "submitted");
    const competing = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    await assert.rejects(() => competing.reserveNote(commitment, new Uint8Array(32).fill(9), owner), /available/);
    await restarted.markSpent(commitment, operation);
    assert.equal((await restarted.getNotes())[0].state, "spent");

    const secondRandomness = new Uint8Array(32).fill(5);
    const secondCommitment = noteCommitment(pool, asset, 43n, owner, secondRandomness);
    const secondOperation = new Uint8Array(32).fill(6);
    await restarted.saveNote({ pool, asset, amount: 43n, ownerCommitment: owner, randomness: secondRandomness, commitment: secondCommitment });
    await restarted.reserveNoteAndBegin(secondCommitment, secondOperation, owner, { id: secondOperation, kind: "unshield", state: "intent", pool, inputCommitment: secondCommitment, metadata: {}, outputNotes: [] });
    const restartedAgain = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    assert.equal((await restartedAgain.getNotes()).find(note => Buffer.from(note.commitment).equals(Buffer.from(secondCommitment))).state, "reserved");
    assert.equal((await restartedAgain.getPendingOperations()).some(operationRecord => Buffer.from(operationRecord.id).equals(Buffer.from(secondOperation))), true);
    await restartedAgain.markSpent(secondCommitment, secondOperation);
    await restartedAgain.markSpent(secondCommitment, secondOperation);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("TreeState decoder uses the frozen account layout", () => {
  const tree = decodeTreeState(new Uint8Array(2664));
  assert.equal(tree.frontier.length, 16);
  assert.equal(tree.emptySubtrees.length, 17);
  assert.equal(tree.roots.length, 32);
  assert.throws(() => decodeTreeState(new Uint8Array(1640)), /TreeState account length/);
});

test("configured LUT identity and finalized activation are validated before private proof setup", async () => {
  const tableAddress = new PublicKey(new Uint8Array(32).fill(11));
  const expectedAddress = new PublicKey(new Uint8Array(32).fill(12));
  const fakeTable = { key: tableAddress, state: { lastExtendedSlot: 1, deactivationSlot: 18446744073709551615n, authority: null, addresses: [expectedAddress] } };
  const connection = fakeConnection({ value: { err: null } }, { });
  let tableReads = 0;
  connection.getSlot = async () => 10;
  connection.getAddressLookupTable = async () => { tableReads++; return { value: fakeTable }; };
  const client = new Lethenymous({
    connection,
    wallet: { publicKey: payer.publicKey, signTransaction: async tx => tx, signVersionedTransaction: async tx => tx },
    lookupTables: [{ address: tableAddress, expectedAuthority: null, expectedAddresses: [expectedAddress] }],
  });
  const ix = new TransactionInstruction({ programId: SystemProgram.programId, keys: [{ pubkey: expectedAddress, isSigner: false, isWritable: false }] });
  await client.validatePrivateTransactionReady([ix]);
  await client.validatePrivateTransactionReady([ix]);
  assert.equal(tableReads, 1);
  const invalid = new Lethenymous({ connection, wallet: client.wallet, lookupTables: [{ address: tableAddress, expectedAddresses: [payer.publicKey] }] });
  await assert.rejects(() => invalid.validatePrivateTransactionReady([ix]), /contents differ|missing/);
  const extendingConnection = { ...connection, getAddressLookupTable: async () => ({ value: { key: tableAddress, state: { ...fakeTable.state, lastExtendedSlot: 10, lastExtendedSlotStartIndex: 0 } } }) };
  const extending = new Lethenymous({ connection: extendingConnection, wallet: client.wallet, lookupTables: [{ address: tableAddress }] });
  await assert.rejects(() => extending.validatePrivateTransactionReady([ix]), /not active/);
  const frozenConnection = { ...connection, getAddressLookupTable: async () => ({ value: { key: tableAddress, state: { ...fakeTable.state, authority: undefined } } }) };
  const frozen = new Lethenymous({ connection: frozenConnection, wallet: client.wallet, lookupTables: [{ address: tableAddress, expectedAuthority: null }] });
  await frozen.validatePrivateTransactionReady([ix]);
  const wrongKeyConnection = { ...connection, getAddressLookupTable: async () => ({ value: { key: payer.publicKey, state: fakeTable.state } }) };
  const wrongKey = new Lethenymous({ connection: wrongKeyConnection, wallet: client.wallet, lookupTables: [{ address: tableAddress }] });
  await assert.rejects(() => wrongKey.validatePrivateTransactionReady([ix]), /wrong account/);
});

test("frozen unshield fits the packet limit with the deployed fixture LUT", () => {
  const payer = Keypair.generate();
  const bob = Keypair.generate();
  const key = seed => new PublicKey(Uint8Array.from({ length: 32 }, (_, index) => (seed + index) & 0xff));
  const poolAddress = key(1);
  const mintA = key(40);
  const mintB = key(80);
  const shielded = pda.shielded(poolAddress, PROGRAM_ID)[0];
  const tree = pda.tree(poolAddress, PROGRAM_ID)[0];
  const custodyA = pda.custodyA(poolAddress, PROGRAM_ID)[0];
  const custodyB = pda.custodyB(poolAddress, PROGRAM_ID)[0];
  const pool = { address: poolAddress, tokenAMint: mintA, tokenBMint: mintB };
  const state = { tree, custodyA, custodyB };
  const tableKey = key(180);
  const filler = count => Array.from({ length: count }, (_, index) => key(200 + index));
  const table = addresses => new AddressLookupTableAccount({
    key: tableKey,
    state: {
      deactivationSlot: 18446744073709551615n,
      lastExtendedSlot: 0,
      lastExtendedSlotStartIndex: 0,
      authority: null,
      addresses,
    },
  });
  const fixtureTable = table([
    poolAddress, shielded, tree, custodyA, custodyB, mintA, mintB,
    ...filler(6), TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID,
  ]);
  const compactTable = table([poolAddress, mintA, mintB, ...filler(8), TOKEN_PROGRAM_ID]);
  const compile = (recipient, lookupTable) => {
    const recipientA = key(20);
    const recipientB = key(60);
    const instruction = unshield(
      payer.publicKey,
      pool,
      state,
      0,
      700n,
      new Uint8Array(32).fill(1),
      100n,
      0n,
      new Uint8Array(32).fill(2),
      recipient,
      recipientA,
      recipientB,
      new Uint8Array(256),
      new Uint8Array(320),
      PROGRAM_ID,
    );
    const message = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: key(120).toBase58(),
      instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 500_000 }), instruction],
    }).compileToV0Message([lookupTable]);
    return { message, serializedLength: new VersionedTransaction(message).serialize().length };
  };
  const self = compile(payer.publicKey, fixtureTable);
  const privateSend = compile(bob.publicKey, fixtureTable);
  const compactPrivateSend = compile(bob.publicKey, compactTable);
  const loaded = privateSend.message.getAccountKeys({ addressLookupTableAccounts: [fixtureTable] });
  const loadedKeys = [...loaded.accountKeysFromLookups.writable, ...loaded.accountKeysFromLookups.readonly];
  assert(loadedKeys.some(address => address.equals(shielded)));
  assert(loadedKeys.some(address => address.equals(tree)));
  assert(loadedKeys.some(address => address.equals(custodyA)));
  assert(loadedKeys.some(address => address.equals(custodyB)));
  assert(!loadedKeys.some(address => address.equals(bob.publicKey)));
  assert.equal(self.serializedLength, 1046);
  assert.equal(privateSend.serializedLength, 1078);
  assert.equal(privateSend.serializedLength - self.serializedLength, 32);
  assert.equal(compactPrivateSend.serializedLength, 1233);
  assert(privateSend.serializedLength <= 1200);
  assert(privateSend.serializedLength <= 1232);
});

test("frozen outer-version-1 shield payload decrypts and authenticates", () => {
  const seed = new Uint8Array(32).fill(7);
  const keys = keyHierarchy(seed);
  const owner = ownerCommitment(keys.spendSecret);
  const pool = new PublicKey(new Uint8Array(32).fill(1));
  const asset = new PublicKey(new Uint8Array(32).fill(2));
  const randomness = new Uint8Array(32).fill(3);
  const commitment = noteCommitment(pool, asset, 42n, owner, randomness);
  const payload = encryptNote(encodeNote(pool, asset, 42n, owner, randomness), keys.viewKey, pool, asset, commitment);
  assert.equal(payload[0], 1);
  assert.equal(decryptNotePayload(payload, keys.viewKey, pool, asset, commitment).amount, 42n);
  payload[payload.length - 1] ^= 1;
  assert.throws(() => decryptNotePayload(payload, keys.viewKey, pool, asset, commitment), /Crypto|payload|cipher|tag/);
});

test("LP-floor math matches the frozen boundary", () => {
  assert.equal(minimumLpClaimReserve(1002n, 1000n), 501n);
  const ordinary = swapOutput(10_000n, 550n, 1_000n, 100);
  assert.equal(ordinary > 0n, true);
  assert.equal(swapOutputPreservingLpClaims(10_000n, 550n, 1_000n, 100, 1002n), ordinary);
  assert.throws(() => swapOutputPreservingLpClaims(10_000n, 549n, 1_000n, 100, 1002n), /LP claims/);
});

test("protocol encoders reject lossy numeric values and noncanonical fields", () => {
  assert.throws(() => u64(1.5), /bigint|Invalid/);
  assert.throws(() => u16(1.5), /Invalid/);
  assert.throws(() => enumByte(1.5), /Invalid/);
  const zero = new Uint8Array(32);
  const keyA = new PublicKey(new Uint8Array(32).fill(1));
  assert.throws(() => encodePrivateSwapPublicInputs({ pool: keyA, assetIn: keyA, assetOut: keyA, root: Uint8Array.from(Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex")), rootSequence: 0n, generation: 0n, nullifier: zero, reserveIn: 1n, reserveOut: 1n, feeBps: 100, amountIn: 1n, amountOut: 1n, changeAmount: 0n, changeCommitment: zero, outputCommitment: zero, direction: 0, swapNonce: 0n }), /Noncanonical/);
});

test("configured program IDs bind PDAs and instruction program IDs", () => {
  const alternate = new PublicKey(new Uint8Array(32).fill(6));
  const mintA = new PublicKey(new Uint8Array(32).fill(1));
  const mintB = new PublicKey(new Uint8Array(32).fill(2));
  assert.notEqual(pda.pool(mintA, mintB, 100)[0].toBase58(), pda.pool(mintA, mintB, 100, alternate)[0].toBase58());
});

test("production prover rejects legacy file IPC and malformed stdin without secret-bearing errors", () => {
  const binary = resolve(process.cwd(), "../audit/tooling/production-prover/target/release/production-prover");
  const pk = resolve(process.cwd(), "../artifacts/production-groth16-v1/unshield_pk.production.bin");
  const legacy = spawnSync(binary, ["unshield", "/tmp/request", "/tmp/output"], { encoding: "utf8" });
  assert.notEqual(legacy.status, 0);
  assert.match(legacy.stderr, /stdin-v1/);
  const malformed = spawnSync(binary, ["--stdin-v1", "unshield", "--pk", pk], { input: "zkcpmm-prover-ipc-v1\nunshield\n0\n", encoding: "utf8" });
  assert.notEqual(malformed.status, 0);
  assert.doesNotMatch(malformed.stderr, /secret|randomness|seed|witness/i);
});
