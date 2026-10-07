import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicKey } from "@solana/web3.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { Lethenymous, ShieldedWallet, InMemoryNoteStore, EncryptedFileNoteStore, PROGRAM_ID, accountDiscriminator, keyHierarchy, ownerCommitment, noteCommitment, noteStoreKey, nullifier, pda, encodeUnshieldPublicInputs, encodePrivateSwapPublicInputs } from "../dist/index.js";

const pk = n => new PublicKey(new Uint8Array(32).fill(n));
const seed = new Uint8Array(32).fill(81), owner = ownerCommitment(keyHierarchy(seed).spendSecret);
const pool = { address: pk(1), tokenAMint: pk(2), tokenBMint: pk(3), lpMint: pk(4), tokenAVault: pk(5), tokenBVault: pk(6), protocolFeeVaultA: pk(7), protocolFeeVaultB: pk(8), creatorFeeVaultA: pk(9), creatorFeeVaultB: pk(10), feeBps: 100, swapNonce: 0n };
const randomness = new Uint8Array(32).fill(82);
const note = { pool: pool.address, asset: pool.tokenAMint, amount: 1000n, ownerCommitment: owner, randomness, commitment: noteCommitment(pool.address, pool.tokenAMint, 1000n, owner, randomness), generation: 0n };
const params = { pool: pool.address, mint: pool.tokenAMint, amount: 1000n, recipient: pk(20) };
const swapParams = { pool: pool.address, inputMint: pool.tokenAMint, outputMint: pool.tokenBMint, amountIn: 500n, minAmountOut: 1n };
const nf = nullifier(note.pool, note.asset, keyHierarchy(seed).spendSecret, note.randomness);
function spentAccount() {
  return { owner: PROGRAM_ID, executable: false, data: Buffer.concat([accountDiscriminator("SpentNullifier"), pool.address.toBuffer(), Buffer.from(nf), Buffer.from([1])]) };
}
function fixture(store, proverOverride) {
  let consumed = false, statement;
  const sdk = {
    programId: PROGRAM_ID, wallet: { publicKey: pk(21) },
    connection: { getMultipleAccountsInfo: async addresses => addresses.map(address => consumed && address.equals(pda.spent(pool.address, nf)[0]) ? spentAccount() : null) },
    assertPrivateTransactionReady() {}, validatePrivateTransactionReady: async () => {},
    getPool: async () => pool, getShieldedState: async () => ({ tree: pda.tree(pool.address, 0n)[0], custodyA: pk(11), custodyB: pk(12) }),
    ensureTreeCapacity: async () => ({ tree: { generation: 0n, nextIndex: 1n }, state: { tree: pda.tree(pool.address, 0n)[0], custodyA: pk(11), custodyB: pk(12) } }),
    getReserves: async () => ({ a: 100000n, b: 200000n }), getLpSupply: async () => 100000n,
    ensureAtas: async () => [pk(22), pk(23)],
    buildAndSendOutcome: async (_ix, options) => { await options.onSubmitted("signature"); consumed = true; return { status: "finalized-success", signature: "signature" }; },
    getFinalizedShieldedEvents: async () => [{ kind: "swap", pool: pool.address, nullifier: statement.nullifier, changeCommitment: statement.changeCommitment, outputCommitment: statement.outputCommitment, amountOut: statement.amountOut, outputGeneration: 0n, changeIndex: 1n, outputIndex: 2n }],
    reconcileTransaction: async () => ({ status: "finalized-failed", error: "expired; history unavailable" }),
  };
  const prover = proverOverride ?? {
    proveUnshield: async i => ({ proof: new Uint8Array(256), publicInputs: encodeUnshieldPublicInputs(i) }),
    provePrivateSwap: async i => { statement = i; return { proof: new Uint8Array(256), publicInputs: encodePrivateSwapPublicInputs(i) }; },
  };
  const witness = { getWitness: async () => ({ generation: 0n, rootSequence: 1n, root: new Uint8Array(32), index: 0n, siblings: Array.from({ length: 16 }, () => new Uint8Array(32)) }) };
  return { sdk, prover, witness, wallet: () => new ShieldedWallet(sdk, seed, prover, witness, store), consume: () => { consumed = true; } };
}

for (const boundary of ["updateOperation", "markSpent", "markOperationFinalized"]) {
  test(`RC-01 finalized unshield restart after interrupted ${boundary}`, async () => {
    const dir = await mkdtemp(join(tmpdir(), "rc01-"));
    try {
      const path = join(dir, "notes"), store = EncryptedFileNoteStore.fromSeed(path, seed, owner);
      await store.saveNote(note);
      const f = fixture(store), original = store[boundary].bind(store);
      let interrupted = false;
      store[boundary] = async (...args) => {
        if (!interrupted && (boundary !== "updateOperation" || args[1].metadata?.finalizedSuccess)) { interrupted = true; throw new Error("interruption"); }
        return original(...args);
      };
      await assert.rejects(() => f.wallet().unshield(params), /outcome is unknown/);
      assert.equal((await store.getPendingOperations()).length, 1);
      assert.notEqual((await store.getNotes())[0].state, "available");
      const restarted = EncryptedFileNoteStore.fromSeed(path, seed, owner);
      const wallet = new ShieldedWallet(f.sdk, seed, f.prover, f.witness, restarted);
      assert.deepEqual(await wallet.reconcilePending(), []);
      assert.equal((await restarted.getNotes())[0].state, "spent");
      assert.deepEqual(await wallet.reconcilePending(), []);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
}

for (const separateWallet of [false, true]) {
  for (const kind of ["unshield", "privateSwap"]) {
    test(`RC-02 ${kind} proving retains ownership (${separateWallet ? "two wallets" : "same wallet"})`, async () => {
      const store = new InMemoryNoteStore(); await store.saveNote(note);
      let entered, resume, calls = 0;
      const started = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { resume = resolve; });
      const prover = { [kind === "unshield" ? "proveUnshield" : "provePrivateSwap"]: async () => { calls++; entered(); await gate; throw new Error("stop proving"); } };
      const f = fixture(store, prover), a = f.wallet(), b = separateWallet ? f.wallet() : a;
      const first = a[kind](kind === "unshield" ? params : swapParams);
      await started; await b.reconcilePending();
      await assert.rejects(() => b[kind](kind === "unshield" ? params : swapParams), /Insufficient private balance|not available/);
      assert.equal(calls, 1); assert.equal((await store.getNotes())[0].state, "reserved");
      resume(); await assert.rejects(() => first, /stop proving/);
      assert.equal((await store.getNotes())[0].state, "available");
    });
  }
}

for (const boundary of ["located-outputs", "markSpent", "first-output", "second-output", "markOperationFinalized"]) {
  test(`RC-01 finalized swap restart after interrupted ${boundary}`, async () => {
    const dir = await mkdtemp(join(tmpdir(), "rc01-swap-"));
    try {
      const path = join(dir, "notes"), store = EncryptedFileNoteStore.fromSeed(path, seed, owner);
      await store.saveNote(note);
      const f = fixture(store);
      const method = boundary === "located-outputs" ? "updateOperation" : boundary.endsWith("output") ? "saveNote" : boundary;
      const original = store[method].bind(store);
      let calls = 0, interrupted = false;
      store[method] = async (...args) => {
        const relevant = method !== "updateOperation" || args[1].outputNotes?.some(n => n.leafIndex !== undefined);
        if (relevant) calls++;
        if (!interrupted && relevant && calls === (boundary === "second-output" ? 2 : 1)) { interrupted = true; throw new Error("interruption"); }
        return original(...args);
      };
      await assert.rejects(() => f.wallet().privateSwap(swapParams), /outcome is unknown/);
      assert.equal((await store.getPendingOperations()).length, 1);
      assert.notEqual((await store.getNotes()).find(n => Buffer.from(n.commitment).equals(Buffer.from(note.commitment))).state, "available");
      const restarted = EncryptedFileNoteStore.fromSeed(path, seed, owner);
      const wallet = new ShieldedWallet(f.sdk, seed, f.prover, f.witness, restarted);
      // Even contradictory/unavailable history must not discard known success.
      await wallet.reconcilePending();
      assert.equal((await restarted.getPendingOperations()).length, 1);
      f.sdk.reconcileTransaction = async () => ({ status: "finalized-success", signature: "signature" });
      f.sdk.hasFinalizedProgramEvent = async () => true;
      assert.deepEqual(await wallet.reconcilePending(), []);
      const notes = await restarted.getNotes();
      assert.equal(notes.length, 3);
      assert.equal(notes.find(n => Buffer.from(n.commitment).equals(Buffer.from(note.commitment))).state, "spent");
      const outputs = notes.filter(n => !Buffer.from(n.commitment).equals(Buffer.from(note.commitment)));
      assert.deepEqual(outputs.map(n => n.leafIndex), [1n, 2n]);
      assert(outputs.every(n => n.state === "available"));
      assert.deepEqual(await wallet.reconcilePending(), []);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
}

test("RC-02 independent encrypted stores share the exclusive proving reservation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rc02-file-"));
  try {
    const path = join(dir, "notes"), store = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    await store.saveNote(note);
    let entered, resume, calls = 0;
    const started = new Promise(resolve => { entered = resolve; }), gate = new Promise(resolve => { resume = resolve; });
    const f = fixture(store, { proveUnshield: async () => { calls++; entered(); await gate; throw new Error("stop proving"); } });
    const first = f.wallet().unshield(params);
    await started;
    const otherStore = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    const other = new ShieldedWallet(f.sdk, seed, f.prover, f.witness, otherStore);
    await other.reconcilePending();
    await assert.rejects(() => other.unshield(params), /Insufficient private balance/);
    assert.equal(calls, 1);
    resume(); await assert.rejects(() => first, /stop proving/);
    assert.equal((await otherStore.getNotes())[0].state, "available");
  } finally { await rm(dir, { recursive: true, force: true }); }
});

for (const mode of ["spent", "absent", "rpc-error", "malformed"]) {
  test(`RC-06 expired unavailable history with canonical ${mode}`, async () => {
    const store = new InMemoryNoteStore(); await store.saveNote(note);
    const id = new Uint8Array(32).fill(89);
    await store.reserveNoteAndBegin(note.commitment, id, owner, { id, kind: "unshield", state: "submitted", pool: note.pool, inputCommitment: note.commitment, signature: "old-signature", lastValidBlockHeight: 1n, metadata: {}, outputNotes: [] });
    await store.markSubmitted(note.commitment, id, "old-signature");
    const f = fixture(store);
    f.sdk.connection.getSignatureStatuses = async () => ({ value: [null] });
    f.sdk.connection.getTransaction = async () => null;
    f.sdk.connection.getBlockHeight = async () => 100;
    const client = new Lethenymous({ connection: f.sdk.connection, wallet: f.sdk.wallet });
    f.sdk.reconcileTransaction = client.reconcileTransaction.bind(client);
    if (mode === "spent") f.consume();
    if (mode === "rpc-error") f.sdk.connection.getMultipleAccountsInfo = async () => { throw new Error("RPC unavailable"); };
    if (mode === "malformed") f.sdk.connection.getMultipleAccountsInfo = async () => [{ ...spentAccount(), owner: pk(99) }];
    await f.wallet().reconcilePending();
    assert.equal((await store.getNotes())[0].state, mode === "spent" ? "spent" : mode === "absent" ? "available" : "submitted");
    assert.equal((await store.getPendingOperations()).length, ["spent", "absent"].includes(mode) ? 0 : 1);
  });
}

test("ordinary finalized transaction failure releases a canonically absent input", async () => {
  const store = new InMemoryNoteStore(); await store.saveNote(note);
  const f = fixture(store);
  f.sdk.buildAndSendOutcome = async (_ix, options) => {
    await options.onSubmitted("failed-signature");
    return { status: "finalized-failed", signature: "failed-signature", error: "execution failed" };
  };
  await assert.rejects(() => f.wallet().unshield(params), /transaction failed/);
  assert.equal((await store.getNotes())[0].state, "available");
  assert.deepEqual(await store.getPendingOperations(), []);
});

test("RC-05 conflicting legacy spent state is consumed in memory and encrypted restart", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rc05-"));
  try {
    const path = join(dir, "notes");
    // Authenticate a genuine old-format record, including its obsolete spent flag.
    const hex = v => Buffer.from(v).toString("hex");
    const legacy = { ...note, pool: note.pool.toBase58(), asset: note.asset.toBase58(), amount: "1000", ownerCommitment: hex(owner), randomness: hex(randomness), commitment: hex(note.commitment), generation: "0", state: "available", spent: true };
    const previous = Buffer.alloc(32), sequence = Buffer.alloc(8); sequence.writeBigUInt64LE(1n);
    const nonce = new Uint8Array(24).fill(90), aad = Buffer.concat([Buffer.from("zkcpmm-v2/note-store/v1"), previous, sequence]);
    const encrypted = xchacha20poly1305(noteStoreKey(seed), nonce, aad).encrypt(Buffer.from(JSON.stringify({ type: "save_note", note: legacy })));
    const body = Buffer.concat([sequence, previous, Buffer.from(nonce), Buffer.from(encrypted)]), length = Buffer.alloc(4); length.writeUInt32LE(body.length);
    await writeFile(path, Buffer.concat([Buffer.from("LNSJ"), Buffer.from([1]), length, body]));
    const memory = new InMemoryNoteStore(); await memory.saveNote({ ...note, state: "available", spent: true });
    for (const store of [memory, EncryptedFileNoteStore.fromSeed(path, seed, owner)]) {
      const wallet = fixture(store).wallet();
      assert.equal((await store.getNotes())[0].state, "spent");
      assert.equal(await wallet.getPrivateBalance({ pool: note.pool, mint: note.asset }), 0n);
      await assert.rejects(() => store.reserveNote(note.commitment, new Uint8Array(32), owner), /not available/);
      await assert.rejects(() => store.releaseReservation(note.commitment), /not reserved/);
      await assert.rejects(() => store.saveNote({ ...note, state: "available", spent: false }), /Conflicting/);
      await assert.rejects(() => wallet.unshield(params), /Insufficient private balance/);
      assert.equal((await store.getNotes())[0].spent, true);
    }
    assert.equal((await EncryptedFileNoteStore.fromSeed(path, seed, owner).getNotes())[0].state, "spent");
  } finally { await rm(dir, { recursive: true, force: true }); }
});
