import test from "node:test";
import assert from "node:assert/strict";
import { RpcMerkleWitnessProvider, MerkleReconstructionError, TREE_CAPACITY, rootFromTree } from "../../dist/index.js";
import { programId, pool, bytesFor, u64, emptyTree, append, shieldData, swapData, unshieldData, rolloverData, addRow, fakeConnection, MemoryCheckpoints } from "../witness-fixtures.mjs";

test("full-capacity replay authenticates rollover, cross-generation outputs, and checkpoint restart", { timeout: 2_400_000 }, async () => {
  const started = performance.now();
  const old = emptyTree(), history = [], transactions = new Map(), commitment = bytesFor(61);
  for (let i = 0; i < Number(TREE_CAPACITY) - 1; i++) {
    const result = append(old, commitment);
    addRow(history, transactions, shieldData(commitment, result), i + 1, `generation-leaf-${i}`);
  }
  let current = emptyTree(1n);
  const generations = new Map([[0n, old], [1n, current]]);
  const rollover = rolloverData(old);
  addRow(history, transactions, rollover, 65536, "generation-rollover");
  const change = bytesFor(62), output = bytesFor(63);
  append(current, change); append(current, output);
  addRow(history, transactions, swapData(change, output, rootFromTree(old), old.sequence, 0n, 1n, 0n, 1n), 65537, "generation-cross-swap");
  addRow(history, transactions, unshieldData(bytesFor(64), old.sequence), 65538, "generation-old-unshield");
  const store = new MemoryCheckpoints();
  const provider = new RpcMerkleWitnessProvider(fakeConnection(history, transactions), programId, async () => current, store, async (_p, g) => generations.get(g));
  const w = await provider.getWitness(pool, commitment, 0n);
  assert.equal(w.generation, 0n); assert.equal(w.rootSequence, 65535n); assert.deepEqual(w.root, Uint8Array.from(rootFromTree(old)));
  const out = await provider.getWitness(pool, output, 1n);
  assert.equal(out.generation, 1n); assert.equal(out.index, 1n);
  const calls = { signatures: 0, transactions: [] };
  const restarted = new RpcMerkleWitnessProvider(fakeConnection(history, transactions, calls), programId, async () => current, store, async (_p, g) => generations.get(g));
  assert.deepEqual(await restarted.getWitness(pool, output, 1n), out); assert.equal(calls.transactions.length, 0);
  assert((await restarted.getSpentNullifiers(pool)).some(v => Buffer.from(v).equals(Buffer.from(bytesFor(9)))));
  const sealed0 = [...store.data].filter(([key]) => JSON.parse(key).generation === "0" && JSON.parse(key).kind !== "nullifier-index");
  for (let next = 2n; next <= 4n; next++) {
    const previous = current;
    while (previous.nextIndex < TREE_CAPACITY - 1n) {
      const result = append(previous, commitment);
      addRow(history, transactions, shieldData(commitment, result, previous.generation), history.length + 1, `generation-${previous.generation}-leaf-${result.index}`);
    }
    addRow(history, transactions, rolloverData(previous), history.length + 1, `generation-rollover-${next}`);
    current = emptyTree(next); generations.set(next, current);
    if (next === 2n) { const oldWitness = await restarted.getWitness(pool, commitment, 0n); assert.equal(oldWitness.generation, 0n); assert.deepEqual(oldWitness.root, w.root); }
  }
  const gen1 = await restarted.getWitness(pool, output, 1n);
  assert.equal(current.generation, 4n); assert.equal(gen1.generation, 1n); assert.equal(gen1.index, 1n); assert.equal(gen1.rootSequence, 65535n);
  assert.deepEqual(gen1.root, Uint8Array.from(rootFromTree(generations.get(1n))));
  for (const [key, bytes] of sealed0) assert.deepEqual(store.data.get(key), bytes);
  const manifests = [...store.data].filter(([key]) => JSON.parse(key).kind === "pool-manifest");
  assert.equal(manifests.length, 1); const [manifestKey, before] = manifests[0];
  addRow(history, transactions, Buffer.concat([rollover.subarray(0, 144), u64(3)]), history.length + 1, "impossible-rollover");
  await assert.rejects(() => restarted.getWitness(pool, output, 1n), e => e instanceof MerkleReconstructionError && e.code === "GENERATION_MISMATCH");
  assert.deepEqual(store.data.get(manifestKey), before);
  console.log(`SCOPED_STRESS_RUNTIME_MS=${Math.round(performance.now() - started)}`);
  for (let g = 0n; g < 4n; g++) {
    const locator = [...store.data].find(([key]) => JSON.parse(key).kind === "sealed-generation" && JSON.parse(key).generation === g.toString());
    const value = JSON.parse(Buffer.from(locator[1]).toString());
    const body = store.data.get(value.snapshot.key);
    const encoded = JSON.parse(Buffer.from(body).toString());
    const size = encoded.kind === "chunked-blob" ? encoded.byteLength : body.length;
    console.log(`GENERATION_CHECKPOINT_BYTES gen=${g} bytes=${size}`);
  }
});
