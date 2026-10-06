import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RpcMerkleWitnessProvider, EncryptedFileNoteStore, MerkleReconstructionError, hash2, keyHierarchy, ownerCommitment, pda, ROOT_HISTORY, TREE_DEPTH, TREE_CAPACITY, rootFromTree } from "../dist/index.js";
import { programId, pool, stream, zero, bytesFor, emptyTree, append, shieldData, unshieldData, rolloverData, addRow, fakeConnection, MemoryCheckpoints } from "./witness-fixtures.mjs";

const hash = b => createHash("sha256").update(b).digest("hex");
const checked = object => Buffer.from(JSON.stringify({ ...object, integrity: { algorithm: "sha256", digest: hash(Buffer.from(JSON.stringify(object))) } }));
const identity = { genesisHash: "genesis-test", programId: programId.toBase58(), pool: pool.toBase58(), stream: stream.toBase58(), format: "pool-generations-v3" };
const key = (kind, generation, digest) => JSON.stringify({ schema: "merkle-v3", identity, kind, generation: generation?.toString(), hash: digest });
const manifestKey = key("pool-manifest");

// Independent complete uniform-tree fixture. Memoization only reuses identical
// Poseidon input pairs; every value is calculated with the real hash function.
// Production loading still validates every leaf and all final root metadata.
let uniformFixture;
function complete(generation) {
  if (!uniformFixture) {
    const tree = emptyTree(), leaf = bytesFor(61), uniform = [leaf], memo = new Map();
    for (let i = 1; i < TREE_DEPTH; i++) uniform.push(Uint8Array.from(hash2(uniform[i - 1], uniform[i - 1])));
    const parent = (a, b) => { const key = Buffer.from(a).toString("hex") + Buffer.from(b).toString("hex"); if (!memo.has(key)) memo.set(key, Uint8Array.from(hash2(a, b))); return memo.get(key); };
    const roots = [];
    for (let count = 1; count < Number(TREE_CAPACITY); count++) {
      let node = zero();
      for (let level = 0; level < TREE_DEPTH; level++) node = (count >> level & 1) ? parent(uniform[level], node) : parent(node, tree.emptySubtrees[level]);
      roots.push(node);
    }
    uniformFixture = { uniform, roots, leaf };
  }
  const { uniform, roots, leaf } = uniformFixture;
  const tree = emptyTree(generation);
  tree.nextIndex = tree.sequence = TREE_CAPACITY - 1n;
  tree.frontier = uniform.map(v => Uint8Array.from(v)); tree.frontierPresent.fill(1);
  for (let sequence = tree.sequence - 31n; sequence <= tree.sequence; sequence++) {
    const slot = Number(sequence % BigInt(ROOT_HISTORY)); tree.roots[slot] = Uint8Array.from(roots[Number(sequence - 1n)]); tree.rootSequences[slot] = sequence; tree.rootGenerations[slot] = generation;
  }
  assert.deepEqual(Uint8Array.from(rootFromTree(tree)), roots.at(-1));
  const encrypted = Buffer.alloc(186); encrypted[0] = 1;
  const appends = new Map();
  for (let i = 0; i < roots.length; i++) {
    const index = BigInt(i), sequence = index + 1n;
    appends.set(index, { index, sequence, commitment: leaf, event: { kind: "shield", pool, asset: 0, amount: 42n, commitment: leaf, encryptedNote: encrypted, root: roots[i], generation, index, sequence, slot: i + 1, signature: `fixture-${generation}-${i}` } });
  }
  return { tree, appends, spentNullifiers: new Set(), identity: { genesisHash: identity.genesisHash, programId: identity.programId, pool: identity.pool, tree: pda.tree(pool, generation, programId)[0].toBase58(), generation } };
}

async function seeded(activeReady = false) {
  const store = new MemoryCheckpoints(), history = [], transactions = new Map(), generations = new Map();
  let current = activeReady ? complete(4n).tree : emptyTree(4n);
  const provider = () => new RpcMerkleWitnessProvider(fakeConnection(history, transactions), programId, async () => current, store, async (_p, g) => generations.get(g));
  const writer = provider();
  for (let g = 0n; g < 4n; g++) {
    const state = complete(g); generations.set(g, state.tree);
    const snapshot = await writer.snapshot(identity, state, true);
    await store.saveMerkleCheckpoint(key("sealed-generation", g), checked({ formatVersion: 3, kind: "sealed-generation", identity: { ...state.identity, generation: g.toString() }, snapshot }));
  }
  const active = activeReady ? complete(4n) : writer.initial(identity, current, 4n); generations.set(4n, current);
  const base = await writer.snapshot(identity, active, false);
  const manifest = { formatVersion: 3, kind: "pool-manifest", identity, activeGeneration: "4", head: { base, segments: 0 }, summary: { nextIndex: current.nextIndex.toString(), sequence: current.sequence.toString(), root: Buffer.from(rootFromTree(current)).toString("hex") }, cursor: {} };
  await store.saveMerkleCheckpoint(manifestKey, checked(manifest));
  store.clearCalls();
  return { store, history, transactions, generations, provider, current: () => current, setCurrent: tree => { current = tree; generations.set(tree.generation, tree); } };
}

test("generation-scoped persistence is lazy and incremental work never rewrites sealed generations", { timeout: 600_000 }, async () => {
  const f = await seeded();
  const sealed = [...f.store.data].filter(([k]) => { const scope = JSON.parse(k); return scope.generation !== undefined && BigInt(scope.generation) < 4n; });
  const digests = new Map(sealed.map(([k, v]) => [k, hash(v)]));
  const gen0 = f.provider();
  assert.equal((await gen0.getWitness(pool, bytesFor(61), 0n)).generation, 0n);
  assert.equal(gen0.getReplayMetrics().generationLoads, 1);
  assert.equal(gen0.getReplayMetrics().validatedLeaves, 65535);
  assert(f.store.reads.every(k => JSON.parse(k).generation === undefined || JSON.parse(k).generation === "0"));
  assert.equal(f.store.writes.length, 0);
  f.store.clearCalls();
  const gen3 = f.provider();
  assert.equal((await gen3.getWitness(pool, bytesFor(61), 3n)).generation, 3n);
  assert.equal(gen3.getReplayMetrics().generationLoads, 1);
  assert(f.store.reads.every(k => JSON.parse(k).generation === undefined || JSON.parse(k).generation === "3"));
  f.store.clearCalls();
  const before = gen0.getReplayMetrics(), next = bytesFor(75), result = append(f.current(), next);
  addRow(f.history, f.transactions, shieldData(next, result, 4n), 300000, "active-gen4-delta");
  assert.equal((await gen0.getWitness(pool, next, 4n)).index, 0n);
  const after = gen0.getReplayMetrics();
  assert.equal(after.serializedAppends - before.serializedAppends, 1);
  assert.equal(after.replayedAppends - before.replayedAppends, 1);
  assert.equal(after.historyTransactions - before.historyTransactions, 1);
  assert.equal(after.sealedWrites - before.sealedWrites, 0);
  assert(f.store.writes.every(({ key: k }) => JSON.parse(k).generation === undefined || JSON.parse(k).generation === "4"));
  assert(f.store.reads.every(k => JSON.parse(k).generation === undefined || JSON.parse(k).generation === "4"));
  for (const [k, d] of digests) assert.equal(hash(f.store.data.get(k)), d);
  const manifest = JSON.parse(Buffer.from(f.store.data.get(manifestKey)).toString());
  assert.equal("events" in manifest, false); assert.equal("generations" in manifest, false);
  assert(f.store.data.get(manifestKey).length < 3000);
  console.log(`SCOPED_INCREMENT serializedLeaves=1 historyTransactions=1 sealedWrites=0 manifestBytes=${f.store.data.get(manifestKey).length}`);
});

test("historical checkpoint corruption and wrong-generation locator fail closed", { timeout: 300_000 }, async () => {
  const f = await seeded();
  const locatorKey = key("sealed-generation", 0n), original = f.store.data.get(locatorKey);
  f.store.data.set(locatorKey, f.store.data.get(key("sealed-generation", 1n)));
  await assert.rejects(() => f.provider().getWitness(pool, bytesFor(61), 0n), e => e instanceof MerkleReconstructionError && e.code === "INVALID_CHECKPOINT");
  f.store.data.set(locatorKey, original);
  const locator = JSON.parse(Buffer.from(original).toString()), blob = f.store.data.get(locator.snapshot.key);
  const corrupt = Uint8Array.from(blob); corrupt[0] ^= 1; f.store.data.set(locator.snapshot.key, corrupt);
  await assert.rejects(() => f.provider().getWitness(pool, bytesFor(61), 0n), e => e instanceof MerkleReconstructionError && e.code === "INVALID_CHECKPOINT");
});

test("interrupted rollover publication recovers from the prior authenticated cursor", { timeout: 600_000 }, async () => {
  const f = await seeded(true), prior = Uint8Array.from(f.store.data.get(manifestKey));
  const old = f.current();
  addRow(f.history, f.transactions, rolloverData(old), 300000, "rollover-4-5"); f.setCurrent(emptyTree(5n));
  f.store.fail = k => JSON.parse(k).kind === "pool-manifest";
  await assert.rejects(() => f.provider().getSpentNullifiers(pool), /injected checkpoint failure/);
  assert.deepEqual(f.store.data.get(manifestKey), prior);
  const orphan = f.store.data.get(key("sealed-generation", 4n)); assert(orphan);
  f.store.fail = undefined;
  await f.provider().getSpentNullifiers(pool);
  assert.equal(JSON.parse(Buffer.from(f.store.data.get(manifestKey)).toString()).activeGeneration, "5");
  assert.deepEqual(f.store.data.get(key("sealed-generation", 4n)), orphan);
});

test("global nullifier index is independent of generation replay and retries unpublished writes safely", async () => {
  const store = new MemoryCheckpoints(), history = [], transactions = new Map(), current = emptyTree();
  const leaf = bytesFor(81), result = append(current, leaf);
  addRow(history, transactions, shieldData(leaf, result), 1, "shield-nf");
  const fresh = () => new RpcMerkleWitnessProvider(fakeConnection(history, transactions), programId, async () => current, store);
  await fresh().getWitness(pool, leaf, 0n);
  const manifestKey = [...store.data.keys()].find(k => JSON.parse(k).kind === "pool-manifest"), prior = store.data.get(manifestKey);
  const nf = bytesFor(82); addRow(history, transactions, unshieldData(nf, current.sequence), 2, "spend-nf");
  store.fail = k => JSON.parse(k).kind === "pool-manifest";
  await assert.rejects(() => fresh().getSpentNullifiers(pool), /injected checkpoint failure/);
  assert.deepEqual(store.data.get(manifestKey), prior);
  store.fail = undefined;
  assert.deepEqual(await fresh().getSpentNullifiers(pool), [nf]);
  addRow(history, transactions, unshieldData(nf, current.sequence), 3, "replay-nf");
  await assert.rejects(() => fresh().getSpentNullifiers(pool), e => e.code === "DUPLICATE_EVENT");
});

test("sealed generation append is rejected before any checkpoint publication", { timeout: 300_000 }, async () => {
  const f = await seeded(); const prior = f.store.data.get(manifestKey);
  const data = shieldData(bytesFor(83), { index: 65535n, root: rootFromTree(f.generations.get(0n)) }, 0n);
  addRow(f.history, f.transactions, data, 300000, "sealed-write-attempt");
  await assert.rejects(() => f.provider().getSpentNullifiers(pool), e => e.code === "GENERATION_MISMATCH");
  assert.deepEqual(f.store.data.get(manifestKey), prior);
});

test("encrypted store compare-and-swap authenticates and serializes manifest publication", async () => {
  const dir = await mkdtemp(join(tmpdir(), "scoped-cas-"));
  try {
    const seed = bytesFor(84), owner = ownerCommitment(keyHierarchy(seed).spendSecret), path = join(dir, "notes");
    const a = EncryptedFileNoteStore.fromSeed(path, seed, owner), b = EncryptedFileNoteStore.fromSeed(path, seed, owner);
    const first = Buffer.from("authenticated-old"), next = Buffer.from("authenticated-new");
    assert.equal(await a.compareAndSwapMerkleCheckpoint("manifest", undefined, first), true);
    assert.equal(await b.compareAndSwapMerkleCheckpoint("manifest", undefined, next), false);
    assert.equal(await b.compareAndSwapMerkleCheckpoint("manifest", hash(first), next), true);
    assert.deepEqual(Buffer.from(await a.loadMerkleCheckpoint("manifest")), next);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("legacy v2 checkpoints are authenticated then rebuilt, not reinterpreted", async () => {
  const store = new MemoryCheckpoints(), history = [], transactions = new Map(), current = emptyTree();
  const leaf = bytesFor(85), result = append(current, leaf);
  addRow(history, transactions, shieldData(leaf, result), 1, "v2-recovery");
  const oldIdentity = { ...identity, format: "pool-generations-v2" };
  const oldKey = JSON.stringify(oldIdentity);
  // An authenticated, empty v2 checkpoint is intentionally behind finalized
  // chain state. Its cursor cannot skip the missing append during v3 recovery.
  const t = emptyTree();
  const serializeTree = t => ({ ...t, pool: pool.toBase58(), generation: t.generation.toString(), nextIndex: t.nextIndex.toString(), sequence: t.sequence.toString(),
    frontier: t.frontier.map(b => Buffer.from(b).toString("hex")), emptySubtrees: t.emptySubtrees.map(b => Buffer.from(b).toString("hex")), roots: t.roots.map(b => Buffer.from(b).toString("hex")), rootSequences: t.rootSequences.map(String), rootGenerations: t.rootGenerations.map(String) });
  store.data.set(oldKey, checked({ formatVersion: 2, identity: oldIdentity, events: [], trees: [serializeTree(t)], cursor: { lastProcessedSignature: "must-not-reuse", lastFinalizedSlot: 0 } }));
  const calls = { signatures: 0, transactions: [] };
  const provider = new RpcMerkleWitnessProvider(fakeConnection(history, transactions, calls), programId, async () => current, store);
  assert.equal((await provider.getWitness(pool, leaf, 0n)).index, 0n);
  assert.deepEqual(calls.transactions, ["v2-recovery"]);
  const manifest = JSON.parse(Buffer.from(store.data.get(manifestKey)).toString());
  assert.equal(manifest.formatVersion, 3); assert.equal("events" in manifest, false);
  const bad = new MemoryCheckpoints(); bad.data.set(oldKey, Buffer.from("incompatible or corrupted legacy checkpoint"));
  await assert.rejects(() => new RpcMerkleWitnessProvider(fakeConnection(history, transactions), programId, async () => current, bad).getWitness(pool, leaf, 0n), e => e.code === "INVALID_CHECKPOINT");
});

test("active delta compaction is bounded to the active generation", async () => {
  const store = new MemoryCheckpoints(), history = [], transactions = new Map(), current = emptyTree();
  const provider = new RpcMerkleWitnessProvider(fakeConnection(history, transactions), programId, async () => current, store);
  for (let i = 0; i < 66; i++) {
    const leaf = bytesFor(86), result = append(current, leaf);
    addRow(history, transactions, shieldData(leaf, result), i + 1, `compaction-${i}`);
    await provider.getWitness(pool, leaf, 0n);
  }
  const manifest = JSON.parse(Buffer.from(store.data.get(manifestKey)).toString());
  assert.equal(manifest.head.segments, 1);
  assert.equal(provider.getReplayMetrics().sealedWrites, 0);
  const restored = new RpcMerkleWitnessProvider(fakeConnection(history, transactions), programId, async () => current, store);
  assert.equal((await restored.getWitness(pool, bytesFor(86), 0n)).rootSequence, 66n);
});
