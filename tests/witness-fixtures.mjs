import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { hash2, pda, rootFromTree, TREE_DEPTH, TREE_CAPACITY, ROOT_HISTORY } from "../dist/index.js";

export const programId = new PublicKey(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
export const pool = new PublicKey(Uint8Array.from({ length: 32 }, (_, i) => i + 40));
export const stream = pda.shielded(pool, programId)[0];
export const zero = () => new Uint8Array(32);
export const bytesFor = v => { const b = zero(); b[31] = v; return b; };
export const u64 = v => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
export const eventId = name => createHash("sha256").update(`event:${name}`).digest().subarray(0, 8);

export function emptyTree(generation = 0n) {
  const emptySubtrees = [zero()];
  for (let i = 0; i < TREE_DEPTH; i++) emptySubtrees.push(Uint8Array.from(hash2(emptySubtrees[i], emptySubtrees[i])));
  const tree = { pool, generation, nextIndex: 0n, sequence: 0n, frontier: Array.from({ length: TREE_DEPTH }, zero), frontierPresent: Array(TREE_DEPTH).fill(0), emptySubtrees,
    roots: Array.from({ length: ROOT_HISTORY }, zero), rootSequences: Array(ROOT_HISTORY).fill(0n), rootGenerations: Array(ROOT_HISTORY).fill(0n) };
  tree.roots[0] = Uint8Array.from(emptySubtrees[TREE_DEPTH]); tree.rootGenerations[0] = generation;
  return tree;
}

export function append(tree, leaf) {
  const index = tree.nextIndex; let carry = Uint8Array.from(leaf);
  for (let i = 0; i < TREE_DEPTH; i++) {
    if ((index >> BigInt(i) & 1n) === 0n) { tree.frontier[i] = carry; tree.frontierPresent[i] = 1; break; }
    carry = Uint8Array.from(hash2(tree.frontier[i], carry)); tree.frontierPresent[i] = 0;
  }
  if (index === TREE_CAPACITY - 1n) { tree.frontier[TREE_DEPTH - 1] = carry; tree.frontierPresent[TREE_DEPTH - 1] = 1; }
  tree.nextIndex++; tree.sequence++;
  const root = rootFromTree(tree), slot = Number(tree.sequence % BigInt(ROOT_HISTORY));
  tree.roots[slot] = Uint8Array.from(root); tree.rootSequences[slot] = tree.sequence; tree.rootGenerations[slot] = tree.generation;
  return { index, sequence: tree.sequence, root: Uint8Array.from(root) };
}

export function shieldData(commitment, result, generation = 0n) {
  const encrypted = Buffer.alloc(186); encrypted[0] = 1;
  return Buffer.concat([eventId("ShieldedNoteAppended"), pool.toBuffer(), Buffer.from([0]), u64(42), Buffer.from(commitment), Buffer.from([186, 0, 0, 0]), encrypted, Buffer.from(result.root), u64(generation), u64(result.index)]);
}
export function swapData(change, output, root, sequence, changeIndex, outputIndex, inputGeneration = 0n, outputGeneration) {
  return Buffer.concat([eventId("PrivateSwapped"), pool.toBuffer(), Buffer.from([0]), u64(1), u64(1), Buffer.from(root), u64(sequence), u64(inputGeneration), bytesFor(9), Buffer.from(change), Buffer.from(output), Buffer.from([1]), u64(changeIndex), u64(outputIndex), ...(outputGeneration === undefined ? [] : [u64(outputGeneration)])]);
}
export function unshieldData(nullifier, sequence, generation = 0n) {
  return Buffer.concat([eventId("Unshielded"), pool.toBuffer(), Buffer.from([0]), u64(1), new PublicKey(new Uint8Array(32).fill(80)).toBuffer(), Buffer.from(nullifier), u64(generation), u64(sequence)]);
}
export function rolloverData(tree) {
  return Buffer.concat([eventId("TreeRolledOver"), pool.toBuffer(), pda.tree(pool, tree.generation, programId)[0].toBuffer(), u64(tree.generation), Buffer.from(rootFromTree(tree)), pda.tree(pool, tree.generation + 1n, programId)[0].toBuffer(), u64(tree.generation + 1n)]);
}
export function addRow(history, transactions, data, slot, signature = `signature-${history.length + 1}`) {
  history.push({ signature, slot, err: null, confirmationStatus: "finalized" });
  transactions.set(signature, { slot, meta: { err: null, logMessages: data ? [`Program ${programId} invoke [1]`, `Program data: ${Buffer.from(data).toString("base64")}`, `Program ${programId} success`] : [] },
    transaction: { signatures: [signature], message: { getAccountKeys: () => ({ get: i => i === 0 ? programId : stream }), compiledInstructions: [{ programIdIndex: 0, accountKeyIndexes: [1] }] } } });
  return signature;
}
export function fakeConnection(history, transactions, calls = { signatures: 0, transactions: [] }) {
  return { getGenesisHash: async () => "genesis-test", getSignaturesForAddress: async (_a, options) => {
    calls.signatures++; const rows = [...history].reverse(); const start = options?.before ? rows.findIndex(r => r.signature === options.before) + 1 : 0;
    return rows.slice(start, start + 1000);
  }, getTransaction: async signature => { calls.transactions.push(signature); return transactions.get(signature) ?? null; } };
}
export class MemoryCheckpoints {
  data = new Map(); reads = []; writes = []; fail;
  async loadMerkleCheckpoint(key) { this.reads.push(key); return this.data.get(key); }
  async saveMerkleCheckpoint(key, bytes) { if (this.fail?.(key, bytes)) throw new Error("injected checkpoint failure"); this.writes.push({ key, bytes: bytes.length }); this.data.set(key, Uint8Array.from(bytes)); }
  async compareAndSwapMerkleCheckpoint(key, expected, bytes) {
    const current = this.data.get(key), digest = current && createHash("sha256").update(current).digest("hex");
    if (digest !== expected) return false; await this.saveMerkleCheckpoint(key, bytes); return true;
  }
  clearCalls() { this.reads = []; this.writes = []; }
}
