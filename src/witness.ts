import { createHash } from "node:crypto";
import { PublicKey, type Connection, type VersionedTransactionResponse } from "@solana/web3.js";
import { hash2 } from "./crypto.js";
import { ROOT_HISTORY, TREE_CAPACITY, TREE_DEPTH, rootFromTree, verifyPath } from "./merkle.js";
import type { MerkleCheckpointStore, MerkleWitness, MerkleWitnessProvider, TreeState } from "./types.js";

const eventId = (name: string) => createHash("sha256").update(`event:${name}`).digest().subarray(0, 8);
const SHIELD = eventId("ShieldedNoteAppended");
const SWAP = eventId("PrivateSwapped");
const UNSHIELD = eventId("Unshielded");
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CHECKPOINT_VERSION = 1;
const same = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
const bytes = (value: string) => Uint8Array.from(Buffer.from(value, "hex"));
const cloneBytes = (value: Uint8Array) => Uint8Array.from(value);
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const u64 = (data: Buffer, offset: number) => data.readBigUInt64LE(offset);
const pubkey = (data: Buffer, offset: number) => new PublicKey(data.subarray(offset, offset + 32));
const canonicalField = (value: Uint8Array) => BigInt(`0x${Buffer.from(value).toString("hex")}`) < BN254_MODULUS;

export interface ShieldAppendEvent {
  kind: "shield";
  pool: PublicKey;
  asset: number;
  amount: bigint;
  commitment: Uint8Array;
  encryptedNote: Uint8Array;
  root: Uint8Array;
  generation: bigint;
  index: bigint;
  sequence: bigint;
  slot: number;
  signature: string;
}

export interface PrivateSwapEvent {
  kind: "swap";
  pool: PublicKey;
  direction: number;
  amountIn: bigint;
  amountOut: bigint;
  root: Uint8Array;
  rootSequence: bigint;
  generation: bigint;
  nullifier: Uint8Array;
  changeCommitment: Uint8Array;
  outputCommitment: Uint8Array;
  changeIndex?: bigint;
  outputIndex: bigint;
  slot: number;
  signature: string;
}

export interface UnshieldEvent {
  kind: "unshield";
  pool: PublicKey;
  asset: number;
  amount: bigint;
  recipient: PublicKey;
  nullifier: Uint8Array;
  generation: bigint;
  rootSequence: bigint;
  slot: number;
  signature: string;
}

export type ShieldedAppendEvent = ShieldAppendEvent | PrivateSwapEvent;
type HistoryEvent = ShieldedAppendEvent | UnshieldEvent;

export type MerkleReconstructionErrorCode =
  | "INVALID_CHECKPOINT"
  | "HISTORY_GAP"
  | "HISTORY_RPC"
  | "GENERATION_MISMATCH"
  | "SEQUENCE_GAP"
  | "ROOT_MISMATCH"
  | "TRANSACTION_MISSING"
  | "FAILED_TRANSACTION"
  | "DUPLICATE_EVENT"
  | "INVALID_TREE";

export class MerkleReconstructionError extends Error {
  constructor(public readonly code: MerkleReconstructionErrorCode, message: string) {
    super(message);
    this.name = "MerkleReconstructionError";
  }
}

interface CheckpointIdentity {
  genesisHash: string;
  programId: string;
  pool: string;
  tree: string;
  generation: bigint;
}

interface AppendRecord {
  index: bigint;
  sequence: bigint;
  commitment: Uint8Array;
  event: ShieldedAppendEvent;
}

interface ReplayState {
  identity: CheckpointIdentity;
  tree: TreeState;
  appends: Map<bigint, AppendRecord>;
  spentNullifiers: Set<string>;
  lastProcessedSignature?: string;
  lastFinalizedSlot?: number;
}

interface HistoryRow {
  signature: string;
  slot: number;
  err: unknown;
  confirmationStatus?: string | null;
}

function reconstruction(code: MerkleReconstructionErrorCode, message: string): never {
  throw new MerkleReconstructionError(code, message);
}

function cloneTree(tree: TreeState): TreeState {
  return {
    pool: new PublicKey(tree.pool),
    generation: tree.generation,
    nextIndex: tree.nextIndex,
    sequence: tree.sequence,
    frontier: tree.frontier.map(cloneBytes),
    frontierPresent: [...tree.frontierPresent],
    emptySubtrees: tree.emptySubtrees.map(cloneBytes),
    roots: tree.roots.map(cloneBytes),
    rootSequences: [...tree.rootSequences],
    rootGenerations: [...tree.rootGenerations],
  };
}

function cloneEvent(event: ShieldedAppendEvent): ShieldedAppendEvent {
  if (event.kind === "shield") {
    return {
      ...event,
      pool: new PublicKey(event.pool),
      commitment: cloneBytes(event.commitment),
      encryptedNote: cloneBytes(event.encryptedNote),
      root: cloneBytes(event.root),
    };
  }
  return {
    ...event,
    pool: new PublicKey(event.pool),
    root: cloneBytes(event.root),
    nullifier: cloneBytes(event.nullifier),
    changeCommitment: cloneBytes(event.changeCommitment),
    outputCommitment: cloneBytes(event.outputCommitment),
  };
}

function cloneState(state: ReplayState): ReplayState {
  return {
    identity: { ...state.identity },
    tree: cloneTree(state.tree),
    appends: new Map([...state.appends].map(([index, record]) => [index, {
      index: record.index,
      sequence: record.sequence,
      commitment: cloneBytes(record.commitment),
      event: cloneEvent(record.event),
    }])),
    spentNullifiers: new Set(state.spentNullifiers),
    lastProcessedSignature: state.lastProcessedSignature,
    lastFinalizedSlot: state.lastFinalizedSlot,
  };
}

function parseBytes(value: unknown, length: number, name: string): Uint8Array {
  if (typeof value !== "string" || !/^[0-9a-f]+$/i.test(value) || value.length !== length * 2) reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
  return bytes(value);
}

function parseBigInt(value: unknown, name: string): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value)) reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
  try { return BigInt(value); } catch { reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`); }
}

function parseSafeInteger(value: unknown, name: string, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
  return value;
}

function parsePublicKey(value: unknown, name: string): PublicKey {
  try {
    if (typeof value !== "string") throw new Error();
    return new PublicKey(value);
  } catch {
    reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
  }
}

function serializeEvent(event: ShieldedAppendEvent): Record<string, unknown> {
  if (event.kind === "shield") {
    return {
      kind: event.kind,
      pool: event.pool.toBase58(),
      asset: event.asset,
      amount: event.amount.toString(),
      commitment: hex(event.commitment),
      encryptedNote: hex(event.encryptedNote),
      root: hex(event.root),
      generation: event.generation.toString(),
      index: event.index.toString(),
      sequence: event.sequence.toString(),
      slot: event.slot,
      signature: event.signature,
    };
  }
  return {
    kind: event.kind,
    pool: event.pool.toBase58(),
    direction: event.direction,
    amountIn: event.amountIn.toString(),
    amountOut: event.amountOut.toString(),
    root: hex(event.root),
    rootSequence: event.rootSequence.toString(),
    generation: event.generation.toString(),
    nullifier: hex(event.nullifier),
    changeCommitment: hex(event.changeCommitment),
    outputCommitment: hex(event.outputCommitment),
    changeIndex: event.changeIndex?.toString(),
    outputIndex: event.outputIndex.toString(),
    slot: event.slot,
    signature: event.signature,
  };
}

function deserializeEvent(value: unknown): ShieldedAppendEvent {
  if (!value || typeof value !== "object") reconstruction("INVALID_CHECKPOINT", "Invalid append event in Merkle checkpoint");
  const event = value as Record<string, unknown>;
  if (event.kind === "shield") {
    return {
      kind: "shield",
      pool: parsePublicKey(event.pool, "shield pool"),
      asset: parseSafeInteger(event.asset, "shield asset"),
      amount: parseBigInt(event.amount, "shield amount"),
      commitment: parseBytes(event.commitment, 32, "shield commitment"),
      encryptedNote: parseBytes(event.encryptedNote, 186, "encrypted note"),
      root: parseBytes(event.root, 32, "shield root"),
      generation: parseBigInt(event.generation, "shield generation"),
      index: parseBigInt(event.index, "shield index"),
      sequence: parseBigInt(event.sequence, "shield sequence"),
      slot: parseSafeInteger(event.slot, "shield slot"),
      signature: typeof event.signature === "string" && event.signature.length > 0 ? event.signature : reconstruction("INVALID_CHECKPOINT", "Invalid shield signature in Merkle checkpoint"),
    };
  }
  if (event.kind === "swap") {
    return {
      kind: "swap",
      pool: parsePublicKey(event.pool, "swap pool"),
      direction: parseSafeInteger(event.direction, "swap direction"),
      amountIn: parseBigInt(event.amountIn, "swap amountIn"),
      amountOut: parseBigInt(event.amountOut, "swap amountOut"),
      root: parseBytes(event.root, 32, "swap root"),
      rootSequence: parseBigInt(event.rootSequence, "swap root sequence"),
      generation: parseBigInt(event.generation, "swap generation"),
      nullifier: parseBytes(event.nullifier, 32, "swap nullifier"),
      changeCommitment: parseBytes(event.changeCommitment, 32, "swap change commitment"),
      outputCommitment: parseBytes(event.outputCommitment, 32, "swap output commitment"),
      changeIndex: event.changeIndex === undefined ? undefined : parseBigInt(event.changeIndex, "swap change index"),
      outputIndex: parseBigInt(event.outputIndex, "swap output index"),
      slot: parseSafeInteger(event.slot, "swap slot"),
      signature: typeof event.signature === "string" && event.signature.length > 0 ? event.signature : reconstruction("INVALID_CHECKPOINT", "Invalid swap signature in Merkle checkpoint"),
    };
  }
  reconstruction("INVALID_CHECKPOINT", "Unknown append event in Merkle checkpoint");
}

function serializeTree(tree: TreeState): Record<string, unknown> {
  return {
    pool: tree.pool.toBase58(),
    generation: tree.generation.toString(),
    nextIndex: tree.nextIndex.toString(),
    sequence: tree.sequence.toString(),
    frontier: tree.frontier.map(hex),
    frontierPresent: [...tree.frontierPresent],
    emptySubtrees: tree.emptySubtrees.map(hex),
    roots: tree.roots.map(hex),
    rootSequences: tree.rootSequences.map(value => value.toString()),
    rootGenerations: tree.rootGenerations.map(value => value.toString()),
  };
}

function deserializeTree(value: unknown): TreeState {
  if (!value || typeof value !== "object") reconstruction("INVALID_CHECKPOINT", "Invalid tree state in Merkle checkpoint");
  const tree = value as Record<string, unknown>;
  const array = (name: string) => {
    const item = tree[name];
    if (!Array.isArray(item)) reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
    return item;
  };
  return {
    pool: parsePublicKey(tree.pool, "tree pool"),
    generation: parseBigInt(tree.generation, "tree generation"),
    nextIndex: parseBigInt(tree.nextIndex, "tree next index"),
    sequence: parseBigInt(tree.sequence, "tree sequence"),
    frontier: array("frontier").map((item, index) => parseBytes(item, 32, `frontier[${index}]`)),
    frontierPresent: array("frontierPresent").map((item, index) => parseSafeInteger(item, `frontierPresent[${index}]`)),
    emptySubtrees: array("emptySubtrees").map((item, index) => parseBytes(item, 32, `emptySubtrees[${index}]`)),
    roots: array("roots").map((item, index) => parseBytes(item, 32, `roots[${index}]`)),
    rootSequences: array("rootSequences").map((item, index) => parseBigInt(item, `rootSequences[${index}]`)),
    rootGenerations: array("rootGenerations").map((item, index) => parseBigInt(item, `rootGenerations[${index}]`)),
  };
}

function identityObject(identity: CheckpointIdentity): Record<string, string> {
  return {
    genesisHash: identity.genesisHash,
    programId: identity.programId,
    pool: identity.pool,
    tree: identity.tree,
    generation: identity.generation.toString(),
  };
}

function identityKey(identity: CheckpointIdentity): string {
  return JSON.stringify(identityObject(identity));
}

function validateTreeShape(tree: TreeState, context: string): void {
  if (tree.frontier.length !== TREE_DEPTH || tree.frontierPresent.length !== TREE_DEPTH || tree.emptySubtrees.length !== TREE_DEPTH + 1 || tree.roots.length !== ROOT_HISTORY || tree.rootSequences.length !== ROOT_HISTORY || tree.rootGenerations.length !== ROOT_HISTORY) reconstruction("INVALID_TREE", `Invalid ${context} array lengths`);
  if (tree.nextIndex < 0n || tree.nextIndex > TREE_CAPACITY || tree.sequence < 0n || tree.sequence !== tree.nextIndex) reconstruction("INVALID_TREE", `Invalid ${context} counters`);
  if (tree.frontier.some(value => value.length !== 32) || tree.emptySubtrees.some(value => value.length !== 32) || tree.roots.some(value => value.length !== 32)) reconstruction("INVALID_TREE", `Invalid ${context} node length`);
  if (tree.frontier.some(value => !canonicalField(value)) || tree.emptySubtrees.some(value => !canonicalField(value)) || tree.roots.some(value => !canonicalField(value))) reconstruction("INVALID_TREE", `Invalid ${context} field element`);
  if (tree.frontierPresent.some(value => value !== 0 && value !== 1)) reconstruction("INVALID_TREE", `Invalid ${context} frontier flags`);
  let root: Uint8Array;
  try { root = rootFromTree(tree); } catch (error) { reconstruction("INVALID_TREE", `${context} root is invalid: ${String(error)}`); }
  const slot = Number(tree.sequence % BigInt(ROOT_HISTORY));
  if (tree.rootSequences[slot] !== tree.sequence || tree.rootGenerations[slot] !== tree.generation || !same(root!, tree.roots[slot])) reconstruction("INVALID_TREE", `${context} root history is inconsistent`);
}

function cloneInitialTree(pool: PublicKey, current: TreeState): TreeState {
  const zero = new Uint8Array(32);
  const tree: TreeState = {
    pool: new PublicKey(pool),
    generation: current.generation,
    nextIndex: 0n,
    sequence: 0n,
    frontier: Array.from({ length: TREE_DEPTH }, () => cloneBytes(zero)),
    frontierPresent: Array(TREE_DEPTH).fill(0),
    emptySubtrees: current.emptySubtrees.map(cloneBytes),
    roots: Array.from({ length: ROOT_HISTORY }, () => cloneBytes(zero)),
    rootSequences: Array(ROOT_HISTORY).fill(0n),
    rootGenerations: Array(ROOT_HISTORY).fill(0n),
  };
  tree.roots[0] = cloneBytes(tree.emptySubtrees[TREE_DEPTH]);
  tree.rootGenerations[0] = current.generation;
  return tree;
}

function rootAt(tree: TreeState, sequence: bigint): Uint8Array | undefined {
  if (sequence > tree.sequence || tree.sequence - sequence >= BigInt(ROOT_HISTORY)) return undefined;
  const slot = Number(sequence % BigInt(ROOT_HISTORY));
  if (tree.rootSequences[slot] !== sequence || tree.rootGenerations[slot] !== tree.generation) return undefined;
  return tree.roots[slot];
}

function assertAcceptedRoot(tree: TreeState, sequence: bigint, root?: Uint8Array): void {
  const accepted = rootAt(tree, sequence);
  if (!accepted || (root && !same(accepted, root))) reconstruction("ROOT_MISMATCH", `Event references an unavailable finalized root sequence ${sequence}`);
}

function appendLeaf(tree: TreeState, leaf: Uint8Array): { index: bigint; sequence: bigint; root: Uint8Array } {
  if (leaf.length !== 32 || !canonicalField(leaf) || same(leaf, new Uint8Array(32))) reconstruction("SEQUENCE_GAP", "Invalid Merkle append commitment");
  if (tree.nextIndex >= TREE_CAPACITY) reconstruction("SEQUENCE_GAP", "Merkle tree is full");
  const index = tree.nextIndex;
  let carry = cloneBytes(leaf);
  for (let level = 0; level < TREE_DEPTH; level++) {
    if (((index >> BigInt(level)) & 1n) === 0n) {
      tree.frontier[level] = carry;
      tree.frontierPresent[level] = 1;
      break;
    }
    if (tree.frontierPresent[level] !== 1) reconstruction("INVALID_TREE", `Missing frontier node at level ${level}`);
    carry = Uint8Array.from(hash2(tree.frontier[level], carry));
    tree.frontierPresent[level] = 0;
  }
  if (index === TREE_CAPACITY - 1n) {
    tree.frontier[TREE_DEPTH - 1] = carry;
    tree.frontierPresent[TREE_DEPTH - 1] = 1;
  }
  tree.nextIndex += 1n;
  tree.sequence += 1n;
  const root = rootFromTree(tree);
  const slot = Number(tree.sequence % BigInt(ROOT_HISTORY));
  tree.roots[slot] = cloneBytes(root);
  tree.rootSequences[slot] = tree.sequence;
  tree.rootGenerations[slot] = tree.generation;
  return { index, sequence: tree.sequence, root: cloneBytes(root) };
}

function assertIdentity(pool: PublicKey, event: HistoryEvent): void {
  if (!event.pool.equals(pool)) reconstruction("GENERATION_MISMATCH", "History event references another pool");
}

function appendRecord(state: ReplayState, result: { index: bigint; sequence: bigint }, commitment: Uint8Array, event: ShieldedAppendEvent): void {
  if (state.appends.has(result.index)) reconstruction("DUPLICATE_EVENT", `Conflicting duplicate Merkle leaf index ${result.index}`);
  state.appends.set(result.index, { index: result.index, sequence: result.sequence, commitment: cloneBytes(commitment), event: cloneEvent(event) });
}

function recordSpentNullifier(state: ReplayState, nullifier: Uint8Array): void {
  const value = hex(nullifier);
  if (state.spentNullifiers.has(value)) reconstruction("DUPLICATE_EVENT", `Conflicting duplicate nullifier ${value}`);
  state.spentNullifiers.add(value);
}

function applyEvent(state: ReplayState, pool: PublicKey, event: HistoryEvent): void {
  assertIdentity(pool, event);
  if (event.generation !== state.tree.generation) reconstruction("GENERATION_MISMATCH", `History event generation ${event.generation} does not match ${state.tree.generation}`);
  if (event.kind === "unshield") {
    assertAcceptedRoot(state.tree, event.rootSequence);
    recordSpentNullifier(state, event.nullifier);
    return;
  }
  if (event.kind === "shield") {
    if (event.index !== state.tree.nextIndex || event.sequence !== state.tree.sequence + 1n) reconstruction("SEQUENCE_GAP", `Shield event index or sequence is not contiguous at ${state.tree.nextIndex}`);
    const result = appendLeaf(state.tree, event.commitment);
    if (result.index !== event.index || result.sequence !== event.sequence || !same(result.root, event.root)) reconstruction("ROOT_MISMATCH", `Shield event root does not match replayed root at ${event.index}`);
    appendRecord(state, result, event.commitment, event);
    return;
  }
  assertAcceptedRoot(state.tree, event.rootSequence, event.root);
  const expectedIndex = state.tree.nextIndex;
  if (event.changeIndex !== undefined && event.changeIndex !== expectedIndex) reconstruction("SEQUENCE_GAP", `Private-swap change index is not contiguous at ${expectedIndex}`);
  if (event.outputIndex !== expectedIndex + (event.changeIndex === undefined ? 0n : 1n)) reconstruction("SEQUENCE_GAP", `Private-swap output index is not contiguous at ${expectedIndex}`);
  if (event.changeIndex !== undefined) {
    const change = appendLeaf(state.tree, event.changeCommitment);
    appendRecord(state, change, event.changeCommitment, event);
  }
  const output = appendLeaf(state.tree, event.outputCommitment);
  appendRecord(state, output, event.outputCommitment, event);
  recordSpentNullifier(state, event.nullifier);
}

function serializeCheckpoint(state: ReplayState): Uint8Array {
  const base = {
    formatVersion: CHECKPOINT_VERSION,
    identity: identityObject(state.identity),
    tree: serializeTree(state.tree),
    cursor: {
      lastProcessedSignature: state.lastProcessedSignature,
      lastFinalizedSlot: state.lastFinalizedSlot,
    },
    appends: [...state.appends.values()].sort((a, b) => Number(a.index - b.index)).map(record => ({
      index: record.index.toString(),
      sequence: record.sequence.toString(),
      commitment: hex(record.commitment),
      event: serializeEvent(record.event),
    })),
    spentNullifiers: [...state.spentNullifiers].sort(),
    reconstructedRoot: hex(rootFromTree(state.tree)),
  };
  const integrity = createHash("sha256").update(JSON.stringify(base)).digest("hex");
  return Uint8Array.from(Buffer.from(JSON.stringify({ ...base, integrity: { algorithm: "sha256", digest: integrity } }), "utf8"));
}

function deserializeCheckpoint(data: Uint8Array, identity: CheckpointIdentity): ReplayState {
  let payload: Record<string, unknown>;
  try { payload = JSON.parse(Buffer.from(data).toString("utf8")) as Record<string, unknown>; } catch { reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint is not valid JSON"); }
  if (payload.formatVersion !== CHECKPOINT_VERSION || !payload.identity || identityKey(identity) !== JSON.stringify(payload.identity)) reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint identity or version mismatch");
  const integrity = payload.integrity as Record<string, unknown> | undefined;
  const base = { ...payload };
  delete base.integrity;
  if (integrity?.algorithm !== "sha256" || typeof integrity.digest !== "string" || createHash("sha256").update(JSON.stringify(base)).digest("hex") !== integrity.digest) reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint integrity mismatch");
  const tree = deserializeTree(payload.tree);
  const state: ReplayState = {
    identity: { ...identity },
    tree,
    appends: new Map(),
    spentNullifiers: new Set(),
    lastProcessedSignature: undefined,
    lastFinalizedSlot: undefined,
  };
  const cursor = payload.cursor as Record<string, unknown> | undefined;
  if (cursor?.lastProcessedSignature !== undefined && typeof cursor.lastProcessedSignature !== "string") reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint cursor");
  if (cursor?.lastFinalizedSlot !== undefined && (!Number.isSafeInteger(cursor.lastFinalizedSlot) || Number(cursor.lastFinalizedSlot) < 0)) reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint slot");
  if ((cursor?.lastProcessedSignature === undefined) !== (cursor?.lastFinalizedSlot === undefined)) reconstruction("INVALID_CHECKPOINT", "Checkpoint cursor and slot must be recorded together");
  state.lastProcessedSignature = cursor?.lastProcessedSignature as string | undefined;
  state.lastFinalizedSlot = cursor?.lastFinalizedSlot === undefined ? undefined : Number(cursor.lastFinalizedSlot);
  if (!Array.isArray(payload.appends) || !Array.isArray(payload.spentNullifiers) || typeof payload.reconstructedRoot !== "string") reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint contents");
  for (const value of payload.spentNullifiers) {
    const nullifier = parseBytes(value, 32, "spent nullifier");
    if (!canonicalField(nullifier) || same(nullifier, new Uint8Array(32))) reconstruction("INVALID_CHECKPOINT", "Invalid spent nullifier in Merkle checkpoint");
    state.spentNullifiers.add(hex(nullifier));
  }
  for (const value of payload.appends) {
    if (!value || typeof value !== "object") reconstruction("INVALID_CHECKPOINT", "Invalid append record");
    const record = value as Record<string, unknown>;
    const index = parseBigInt(record.index, "append index");
    const sequence = parseBigInt(record.sequence, "append sequence");
    const commitment = parseBytes(record.commitment, 32, "append commitment");
    const event = deserializeEvent(record.event);
    if (state.appends.has(index)) reconstruction("INVALID_CHECKPOINT", "Duplicate append index in checkpoint");
    state.appends.set(index, { index, sequence, commitment, event });
  }
  validateReplayState(state, identity.pool, parseBytes(payload.reconstructedRoot, 32, "reconstructed root"));
  return state;
}

function validateReplayState(state: ReplayState, pool: string | PublicKey, expectedRoot?: Uint8Array): void {
  const poolKey = typeof pool === "string" ? pool : pool.toBase58();
  validateTreeShape(state.tree, "checkpoint tree");
  if (state.tree.pool.toBase58() !== poolKey || state.identity.pool !== poolKey || state.identity.tree.length === 0 || state.identity.generation !== state.tree.generation) reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint tree identity mismatch");
  if (expectedRoot && !same(rootFromTree(state.tree), expectedRoot)) reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint root mismatch");
  if (state.appends.size !== Number(state.tree.nextIndex)) reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint append count is inconsistent");
  for (let index = 0n; index < state.tree.nextIndex; index++) {
    const record = state.appends.get(index);
    if (!record || record.index !== index || record.sequence !== index + 1n || record.commitment.length !== 32 || !canonicalField(record.commitment) || same(record.commitment, new Uint8Array(32))) reconstruction("INVALID_CHECKPOINT", `Merkle checkpoint is missing leaf ${index}`);
    if (!record.event.pool.equals(state.tree.pool) || record.event.generation !== state.tree.generation) reconstruction("INVALID_CHECKPOINT", `Merkle checkpoint leaf ${index} has the wrong identity`);
    if (record.event.kind === "shield") {
      if (record.event.asset < 0 || record.event.asset > 1 || record.event.amount <= 0n || record.event.index !== record.index || record.event.sequence !== record.sequence || !same(record.event.commitment, record.commitment) || record.event.encryptedNote.length !== 186 || record.event.encryptedNote[0] !== 1 || !canonicalField(record.event.root) || same(record.event.root, new Uint8Array(32))) reconstruction("INVALID_CHECKPOINT", `Invalid shield append record ${index}`);
    } else {
      const expected = record.index === record.event.changeIndex ? record.event.changeCommitment : record.index === record.event.outputIndex ? record.event.outputCommitment : undefined;
      if (record.event.direction < 0 || record.event.direction > 1 || record.event.amountIn <= 0n || record.event.amountOut <= 0n || !expected || !same(expected, record.commitment) || !canonicalField(record.event.root) || !canonicalField(record.event.nullifier) || !canonicalField(record.event.outputCommitment) || same(record.event.outputCommitment, new Uint8Array(32)) || (record.event.changeIndex !== undefined && (!canonicalField(record.event.changeCommitment) || same(record.event.changeCommitment, new Uint8Array(32))))) reconstruction("INVALID_CHECKPOINT", `Invalid private-swap append record ${index}`);
    }
  }
  validateCheckpointReplay(state);
}

function compareTreeState(local: TreeState, current: TreeState): void {
  validateTreeShape(current, "finalized tree");
  if (!local.pool.equals(current.pool) || local.generation !== current.generation || local.nextIndex !== current.nextIndex || local.sequence !== current.sequence) reconstruction("ROOT_MISMATCH", "Reconstructed tree counters disagree with finalized state");
  const arrays: Array<[string, Uint8Array[], Uint8Array[]]> = [
    ["frontier", local.frontier, current.frontier],
    ["emptySubtrees", local.emptySubtrees, current.emptySubtrees],
    ["roots", local.roots, current.roots],
  ];
  for (const [name, left, right] of arrays) if (left.length !== right.length || left.some((value, index) => !same(value, right[index]))) reconstruction("ROOT_MISMATCH", `${name} disagrees with finalized state`);
  if (local.frontierPresent.some((value, index) => value !== current.frontierPresent[index]) || local.rootSequences.some((value, index) => value !== current.rootSequences[index]) || local.rootGenerations.some((value, index) => value !== current.rootGenerations[index])) reconstruction("ROOT_MISMATCH", "Finalized Merkle metadata disagrees with reconstruction");
  if (!same(rootFromTree(local), rootFromTree(current))) reconstruction("ROOT_MISMATCH", "Reconstructed root disagrees with finalized root");
}

function validateCheckpointReplay(state: ReplayState): void {
  const replay: ReplayState = {
    identity: { ...state.identity },
    tree: cloneInitialTree(state.tree.pool, state.tree),
    appends: new Map(),
    spentNullifiers: new Set(),
  };
  const seenEvents = new Set<string>();
  const records = [...state.appends.values()].sort((left, right) => Number(left.index - right.index));
  for (const record of records) {
    const eventKey = JSON.stringify(serializeEvent(record.event));
    if (seenEvents.has(eventKey)) {
      if (record.event.kind !== "swap") reconstruction("INVALID_CHECKPOINT", `Duplicate non-swap event in checkpoint at leaf ${record.index}`);
      continue;
    }
    seenEvents.add(eventKey);
    applyEvent(replay, state.tree.pool, record.event);
  }
  compareTreeState(replay.tree, state.tree);
  if (replay.appends.size !== state.appends.size) reconstruction("INVALID_CHECKPOINT", "Checkpoint append records do not replay to the recorded tree");
  for (const [index, record] of state.appends) {
    const replayed = replay.appends.get(index);
    if (!replayed || replayed.sequence !== record.sequence || !same(replayed.commitment, record.commitment) || JSON.stringify(serializeEvent(replayed.event)) !== JSON.stringify(serializeEvent(record.event))) reconstruction("INVALID_CHECKPOINT", `Checkpoint append record ${index} does not match replay`);
  }
  for (const nullifier of replay.spentNullifiers) if (!state.spentNullifiers.has(nullifier)) reconstruction("INVALID_CHECKPOINT", `Checkpoint is missing spent nullifier ${nullifier}`);
}

function messageHasProgramInstruction(transaction: VersionedTransactionResponse, programId: PublicKey, treeAddress: PublicKey): boolean {
  const message = transaction.transaction.message;
  const loaded = transaction.meta?.loadedAddresses;
  const keys = message.getAccountKeys(loaded ? { accountKeysFromLookups: loaded } : undefined);
  return message.compiledInstructions.some(instruction => {
    const instructionProgram = keys.get(instruction.programIdIndex);
    return instructionProgram?.equals(programId) === true && instruction.accountKeyIndexes.some(index => keys.get(index)?.equals(treeAddress) === true);
  });
}

function programEventLogs(transaction: VersionedTransactionResponse, programId: PublicKey): Buffer[] {
  const logs = transaction.meta?.logMessages ?? [];
  const expected = programId.toBase58();
  const stack: string[] = [];
  const result: Buffer[] = [];
  for (const log of logs) {
    const invoke = /^Program ([1-9A-HJ-NP-Za-km-z]+) invoke \[\d+\]$/.exec(log);
    if (invoke) { stack.push(invoke[1]); continue; }
    const finished = /^Program ([1-9A-HJ-NP-z]+) (success|failed:.*)$/.exec(log);
    if (finished) { if (stack.length) stack.pop(); continue; }
    if (log.startsWith("Program data: ") && stack.at(-1) === expected) result.push(Buffer.from(log.slice("Program data: ".length), "base64"));
  }
  return result;
}

function parseEvent(data: Buffer, signature: string, slot: number): HistoryEvent | undefined {
  if (data.subarray(0, 8).equals(SHIELD)) {
    if (data.length < 85) throw new Error("Malformed shield event");
    let offset = 8;
    const pool = pubkey(data, offset); offset += 32;
    const asset = data[offset++];
    const amount = u64(data, offset); offset += 8;
    const commitment = data.subarray(offset, offset + 32); offset += 32;
    const encryptedLength = data.readUInt32LE(offset); offset += 4;
    if (asset > 1 || amount === 0n || encryptedLength !== 186 || data.length !== 8 + 32 + 1 + 8 + 32 + 4 + encryptedLength + 32 + 8 + 8) throw new Error("Malformed shield event length or fields");
    const encryptedNote = data.subarray(offset, offset + encryptedLength); offset += encryptedLength;
    const root = data.subarray(offset, offset + 32); offset += 32;
    if (encryptedNote[0] !== 1 || same(commitment, new Uint8Array(32)) || !canonicalField(commitment) || !canonicalField(root)) throw new Error("Malformed shield event payload");
    const generation = u64(data, offset); offset += 8;
    const index = u64(data, offset);
    return { kind: "shield", pool, asset, amount, commitment: Uint8Array.from(commitment), encryptedNote: Uint8Array.from(encryptedNote), root: Uint8Array.from(root), generation, index, sequence: index + 1n, slot, signature };
  }
  if (data.subarray(0, 8).equals(SWAP)) {
    if (data.length !== 210 && data.length !== 218) throw new Error("Malformed private-swap event length");
    let offset = 8;
    const pool = pubkey(data, offset); offset += 32;
    const direction = data[offset++];
    const amountIn = u64(data, offset); offset += 8;
    const amountOut = u64(data, offset); offset += 8;
    const root = data.subarray(offset, offset + 32); offset += 32;
    const rootSequence = u64(data, offset); offset += 8;
    const generation = u64(data, offset); offset += 8;
    const nullifier = data.subarray(offset, offset + 32); offset += 32;
    const changeCommitment = data.subarray(offset, offset + 32); offset += 32;
    const outputCommitment = data.subarray(offset, offset + 32); offset += 32;
    const hasChangeValue = data[offset++];
    if (hasChangeValue > 1) throw new Error("Private-swap event has an invalid change flag");
    const hasChange = hasChangeValue === 1;
    if (direction > 1 || amountIn === 0n || amountOut === 0n || !canonicalField(root) || !canonicalField(nullifier) || same(nullifier, new Uint8Array(32)) || !canonicalField(outputCommitment) || (hasChange && !canonicalField(changeCommitment)) || same(outputCommitment, new Uint8Array(32)) || (hasChange && data.length !== 218) || (!hasChange && data.length !== 210)) throw new Error("Malformed private-swap event fields");
    const changeIndex = hasChange ? u64(data, offset) : undefined;
    if (hasChange) offset += 8;
    const outputIndex = u64(data, offset);
    if (!hasChange && !same(changeCommitment, new Uint8Array(32))) throw new Error("Private-swap event has a change commitment without an index");
    if (hasChange && same(changeCommitment, new Uint8Array(32))) throw new Error("Private-swap event has an empty change commitment");
    return { kind: "swap", pool, direction, amountIn, amountOut, root: Uint8Array.from(root), rootSequence, generation, nullifier: Uint8Array.from(nullifier), changeCommitment: Uint8Array.from(changeCommitment), outputCommitment: Uint8Array.from(outputCommitment), changeIndex, outputIndex, slot, signature };
  }
  if (data.subarray(0, 8).equals(UNSHIELD)) {
    if (data.length !== 129) throw new Error("Malformed unshield event length");
    let offset = 8;
    const pool = pubkey(data, offset); offset += 32;
    const asset = data[offset++];
    const amount = u64(data, offset); offset += 8;
    const recipient = pubkey(data, offset); offset += 32;
    const nullifier = data.subarray(offset, offset + 32); offset += 32;
    const generation = u64(data, offset); offset += 8;
    const rootSequence = u64(data, offset);
    if (asset > 1 || amount === 0n || !canonicalField(nullifier) || same(nullifier, new Uint8Array(32))) throw new Error("Malformed unshield event fields");
    return { kind: "unshield", pool, asset, amount, recipient, nullifier: Uint8Array.from(nullifier), generation, rootSequence, slot, signature };
  }
  return undefined;
}

function isRateLimit(error: unknown): boolean {
  return /429|too many requests|rate limit/i.test(String(error));
}

async function retryRpc<T>(label: string, operation: () => Promise<T>, retryNull = false): Promise<T> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      const result = await operation();
      if (!(retryNull && result === null)) return result;
      lastError = new Error(`${label} returned no result`);
    } catch (error) {
      if (!isRateLimit(error)) throw new MerkleReconstructionError("HISTORY_RPC", `${label} failed: ${String(error)}`);
      lastError = error;
    }
    if (attempt < 4) await sleep(Math.min(4_000, 250 * 2 ** attempt) + Math.floor(Math.random() * 100));
  }
  throw new MerkleReconstructionError("HISTORY_RPC", `${label} retry limit exceeded: ${String(lastError)}`);
}

async function retryTransaction(connection: Connection, signature: string): Promise<VersionedTransactionResponse> {
  try {
    const transaction = await retryRpc(`getTransaction ${signature}`, () => connection.getTransaction(signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 }), true);
    if (!transaction) reconstruction("TRANSACTION_MISSING", `Finalized transaction is missing: ${signature}`);
    return transaction;
  } catch (error) {
    if (error instanceof MerkleReconstructionError && error.code === "HISTORY_RPC" && error.message.includes("returned no result")) reconstruction("TRANSACTION_MISSING", `Finalized transaction is missing: ${signature}`);
    throw error;
  }
}

export class RpcMerkleWitnessProvider implements MerkleWitnessProvider {
  private readonly states = new Map<string, ReplayState>();
  private readonly syncing = new Map<string, Promise<ReplayState>>();
  private genesisHash?: string;

  constructor(
    private readonly connection: Connection,
    private readonly programId: PublicKey,
    private readonly getTree: (pool: PublicKey) => Promise<TreeState>,
    private readonly checkpointStore?: MerkleCheckpointStore,
  ) {}

  private async getGenesisIdentity(): Promise<string> {
    if (this.genesisHash) return this.genesisHash;
    const genesisHash = await retryRpc("getGenesisHash", () => this.connection.getGenesisHash());
    if (typeof genesisHash !== "string" || genesisHash.length === 0) reconstruction("HISTORY_RPC", "RPC returned an invalid genesis hash");
    return this.genesisHash = genesisHash;
  }

  private async identity(pool: PublicKey, tree: TreeState): Promise<CheckpointIdentity> {
    const [treeAddress] = PublicKey.findProgramAddressSync([Buffer.from("tree"), pool.toBuffer()], this.programId);
    return { genesisHash: await this.getGenesisIdentity(), programId: this.programId.toBase58(), pool: pool.toBase58(), tree: treeAddress.toBase58(), generation: tree.generation };
  }

  private async loadCheckpoint(identity: CheckpointIdentity, pool: PublicKey): Promise<ReplayState | undefined> {
    if (!this.checkpointStore) return undefined;
    let data: Uint8Array | undefined;
    try {
      data = await this.checkpointStore.loadMerkleCheckpoint(identityKey(identity));
    } catch (error) {
      if (error instanceof MerkleReconstructionError) throw error;
      reconstruction("INVALID_CHECKPOINT", `Unable to authenticate Merkle checkpoint: ${String(error)}`);
    }
    if (!data) return undefined;
    const state = deserializeCheckpoint(data, identity);
    validateReplayState(state, pool);
    return state;
  }

  private async collectRows(treeAddress: PublicKey, cursor?: string): Promise<HistoryRow[]> {
    let before: string | undefined;
    let foundCursor = cursor === undefined;
    const rows: HistoryRow[] = [];
    const seenSignatures = new Set<string>();
    let previousSlot: number | undefined;
    for (;;) {
      const page = await retryRpc("getSignaturesForAddress", () => this.connection.getSignaturesForAddress(treeAddress, { before, limit: 1000 }, "finalized"));
      if (!page.length) break;
      if (page.length > 1000) reconstruction("HISTORY_GAP", "RPC returned an oversized finalized history page");
      for (const row of page) {
        if (typeof row.signature !== "string" || row.signature.length === 0 || !Number.isSafeInteger(row.slot) || row.slot < 0) reconstruction("HISTORY_GAP", "RPC returned malformed finalized signature history");
        if (seenSignatures.has(row.signature)) reconstruction("DUPLICATE_EVENT", `Duplicate finalized transaction signature: ${row.signature}`);
        seenSignatures.add(row.signature);
        if (previousSlot !== undefined && row.slot > previousSlot) reconstruction("HISTORY_GAP", "Finalized signature history is not in canonical slot order");
        previousSlot = row.slot;
        if (row.confirmationStatus !== "finalized") reconstruction("HISTORY_GAP", `Finalized signature has unexpected confirmation status: ${row.signature}`);
        if (cursor !== undefined && row.signature === cursor) {
          foundCursor = true;
          break;
        }
        rows.push({ signature: row.signature, slot: row.slot, err: row.err, confirmationStatus: row.confirmationStatus });
      }
      if ((cursor !== undefined && foundCursor) || page.length < 1000) break;
      const nextBefore = page[page.length - 1].signature;
      if (nextBefore === before) reconstruction("HISTORY_GAP", "Finalized signature pagination did not advance");
      before = nextBefore;
    }
    if (cursor !== undefined && !foundCursor) reconstruction("HISTORY_GAP", `Checkpoint cursor ${cursor} is not present in finalized history`);
    return rows.reverse();
  }

  private async transaction(row: HistoryRow): Promise<VersionedTransactionResponse> {
    const transaction = await retryTransaction(this.connection, row.signature);
    if (!Number.isSafeInteger(transaction.slot) || transaction.slot < 0) reconstruction("HISTORY_GAP", `Transaction has an invalid slot: ${row.signature}`);
    if (transaction.slot !== row.slot) reconstruction("HISTORY_GAP", `Transaction slot disagrees with signature history: ${row.signature}`);
    if (!transaction.meta || transaction.meta.err !== null || row.err !== null && row.err !== undefined) reconstruction("FAILED_TRANSACTION", `Finalized history transaction failed: ${row.signature}`);
    if (!Array.isArray(transaction.transaction.signatures) || transaction.transaction.signatures[0] !== row.signature) reconstruction("HISTORY_GAP", `Transaction signature does not match finalized history: ${row.signature}`);
    return transaction;
  }

  private async syncPool(pool: PublicKey): Promise<ReplayState> {
    const poolKey = pool.toBase58();
    const current = await this.getTree(pool);
    validateTreeShape(current, "finalized tree");
    if (!current.pool.equals(pool)) reconstruction("INVALID_TREE", "Finalized tree belongs to another pool");
    const identity = await this.identity(pool, current);
    const stateKey = identityKey(identity);
    let state = this.states.get(stateKey);
    if (!state) state = await this.loadCheckpoint(identity, pool);
    if (state) {
      if (state.identity.generation !== current.generation) reconstruction("GENERATION_MISMATCH", "Checkpoint generation differs from finalized tree");
      if (!state.tree.emptySubtrees.every((value, index) => same(value, current.emptySubtrees[index]))) reconstruction("ROOT_MISMATCH", "Checkpoint empty subtrees differ from finalized tree");
      if (state.tree.nextIndex > current.nextIndex) reconstruction("SEQUENCE_GAP", "Checkpoint is ahead of finalized tree");
      if (state.tree.nextIndex === current.nextIndex) {
        const stateRoot = rootFromTree(state.tree);
        if (!same(stateRoot, rootFromTree(current))) reconstruction("ROOT_MISMATCH", "Checkpoint root differs from finalized tree");
      }
      state = cloneState(state);
    } else {
      state = { identity, tree: cloneInitialTree(pool, current), appends: new Map(), spentNullifiers: new Set() };
    }
    const [treeAddress] = PublicKey.findProgramAddressSync([Buffer.from("tree"), pool.toBuffer()], this.programId);
    const rows = await this.collectRows(treeAddress, state.lastProcessedSignature);
    for (const row of rows) {
      state.lastProcessedSignature = row.signature;
      state.lastFinalizedSlot = row.slot;
      const transaction = await this.transaction(row);
      if (!messageHasProgramInstruction(transaction, this.programId, treeAddress)) continue;
      for (const data of programEventLogs(transaction, this.programId)) {
        let event: HistoryEvent | undefined;
        try { event = parseEvent(data, row.signature, row.slot); } catch (error) { reconstruction("HISTORY_GAP", `Malformed finalized event in ${row.signature}: ${String(error)}`); }
        if (event) applyEvent(state, pool, event);
      }
    }
    compareTreeState(state.tree, current);
    if (this.checkpointStore && (rows.length > 0 || !this.states.has(stateKey))) await this.checkpointStore.saveMerkleCheckpoint(stateKey, serializeCheckpoint(state));
    this.states.set(stateKey, state);
    return state;
  }

  private async load(pool: PublicKey): Promise<ReplayState> {
    const poolKey = pool.toBase58();
    const running = this.syncing.get(poolKey);
    if (running) return running;
    const task = this.syncPool(pool);
    this.syncing.set(poolKey, task);
    try { return await task; } finally { this.syncing.delete(poolKey); }
  }

  async getShieldEvents(pool: PublicKey): Promise<ShieldAppendEvent[]> {
    const state = await this.load(pool);
    return [...state.appends.values()].filter(record => record.event.kind === "shield").sort((a, b) => Number(a.index - b.index)).map(record => cloneEvent(record.event) as ShieldAppendEvent);
  }

  async getSpentNullifiers(pool: PublicKey): Promise<Uint8Array[]> {
    const state = await this.load(pool);
    return [...state.spentNullifiers].map(bytes);
  }

  async getWitness(pool: PublicKey, commitment: Uint8Array): Promise<MerkleWitness> {
    const state = await this.load(pool);
    const current = await this.getTree(pool);
    compareTreeState(state.tree, current);
    const leaf = [...state.appends.values()].find(record => same(record.commitment, commitment));
    if (!leaf) throw new Error("Note commitment is not present in the reconstructed tree");
    let levelNodes = new Map<bigint, Uint8Array>([...state.appends.values()].map(record => [record.index, record.commitment]));
    const siblings: Uint8Array[] = [];
    let nodeIndex = leaf.index;
    for (let level = 0; level < TREE_DEPTH; level++) {
      const siblingIndex = nodeIndex ^ 1n;
      siblings.push(cloneBytes(levelNodes.get(siblingIndex) ?? current.emptySubtrees[level]));
      const next = new Map<bigint, Uint8Array>();
      const parents = new Set([...levelNodes.keys()].map(index => index >> 1n));
      parents.add(nodeIndex >> 1n);
      for (const parent of parents) {
        const left = levelNodes.get(parent * 2n) ?? current.emptySubtrees[level];
        const right = levelNodes.get(parent * 2n + 1n) ?? current.emptySubtrees[level];
        next.set(parent, hash2(left, right));
      }
      levelNodes = next;
      nodeIndex >>= 1n;
    }
    const sequence = current.sequence;
    const root = current.roots[Number(sequence % BigInt(ROOT_HISTORY))];
    if (!root || !verifyPath(commitment, leaf.index, siblings, root)) reconstruction("ROOT_MISMATCH", "Reconstructed Merkle witness does not match finalized root");
    return { index: leaf.index, siblings, root: cloneBytes(root), rootSequence: sequence, generation: current.generation };
  }
}
