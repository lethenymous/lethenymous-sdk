import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { hash2 } from "./crypto.js";
import { accountDiscriminator } from "./encoding.js";
import { decodeTreeState } from "./accounts.js";
import { pda } from "./pda.js";
import { ROOT_HISTORY, TREE_CAPACITY, TREE_DEPTH, rootFromTree, verifyPath } from "./merkle.js";
const eventId = (name) => createHash("sha256").update(`event:${name}`).digest().subarray(0, 8);
const SHIELD = eventId("ShieldedNoteAppended");
const SWAP = eventId("PrivateSwapped");
const UNSHIELD = eventId("Unshielded");
const ROLLOVER = eventId("TreeRolledOver");
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const CHECKPOINT_VERSION = 1;
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const cloneBytes = (value) => Uint8Array.from(value);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const u64 = (data, offset) => data.readBigUInt64LE(offset);
const pubkey = (data, offset) => new PublicKey(data.subarray(offset, offset + 32));
const canonicalField = (value) => BigInt(`0x${Buffer.from(value).toString("hex")}`) < BN254_MODULUS;
export class MerkleReconstructionError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "MerkleReconstructionError";
    }
}
function reconstruction(code, message) {
    throw new MerkleReconstructionError(code, message);
}
function cloneTree(tree) {
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
function cloneEvent(event) {
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
function cloneState(state) {
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
function parseBytes(value, length, name) {
    if (typeof value !== "string" || !/^[0-9a-f]+$/i.test(value) || value.length !== length * 2)
        reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
    return bytes(value);
}
function parseBigInt(value, name) {
    if (typeof value !== "string" || !/^\d+$/.test(value))
        reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
    try {
        return BigInt(value);
    }
    catch {
        reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
    }
}
function parseSafeInteger(value, name, minimum = 0) {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum)
        reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
    return value;
}
function parsePublicKey(value, name) {
    try {
        if (typeof value !== "string")
            throw new Error();
        return new PublicKey(value);
    }
    catch {
        reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
    }
}
function serializeEvent(event) {
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
        outputGeneration: event.outputGeneration.toString(),
        nullifier: hex(event.nullifier),
        changeCommitment: hex(event.changeCommitment),
        outputCommitment: hex(event.outputCommitment),
        changeIndex: event.changeIndex?.toString(),
        outputIndex: event.outputIndex.toString(),
        slot: event.slot,
        signature: event.signature,
    };
}
function deserializeEvent(value) {
    if (!value || typeof value !== "object")
        reconstruction("INVALID_CHECKPOINT", "Invalid append event in Merkle checkpoint");
    const event = value;
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
            outputGeneration: event.outputGeneration === undefined ? parseBigInt(event.generation, "swap generation") : parseBigInt(event.outputGeneration, "swap output generation"),
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
function serializeTree(tree) {
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
function deserializeTree(value) {
    if (!value || typeof value !== "object")
        reconstruction("INVALID_CHECKPOINT", "Invalid tree state in Merkle checkpoint");
    const tree = value;
    const array = (name) => {
        const item = tree[name];
        if (!Array.isArray(item))
            reconstruction("INVALID_CHECKPOINT", `Invalid ${name} in Merkle checkpoint`);
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
function identityObject(identity) {
    return {
        genesisHash: identity.genesisHash,
        programId: identity.programId,
        pool: identity.pool,
        tree: identity.tree,
        generation: identity.generation.toString(),
    };
}
function identityKey(identity) {
    return JSON.stringify(identityObject(identity));
}
function validateTreeShape(tree, context) {
    if (tree.frontier.length !== TREE_DEPTH || tree.frontierPresent.length !== TREE_DEPTH || tree.emptySubtrees.length !== TREE_DEPTH + 1 || tree.roots.length !== ROOT_HISTORY || tree.rootSequences.length !== ROOT_HISTORY || tree.rootGenerations.length !== ROOT_HISTORY)
        reconstruction("INVALID_TREE", `Invalid ${context} array lengths`);
    if (tree.nextIndex < 0n || tree.nextIndex > TREE_CAPACITY || tree.sequence < 0n || tree.sequence !== tree.nextIndex)
        reconstruction("INVALID_TREE", `Invalid ${context} counters`);
    if (tree.frontier.some(value => value.length !== 32) || tree.emptySubtrees.some(value => value.length !== 32) || tree.roots.some(value => value.length !== 32))
        reconstruction("INVALID_TREE", `Invalid ${context} node length`);
    if (tree.frontier.some(value => !canonicalField(value)) || tree.emptySubtrees.some(value => !canonicalField(value)) || tree.roots.some(value => !canonicalField(value)))
        reconstruction("INVALID_TREE", `Invalid ${context} field element`);
    if (tree.frontierPresent.some(value => value !== 0 && value !== 1))
        reconstruction("INVALID_TREE", `Invalid ${context} frontier flags`);
    let root;
    try {
        root = rootFromTree(tree);
    }
    catch (error) {
        reconstruction("INVALID_TREE", `${context} root is invalid: ${String(error)}`);
    }
    const slot = Number(tree.sequence % BigInt(ROOT_HISTORY));
    if (tree.rootSequences[slot] !== tree.sequence || tree.rootGenerations[slot] !== tree.generation || !same(root, tree.roots[slot]))
        reconstruction("INVALID_TREE", `${context} root history is inconsistent`);
}
function cloneInitialTree(pool, current) {
    const zero = new Uint8Array(32);
    const tree = {
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
function rootAt(tree, sequence) {
    if (sequence > tree.sequence || tree.sequence - sequence >= BigInt(ROOT_HISTORY))
        return undefined;
    const slot = Number(sequence % BigInt(ROOT_HISTORY));
    if (tree.rootSequences[slot] !== sequence || tree.rootGenerations[slot] !== tree.generation)
        return undefined;
    return tree.roots[slot];
}
function assertAcceptedRoot(tree, sequence, root) {
    const accepted = rootAt(tree, sequence);
    if (!accepted || (root && !same(accepted, root)))
        reconstruction("ROOT_MISMATCH", `Event references an unavailable finalized root sequence ${sequence}`);
}
function appendLeaf(tree, leaf) {
    if (leaf.length !== 32 || !canonicalField(leaf) || same(leaf, new Uint8Array(32)))
        reconstruction("SEQUENCE_GAP", "Invalid Merkle append commitment");
    if (tree.nextIndex >= TREE_CAPACITY)
        reconstruction("SEQUENCE_GAP", "Merkle tree is full");
    const index = tree.nextIndex;
    let carry = cloneBytes(leaf);
    for (let level = 0; level < TREE_DEPTH; level++) {
        if (((index >> BigInt(level)) & 1n) === 0n) {
            tree.frontier[level] = carry;
            tree.frontierPresent[level] = 1;
            break;
        }
        if (tree.frontierPresent[level] !== 1)
            reconstruction("INVALID_TREE", `Missing frontier node at level ${level}`);
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
function assertIdentity(pool, event) {
    if (!event.pool.equals(pool))
        reconstruction("GENERATION_MISMATCH", "History event references another pool");
}
function appendRecord(state, result, commitment, event) {
    if (state.appends.has(result.index))
        reconstruction("DUPLICATE_EVENT", `Conflicting duplicate Merkle leaf index ${result.index}`);
    state.appends.set(result.index, { index: result.index, sequence: result.sequence, commitment: cloneBytes(commitment), event: cloneEvent(event) });
}
function recordSpentNullifier(state, nullifier) {
    const value = hex(nullifier);
    if (state.spentNullifiers.has(value))
        reconstruction("DUPLICATE_EVENT", `Conflicting duplicate nullifier ${value}`);
    state.spentNullifiers.add(value);
}
function applyEvent(state, pool, event) {
    if (event.kind === "rollover")
        reconstruction("GENERATION_MISMATCH", "Legacy checkpoint cannot contain rollover");
    assertIdentity(pool, event);
    if (event.generation !== state.tree.generation)
        reconstruction("GENERATION_MISMATCH", `History event generation ${event.generation} does not match ${state.tree.generation}`);
    if (event.kind === "unshield") {
        assertAcceptedRoot(state.tree, event.rootSequence);
        recordSpentNullifier(state, event.nullifier);
        return;
    }
    if (event.kind === "shield") {
        if (event.index !== state.tree.nextIndex || event.sequence !== state.tree.sequence + 1n)
            reconstruction("SEQUENCE_GAP", `Shield event index or sequence is not contiguous at ${state.tree.nextIndex}`);
        const result = appendLeaf(state.tree, event.commitment);
        if (result.index !== event.index || result.sequence !== event.sequence || !same(result.root, event.root))
            reconstruction("ROOT_MISMATCH", `Shield event root does not match replayed root at ${event.index}`);
        appendRecord(state, result, event.commitment, event);
        return;
    }
    assertAcceptedRoot(state.tree, event.rootSequence, event.root);
    const expectedIndex = state.tree.nextIndex;
    if (event.changeIndex !== undefined && event.changeIndex !== expectedIndex)
        reconstruction("SEQUENCE_GAP", `Private-swap change index is not contiguous at ${expectedIndex}`);
    if (event.outputIndex !== expectedIndex + (event.changeIndex === undefined ? 0n : 1n))
        reconstruction("SEQUENCE_GAP", `Private-swap output index is not contiguous at ${expectedIndex}`);
    if (event.changeIndex !== undefined) {
        const change = appendLeaf(state.tree, event.changeCommitment);
        appendRecord(state, change, event.changeCommitment, event);
    }
    const output = appendLeaf(state.tree, event.outputCommitment);
    appendRecord(state, output, event.outputCommitment, event);
    recordSpentNullifier(state, event.nullifier);
}
function serializeCheckpoint(state) {
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
function deserializeCheckpoint(data, identity) {
    let payload;
    try {
        payload = JSON.parse(Buffer.from(data).toString("utf8"));
    }
    catch {
        reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint is not valid JSON");
    }
    if (payload.formatVersion !== CHECKPOINT_VERSION || !payload.identity || identityKey(identity) !== JSON.stringify(payload.identity))
        reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint identity or version mismatch");
    const integrity = payload.integrity;
    const base = { ...payload };
    delete base.integrity;
    if (integrity?.algorithm !== "sha256" || typeof integrity.digest !== "string" || createHash("sha256").update(JSON.stringify(base)).digest("hex") !== integrity.digest)
        reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint integrity mismatch");
    const tree = deserializeTree(payload.tree);
    const state = {
        identity: { ...identity },
        tree,
        appends: new Map(),
        spentNullifiers: new Set(),
        lastProcessedSignature: undefined,
        lastFinalizedSlot: undefined,
    };
    const cursor = payload.cursor;
    if (cursor?.lastProcessedSignature !== undefined && typeof cursor.lastProcessedSignature !== "string")
        reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint cursor");
    if (cursor?.lastFinalizedSlot !== undefined && (!Number.isSafeInteger(cursor.lastFinalizedSlot) || Number(cursor.lastFinalizedSlot) < 0))
        reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint slot");
    if ((cursor?.lastProcessedSignature === undefined) !== (cursor?.lastFinalizedSlot === undefined))
        reconstruction("INVALID_CHECKPOINT", "Checkpoint cursor and slot must be recorded together");
    state.lastProcessedSignature = cursor?.lastProcessedSignature;
    state.lastFinalizedSlot = cursor?.lastFinalizedSlot === undefined ? undefined : Number(cursor.lastFinalizedSlot);
    if (!Array.isArray(payload.appends) || !Array.isArray(payload.spentNullifiers) || typeof payload.reconstructedRoot !== "string")
        reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint contents");
    for (const value of payload.spentNullifiers) {
        const nullifier = parseBytes(value, 32, "spent nullifier");
        if (!canonicalField(nullifier) || same(nullifier, new Uint8Array(32)))
            reconstruction("INVALID_CHECKPOINT", "Invalid spent nullifier in Merkle checkpoint");
        state.spentNullifiers.add(hex(nullifier));
    }
    for (const value of payload.appends) {
        if (!value || typeof value !== "object")
            reconstruction("INVALID_CHECKPOINT", "Invalid append record");
        const record = value;
        const index = parseBigInt(record.index, "append index");
        const sequence = parseBigInt(record.sequence, "append sequence");
        const commitment = parseBytes(record.commitment, 32, "append commitment");
        const event = deserializeEvent(record.event);
        if (state.appends.has(index))
            reconstruction("INVALID_CHECKPOINT", "Duplicate append index in checkpoint");
        state.appends.set(index, { index, sequence, commitment, event });
    }
    validateReplayState(state, identity.pool, parseBytes(payload.reconstructedRoot, 32, "reconstructed root"));
    return state;
}
function validateReplayState(state, pool, expectedRoot) {
    const poolKey = typeof pool === "string" ? pool : pool.toBase58();
    validateTreeShape(state.tree, "checkpoint tree");
    if (state.tree.pool.toBase58() !== poolKey || state.identity.pool !== poolKey || state.identity.tree.length === 0 || state.identity.generation !== state.tree.generation)
        reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint tree identity mismatch");
    if (expectedRoot && !same(rootFromTree(state.tree), expectedRoot))
        reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint root mismatch");
    if (state.appends.size !== Number(state.tree.nextIndex))
        reconstruction("INVALID_CHECKPOINT", "Merkle checkpoint append count is inconsistent");
    for (let index = 0n; index < state.tree.nextIndex; index++) {
        const record = state.appends.get(index);
        if (!record || record.index !== index || record.sequence !== index + 1n || record.commitment.length !== 32 || !canonicalField(record.commitment) || same(record.commitment, new Uint8Array(32)))
            reconstruction("INVALID_CHECKPOINT", `Merkle checkpoint is missing leaf ${index}`);
        if (!record.event.pool.equals(state.tree.pool) || record.event.generation !== state.tree.generation)
            reconstruction("INVALID_CHECKPOINT", `Merkle checkpoint leaf ${index} has the wrong identity`);
        if (record.event.kind === "shield") {
            if (record.event.asset < 0 || record.event.asset > 1 || record.event.amount <= 0n || record.event.index !== record.index || record.event.sequence !== record.sequence || !same(record.event.commitment, record.commitment) || record.event.encryptedNote.length !== 186 || record.event.encryptedNote[0] !== 1 || !canonicalField(record.event.root) || same(record.event.root, new Uint8Array(32)))
                reconstruction("INVALID_CHECKPOINT", `Invalid shield append record ${index}`);
        }
        else {
            const expected = record.index === record.event.changeIndex ? record.event.changeCommitment : record.index === record.event.outputIndex ? record.event.outputCommitment : undefined;
            if (record.event.direction < 0 || record.event.direction > 1 || record.event.amountIn <= 0n || record.event.amountOut <= 0n || !expected || !same(expected, record.commitment) || !canonicalField(record.event.root) || !canonicalField(record.event.nullifier) || !canonicalField(record.event.outputCommitment) || same(record.event.outputCommitment, new Uint8Array(32)) || (record.event.changeIndex !== undefined && (!canonicalField(record.event.changeCommitment) || same(record.event.changeCommitment, new Uint8Array(32)))))
                reconstruction("INVALID_CHECKPOINT", `Invalid private-swap append record ${index}`);
        }
    }
    validateCheckpointReplay(state);
}
function compareTreeState(local, current) {
    validateTreeShape(current, "finalized tree");
    if (!local.pool.equals(current.pool) || local.generation !== current.generation || local.nextIndex !== current.nextIndex || local.sequence !== current.sequence)
        reconstruction("ROOT_MISMATCH", "Reconstructed tree counters disagree with finalized state");
    const arrays = [
        ["frontier", local.frontier, current.frontier],
        ["emptySubtrees", local.emptySubtrees, current.emptySubtrees],
        ["roots", local.roots, current.roots],
    ];
    for (const [name, left, right] of arrays)
        if (left.length !== right.length || left.some((value, index) => !same(value, right[index])))
            reconstruction("ROOT_MISMATCH", `${name} disagrees with finalized state`);
    if (local.frontierPresent.some((value, index) => value !== current.frontierPresent[index]) || local.rootSequences.some((value, index) => value !== current.rootSequences[index]) || local.rootGenerations.some((value, index) => value !== current.rootGenerations[index]))
        reconstruction("ROOT_MISMATCH", "Finalized Merkle metadata disagrees with reconstruction");
    if (!same(rootFromTree(local), rootFromTree(current)))
        reconstruction("ROOT_MISMATCH", "Reconstructed root disagrees with finalized root");
}
function validateCheckpointReplay(state) {
    const replay = {
        identity: { ...state.identity },
        tree: cloneInitialTree(state.tree.pool, state.tree),
        appends: new Map(),
        spentNullifiers: new Set(),
    };
    const seenEvents = new Set();
    const records = [...state.appends.values()].sort((left, right) => Number(left.index - right.index));
    for (const record of records) {
        const eventKey = JSON.stringify(serializeEvent(record.event));
        if (seenEvents.has(eventKey)) {
            if (record.event.kind !== "swap")
                reconstruction("INVALID_CHECKPOINT", `Duplicate non-swap event in checkpoint at leaf ${record.index}`);
            continue;
        }
        seenEvents.add(eventKey);
        applyEvent(replay, state.tree.pool, record.event);
    }
    compareTreeState(replay.tree, state.tree);
    if (replay.appends.size !== state.appends.size)
        reconstruction("INVALID_CHECKPOINT", "Checkpoint append records do not replay to the recorded tree");
    for (const [index, record] of state.appends) {
        const replayed = replay.appends.get(index);
        if (!replayed || replayed.sequence !== record.sequence || !same(replayed.commitment, record.commitment) || JSON.stringify(serializeEvent(replayed.event)) !== JSON.stringify(serializeEvent(record.event)))
            reconstruction("INVALID_CHECKPOINT", `Checkpoint append record ${index} does not match replay`);
    }
    for (const nullifier of replay.spentNullifiers)
        if (!state.spentNullifiers.has(nullifier))
            reconstruction("INVALID_CHECKPOINT", `Checkpoint is missing spent nullifier ${nullifier}`);
}
function messageHasProgramInstruction(transaction, programId, treeAddress) {
    const message = transaction.transaction.message;
    const loaded = transaction.meta?.loadedAddresses;
    const keys = message.getAccountKeys(loaded ? { accountKeysFromLookups: loaded } : undefined);
    const direct = message.compiledInstructions.some(instruction => {
        const instructionProgram = keys.get(instruction.programIdIndex);
        return instructionProgram?.equals(programId) === true && instruction.accountKeyIndexes.some(index => keys.get(index)?.equals(treeAddress) === true);
    });
    if (direct)
        return true;
    return (transaction.meta?.innerInstructions ?? []).some(group => group.instructions.some(instruction => keys.get(instruction.programIdIndex)?.equals(programId) === true && instruction.accounts.some(index => keys.get(index)?.equals(treeAddress) === true)));
}
function programEventLogs(transaction, programId) {
    const logs = transaction.meta?.logMessages ?? [];
    const expected = programId.toBase58();
    const stack = [];
    const result = [];
    for (const log of logs) {
        const invoke = /^Program ([1-9A-HJ-NP-Za-km-z]+) invoke \[\d+\]$/.exec(log);
        if (invoke) {
            stack.push(invoke[1]);
            continue;
        }
        const finished = /^Program ([1-9A-HJ-NP-z]+) (success|failed:.*)$/.exec(log);
        if (finished) {
            if (stack.length)
                stack.pop();
            continue;
        }
        if (log.startsWith("Program data: ") && stack.at(-1) === expected)
            result.push(Buffer.from(log.slice("Program data: ".length), "base64"));
    }
    return result;
}
export function parseShieldedEvent(data, signature, slot) {
    if (data.subarray(0, 8).equals(SHIELD)) {
        if (data.length < 85)
            throw new Error("Malformed shield event");
        let offset = 8;
        const pool = pubkey(data, offset);
        offset += 32;
        const asset = data[offset++];
        const amount = u64(data, offset);
        offset += 8;
        const commitment = data.subarray(offset, offset + 32);
        offset += 32;
        const encryptedLength = data.readUInt32LE(offset);
        offset += 4;
        if (asset > 1 || amount === 0n || encryptedLength !== 186 || data.length !== 8 + 32 + 1 + 8 + 32 + 4 + encryptedLength + 32 + 8 + 8)
            throw new Error("Malformed shield event length or fields");
        const encryptedNote = data.subarray(offset, offset + encryptedLength);
        offset += encryptedLength;
        const root = data.subarray(offset, offset + 32);
        offset += 32;
        if (encryptedNote[0] !== 1 || same(commitment, new Uint8Array(32)) || !canonicalField(commitment) || !canonicalField(root))
            throw new Error("Malformed shield event payload");
        const generation = u64(data, offset);
        offset += 8;
        const index = u64(data, offset);
        return { kind: "shield", pool, asset, amount, commitment: Uint8Array.from(commitment), encryptedNote: Uint8Array.from(encryptedNote), root: Uint8Array.from(root), generation, index, sequence: index + 1n, slot, signature };
    }
    if (data.subarray(0, 8).equals(SWAP)) {
        if (![210, 218, 226].includes(data.length))
            throw new Error("Malformed private-swap event length");
        let offset = 8;
        const pool = pubkey(data, offset);
        offset += 32;
        const direction = data[offset++];
        const amountIn = u64(data, offset);
        offset += 8;
        const amountOut = u64(data, offset);
        offset += 8;
        const root = data.subarray(offset, offset + 32);
        offset += 32;
        const rootSequence = u64(data, offset);
        offset += 8;
        const generation = u64(data, offset);
        offset += 8;
        const nullifier = data.subarray(offset, offset + 32);
        offset += 32;
        const changeCommitment = data.subarray(offset, offset + 32);
        offset += 32;
        const outputCommitment = data.subarray(offset, offset + 32);
        offset += 32;
        const hasChangeValue = data[offset++];
        if (hasChangeValue > 1)
            throw new Error("Private-swap event has an invalid change flag");
        const hasChange = hasChangeValue === 1;
        const legacyLength = hasChange ? 218 : 210;
        if (direction > 1 || amountIn === 0n || amountOut === 0n || !canonicalField(root) || !canonicalField(nullifier) || same(nullifier, new Uint8Array(32)) || !canonicalField(outputCommitment) || (hasChange && !canonicalField(changeCommitment)) || same(outputCommitment, new Uint8Array(32)) || (data.length !== legacyLength && data.length !== legacyLength + 8))
            throw new Error("Malformed private-swap event fields");
        const changeIndex = hasChange ? u64(data, offset) : undefined;
        if (hasChange)
            offset += 8;
        const outputIndex = u64(data, offset);
        const outputGeneration = data.length === legacyLength ? generation : u64(data, offset + 8);
        if (!hasChange && !same(changeCommitment, new Uint8Array(32)))
            throw new Error("Private-swap event has a change commitment without an index");
        if (hasChange && same(changeCommitment, new Uint8Array(32)))
            throw new Error("Private-swap event has an empty change commitment");
        return { kind: "swap", pool, direction, amountIn, amountOut, root: Uint8Array.from(root), rootSequence, generation, outputGeneration, nullifier: Uint8Array.from(nullifier), changeCommitment: Uint8Array.from(changeCommitment), outputCommitment: Uint8Array.from(outputCommitment), changeIndex, outputIndex, slot, signature };
    }
    if (data.subarray(0, 8).equals(UNSHIELD)) {
        if (data.length !== 129)
            throw new Error("Malformed unshield event length");
        let offset = 8;
        const pool = pubkey(data, offset);
        offset += 32;
        const asset = data[offset++];
        const amount = u64(data, offset);
        offset += 8;
        const recipient = pubkey(data, offset);
        offset += 32;
        const nullifier = data.subarray(offset, offset + 32);
        offset += 32;
        const generation = u64(data, offset);
        offset += 8;
        const rootSequence = u64(data, offset);
        if (asset > 1 || amount === 0n || !canonicalField(nullifier) || same(nullifier, new Uint8Array(32)))
            throw new Error("Malformed unshield event fields");
        return { kind: "unshield", pool, asset, amount, recipient, nullifier: Uint8Array.from(nullifier), generation, rootSequence, slot, signature };
    }
    if (data.subarray(0, 8).equals(ROLLOVER)) {
        if (data.length !== 152)
            throw new Error("Malformed rollover event length");
        return { kind: "rollover", pool: pubkey(data, 8), previousTree: pubkey(data, 40), previousGeneration: u64(data, 72),
            previousFinalRoot: cloneBytes(data.subarray(80, 112)), newTree: pubkey(data, 112), newGeneration: u64(data, 144), slot, signature };
    }
    return undefined;
}
function isRateLimit(error) {
    return /429|too many requests|rate limit/i.test(String(error));
}
async function retryRpc(label, operation, retryNull = false) {
    let lastError;
    for (let attempt = 0; attempt < 5; attempt++) {
        try {
            const result = await operation();
            if (!(retryNull && result === null))
                return result;
            lastError = new Error(`${label} returned no result`);
        }
        catch (error) {
            if (!isRateLimit(error))
                throw new MerkleReconstructionError("HISTORY_RPC", `${label} failed: ${String(error)}`);
            lastError = error;
        }
        if (attempt < 4)
            await sleep(Math.min(4_000, 250 * 2 ** attempt) + Math.floor(Math.random() * 100));
    }
    throw new MerkleReconstructionError("HISTORY_RPC", `${label} retry limit exceeded: ${String(lastError)}`);
}
async function retryTransaction(connection, signature) {
    try {
        const transaction = await retryRpc(`getTransaction ${signature}`, () => connection.getTransaction(signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 }), true);
        if (!transaction)
            reconstruction("TRANSACTION_MISSING", `Finalized transaction is missing: ${signature}`);
        return transaction;
    }
    catch (error) {
        if (error instanceof MerkleReconstructionError && error.code === "HISTORY_RPC" && error.message.includes("returned no result"))
            reconstruction("TRANSACTION_MISSING", `Finalized transaction is missing: ${signature}`);
        throw error;
    }
}
const digest = (data) => createHash("sha256").update(data).digest("hex");
const MAX_SEGMENTS = 64;
function checkedBytes(value) {
    return Buffer.from(JSON.stringify({ ...value, integrity: { algorithm: "sha256", digest: digest(Buffer.from(JSON.stringify(value))) } }));
}
function checkedObject(data) {
    let value;
    try {
        value = JSON.parse(Buffer.from(data).toString("utf8"));
    }
    catch {
        reconstruction("INVALID_CHECKPOINT", "Checkpoint is not valid JSON");
    }
    if (!value || typeof value !== "object" || Array.isArray(value))
        reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint object");
    const integrity = value.integrity;
    const base = { ...value };
    delete base.integrity;
    if (integrity?.algorithm !== "sha256" || integrity.digest !== digest(Buffer.from(JSON.stringify(base))))
        reconstruction("INVALID_CHECKPOINT", "Checkpoint integrity mismatch");
    return base;
}
function reference(value) {
    const ref = value;
    if (!ref || typeof ref.key !== "string" || !/^[0-9a-f]{64}$/.test(ref.digest))
        reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint reference");
    return { key: ref.key, digest: ref.digest };
}
function recordObject(record) {
    return { index: record.index.toString(), sequence: record.sequence.toString(), commitment: hex(record.commitment), event: serializeEvent(record.event) };
}
function readRecord(value) {
    if (!value || typeof value !== "object")
        reconstruction("INVALID_CHECKPOINT", "Invalid generation append record");
    const r = value;
    return { index: parseBigInt(r.index, "index"), sequence: parseBigInt(r.sequence, "sequence"), commitment: parseBytes(r.commitment, 32, "commitment"), event: deserializeEvent(r.event) };
}
/** Reconstruct ONLY one generation's leaves; cross-generation input history is not needed. */
function applyStoredRecord(state, record) {
    const e = record.event;
    if (record.index !== state.tree.nextIndex || record.sequence !== record.index + 1n || !e.pool.equals(state.tree.pool))
        reconstruction("INVALID_CHECKPOINT", "Generation append continuity/identity mismatch");
    if (e.kind === "shield") {
        if (e.generation !== state.tree.generation || e.index !== record.index || e.sequence !== record.sequence || e.amount <= 0n || e.asset > 1 || e.encryptedNote.length !== 186 || e.encryptedNote[0] !== 1 || !same(e.commitment, record.commitment))
            reconstruction("INVALID_CHECKPOINT", "Invalid shield append record");
    }
    else {
        if (e.outputGeneration !== state.tree.generation || e.direction > 1 || e.amountIn <= 0n || e.amountOut <= 0n || !canonicalField(e.root) || !canonicalField(e.nullifier))
            reconstruction("INVALID_CHECKPOINT", "Invalid swap append record");
        const expected = record.index === e.changeIndex ? e.changeCommitment : record.index === e.outputIndex ? e.outputCommitment : undefined;
        if (!expected || !same(expected, record.commitment) || (e.changeIndex !== undefined && e.outputIndex !== e.changeIndex + 1n))
            reconstruction("INVALID_CHECKPOINT", "Swap append commitment/index mismatch");
        if (record.index === e.outputIndex && e.changeIndex !== undefined) {
            const change = state.appends.get(e.changeIndex);
            if (!change || JSON.stringify(serializeEvent(change.event)) !== JSON.stringify(serializeEvent(e)))
                reconstruction("INVALID_CHECKPOINT", "Swap outputs were not persisted together");
        }
    }
    const result = appendLeaf(state.tree, record.commitment);
    if (e.kind === "shield" && !same(result.root, e.root))
        reconstruction("INVALID_CHECKPOINT", "Shield checkpoint root mismatch");
    state.appends.set(record.index, record);
}
function completeGeneration(state) {
    const last = state.appends.get(state.tree.nextIndex - 1n);
    if (last?.event.kind === "swap" && last.index !== last.event.outputIndex)
        reconstruction("INVALID_CHECKPOINT", "Incomplete atomic swap outputs");
}
function serializeHistory(event) {
    if (event.kind === "shield" || event.kind === "swap")
        return serializeEvent(event);
    if (event.kind === "unshield")
        return { ...event, pool: event.pool.toBase58(), amount: event.amount.toString(), recipient: event.recipient.toBase58(), nullifier: hex(event.nullifier), generation: event.generation.toString(), rootSequence: event.rootSequence.toString() };
    return { ...event, pool: event.pool.toBase58(), previousTree: event.previousTree.toBase58(), previousGeneration: event.previousGeneration.toString(), previousFinalRoot: hex(event.previousFinalRoot), newTree: event.newTree.toBase58(), newGeneration: event.newGeneration.toString() };
}
function deserializeHistory(value) {
    if (!value || typeof value !== "object")
        reconstruction("INVALID_CHECKPOINT", "Invalid pool event");
    const e = value;
    if (e.kind === "shield" || e.kind === "swap")
        return deserializeEvent(e);
    const common = { pool: parsePublicKey(e.pool, "pool"), signature: typeof e.signature === "string" && e.signature.length ? e.signature : reconstruction("INVALID_CHECKPOINT", "Invalid event signature"), slot: parseSafeInteger(e.slot, "slot") };
    if (e.kind === "unshield")
        return { ...common, kind: "unshield", asset: parseSafeInteger(e.asset, "asset"), amount: parseBigInt(e.amount, "amount"), recipient: parsePublicKey(e.recipient, "recipient"), nullifier: parseBytes(e.nullifier, 32, "nullifier"), generation: parseBigInt(e.generation, "generation"), rootSequence: parseBigInt(e.rootSequence, "sequence") };
    if (e.kind === "rollover")
        return { ...common, kind: "rollover", previousTree: parsePublicKey(e.previousTree, "previous tree"), previousGeneration: parseBigInt(e.previousGeneration, "previous generation"), previousFinalRoot: parseBytes(e.previousFinalRoot, 32, "final root"), newTree: parsePublicKey(e.newTree, "new tree"), newGeneration: parseBigInt(e.newGeneration, "new generation") };
    reconstruction("INVALID_CHECKPOINT", "Unknown pool event");
}
export class RpcMerkleWitnessProvider {
    connection;
    programId;
    getTree;
    checkpointStore;
    getGenerationTree;
    states = new Map();
    syncing = new Map();
    genesisHash;
    blobs = new Map();
    historical = new Map();
    metrics = { generationLoads: 0, validatedLeaves: 0, replayedAppends: 0, serializedAppends: 0, sealedWrites: 0, activeDeltaWrites: 0, manifestWrites: 0, historyTransactions: 0, nullifierReads: 0, nullifierWrites: 0, serializedBytes: 0 };
    getReplayMetrics() { return { ...this.metrics }; }
    constructor(connection, programId, getTree, checkpointStore, getGenerationTree) {
        this.connection = connection;
        this.programId = programId;
        this.getTree = getTree;
        this.checkpointStore = checkpointStore;
        this.getGenerationTree = getGenerationTree;
    }
    async getGenesisIdentity() {
        if (this.genesisHash)
            return this.genesisHash;
        const genesisHash = await retryRpc("getGenesisHash", () => this.connection.getGenesisHash());
        if (typeof genesisHash !== "string" || genesisHash.length === 0)
            reconstruction("HISTORY_RPC", "RPC returned an invalid genesis hash");
        return this.genesisHash = genesisHash;
    }
    async identity(pool, tree) {
        const [treeAddress] = PublicKey.findProgramAddressSync([Buffer.from("tree"), pool.toBuffer()], this.programId);
        return { genesisHash: await this.getGenesisIdentity(), programId: this.programId.toBase58(), pool: pool.toBase58(), tree: treeAddress.toBase58(), generation: tree.generation };
    }
    async loadCheckpoint(identity, pool) {
        if (!this.checkpointStore)
            return undefined;
        let data;
        try {
            data = await this.checkpointStore.loadMerkleCheckpoint(identityKey(identity));
        }
        catch (error) {
            if (error instanceof MerkleReconstructionError)
                throw error;
            reconstruction("INVALID_CHECKPOINT", `Unable to authenticate Merkle checkpoint: ${String(error)}`);
        }
        if (!data)
            return undefined;
        const state = deserializeCheckpoint(data, identity);
        validateReplayState(state, pool);
        return state;
    }
    async collectRows(treeAddress, cursor) {
        let before;
        let foundCursor = cursor === undefined;
        const rows = [];
        const seenSignatures = new Set();
        let previousSlot;
        for (;;) {
            const page = await retryRpc("getSignaturesForAddress", () => this.connection.getSignaturesForAddress(treeAddress, { before, limit: 1000 }, "finalized"));
            if (!page.length)
                break;
            if (page.length > 1000)
                reconstruction("HISTORY_GAP", "RPC returned an oversized finalized history page");
            for (const row of page) {
                if (typeof row.signature !== "string" || row.signature.length === 0 || !Number.isSafeInteger(row.slot) || row.slot < 0)
                    reconstruction("HISTORY_GAP", "RPC returned malformed finalized signature history");
                if (seenSignatures.has(row.signature))
                    reconstruction("DUPLICATE_EVENT", `Duplicate finalized transaction signature: ${row.signature}`);
                seenSignatures.add(row.signature);
                if (previousSlot !== undefined && row.slot > previousSlot)
                    reconstruction("HISTORY_GAP", "Finalized signature history is not in canonical slot order");
                previousSlot = row.slot;
                if (row.confirmationStatus !== "finalized")
                    reconstruction("HISTORY_GAP", `Finalized signature has unexpected confirmation status: ${row.signature}`);
                if (cursor !== undefined && row.signature === cursor) {
                    foundCursor = true;
                    break;
                }
                rows.push({ signature: row.signature, slot: row.slot, err: row.err, confirmationStatus: row.confirmationStatus });
            }
            if ((cursor !== undefined && foundCursor) || page.length < 1000)
                break;
            const nextBefore = page[page.length - 1].signature;
            if (nextBefore === before)
                reconstruction("HISTORY_GAP", "Finalized signature pagination did not advance");
            before = nextBefore;
        }
        if (cursor !== undefined && !foundCursor)
            reconstruction("HISTORY_GAP", `Checkpoint cursor ${cursor} is not present in finalized history`);
        return rows.reverse();
    }
    async transaction(row) {
        const transaction = await retryTransaction(this.connection, row.signature);
        if (!Number.isSafeInteger(transaction.slot) || transaction.slot < 0)
            reconstruction("HISTORY_GAP", `Transaction has an invalid slot: ${row.signature}`);
        if (transaction.slot !== row.slot)
            reconstruction("HISTORY_GAP", `Transaction slot disagrees with signature history: ${row.signature}`);
        if (!transaction.meta)
            reconstruction("HISTORY_GAP", `Finalized transaction metadata is missing: ${row.signature}`);
        if ((transaction.meta.err !== null) !== (row.err !== null && row.err !== undefined))
            reconstruction("FAILED_TRANSACTION", `RPC failure status disagrees with finalized transaction: ${row.signature}`);
        if (!Array.isArray(transaction.transaction.signatures) || transaction.transaction.signatures[0] !== row.signature)
            reconstruction("HISTORY_GAP", `Transaction signature does not match finalized history: ${row.signature}`);
        return transaction;
    }
    async historicalTree(pool, generation) {
        if (this.getGenerationTree) {
            const tree = await this.getGenerationTree(pool, generation);
            if (!tree.pool.equals(pool) || tree.generation !== generation)
                reconstruction("INVALID_TREE", "Historical tree identity mismatch");
            return tree;
        }
        const address = pda.tree(pool, generation, this.programId)[0];
        const info = await retryRpc("historical TreeState", () => this.connection.getAccountInfo(address, "finalized"));
        if (!info || !info.owner.equals(this.programId) || !info.data.subarray(0, 8).equals(accountDiscriminator("TreeState")))
            reconstruction("INVALID_TREE", "Historical tree missing or has wrong owner/discriminator");
        const tree = decodeTreeState(info.data.subarray(8));
        if (!tree.pool.equals(pool) || tree.generation !== generation)
            reconstruction("INVALID_TREE", "Historical tree PDA/generation mismatch");
        return tree;
    }
    async poolCheckpointBytes(identity) {
        const data = await this.checkpointStore?.loadMerkleCheckpoint(identity);
        if (!data)
            return undefined;
        let manifest;
        try {
            manifest = JSON.parse(Buffer.from(data).toString("utf8"));
        }
        catch {
            reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint JSON");
        }
        if (manifest.chunked !== true)
            return data;
        if (manifest.formatVersion !== 2 || manifest.identity !== identity || !Array.isArray(manifest.chunks) || typeof manifest.digest !== "string")
            reconstruction("INVALID_CHECKPOINT", "Invalid chunked checkpoint manifest");
        const chunks = [];
        for (const value of manifest.chunks) {
            if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
                reconstruction("INVALID_CHECKPOINT", "Invalid checkpoint chunk digest");
            const key = JSON.stringify({ poolCheckpoint: identity, sha256: value });
            const chunk = await this.checkpointStore.loadMerkleCheckpoint(key);
            if (!chunk || chunk.length > 8 * 1024 * 1024 || createHash("sha256").update(chunk).digest("hex") !== value)
                reconstruction("INVALID_CHECKPOINT", "Missing or unauthenticated checkpoint chunk");
            chunks.push(Buffer.from(chunk));
        }
        const result = Buffer.concat(chunks);
        if (manifest.byteLength !== result.length || createHash("sha256").update(result).digest("hex") !== manifest.digest)
            reconstruction("INVALID_CHECKPOINT", "Chunked checkpoint integrity mismatch");
        return result;
    }
    storageKey(identity, kind, generation, hash) {
        return JSON.stringify({ schema: "merkle-v3", identity, kind, generation: generation?.toString(), hash });
    }
    async read(key) {
        try {
            return this.checkpointStore ? await this.checkpointStore.loadMerkleCheckpoint(key) : this.blobs.get(key);
        }
        catch {
            reconstruction("INVALID_CHECKPOINT", "Checkpoint authentication/read failed");
        }
    }
    async immutable(key, data) {
        const existing = await this.read(key);
        if (existing) {
            if (!same(existing, data))
                reconstruction("INVALID_CHECKPOINT", "Conflicting immutable checkpoint write");
            return false;
        }
        if (!this.checkpointStore) {
            this.blobs.set(key, cloneBytes(data));
            return true;
        }
        if (this.checkpointStore.compareAndSwapMerkleCheckpoint) {
            if (!await this.checkpointStore.compareAndSwapMerkleCheckpoint(key, undefined, data)) {
                const winner = await this.read(key);
                if (!winner || !same(winner, data))
                    reconstruction("INVALID_CHECKPOINT", "Concurrent immutable checkpoint conflict");
                return false;
            }
        }
        else
            await this.checkpointStore.saveMerkleCheckpoint(key, data);
        return true;
    }
    async putBlob(identity, generation, data) {
        const hash = digest(data);
        const key = this.storageKey(identity, "blob", generation, hash);
        const chunkSize = 8 * 1024 * 1024;
        if (data.length <= chunkSize)
            await this.immutable(key, data);
        else {
            const chunks = [];
            for (let offset = 0; offset < data.length; offset += chunkSize) {
                const chunk = data.subarray(offset, offset + chunkSize);
                const ref = { key: this.storageKey(identity, "chunk", generation, digest(chunk)), digest: digest(chunk) };
                await this.immutable(ref.key, chunk);
                chunks.push(ref);
            }
            await this.immutable(key, checkedBytes({ formatVersion: 3, kind: "chunked-blob", digest: hash, byteLength: data.length, chunks }));
        }
        this.metrics.serializedBytes += data.length;
        return { key, digest: hash };
    }
    async readBlob(identity, generation, ref) {
        if (ref.key !== this.storageKey(identity, "blob", generation, ref.digest))
            reconstruction("INVALID_CHECKPOINT", "Blob scope mismatch");
        const data = await this.read(ref.key);
        if (!data)
            reconstruction("INVALID_CHECKPOINT", "Checkpoint blob is missing");
        if (digest(data) === ref.digest)
            return data;
        const wrapper = checkedObject(data);
        if (wrapper.formatVersion !== 3 || wrapper.kind !== "chunked-blob" || wrapper.digest !== ref.digest || !Array.isArray(wrapper.chunks))
            reconstruction("INVALID_CHECKPOINT", "Blob digest mismatch");
        const buffers = [];
        for (const value of wrapper.chunks) {
            const chunk = reference(value);
            if (chunk.key !== this.storageKey(identity, "chunk", generation, chunk.digest))
                reconstruction("INVALID_CHECKPOINT", "Chunk scope mismatch");
            const bytes = await this.read(chunk.key);
            if (!bytes || bytes.length > 8 * 1024 * 1024 || digest(bytes) !== chunk.digest)
                reconstruction("INVALID_CHECKPOINT", "Checkpoint chunk is missing/corrupt");
            buffers.push(bytes);
        }
        const joined = Buffer.concat(buffers);
        if (joined.length !== wrapper.byteLength || digest(joined) !== ref.digest)
            reconstruction("INVALID_CHECKPOINT", "Assembled checkpoint integrity mismatch");
        return joined;
    }
    generationIdentity(identity, generation) {
        const pool = new PublicKey(identity.pool);
        return { genesisHash: identity.genesisHash, programId: identity.programId, pool: identity.pool, tree: pda.tree(pool, generation, this.programId)[0].toBase58(), generation };
    }
    initial(identity, current, generation) {
        return { identity: this.generationIdentity(identity, generation), tree: cloneInitialTree(current.pool, { ...current, generation }), appends: new Map(), spentNullifiers: new Set() };
    }
    assertGenerationObject(value, identity, generation, kind) {
        if (value.formatVersion !== 3 || value.kind !== kind || JSON.stringify(value.identity) !== identityKey(this.generationIdentity(identity, generation)))
            reconstruction("INVALID_CHECKPOINT", "Generation checkpoint identity/version/PDA mismatch");
    }
    async snapshot(identity, state, sealed) {
        this.metrics.serializedAppends += state.appends.size;
        return this.putBlob(identity, state.tree.generation, checkedBytes({ formatVersion: 3, kind: "generation-snapshot", identity: identityObject(state.identity), sealed,
            tree: serializeTree(state.tree), appends: [...state.appends.values()].map(recordObject) }));
    }
    async loadGeneration(identity, generation, head, sealed) {
        this.metrics.generationLoads++;
        const base = checkedObject(await this.readBlob(identity, generation, head.base));
        this.assertGenerationObject(base, identity, generation, "generation-snapshot");
        if (base.sealed !== sealed || !Array.isArray(base.appends))
            reconstruction("INVALID_CHECKPOINT", "Invalid generation snapshot role/records");
        const claimed = deserializeTree(base.tree);
        validateTreeShape(claimed, "generation snapshot");
        if (!claimed.pool.equals(new PublicKey(identity.pool)) || claimed.generation !== generation)
            reconstruction("INVALID_CHECKPOINT", "Generation tree identity mismatch");
        const state = this.initial(identity, claimed, generation);
        const apply = (records) => { for (const value of records) {
            applyStoredRecord(state, readRecord(value));
            this.metrics.validatedLeaves++;
        } completeGeneration(state); };
        apply(base.appends);
        compareTreeState(state.tree, claimed);
        if (sealed && TREE_CAPACITY - state.tree.nextIndex > 1n)
            reconstruction("INVALID_CHECKPOINT", "Sealed generation was not rollover-ready");
        if (!Number.isSafeInteger(head.segments) || head.segments < 0 || head.segments > MAX_SEGMENTS || (head.segments === 0) !== (head.tail === undefined) || sealed && head.segments !== 0)
            reconstruction("INVALID_CHECKPOINT", "Invalid generation delta head");
        const segments = [];
        let tail = head.tail;
        while (tail) {
            if (segments.length >= head.segments)
                reconstruction("INVALID_CHECKPOINT", "Generation delta chain exceeds declared length");
            const segment = checkedObject(await this.readBlob(identity, generation, tail));
            this.assertGenerationObject(segment, identity, generation, "generation-delta");
            if (segment.baseDigest !== head.base.digest || !Array.isArray(segment.appends))
                reconstruction("INVALID_CHECKPOINT", "Generation delta belongs to another base");
            segments.push(segment);
            tail = segment.previous === undefined ? undefined : reference(segment.previous);
        }
        if (segments.length !== head.segments)
            reconstruction("INVALID_CHECKPOINT", "Generation delta chain is incomplete");
        for (const segment of segments.reverse()) {
            apply(segment.appends);
            compareTreeState(state.tree, deserializeTree(segment.tree));
        }
        return state;
    }
    async sealedGeneration(identity, generation) {
        if (!this.checkpointStore)
            return this.recoverVolatileGeneration(identity, generation);
        const key = this.storageKey(identity, "sealed-generation", generation);
        const data = await this.read(key);
        if (!data)
            reconstruction("INVALID_CHECKPOINT", "Historical generation checkpoint is missing");
        const locator = checkedObject(data);
        this.assertGenerationObject(locator, identity, generation, "sealed-generation");
        const ref = reference(locator.snapshot);
        let state = this.historical.get(key);
        if (!state || state.lastProcessedSignature !== ref.digest) {
            state = await this.loadGeneration(identity, generation, { base: ref, segments: 0 }, true);
            state.lastProcessedSignature = ref.digest;
            this.historical.delete(key);
            this.historical.set(key, state);
            // Leaf-set cache is independent of total lifetime generation count.
            while (this.historical.size > 2)
                this.historical.delete(this.historical.keys().next().value);
        }
        compareTreeState(state.tree, await this.historicalTree(new PublicKey(identity.pool), generation));
        return state;
    }
    async recoverVolatileGeneration(identity, generation) {
        const pool = new PublicKey(identity.pool), chain = await this.historicalTree(pool, generation);
        const cacheKey = this.storageKey(identity, "volatile-generation", generation);
        const cached = this.historical.get(cacheKey);
        if (cached) {
            compareTreeState(cached.tree, chain);
            return cached;
        }
        // No storage was configured: recover the requested tree's public appends
        // rather than retaining every sealed leaf set/serialized archive in RAM.
        const state = this.initial(identity, chain, generation);
        const rows = await this.collectRows(pda.tree(pool, generation, this.programId)[0]);
        for (const row of rows) {
            const transaction = await this.transaction(row);
            if (transaction.meta.err !== null || !messageHasProgramInstruction(transaction, this.programId, new PublicKey(identity.stream)))
                continue;
            for (const data of programEventLogs(transaction, this.programId)) {
                let event;
                try {
                    event = parseShieldedEvent(data, row.signature, row.slot);
                }
                catch {
                    reconstruction("HISTORY_GAP", "Malformed generation recovery event");
                }
                if (!event || !event.pool.equals(pool))
                    continue;
                if (event.kind === "shield" && event.generation === generation)
                    applyStoredRecord(state, { index: event.index, sequence: event.index + 1n, commitment: event.commitment, event });
                if (event.kind === "swap" && event.outputGeneration === generation) {
                    if (event.changeIndex !== undefined)
                        applyStoredRecord(state, { index: event.changeIndex, sequence: event.changeIndex + 1n, commitment: event.changeCommitment, event });
                    applyStoredRecord(state, { index: event.outputIndex, sequence: event.outputIndex + 1n, commitment: event.outputCommitment, event });
                }
            }
        }
        completeGeneration(state);
        compareTreeState(state.tree, chain);
        this.historical.set(cacheKey, state);
        while (this.historical.size > 2)
            this.historical.delete(this.historical.keys().next().value);
        return state;
    }
    async publish(key, previous, next) {
        if (this.checkpointStore?.compareAndSwapMerkleCheckpoint) {
            if (!await this.checkpointStore.compareAndSwapMerkleCheckpoint(key, previous && digest(previous), next))
                reconstruction("HISTORY_GAP", "Concurrent checkpoint publication; retry from authenticated manifest");
        }
        else {
            const current = await this.read(key);
            if ((current === undefined) !== (previous === undefined) || current && previous && !same(current, previous))
                reconstruction("HISTORY_GAP", "Checkpoint cursor changed during publication");
            if (this.checkpointStore)
                await this.checkpointStore.saveMerkleCheckpoint(key, next);
            else
                this.blobs.set(key, cloneBytes(next));
        }
        this.metrics.manifestWrites++;
    }
    manifest(data, identity) {
        const value = checkedObject(data);
        if (value.formatVersion !== 3 || value.kind !== "pool-manifest" || JSON.stringify(value.identity) !== JSON.stringify(identity))
            reconstruction("INVALID_CHECKPOINT", "Pool manifest identity/version mismatch");
        const generation = parseBigInt(value.activeGeneration, "active generation");
        if (generation > 0xffffffffffffffffn)
            reconstruction("INVALID_CHECKPOINT", "Generation exceeds u64");
        const head = value.head;
        if (!head || !Number.isSafeInteger(head.segments) || head.segments < 0 || head.segments > MAX_SEGMENTS)
            reconstruction("INVALID_CHECKPOINT", "Invalid active head");
        reference(head.base);
        if (head.tail)
            reference(head.tail);
        if ((head.segments === 0) !== (head.tail === undefined))
            reconstruction("INVALID_CHECKPOINT", "Inconsistent active delta head");
        const summary = value.summary;
        if (!summary || parseBigInt(summary.nextIndex, "next index") > TREE_CAPACITY || parseBigInt(summary.sequence, "sequence") !== BigInt(summary.nextIndex))
            reconstruction("INVALID_CHECKPOINT", "Invalid active counters");
        parseBytes(summary.root, 32, "active root");
        const cursor = value.cursor;
        if (!cursor || (cursor.lastProcessedSignature === undefined) !== (cursor.lastFinalizedSlot === undefined))
            reconstruction("INVALID_CHECKPOINT", "Invalid finalized cursor");
        if (cursor.lastProcessedSignature !== undefined && (typeof cursor.lastProcessedSignature !== "string" || !cursor.lastProcessedSignature.length))
            reconstruction("INVALID_CHECKPOINT", "Invalid cursor signature");
        if (cursor.lastFinalizedSlot !== undefined)
            parseSafeInteger(cursor.lastFinalizedSlot, "cursor slot");
        if (value.nullifierHead !== undefined)
            reference(value.nullifierHead);
        return value;
    }
    compareSummary(manifest, tree) {
        if (manifest.activeGeneration !== tree.generation.toString() || manifest.summary.nextIndex !== tree.nextIndex.toString() || manifest.summary.sequence !== tree.sequence.toString() || manifest.summary.root !== hex(rootFromTree(tree)))
            reconstruction("ROOT_MISMATCH", "Manifest summary disagrees with canonical finalized active tree");
    }
    async activeState(session) {
        if (!session.active) {
            session.active = await this.loadGeneration(session.manifest.identity, BigInt(session.manifest.activeGeneration), session.manifest.head, false);
            this.compareSummary(session.manifest, session.active.tree);
        }
        return session.active;
    }
    async nullifier(identity, event, eventOffset, pending) {
        if (!canonicalField(event.nullifier) || same(event.nullifier, new Uint8Array(32)))
            reconstruction("HISTORY_GAP", "Invalid pool-global nullifier");
        const nf = hex(event.nullifier);
        if (pending.has(nf))
            reconstruction("DUPLICATE_EVENT", "Duplicate pool-global nullifier in suffix");
        const data = checkedBytes({ formatVersion: 3, kind: "nullifier-record", identity, nullifier: nf, signature: event.signature, slot: event.slot, eventOffset });
        const existing = await this.read(this.storageKey(identity, "nullifier-index", undefined, nf));
        this.metrics.nullifierReads++;
        if (existing) {
            const record = checkedObject(existing);
            if (record.formatVersion !== 3 || record.kind !== "nullifier-record" || JSON.stringify(record.identity) !== JSON.stringify(identity) || record.nullifier !== nf)
                reconstruction("INVALID_CHECKPOINT", "Invalid global nullifier index record");
            // Retry of an unpublished batch is idempotent. A different transaction or
            // event position is a replay, regardless of its input/output generation.
            if (!same(existing, data))
                reconstruction("DUPLICATE_EVENT", "Pool-global nullifier was spent by a different event");
        }
        pending.set(nf, data);
    }
    async flushNullifiers(manifest, pending) {
        if (!pending.size)
            return;
        const values = [...pending];
        for (const [nf, data] of values) {
            if (await this.immutable(this.storageKey(manifest.identity, "nullifier-index", undefined, nf), data))
                this.metrics.nullifierWrites++;
        }
        for (let offset = 0; offset < values.length; offset += 4096) {
            manifest.nullifierHead = await this.putBlob(manifest.identity, undefined, checkedBytes({ formatVersion: 3, kind: "nullifier-segment", identity: manifest.identity,
                previous: manifest.nullifierHead, entries: values.slice(offset, offset + 4096).map(([nf, data]) => ({ nullifier: nf, digest: digest(data) })) }));
        }
        pending.clear();
    }
    async syncPool(pool) {
        const current = await this.getTree(pool);
        validateTreeShape(current, "finalized tree");
        if (!current.pool.equals(pool))
            reconstruction("INVALID_TREE", "Finalized tree belongs to another pool");
        const identity = { genesisHash: await this.getGenesisIdentity(), programId: this.programId.toBase58(), pool: pool.toBase58(), stream: pda.shielded(pool, this.programId)[0].toBase58(), format: "pool-generations-v3" };
        const key = this.storageKey(identity, "pool-manifest");
        const cached = this.states.get(key);
        const previous = await this.read(key);
        let session;
        if (previous) {
            const manifest = this.manifest(previous, identity);
            session = { manifest, manifestBytes: previous, active: cached?.manifestBytes && same(cached.manifestBytes, previous) ? cached.active : undefined };
        }
        else {
            // Explicit one-time migration: authenticate old formats, then recover
            // from finalized RPC. Neither their cursors nor their trees become v3 state.
            const legacyIdentity = await this.identity(pool, { ...current, generation: 0n });
            const oldIdentity = { ...identity, format: "pool-generations-v2" };
            const old = await this.poolCheckpointBytes(JSON.stringify(oldIdentity));
            if (old) {
                const value = checkedObject(old);
                if (value.formatVersion !== 2 || JSON.stringify(value.identity) !== JSON.stringify(oldIdentity) || !Array.isArray(value.events) || !Array.isArray(value.trees))
                    reconstruction("INVALID_CHECKPOINT", "Invalid legacy v2 checkpoint");
                for (const event of value.events)
                    deserializeHistory(event);
                for (const tree of value.trees) {
                    const decoded = deserializeTree(tree);
                    validateTreeShape(decoded, "legacy tree");
                    if (!decoded.pool.equals(pool))
                        reconstruction("INVALID_CHECKPOINT", "Legacy tree pool mismatch");
                }
            }
            else
                await this.loadCheckpoint(legacyIdentity, pool);
            const active = this.initial(identity, current, 0n);
            const base = await this.snapshot(identity, active, false);
            session = { active, manifest: { formatVersion: 3, kind: "pool-manifest", identity, activeGeneration: "0", head: { base, segments: 0 }, summary: { nextIndex: "0", sequence: "0", root: hex(rootFromTree(active.tree)) }, cursor: {} } };
        }
        const rows = await this.collectRows(new PublicKey(identity.stream), session.manifest.cursor.lastProcessedSignature);
        if (!rows.length) {
            if (BigInt(session.manifest.activeGeneration) !== current.generation)
                reconstruction("GENERATION_MISMATCH", "Finalized history is missing rollover");
            this.compareSummary(session.manifest, current);
            if (!previous) {
                const data = checkedBytes(session.manifest);
                await this.publish(key, previous, data);
                session.manifestBytes = data;
            }
            this.states.set(key, session);
            return session;
        }
        session.active = cloneState(await this.activeState(session));
        const pendingNullifiers = new Map();
        let newRecords = [];
        const manifest = session.manifest;
        for (const row of rows) {
            const transaction = await this.transaction(row);
            this.metrics.historyTransactions++;
            if (transaction.meta.err === null && messageHasProgramInstruction(transaction, this.programId, new PublicKey(identity.stream))) {
                const logs = programEventLogs(transaction, this.programId);
                for (let offset = 0; offset < logs.length; offset++) {
                    let event;
                    try {
                        event = parseShieldedEvent(logs[offset], row.signature, row.slot);
                    }
                    catch {
                        reconstruction("HISTORY_GAP", `Malformed finalized event in ${row.signature}`);
                    }
                    if (!event)
                        continue;
                    assertIdentity(pool, event);
                    const active = session.active;
                    const generation = active.tree.generation;
                    if (event.kind === "rollover") {
                        if (event.previousGeneration !== generation || event.newGeneration !== generation + 1n || event.newGeneration > 0xffffffffffffffffn || !event.previousTree.equals(pda.tree(pool, generation, this.programId)[0]) || !event.newTree.equals(pda.tree(pool, event.newGeneration, this.programId)[0]))
                            reconstruction("GENERATION_MISMATCH", "Impossible rollover identity/continuity");
                        if (TREE_CAPACITY - active.tree.nextIndex > 1n || !same(event.previousFinalRoot, rootFromTree(active.tree)))
                            reconstruction("ROOT_MISMATCH", "Rollover final root/capacity mismatch");
                        compareTreeState(active.tree, await this.historicalTree(pool, generation));
                        const snapshot = await this.snapshot(identity, active, true);
                        if (await this.immutable(this.storageKey(identity, "sealed-generation", generation), checkedBytes({ formatVersion: 3, kind: "sealed-generation", identity: identityObject(active.identity), snapshot })))
                            this.metrics.sealedWrites++;
                        await this.flushNullifiers(manifest, pendingNullifiers);
                        session.active = this.initial(identity, current, event.newGeneration);
                        manifest.activeGeneration = event.newGeneration.toString();
                        manifest.head = { base: await this.snapshot(identity, session.active, false), segments: 0 };
                        newRecords = [];
                    }
                    else if (event.kind === "shield") {
                        if (event.generation !== generation)
                            reconstruction("GENERATION_MISMATCH", "Cannot append to a sealed generation");
                        applyEvent(active, pool, event);
                        newRecords.push(active.appends.get(event.index));
                        this.metrics.replayedAppends++;
                    }
                    else {
                        if (event.generation > generation)
                            reconstruction("GENERATION_MISMATCH", "Input generation has not been initialized");
                        const input = event.generation === generation ? active.tree : await this.historicalTree(pool, event.generation);
                        assertAcceptedRoot(input, event.rootSequence, event.kind === "swap" ? event.root : undefined);
                        await this.nullifier(identity, event, offset, pendingNullifiers);
                        if (event.kind === "swap") {
                            if (event.outputGeneration !== generation)
                                reconstruction("GENERATION_MISMATCH", "Cannot append swap outputs to a sealed generation");
                            const index = active.tree.nextIndex;
                            if (event.changeIndex !== undefined && event.changeIndex !== index || event.outputIndex !== index + (event.changeIndex === undefined ? 0n : 1n))
                                reconstruction("SEQUENCE_GAP", "Swap output indices are not contiguous");
                            if (event.changeIndex !== undefined) {
                                appendRecord(active, appendLeaf(active.tree, event.changeCommitment), event.changeCommitment, event);
                                newRecords.push(active.appends.get(event.changeIndex));
                                this.metrics.replayedAppends++;
                            }
                            appendRecord(active, appendLeaf(active.tree, event.outputCommitment), event.outputCommitment, event);
                            newRecords.push(active.appends.get(event.outputIndex));
                            this.metrics.replayedAppends++;
                        }
                    }
                }
            }
            manifest.cursor = { lastProcessedSignature: row.signature, lastFinalizedSlot: row.slot };
        }
        const active = session.active;
        if (active.tree.generation !== current.generation)
            reconstruction("GENERATION_MISMATCH", "Active generation disagrees with finalized history");
        compareTreeState(active.tree, current);
        completeGeneration(active);
        if (newRecords.length) {
            if (manifest.head.segments >= MAX_SEGMENTS)
                manifest.head = { base: await this.snapshot(identity, active, false), segments: 0 };
            else {
                this.metrics.serializedAppends += newRecords.length;
                const tail = await this.putBlob(identity, active.tree.generation, checkedBytes({ formatVersion: 3, kind: "generation-delta", identity: identityObject(active.identity), baseDigest: manifest.head.base.digest,
                    previous: manifest.head.tail, appends: newRecords.map(recordObject), tree: serializeTree(active.tree) }));
                manifest.head = { ...manifest.head, tail, segments: manifest.head.segments + 1 };
                this.metrics.activeDeltaWrites++;
            }
        }
        await this.flushNullifiers(manifest, pendingNullifiers);
        manifest.summary = { nextIndex: active.tree.nextIndex.toString(), sequence: active.tree.sequence.toString(), root: hex(rootFromTree(active.tree)) };
        const data = checkedBytes(manifest);
        await this.publish(key, previous, data);
        session.manifestBytes = data;
        this.states.set(key, session);
        if (!this.checkpointStore) {
            for (const storedKey of this.blobs.keys()) {
                const scope = JSON.parse(storedKey);
                if (JSON.stringify(scope.identity) === JSON.stringify(identity) && scope.generation !== undefined && BigInt(scope.generation) < active.tree.generation)
                    this.blobs.delete(storedKey);
            }
        }
        return session;
    }
    async load(pool) {
        const poolKey = pool.toBase58();
        const running = this.syncing.get(poolKey);
        if (running)
            return running;
        const task = this.syncPool(pool);
        this.syncing.set(poolKey, task);
        try {
            return await task;
        }
        finally {
            this.syncing.delete(poolKey);
        }
    }
    async getShieldEvents(pool) {
        const session = await this.load(pool);
        const result = [];
        for (let generation = 0n; generation <= BigInt(session.manifest.activeGeneration); generation++) {
            const state = generation === BigInt(session.manifest.activeGeneration) ? await this.activeState(session) : await this.sealedGeneration(session.manifest.identity, generation);
            for (const record of state.appends.values())
                if (record.event.kind === "shield")
                    result.push(cloneEvent(record.event));
        }
        return result;
    }
    async getSpentNullifiers(pool) {
        // Explicit exhaustive API: normal witness requests never enumerate this log.
        const session = await this.load(pool);
        const identity = session.manifest.identity;
        const nullifiers = new Set();
        const seen = new Set();
        let head = session.manifest.nullifierHead;
        while (head) {
            if (seen.has(head.digest))
                reconstruction("INVALID_CHECKPOINT", "Cyclic nullifier journal");
            seen.add(head.digest);
            const value = checkedObject(await this.readBlob(identity, undefined, head));
            if (value.formatVersion !== 3 || value.kind !== "nullifier-segment" || JSON.stringify(value.identity) !== JSON.stringify(identity) || !Array.isArray(value.entries) || value.entries.length > 4096)
                reconstruction("INVALID_CHECKPOINT", "Invalid nullifier journal segment");
            for (const entry of value.entries) {
                const nf = parseBytes(entry.nullifier, 32, "nullifier");
                if (!canonicalField(nf) || nullifiers.has(entry.nullifier))
                    reconstruction("INVALID_CHECKPOINT", "Invalid/duplicate committed nullifier");
                const record = await this.read(this.storageKey(identity, "nullifier-index", undefined, entry.nullifier));
                if (!record || digest(record) !== entry.digest)
                    reconstruction("INVALID_CHECKPOINT", "Committed nullifier index is missing/corrupt");
                nullifiers.add(entry.nullifier);
            }
            head = value.previous === undefined ? undefined : reference(value.previous);
        }
        return [...nullifiers].map(bytes);
    }
    async getWitness(pool, commitment, generation) {
        const session = await this.load(pool);
        const activeGeneration = BigInt(session.manifest.activeGeneration);
        if (generation !== undefined && (generation < 0n || generation > activeGeneration))
            reconstruction("GENERATION_MISMATCH", "Requested generation is not initialized");
        let state;
        let leaf;
        // The optional legacy search is deliberately exhaustive. Wallets pass the
        // note generation, so their normal path loads only that leaf set (plus any
        // active state needed to apply a new finalized suffix).
        for (let g = generation ?? 0n; g <= (generation ?? activeGeneration); g++) {
            const candidate = g === activeGeneration ? await this.activeState(session) : await this.sealedGeneration(session.manifest.identity, g);
            leaf = [...candidate.appends.values()].find(record => same(record.commitment, commitment));
            if (leaf) {
                state = candidate;
                break;
            }
        }
        if (!leaf)
            throw new Error("Note commitment is not present in the reconstructed tree");
        const current = state.tree;
        compareTreeState(current, current.generation === activeGeneration ? await this.getTree(pool) : await this.historicalTree(pool, current.generation));
        let levelNodes = new Map([...state.appends.values()].map(record => [record.index, record.commitment]));
        const siblings = [];
        let nodeIndex = leaf.index;
        for (let level = 0; level < TREE_DEPTH; level++) {
            const siblingIndex = nodeIndex ^ 1n;
            siblings.push(cloneBytes(levelNodes.get(siblingIndex) ?? current.emptySubtrees[level]));
            const next = new Map();
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
        if (!root || !verifyPath(commitment, leaf.index, siblings, root))
            reconstruction("ROOT_MISMATCH", "Reconstructed Merkle witness does not match finalized root");
        return { index: leaf.index, siblings, root: cloneBytes(root), rootSequence: sequence, generation: current.generation };
    }
}
