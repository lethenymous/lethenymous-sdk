import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { hash2 } from "./crypto.js";
import { TREE_DEPTH, verifyPath } from "./merkle.js";
const eventId = (name) => createHash("sha256").update(`event:${name}`).digest().subarray(0, 8);
const SHIELD = eventId("ShieldedNoteAppended");
const SWAP = eventId("PrivateSwapped");
const UNSHIELD = eventId("Unshielded");
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const equal = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
const u64 = (data, offset) => data.readBigUInt64LE(offset);
const pubkey = (data, offset) => new PublicKey(data.subarray(offset, offset + 32));
const canonicalField = (value) => BigInt(`0x${Buffer.from(value).toString("hex")}`) < BN254_MODULUS;
function parseEvent(data, signature, slot) {
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
        if (encryptedNote[0] !== 1 || equal(commitment, new Uint8Array(32)) || !canonicalField(commitment) || !canonicalField(root))
            throw new Error("Malformed shield event payload");
        const generation = u64(data, offset);
        offset += 8;
        const index = u64(data, offset);
        return { kind: "shield", pool, asset, amount, commitment: Uint8Array.from(commitment), encryptedNote: Uint8Array.from(encryptedNote), root: Uint8Array.from(root), generation, index, sequence: index + 1n, slot, signature };
    }
    if (data.subarray(0, 8).equals(SWAP)) {
        if (data.length !== 210 && data.length !== 218)
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
        const hasChange = data[offset++] === 1;
        if (direction > 1 || amountIn === 0n || amountOut === 0n || !canonicalField(root) || !canonicalField(nullifier) || !canonicalField(outputCommitment) || (hasChange && !canonicalField(changeCommitment)) || equal(outputCommitment, new Uint8Array(32)) || (hasChange && data.length !== 218) || (!hasChange && data.length !== 210))
            throw new Error("Malformed private-swap event fields");
        const changeIndex = hasChange ? u64(data, offset) : undefined;
        if (hasChange)
            offset += 8;
        const outputIndex = u64(data, offset);
        if (!hasChange && !equal(changeCommitment, new Uint8Array(32)))
            throw new Error("Private-swap event has a change commitment without an index");
        if (hasChange && equal(changeCommitment, new Uint8Array(32)))
            throw new Error("Private-swap event has an empty change commitment");
        return { kind: "swap", pool, direction, amountIn, amountOut, root: Uint8Array.from(root), rootSequence, generation, nullifier: Uint8Array.from(nullifier), changeCommitment: Uint8Array.from(changeCommitment), outputCommitment: Uint8Array.from(outputCommitment), changeIndex, outputIndex, slot, signature };
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
        if (asset > 1 || amount === 0n || !canonicalField(nullifier))
            throw new Error("Malformed unshield event fields");
        return { kind: "unshield", pool, asset, amount, recipient, nullifier: Uint8Array.from(nullifier), generation, rootSequence, slot, signature };
    }
    return undefined;
}
function messageHasProgramInstruction(transaction, programId, treeAddress) {
    const message = transaction.transaction.message;
    const loaded = transaction.meta?.loadedAddresses;
    const keys = message.getAccountKeys(loaded ? { accountKeysFromLookups: loaded } : undefined);
    return message.compiledInstructions.some(instruction => {
        const instructionProgram = keys.get(instruction.programIdIndex);
        return instructionProgram?.equals(programId) === true && instruction.accountKeyIndexes.some(index => keys.get(index)?.equals(treeAddress) === true);
    });
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
        if (log.startsWith("Program data: ") && stack.at(-1) === expected) {
            const encoded = log.slice("Program data: ".length);
            result.push(Buffer.from(encoded, "base64"));
        }
    }
    return result;
}
function replayRoot(leaves, emptySubtrees) {
    let nodes = new Map(leaves);
    for (let level = 0; level < TREE_DEPTH; level++) {
        const parents = new Set([...nodes.keys()].map(index => index >> 1n));
        const next = new Map();
        for (const parent of parents) {
            const left = nodes.get(parent * 2n) ?? emptySubtrees[level];
            const right = nodes.get(parent * 2n + 1n) ?? emptySubtrees[level];
            next.set(parent, hash2(left, right));
        }
        nodes = next;
    }
    return nodes.get(0n) ?? emptySubtrees[TREE_DEPTH];
}
export class RpcMerkleWitnessProvider {
    connection;
    programId;
    getTree;
    appends = new Map();
    spentNullifiers = new Map();
    loadedNext = new Map();
    constructor(connection, programId, getTree) {
        this.connection = connection;
        this.programId = programId;
        this.getTree = getTree;
    }
    async getShieldEvents(pool) {
        await this.load(pool);
        return [...this.appends.values()].filter((event) => event.kind === "shield" && event.pool.equals(pool)).map(event => ({ ...event, commitment: Uint8Array.from(event.commitment), encryptedNote: Uint8Array.from(event.encryptedNote), root: Uint8Array.from(event.root) }));
    }
    async load(pool) {
        const poolKey = pool.toBase58();
        const tree = await this.getTree(pool);
        if (this.loadedNext.get(poolKey) === tree.nextIndex)
            return;
        for (const appendKey of this.appends.keys())
            if (appendKey.startsWith(`${poolKey}:`))
                this.appends.delete(appendKey);
        this.spentNullifiers.delete(poolKey);
        const spent = new Set();
        this.spentNullifiers.set(poolKey, spent);
        const [treeAddress] = PublicKey.findProgramAddressSync([Buffer.from("tree"), pool.toBuffer()], this.programId);
        let before;
        const rows = [];
        for (;;) {
            const page = await this.connection.getSignaturesForAddress(treeAddress, { before, limit: 1000 }, "finalized");
            if (!page.length)
                break;
            rows.push(...page.filter(row => !row.err && row.confirmationStatus === "finalized").map(row => ({ signature: row.signature, slot: row.slot })));
            if (page.length < 1000)
                break;
            before = page[page.length - 1].signature;
        }
        rows.reverse();
        const leaves = new Map();
        const seenSignatures = new Set();
        const replayedRoots = new Map([[`${tree.generation}:0`, replayRoot(leaves, tree.emptySubtrees)]]);
        for (const row of rows) {
            if (seenSignatures.has(row.signature))
                throw new Error("Duplicate finalized transaction signature in Merkle history");
            seenSignatures.add(row.signature);
            let transaction = null;
            for (let attempt = 0; attempt < 6 && !transaction; attempt++) {
                try {
                    transaction = await this.connection.getTransaction(row.signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
                }
                catch (error) {
                    if (!String(error).includes("429"))
                        throw error;
                }
                if (!transaction)
                    await sleep(500 * (attempt + 1));
            }
            if (!transaction || transaction.meta?.err !== null && transaction.meta?.err !== undefined)
                throw new Error(`RPC history incomplete or failed: ${row.signature}`);
            if (!messageHasProgramInstruction(transaction, this.programId, treeAddress))
                continue;
            for (const data of programEventLogs(transaction, this.programId)) {
                const event = parseEvent(data, row.signature, row.slot);
                if (!event)
                    continue;
                if (!event.pool.equals(pool))
                    throw new Error("zkCPMM event references another pool");
                if (event.kind === "unshield") {
                    if (event.generation !== tree.generation)
                        throw new Error("Unshield event references another tree generation");
                    spent.add(Buffer.from(event.nullifier).toString("hex"));
                    continue;
                }
                if (event.kind === "swap") {
                    const currentSequence = BigInt(leaves.size);
                    const rootKey = `${event.generation}:${event.rootSequence}`;
                    if (event.generation !== tree.generation || event.rootSequence > currentSequence || currentSequence - event.rootSequence >= 32n || !replayedRoots.has(rootKey) || !equal(replayedRoots.get(rootKey), event.root))
                        throw new Error("Private-swap event references an unaccepted root");
                    const expectedIndex = leaves.size;
                    if (event.changeIndex !== undefined && event.changeIndex !== BigInt(expectedIndex))
                        throw new Error("Private-swap change index is not contiguous");
                    if (event.outputIndex !== BigInt(expectedIndex + (event.changeIndex === undefined ? 0 : 1)))
                        throw new Error("Private-swap output index is not contiguous");
                    if (event.changeIndex !== undefined) {
                        leaves.set(event.changeIndex, event.changeCommitment);
                        replayedRoots.set(`${event.generation}:${event.changeIndex + 1n}`, replayRoot(leaves, tree.emptySubtrees));
                        this.storeAppend(poolKey, event.changeIndex, { ...event, commitment: event.changeCommitment, index: event.changeIndex, sequence: event.changeIndex + 1n });
                    }
                    leaves.set(event.outputIndex, event.outputCommitment);
                    replayedRoots.set(`${event.generation}:${event.outputIndex + 1n}`, replayRoot(leaves, tree.emptySubtrees));
                    this.storeAppend(poolKey, event.outputIndex, { ...event, commitment: event.outputCommitment, index: event.outputIndex, sequence: event.outputIndex + 1n });
                }
                else {
                    if (event.generation !== tree.generation || event.index !== BigInt(leaves.size))
                        throw new Error("Shield event index or generation is not contiguous");
                    leaves.set(event.index, event.commitment);
                    const root = replayRoot(leaves, tree.emptySubtrees);
                    if (!equal(root, event.root))
                        throw new Error("Shield event root does not match replayed tree");
                    replayedRoots.set(`${event.generation}:${event.index + 1n}`, root);
                    this.storeAppend(poolKey, event.index, event);
                }
            }
        }
        const root = replayRoot(leaves, tree.emptySubtrees);
        if (BigInt(leaves.size) !== tree.nextIndex || !equal(root, tree.roots[Number(tree.sequence % 32n)] ?? new Uint8Array(32)))
            throw new Error(`Incomplete Merkle append history; found ${leaves.size} of ${tree.nextIndex} appends`);
        this.loadedNext.set(poolKey, tree.nextIndex);
    }
    async getSpentNullifiers(pool) {
        await this.load(pool);
        return [...(this.spentNullifiers.get(pool.toBase58()) ?? [])].map(value => Uint8Array.from(Buffer.from(value, "hex")));
    }
    storeAppend(poolKey, index, event) {
        const mapKey = `${poolKey}:${index}`;
        if (this.appends.has(mapKey))
            throw new Error("Conflicting duplicate Merkle leaf index");
        this.appends.set(mapKey, event);
    }
    async getWitness(pool, commitment) {
        await this.load(pool);
        const tree = await this.getTree(pool);
        const entries = [...this.appends.values()].filter(event => event.pool.equals(pool)).map(event => ({ index: "index" in event ? event.index : 0n, commitment: "commitment" in event ? event.commitment : event.outputCommitment }));
        const leaf = entries.find(entry => equal(entry.commitment, commitment));
        if (!leaf)
            throw new Error("Note commitment is not present in the reconstructed tree");
        let levelNodes = new Map(entries.map(entry => [entry.index, entry.commitment]));
        const siblings = [];
        let nodeIndex = leaf.index;
        for (let level = 0; level < TREE_DEPTH; level++) {
            const siblingIndex = nodeIndex ^ 1n;
            siblings.push(levelNodes.get(siblingIndex) ?? tree.emptySubtrees[level]);
            const next = new Map();
            const parents = new Set([...levelNodes.keys()].map(index => index >> 1n));
            parents.add(nodeIndex >> 1n);
            for (const parent of parents) {
                const left = levelNodes.get(parent * 2n) ?? tree.emptySubtrees[level];
                const right = levelNodes.get(parent * 2n + 1n) ?? tree.emptySubtrees[level];
                next.set(parent, hash2(left, right));
            }
            levelNodes = next;
            nodeIndex >>= 1n;
        }
        const sequence = tree.sequence;
        const root = tree.roots[Number(sequence % 32n)];
        if (!root || !verifyPath(commitment, leaf.index, siblings, root))
            throw new Error("Reconstructed Merkle witness does not match the current on-chain root");
        return { index: leaf.index, siblings, root, rootSequence: sequence, generation: tree.generation };
    }
}
