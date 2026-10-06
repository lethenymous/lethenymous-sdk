import { createHash } from "node:crypto";
import { mkdir, open, readFile, rename, rm, stat, truncate, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { PublicKey } from "@solana/web3.js";
import { noteCommitment, noteStoreKey } from "./crypto.js";
const MAGIC = Buffer.from("LNSJ");
const FORMAT_VERSION = 1;
const AAD_PREFIX = Buffer.from("zkcpmm-v2/note-store/v1");
const ZERO_DIGEST = new Uint8Array(32);
const MAX_FRAME = 2 * 1024 * 1024;
const CHECKPOINT_MAGIC = Buffer.from("LMCP");
const CHECKPOINT_VERSION = 1;
const CHECKPOINT_AAD_PREFIX = Buffer.from("zkcpmm-v2/merkle-checkpoint/v1");
const MAX_CHECKPOINT = 64 * 1024 * 1024;
const LOCK_STALE_MS = 30_000;
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const cloneBytes = (value) => value ? Uint8Array.from(value) : undefined;
const idOf = (value) => hex(value);
function cloneNote(note) {
    return {
        ...note,
        generation: note.generation ?? 0n,
        ownerCommitment: Uint8Array.from(note.ownerCommitment),
        randomness: Uint8Array.from(note.randomness),
        commitment: Uint8Array.from(note.commitment),
        encryptedPayload: cloneBytes(note.encryptedPayload),
        operationId: cloneBytes(note.operationId),
    };
}
function noteState(note) {
    if (note.state)
        return note.state;
    return note.spent ? "spent" : "available";
}
function serializeNote(note) {
    return {
        pool: note.pool.toBase58(),
        asset: note.asset.toBase58(),
        amount: note.amount.toString(),
        ownerCommitment: hex(note.ownerCommitment),
        randomness: hex(note.randomness),
        commitment: hex(note.commitment),
        encryptedPayload: note.encryptedPayload ? hex(note.encryptedPayload) : undefined,
        leafIndex: note.leafIndex?.toString(),
        generation: (note.generation ?? 0n).toString(),
        state: noteState(note),
        operationId: note.operationId ? hex(note.operationId) : undefined,
        transactionSignature: note.transactionSignature,
    };
}
function deserializeNote(value) {
    const note = {
        pool: new PublicKey(String(value.pool)),
        asset: new PublicKey(String(value.asset)),
        amount: BigInt(String(value.amount)),
        ownerCommitment: bytes(String(value.ownerCommitment)),
        randomness: bytes(String(value.randomness)),
        commitment: bytes(String(value.commitment)),
        encryptedPayload: typeof value.encryptedPayload === "string" ? bytes(value.encryptedPayload) : undefined,
        leafIndex: value.leafIndex === undefined ? undefined : BigInt(String(value.leafIndex)),
        generation: value.generation === undefined ? 0n : BigInt(String(value.generation)),
        state: String(value.state),
        operationId: typeof value.operationId === "string" ? bytes(value.operationId) : undefined,
        transactionSignature: typeof value.transactionSignature === "string" ? value.transactionSignature : undefined,
    };
    note.spent = note.state === "spent";
    return note;
}
function serializeOperation(operation) {
    return {
        id: hex(operation.id),
        kind: operation.kind,
        state: operation.state,
        pool: operation.pool.toBase58(),
        inputCommitment: operation.inputCommitment ? hex(operation.inputCommitment) : undefined,
        signature: operation.signature,
        lastValidBlockHeight: operation.lastValidBlockHeight?.toString(),
        signedTransaction: operation.signedTransaction ? hex(operation.signedTransaction) : undefined,
        metadata: operation.metadata,
        outputNotes: operation.outputNotes.map(serializeNote),
    };
}
function deserializeOperation(value) {
    return {
        id: bytes(String(value.id)),
        kind: value.kind,
        state: value.state,
        pool: new PublicKey(String(value.pool)),
        inputCommitment: typeof value.inputCommitment === "string" ? bytes(value.inputCommitment) : undefined,
        signature: typeof value.signature === "string" ? value.signature : undefined,
        lastValidBlockHeight: value.lastValidBlockHeight === undefined ? undefined : BigInt(String(value.lastValidBlockHeight)),
        signedTransaction: typeof value.signedTransaction === "string" ? bytes(value.signedTransaction) : undefined,
        metadata: (value.metadata ?? {}),
        outputNotes: Array.isArray(value.outputNotes) ? value.outputNotes.map(item => deserializeNote(item)) : [],
    };
}
export class EncryptedFileNoteStore {
    path;
    encryptionKey;
    owner;
    lockPath;
    notes = new Map();
    operations = new Map();
    sequence = 0n;
    previousDigest = Uint8Array.from(ZERO_DIGEST);
    constructor(path, encryptionKey, owner) {
        this.path = path;
        this.encryptionKey = encryptionKey;
        this.owner = owner;
        if (encryptionKey.length !== 32 || owner.length !== 32)
            throw new Error("Note store key and owner must be 32 bytes");
        this.lockPath = `${path}.lock`;
    }
    static fromSeed(path, seed, owner) {
        return new EncryptedFileNoteStore(path, noteStoreKey(seed), owner);
    }
    validateNote(note) {
        if (note.generation !== undefined && (note.generation < 0n || note.generation > 0xffffffffffffffffn))
            throw new Error("Invalid note generation");
        if (note.state !== undefined && !["available", "reserved", "submitted", "spent"].includes(note.state))
            throw new Error("Invalid note state");
        if (note.amount <= 0n || note.ownerCommitment.length !== 32 || note.randomness.length !== 32 || note.commitment.length !== 32)
            throw new Error("Invalid note");
        if (!Buffer.from(noteCommitment(note.pool, note.asset, note.amount, note.ownerCommitment, note.randomness)).equals(Buffer.from(note.commitment)))
            throw new Error("Note commitment mismatch");
        if (!Buffer.from(note.ownerCommitment).equals(Buffer.from(this.owner)))
            throw new Error("Note belongs to another wallet");
        if (note.encryptedPayload && note.encryptedPayload.length !== 186)
            throw new Error("Invalid encrypted note payload");
        return { ...cloneNote(note), state: noteState(note), spent: noteState(note) === "spent" };
    }
    apply(event) {
        if (event.type === "save_note" && event.note) {
            const note = this.validateNote(deserializeNote(event.note));
            const key = idOf(note.commitment);
            const current = this.notes.get(key);
            if (current && JSON.stringify(serializeNote(current)) !== JSON.stringify(serializeNote(note)))
                throw new Error("Conflicting duplicate note commitment");
            this.notes.set(key, note);
            return;
        }
        if (event.type === "reserve_note" && event.id) {
            const note = this.notes.get(event.id);
            if (!note)
                throw new Error("Note is not available");
            if (noteState(note) === "reserved" && note.operationId && same(note.operationId, bytes(String(event.signature))))
                return;
            if (noteState(note) === "submitted" && note.operationId && same(note.operationId, bytes(String(event.signature))))
                return;
            if (noteState(note) !== "available")
                throw new Error("Note is not available");
            note.state = "reserved";
            note.spent = false;
            note.operationId = bytes(String(event.signature));
            return;
        }
        if (event.type === "submit_note" && event.id && event.signature) {
            const note = this.notes.get(event.id);
            if (!note)
                throw new Error("Note is not reserved");
            if (noteState(note) === "submitted" && note.transactionSignature === event.signature)
                return;
            if (noteState(note) !== "reserved")
                throw new Error("Note is not reserved");
            note.state = "submitted";
            note.transactionSignature = event.signature;
            return;
        }
        if (event.type === "release_note" && event.id) {
            const note = this.notes.get(event.id);
            if (!note || noteState(note) === "spent")
                throw new Error("Note cannot be released");
            if (noteState(note) === "available")
                return;
            note.state = "available";
            note.spent = false;
            note.operationId = undefined;
            note.transactionSignature = undefined;
            return;
        }
        if (event.type === "spend_note" && event.id) {
            const note = this.notes.get(event.id);
            if (note && noteState(note) === "spent")
                return;
            if (!note || (noteState(note) !== "submitted" && noteState(note) !== "reserved"))
                throw new Error("Note is not pending spend");
            note.state = "spent";
            note.spent = true;
            note.operationId = undefined;
            if (event.signature)
                note.transactionSignature = event.signature;
            return;
        }
        if (event.type === "reserve_and_begin" && event.id && event.signature && event.operation) {
            const note = this.notes.get(event.id);
            const operation = deserializeOperation(event.operation);
            if (!note || !Buffer.from(note.ownerCommitment).equals(Buffer.from(this.owner)) || noteState(note) !== "available")
                throw new Error("Note is not available");
            if (idOf(operation.id) !== event.signature || !operation.inputCommitment || idOf(operation.inputCommitment) !== event.id)
                throw new Error("Invalid reserve-and-begin operation");
            if (this.operations.has(idOf(operation.id)))
                throw new Error("Duplicate operation ID in journal");
            operation.outputNotes = operation.outputNotes.map(value => this.validateNote(value));
            note.state = "reserved";
            note.spent = false;
            note.operationId = Uint8Array.from(operation.id);
            this.operations.set(idOf(operation.id), operation);
            return;
        }
        if (event.type === "operation_begin" && event.operation) {
            const operation = deserializeOperation(event.operation);
            if (this.operations.has(idOf(operation.id)))
                throw new Error("Duplicate operation ID in journal");
            operation.outputNotes = operation.outputNotes.map(note => this.validateNote(note));
            this.operations.set(idOf(operation.id), operation);
            return;
        }
        if (event.type === "operation_prepared" && event.id) {
            const operation = this.operations.get(event.id);
            if (!operation)
                throw new Error("Unknown operation");
            operation.state = "prepared";
            operation.signedTransaction = event.signedTransaction ? bytes(event.signedTransaction) : undefined;
            operation.lastValidBlockHeight = event.lastValidBlockHeight ? BigInt(event.lastValidBlockHeight) : undefined;
            return;
        }
        if (event.type === "operation_update" && event.id && event.operation) {
            const operation = this.operations.get(event.id);
            if (!operation)
                throw new Error("Unknown operation");
            const patch = deserializeOperation(event.operation);
            operation.metadata = { ...operation.metadata, ...patch.metadata };
            operation.outputNotes = patch.outputNotes.map(note => this.validateNote(note));
            return;
        }
        if (event.type === "operation_submitted" && event.id && event.signature) {
            const operation = this.operations.get(event.id);
            if (!operation)
                throw new Error("Unknown operation");
            operation.state = "submitted";
            operation.signature = event.signature;
            return;
        }
        if (event.type === "operation_finalized" && event.id) {
            const operation = this.operations.get(event.id);
            if (!operation)
                throw new Error("Unknown operation");
            if (operation.state === "finalized")
                return;
            operation.state = "finalized";
            return;
        }
        if (event.type === "operation_failed" && event.id) {
            const operation = this.operations.get(event.id);
            if (!operation)
                throw new Error("Unknown operation");
            if (operation.state === "failed")
                return;
            operation.state = "failed";
            operation.metadata.failure = event.reason ?? "transaction failed";
            return;
        }
        if (event.type === "operation_unknown" && event.id) {
            const operation = this.operations.get(event.id);
            if (!operation)
                throw new Error("Unknown operation");
            if (operation.state === "unknown")
                return;
            operation.state = "unknown";
            operation.metadata.unknown = event.reason ?? "transaction outcome unknown";
        }
    }
    async readJournal(repairPartial = false) {
        this.notes.clear();
        this.operations.clear();
        this.sequence = 0n;
        this.previousDigest = Uint8Array.from(ZERO_DIGEST);
        let data;
        try {
            data = await readFile(this.path);
        }
        catch (error) {
            if (error.code === "ENOENT")
                return;
            throw error;
        }
        if (data.length < 5 || !data.subarray(0, 4).equals(MAGIC) || data[4] !== FORMAT_VERSION)
            throw new Error("Invalid note store header");
        let offset = 5;
        let validOffset = offset;
        while (offset < data.length) {
            if (data.length - offset < 4)
                break;
            const frameLength = data.readUInt32LE(offset);
            if (frameLength > MAX_FRAME || frameLength < 8 + 32 + 24 + 16)
                throw new Error("Invalid note store frame length");
            if (data.length - offset - 4 < frameLength)
                break;
            const frameStart = offset;
            const body = data.subarray(offset + 4, offset + 4 + frameLength);
            const sequence = body.readBigUInt64LE(0);
            const previous = body.subarray(8, 40);
            const nonce = body.subarray(40, 64);
            const ciphertext = body.subarray(64);
            if (sequence !== this.sequence + 1n || !Buffer.from(previous).equals(Buffer.from(this.previousDigest)))
                throw new Error("Invalid note store journal chain");
            const aad = Buffer.concat([AAD_PREFIX, Buffer.from(previous), Buffer.alloc(8)]);
            aad.writeBigUInt64LE(sequence, AAD_PREFIX.length + 32);
            const plaintext = xchacha20poly1305(this.encryptionKey, nonce, aad).decrypt(ciphertext);
            const event = JSON.parse(Buffer.from(plaintext).toString("utf8"));
            this.apply(event);
            this.sequence = sequence;
            this.previousDigest = createHash("sha256").update(data.subarray(frameStart, offset + 4 + frameLength)).digest();
            offset += 4 + frameLength;
            validOffset = offset;
        }
        if (repairPartial && validOffset !== data.length)
            await truncate(this.path, validOffset);
    }
    async acquireLock() {
        await mkdir(dirname(this.path), { recursive: true });
        const started = Date.now();
        for (;;) {
            try {
                const handle = await open(this.lockPath, "wx", 0o600);
                await handle.writeFile(String(process.pid));
                await handle.sync();
                await handle.close();
                return async () => { await rm(this.lockPath, { force: true }); };
            }
            catch (error) {
                if (error.code !== "EEXIST")
                    throw error;
                let stale = false;
                try {
                    const lock = (await readFile(this.lockPath, "utf8")).trim();
                    const pid = Number(lock);
                    if (Number.isSafeInteger(pid) && pid > 0) {
                        try {
                            process.kill(pid, 0);
                        }
                        catch (probeError) {
                            stale = probeError.code === "ESRCH";
                        }
                    }
                    else {
                        stale = Date.now() - (await stat(this.lockPath)).mtimeMs > LOCK_STALE_MS;
                    }
                }
                catch (probeError) {
                    if (probeError.code === "ENOENT")
                        continue;
                    stale = Date.now() - (await stat(this.lockPath)).mtimeMs > LOCK_STALE_MS;
                }
                if (stale) {
                    await rm(this.lockPath, { force: true });
                    continue;
                }
                if (Date.now() - started > 5_000)
                    throw new Error("Note store writer lock is busy");
                await new Promise(resolve => setTimeout(resolve, 25));
            }
        }
    }
    async append(events) {
        await mkdir(dirname(this.path), { recursive: true });
        let exists = true;
        try {
            await stat(this.path);
        }
        catch (error) {
            if (error.code === "ENOENT")
                exists = false;
            else
                throw error;
        }
        if (!exists) {
            const temporary = `${this.path}.init-${process.pid}-${Date.now()}`;
            const initializer = await open(temporary, "wx", 0o600);
            try {
                await initializer.write(Buffer.concat([MAGIC, Buffer.from([FORMAT_VERSION])]));
                await initializer.sync();
            }
            finally {
                await initializer.close();
            }
            try {
                await rename(temporary, this.path);
            }
            finally {
                await rm(temporary, { force: true });
            }
        }
        const handle = await open(this.path, "a", 0o600);
        try {
            for (const event of events) {
                const sequence = this.sequence + 1n;
                const previous = this.previousDigest;
                const aad = Buffer.concat([AAD_PREFIX, Buffer.from(previous), Buffer.alloc(8)]);
                aad.writeBigUInt64LE(sequence, AAD_PREFIX.length + 32);
                const nonce = cryptoRandom(24);
                const ciphertext = xchacha20poly1305(this.encryptionKey, nonce, aad).encrypt(Buffer.from(JSON.stringify(event)));
                const body = Buffer.alloc(8 + 32 + 24 + ciphertext.length);
                body.writeBigUInt64LE(sequence, 0);
                Buffer.from(previous).copy(body, 8);
                Buffer.from(nonce).copy(body, 40);
                Buffer.from(ciphertext).copy(body, 64);
                const frame = Buffer.alloc(4 + body.length);
                frame.writeUInt32LE(body.length, 0);
                body.copy(frame, 4);
                await handle.write(frame);
                this.apply(event);
                this.sequence = sequence;
                this.previousDigest = createHash("sha256").update(frame).digest();
            }
            await handle.sync();
        }
        finally {
            await handle.close();
        }
    }
    async mutate(operation) {
        const unlock = await this.acquireLock();
        try {
            await this.readJournal(true);
            const { result, events } = await operation();
            if (events.length)
                await this.append(events);
            return result;
        }
        finally {
            await unlock();
        }
    }
    async getNotes(ownerCommitment = this.owner) {
        const unlock = await this.acquireLock();
        try {
            await this.readJournal(true);
            if (!Buffer.from(ownerCommitment).equals(Buffer.from(this.owner)))
                throw new Error("Note owner mismatch");
            return [...this.notes.values()].map(cloneNote);
        }
        finally {
            await unlock();
        }
    }
    async saveNote(input) {
        const note = this.validateNote(input);
        await this.mutate(async () => {
            const current = this.notes.get(idOf(note.commitment));
            if (current) {
                if (JSON.stringify(serializeNote(current)) !== JSON.stringify(serializeNote(note)))
                    throw new Error("Conflicting duplicate note commitment");
                return { result: undefined, events: [] };
            }
            return { result: undefined, events: [{ type: "save_note", note: serializeNote(note) }] };
        });
    }
    async reserveNote(commitment, operationId, ownerCommitment) {
        if (!Buffer.from(ownerCommitment).equals(Buffer.from(this.owner)))
            throw new Error("Note owner mismatch");
        return this.mutate(async () => {
            const note = this.notes.get(idOf(commitment));
            if (!note || !Buffer.from(note.ownerCommitment).equals(Buffer.from(ownerCommitment)) || noteState(note) !== "available")
                throw new Error("Note is not available");
            return { result: cloneNote(note), events: [{ type: "reserve_note", id: idOf(commitment), signature: idOf(operationId) }] };
        });
    }
    async reserveNoteAndBegin(commitment, operationId, ownerCommitment, operation) {
        if (!Buffer.from(ownerCommitment).equals(Buffer.from(this.owner)))
            throw new Error("Note owner mismatch");
        return this.mutate(async () => {
            const note = this.notes.get(idOf(commitment));
            if (!note || !Buffer.from(note.ownerCommitment).equals(Buffer.from(ownerCommitment)) || noteState(note) !== "available")
                throw new Error("Note is not available");
            if (!Buffer.from(operation.id).equals(Buffer.from(operationId)) || !operation.inputCommitment || !Buffer.from(operation.inputCommitment).equals(Buffer.from(commitment)))
                throw new Error("Invalid reserve-and-begin operation");
            if (this.operations.has(idOf(operationId)))
                throw new Error("Duplicate operation ID");
            return { result: cloneNote(note), events: [{ type: "reserve_and_begin", id: idOf(commitment), signature: idOf(operationId), operation: serializeOperation(operation) }] };
        });
    }
    async markSubmitted(commitment, operationId, signature) {
        await this.mutate(async () => {
            const note = this.notes.get(idOf(commitment));
            if (note && noteState(note) === "submitted" && note.transactionSignature === signature)
                return { result: undefined, events: [] };
            if (!note || noteState(note) !== "reserved" || !note.operationId || !Buffer.from(note.operationId).equals(Buffer.from(operationId)))
                throw new Error("Note reservation mismatch");
            return { result: undefined, events: [{ type: "submit_note", id: idOf(commitment), signature }] };
        });
    }
    async markSpent(commitment, operationId) {
        await this.mutate(async () => {
            const note = this.notes.get(idOf(commitment));
            if (note && noteState(note) === "spent")
                return { result: undefined, events: [] };
            if (!note || (noteState(note) !== "submitted" && noteState(note) !== "reserved"))
                throw new Error("Note is not pending spend");
            if (operationId && (!note.operationId || !Buffer.from(note.operationId).equals(Buffer.from(operationId))))
                throw new Error("Note reservation mismatch");
            return { result: undefined, events: [{ type: "spend_note", id: idOf(commitment), signature: note.transactionSignature }] };
        });
    }
    async releaseReservation(commitment, operationId) {
        await this.mutate(async () => {
            const note = this.notes.get(idOf(commitment));
            if (note && noteState(note) === "available")
                return { result: undefined, events: [] };
            if (!note || (noteState(note) !== "reserved" && noteState(note) !== "submitted"))
                throw new Error("Note is not reserved");
            if (operationId && (!note.operationId || !Buffer.from(note.operationId).equals(Buffer.from(operationId))))
                throw new Error("Note reservation mismatch");
            return { result: undefined, events: [{ type: "release_note", id: idOf(commitment) }] };
        });
    }
    async beginOperation(operation) {
        await this.mutate(async () => {
            if (this.operations.has(idOf(operation.id)))
                throw new Error("Duplicate operation ID");
            return { result: undefined, events: [{ type: "operation_begin", operation: serializeOperation(operation) }] };
        });
    }
    async updateOperation(id, patch) {
        await this.mutate(async () => {
            const operation = this.operations.get(idOf(id));
            if (!operation)
                throw new Error("Unknown operation");
            const updated = { ...operation, metadata: { ...operation.metadata, ...(patch.metadata ?? {}) }, outputNotes: (patch.outputNotes ?? operation.outputNotes).map(cloneNote) };
            return { result: undefined, events: [{ type: "operation_update", id: idOf(id), operation: serializeOperation(updated) }] };
        });
    }
    async markPrepared(id, signedTransaction, lastValidBlockHeight) {
        await this.mutate(async () => ({ result: undefined, events: [{ type: "operation_prepared", id: idOf(id), signedTransaction: hex(signedTransaction), lastValidBlockHeight: lastValidBlockHeight.toString() }] }));
    }
    async markOperationSubmitted(id, signature) {
        await this.mutate(async () => ({ result: undefined, events: [{ type: "operation_submitted", id: idOf(id), signature }] }));
    }
    async markOperationFinalized(id) {
        await this.mutate(async () => ({ result: undefined, events: [{ type: "operation_finalized", id: idOf(id) }] }));
    }
    async markOperationFailed(id, reason) {
        await this.mutate(async () => ({ result: undefined, events: [{ type: "operation_failed", id: idOf(id), reason: reason.slice(0, 256) }] }));
    }
    async markOperationUnknown(id, reason) {
        await this.mutate(async () => ({ result: undefined, events: [{ type: "operation_unknown", id: idOf(id), reason: reason.slice(0, 256) }] }));
    }
    async getPendingOperations() {
        const unlock = await this.acquireLock();
        try {
            await this.readJournal(true);
            return [...this.operations.values()].filter(operation => operation.state !== "finalized" && operation.state !== "failed").map(operation => ({ ...operation, id: Uint8Array.from(operation.id), outputNotes: operation.outputNotes.map(cloneNote), metadata: { ...operation.metadata } }));
        }
        finally {
            await unlock();
        }
    }
    async exportBackup() {
        const unlock = await this.acquireLock();
        try {
            await this.readJournal(true);
            try {
                return Uint8Array.from(await readFile(this.path));
            }
            catch (error) {
                if (error.code === "ENOENT")
                    return Uint8Array.from(Buffer.concat([MAGIC, Buffer.from([FORMAT_VERSION])]));
                throw error;
            }
        }
        finally {
            await unlock();
        }
    }
    async importBackup(backup) {
        const temporary = `${this.path}.import-${process.pid}-${Date.now()}`;
        await mkdir(dirname(this.path), { recursive: true });
        await writeFile(temporary, backup, { mode: 0o600 });
        try {
            const candidate = new EncryptedFileNoteStore(temporary, this.encryptionKey, this.owner);
            await candidate.getNotes();
            const unlock = await this.acquireLock();
            try {
                await rename(temporary, this.path);
                await this.readJournal(true);
            }
            finally {
                await unlock();
            }
        }
        finally {
            await rm(temporary, { force: true });
        }
    }
    checkpointPath(identity) {
        const digest = createHash("sha256").update(Buffer.from("zkcpmm-merkle-checkpoint-path/v1\0")).update(identity).digest("hex");
        return `${this.path}.merkle-${digest}`;
    }
    async loadMerkleCheckpoint(identity) {
        const unlock = await this.acquireLock();
        try {
            let data;
            try {
                data = await readFile(this.checkpointPath(identity));
            }
            catch (error) {
                if (error.code === "ENOENT")
                    return undefined;
                throw error;
            }
            if (data.length < CHECKPOINT_MAGIC.length + 1 + 24 + 16 || !data.subarray(0, CHECKPOINT_MAGIC.length).equals(CHECKPOINT_MAGIC) || data[CHECKPOINT_MAGIC.length] !== CHECKPOINT_VERSION) {
                throw new Error("Invalid Merkle checkpoint header");
            }
            const nonceOffset = CHECKPOINT_MAGIC.length + 1;
            const nonce = data.subarray(nonceOffset, nonceOffset + 24);
            const ciphertext = data.subarray(nonceOffset + 24);
            if (ciphertext.length > MAX_CHECKPOINT + 16)
                throw new Error("Merkle checkpoint is too large");
            const aad = Buffer.concat([CHECKPOINT_AAD_PREFIX, Buffer.from(identity)]);
            try {
                return Uint8Array.from(xchacha20poly1305(this.encryptionKey, nonce, aad).decrypt(ciphertext));
            }
            catch {
                throw new Error("Invalid Merkle checkpoint integrity");
            }
        }
        finally {
            await unlock();
        }
    }
    async saveMerkleCheckpoint(identity, checkpoint) {
        if (checkpoint.length > MAX_CHECKPOINT)
            throw new Error("Merkle checkpoint is too large");
        const unlock = await this.acquireLock();
        const path = this.checkpointPath(identity);
        const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
        try {
            const nonce = cryptoRandom(24);
            const aad = Buffer.concat([CHECKPOINT_AAD_PREFIX, Buffer.from(identity)]);
            const ciphertext = xchacha20poly1305(this.encryptionKey, nonce, aad).encrypt(checkpoint);
            const encoded = Buffer.concat([CHECKPOINT_MAGIC, Buffer.from([CHECKPOINT_VERSION]), Buffer.from(nonce), Buffer.from(ciphertext)]);
            const handle = await open(temporary, "wx", 0o600);
            try {
                await handle.write(encoded);
                await handle.sync();
            }
            finally {
                await handle.close();
            }
            await rename(temporary, path);
        }
        finally {
            await rm(temporary, { force: true });
            await unlock();
        }
    }
}
function cryptoRandom(length) {
    if (!globalThis.crypto)
        throw new Error("Secure randomness unavailable");
    const value = new Uint8Array(length);
    globalThis.crypto.getRandomValues(value);
    return value;
}
