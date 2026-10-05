import { ComputeBudgetProgram } from "@solana/web3.js";
import { getAssociatedTokenAddressSync, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID } from "@solana/spl-token";
import { cryptoRandom, decryptNotePayload, encryptNote, encodeNote, keyHierarchy, noteCommitment, nullifier, ownerCommitment } from "./crypto.js";
import { accountDiscriminator } from "./encoding.js";
import { privateSwap as privateSwapIx, shield as shieldIx, unshield as unshieldIx } from "./instructions.js";
import { encodePrivateSwapPublicInputs, encodeUnshieldPublicInputs } from "./prover.js";
import { swapOutputPreservingLpClaims } from "./math.js";
import { pda } from "./pda.js";
import { transactionSignatureFromBytes } from "./client.js";
const key = (value) => Buffer.from(value).toString("hex");
const clone = (note) => ({ ...note, ownerCommitment: Uint8Array.from(note.ownerCommitment), randomness: Uint8Array.from(note.randomness), commitment: Uint8Array.from(note.commitment), encryptedPayload: note.encryptedPayload && Uint8Array.from(note.encryptedPayload), operationId: note.operationId && Uint8Array.from(note.operationId) });
const state = (note) => note.state ?? (note.spent ? "spent" : "available");
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
const noteFingerprint = (note) => JSON.stringify({ pool: note.pool.toBase58(), asset: note.asset.toBase58(), amount: note.amount.toString(), ownerCommitment: key(note.ownerCommitment), randomness: key(note.randomness), commitment: key(note.commitment), encryptedPayload: note.encryptedPayload && key(note.encryptedPayload), leafIndex: note.leafIndex?.toString(), state: state(note), operationId: note.operationId && key(note.operationId), transactionSignature: note.transactionSignature });
export class InMemoryNoteStore {
    notes = new Map();
    operations = new Map();
    async getNotes(ownerCommitment) {
        return [...this.notes.values()].filter(note => !ownerCommitment || same(note.ownerCommitment, ownerCommitment)).map(clone);
    }
    async saveNote(input) {
        const note = clone({ ...input, state: input.state ?? "available", spent: input.state === "spent" || input.spent === true });
        const existing = this.notes.get(key(note.commitment));
        if (existing && noteFingerprint(existing) !== noteFingerprint(note))
            throw new Error("Conflicting duplicate note commitment");
        if (!existing)
            this.notes.set(key(note.commitment), note);
    }
    async reserveNote(commitment, operationId, owner) {
        const note = this.notes.get(key(commitment));
        if (!note || !same(note.ownerCommitment, owner) || state(note) !== "available")
            throw new Error("Note is not available");
        note.state = "reserved";
        note.spent = false;
        note.operationId = Uint8Array.from(operationId);
        return clone(note);
    }
    async reserveNoteAndBegin(commitment, operationId, owner, operation) {
        const note = this.notes.get(key(commitment));
        if (!note || !same(note.ownerCommitment, owner) || state(note) !== "available")
            throw new Error("Note is not available");
        if (!same(operation.id, operationId) || !operation.inputCommitment || !same(operation.inputCommitment, commitment))
            throw new Error("Invalid reserve-and-begin operation");
        if (this.operations.has(key(operationId)))
            throw new Error("Duplicate operation ID");
        note.state = "reserved";
        note.spent = false;
        note.operationId = Uint8Array.from(operationId);
        this.operations.set(key(operationId), { ...operation, id: Uint8Array.from(operation.id), outputNotes: operation.outputNotes.map(clone), metadata: { ...operation.metadata } });
        return clone(note);
    }
    async markSubmitted(commitment, operationId, signature) {
        const note = this.notes.get(key(commitment));
        if (note && state(note) === "submitted" && note.transactionSignature === signature)
            return;
        if (!note || state(note) !== "reserved" || !note.operationId || !same(note.operationId, operationId))
            throw new Error("Note reservation mismatch");
        note.state = "submitted";
        note.transactionSignature = signature;
    }
    async markSpent(commitment, operationId) {
        const note = this.notes.get(key(commitment));
        if (note && state(note) === "spent")
            return;
        if (!note || (state(note) !== "reserved" && state(note) !== "submitted"))
            throw new Error("Note is not pending spend");
        if (operationId && (!note.operationId || !same(note.operationId, operationId)))
            throw new Error("Note reservation mismatch");
        note.state = "spent";
        note.spent = true;
        note.operationId = undefined;
    }
    async releaseReservation(commitment, operationId) {
        const note = this.notes.get(key(commitment));
        if (note && state(note) === "available")
            return;
        if (!note || (state(note) !== "reserved" && state(note) !== "submitted"))
            throw new Error("Note is not reserved");
        if (operationId && (!note.operationId || !same(note.operationId, operationId)))
            throw new Error("Note reservation mismatch");
        note.state = "available";
        note.spent = false;
        note.operationId = undefined;
        note.transactionSignature = undefined;
    }
    async beginOperation(operation) { if (this.operations.has(key(operation.id)))
        throw new Error("Duplicate operation ID"); this.operations.set(key(operation.id), { ...operation, id: Uint8Array.from(operation.id), outputNotes: operation.outputNotes.map(clone), metadata: { ...operation.metadata } }); }
    async updateOperation(id, patch) { const operation = this.operations.get(key(id)); if (!operation)
        throw new Error("Unknown operation"); operation.metadata = { ...operation.metadata, ...(patch.metadata ?? {}) }; if (patch.outputNotes)
        operation.outputNotes = patch.outputNotes.map(clone); }
    async markPrepared(id, signedTransaction, lastValidBlockHeight) { const operation = this.operations.get(key(id)); if (!operation)
        throw new Error("Unknown operation"); operation.state = "prepared"; operation.signedTransaction = Uint8Array.from(signedTransaction); operation.lastValidBlockHeight = lastValidBlockHeight; }
    async markOperationSubmitted(id, signature) { const operation = this.operations.get(key(id)); if (!operation)
        throw new Error("Unknown operation"); operation.state = "submitted"; operation.signature = signature; }
    async markOperationFinalized(id) { const operation = this.operations.get(key(id)); if (!operation)
        throw new Error("Unknown operation"); if (operation.state === "finalized")
        return; operation.state = "finalized"; }
    async markOperationFailed(id, reason) { const operation = this.operations.get(key(id)); if (!operation)
        throw new Error("Unknown operation"); if (operation.state === "failed")
        return; operation.state = "failed"; operation.metadata.failure = reason; }
    async markOperationUnknown(id, reason) { const operation = this.operations.get(key(id)); if (!operation)
        throw new Error("Unknown operation"); if (operation.state === "unknown")
        return; operation.state = "unknown"; operation.metadata.unknown = reason; }
    async getPendingOperations() { return [...this.operations.values()].filter(operation => operation.state !== "finalized" && operation.state !== "failed").map(operation => ({ ...operation, id: Uint8Array.from(operation.id), outputNotes: operation.outputNotes.map(clone), metadata: { ...operation.metadata } })); }
}
export class ShieldedWallet {
    sdk;
    prover;
    witnessProvider;
    spendSecret;
    viewKey;
    ownerCommitment;
    store;
    constructor(sdk, seed, prover, witnessProvider, store) {
        this.sdk = sdk;
        this.prover = prover;
        this.witnessProvider = witnessProvider;
        if (!store)
            throw new Error("An explicit NoteStore is required; volatile storage is not a production default");
        const keys = keyHierarchy(seed);
        this.spendSecret = keys.spendSecret;
        this.viewKey = keys.viewKey;
        this.ownerCommitment = ownerCommitment(this.spendSecret);
        this.store = store;
    }
    journal() {
        const store = this.store;
        return typeof store.beginOperation === "function" && typeof store.reserveNoteAndBegin === "function" ? store : undefined;
    }
    async addNote(note) {
        await this.store.saveNote(note);
    }
    async getNotes() {
        return this.store.getNotes(this.ownerCommitment);
    }
    async getPrivateBalance(input) {
        return (await this.getNotes()).filter(note => note.pool.equals(input.pool) && note.asset.equals(input.mint) && state(note) === "available").reduce((amount, note) => amount + note.amount, 0n);
    }
    requireBackend() {
        if (!this.prover)
            throw new Error("A production prover is required");
        if (!this.witnessProvider)
            throw new Error("A Merkle witness provider is required");
        return { prover: this.prover, witness: this.witnessProvider };
    }
    async select(pool, mint, amount) {
        const candidates = (await this.getNotes()).filter(note => note.pool.equals(pool) && note.asset.equals(mint) && state(note) === "available" && note.amount >= amount);
        if (!candidates.length)
            throw new Error("Insufficient private balance");
        return candidates[0];
    }
    async begin(operation) {
        const journal = this.journal();
        if (journal)
            await journal.beginOperation(operation);
    }
    async reserveAndBegin(note, operation) {
        const journal = this.journal();
        if (journal)
            return journal.reserveNoteAndBegin(note.commitment, operation.id, this.ownerCommitment, operation);
        await this.store.reserveNote(note.commitment, operation.id, this.ownerCommitment);
        return note;
    }
    async fail(operationId, note, reason, journaled = true) {
        try {
            if (note)
                await this.store.releaseReservation(note.commitment, operationId);
        }
        finally {
            const journal = this.journal();
            if (journal && journaled)
                await journal.markOperationFailed(operationId, reason ?? "operation failed");
        }
    }
    async unknown(operationId, reason, signature) {
        const journal = this.journal();
        if (!journal)
            return;
        try {
            if (signature)
                await journal.updateOperation(operationId, { metadata: { signature } });
            await journal.markOperationUnknown(operationId, reason);
        }
        catch {
            // Keep reserved notes untouched when local journaling is unavailable.
        }
    }
    async submitted(operationId, signature, note) {
        if (note)
            await this.store.markSubmitted(note.commitment, operationId, signature);
        const journal = this.journal();
        if (journal)
            await journal.markOperationSubmitted(operationId, signature);
    }
    async finalized(operationId, note, outputNotes = []) {
        if (note)
            await this.store.markSpent(note.commitment, operationId);
        for (const output of outputNotes)
            await this.store.saveNote(output);
        const journal = this.journal();
        if (journal)
            await journal.markOperationFinalized(operationId);
    }
    async shield(input) {
        const pool = await this.sdk.getPool(input.pool);
        const stateAccount = await this.sdk.getShieldedState(input.pool);
        const asset = input.mint.equals(pool.tokenAMint) ? 0 : input.mint.equals(pool.tokenBMint) ? 1 : -1;
        if (asset < 0)
            throw new Error("Mint is not a pool asset");
        const randomness = cryptoRandom(32);
        const commitment = noteCommitment(input.pool, input.mint, input.amount, this.ownerCommitment, randomness);
        const encrypted = encryptNote(encodeNote(input.pool, input.mint, input.amount, this.ownerCommitment, randomness), this.viewKey, input.pool, input.mint, commitment);
        const note = { pool: input.pool, asset: input.mint, amount: input.amount, ownerCommitment: this.ownerCommitment, randomness, commitment, encryptedPayload: encrypted, state: "available" };
        const operationId = cryptoRandom(32);
        await this.begin({ id: operationId, kind: "shield", state: "intent", pool: input.pool, metadata: { asset: input.mint.toBase58(), amount: input.amount.toString(), commitment: key(commitment) }, outputNotes: [note] });
        try {
            const [depositorA, depositorB] = await this.sdk.ensureAtas([{ mint: pool.tokenAMint, owner: this.sdk.wallet.publicKey }, { mint: pool.tokenBMint, owner: this.sdk.wallet.publicKey }]);
            const outcome = await this.sdk.buildAndSendOutcome([
                shieldIx(this.sdk.wallet.publicKey, pool, stateAccount, asset, input.amount, this.ownerCommitment, randomness, encrypted, depositorA, depositorB, this.sdk.programId),
            ], {
                onPrepared: async (transaction, lastValidBlockHeight) => { const journal = this.journal(); if (journal)
                    await journal.markPrepared(operationId, transaction, lastValidBlockHeight); },
                onSubmitted: async (signature) => this.submitted(operationId, signature),
            });
            if (outcome.status === "finalized-success") {
                await this.finalized(operationId, undefined, [note]);
                return { signature: outcome.signature, note };
            }
            if (outcome.status === "finalized-failed") {
                await this.fail(operationId, undefined, String(outcome.error));
                throw new Error(`Shield transaction failed: ${String(outcome.error)}`);
            }
            await this.unknown(operationId, outcome.reason, outcome.signature);
            throw new Error(`Shield transaction outcome is unknown: ${outcome.reason}`);
        }
        catch (error) {
            if (!String(error).includes("outcome is unknown") && !String(error).includes("TransactionUnknownError"))
                await this.fail(operationId, undefined, String(error));
            throw error;
        }
    }
    async unshield(input) {
        const { prover, witness } = this.requireBackend();
        this.sdk.assertPrivateTransactionReady();
        const operationId = cryptoRandom(32);
        let note = await this.select(input.pool, input.mint, input.amount);
        let journaled = false;
        let reserved = false;
        try {
            if (note.amount !== input.amount)
                throw new Error("Unshield consumes a complete note; partial unshield is not supported");
            note = await this.reserveAndBegin(note, { id: operationId, kind: "unshield", state: "intent", pool: input.pool, inputCommitment: note.commitment, metadata: { asset: input.mint.toBase58(), amount: input.amount.toString(), recipient: input.recipient.toBase58() }, outputNotes: [] });
            journaled = true;
            reserved = true;
            const pool = await this.sdk.getPool(input.pool);
            const stateAccount = await this.sdk.getShieldedState(input.pool);
            const witnessValue = await witness.getWitness(input.pool, note.commitment);
            const nullifierValue = nullifier(input.pool, input.mint, this.spendSecret, note.randomness);
            const preflightRecipientA = getAssociatedTokenAddressSync(pool.tokenAMint, input.recipient, true, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
            const preflightRecipientB = getAssociatedTokenAddressSync(pool.tokenBMint, input.recipient, true, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
            await this.sdk.validatePrivateTransactionReady([
                ComputeBudgetProgram.setComputeUnitLimit({ units: 500_000 }),
                unshieldIx(this.sdk.wallet.publicKey, pool, stateAccount, input.mint.equals(pool.tokenAMint) ? 0 : 1, note.amount, witnessValue.root, witnessValue.rootSequence, witnessValue.generation, nullifierValue, input.recipient, preflightRecipientA, preflightRecipientB, new Uint8Array(256), new Uint8Array(320), this.sdk.programId),
            ]);
            const journal = this.journal();
            if (journal)
                await journal.updateOperation(operationId, { metadata: { nullifier: key(nullifierValue), amount: note.amount.toString() } });
            const result = await prover.proveUnshield({ pool: input.pool, asset: input.mint, root: witnessValue.root, rootSequence: witnessValue.rootSequence, generation: witnessValue.generation, nullifier: nullifierValue, amount: note.amount, recipient: input.recipient, spendSecret: this.spendSecret, randomness: note.randomness, witness: witnessValue });
            const expected = encodeUnshieldPublicInputs({ pool: input.pool, asset: input.mint, root: witnessValue.root, nullifier: nullifierValue, amount: note.amount, recipient: input.recipient });
            if (!Buffer.from(result.publicInputs).equals(Buffer.from(expected)))
                throw new Error("Prover returned mismatched unshield public inputs");
            const [recipientA, recipientB] = await this.sdk.ensureAtas([{ mint: pool.tokenAMint, owner: input.recipient, allowOwnerOffCurve: true }, { mint: pool.tokenBMint, owner: input.recipient, allowOwnerOffCurve: true }]);
            const outcome = await this.sdk.buildAndSendOutcome([
                ComputeBudgetProgram.setComputeUnitLimit({ units: 500_000 }),
                unshieldIx(this.sdk.wallet.publicKey, pool, stateAccount, input.mint.equals(pool.tokenAMint) ? 0 : 1, note.amount, witnessValue.root, witnessValue.rootSequence, witnessValue.generation, nullifierValue, input.recipient, recipientA, recipientB, result.proof, result.publicInputs, this.sdk.programId),
            ], {
                requireVersioned: true,
                onPrepared: async (transaction, lastValidBlockHeight) => { const journal = this.journal(); if (journal)
                    await journal.markPrepared(operationId, transaction, lastValidBlockHeight); },
                onSubmitted: async (signature) => this.submitted(operationId, signature, note),
            });
            if (outcome.status === "finalized-success") {
                await this.finalized(operationId, note);
                return outcome.signature;
            }
            if (outcome.status === "finalized-failed") {
                await this.fail(operationId, note, String(outcome.error), journaled);
                throw new Error(`Unshield transaction failed: ${String(outcome.error)}`);
            }
            await this.unknown(operationId, outcome.reason, outcome.signature);
            throw new Error(`Unshield transaction outcome is unknown: ${outcome.reason}`);
        }
        catch (error) {
            if (!String(error).includes("outcome is unknown") && !String(error).includes("TransactionUnknownError"))
                await this.fail(operationId, reserved ? note : undefined, String(error), journaled);
            throw error;
        }
    }
    async privateSend(input) {
        return this.unshield(input);
    }
    async privateSwap(input) {
        const { prover, witness } = this.requireBackend();
        this.sdk.assertPrivateTransactionReady();
        const operationId = cryptoRandom(32);
        let note = await this.select(input.pool, input.inputMint, input.amountIn);
        let journaled = false;
        let reserved = false;
        try {
            if (input.amountIn > note.amount)
                throw new Error("Insufficient private balance");
            note = await this.reserveAndBegin(note, { id: operationId, kind: "private_swap", state: "intent", pool: input.pool, inputCommitment: note.commitment, metadata: { assetIn: input.inputMint.toBase58(), assetOut: input.outputMint.toBase58(), amountIn: input.amountIn.toString() }, outputNotes: [] });
            journaled = true;
            reserved = true;
            const pool = await this.sdk.getPool(input.pool);
            const stateAccount = await this.sdk.getShieldedState(input.pool);
            const direction = input.inputMint.equals(pool.tokenAMint) && input.outputMint.equals(pool.tokenBMint) ? 0 : input.inputMint.equals(pool.tokenBMint) && input.outputMint.equals(pool.tokenAMint) ? 1 : -1;
            if (direction < 0)
                throw new Error("Input and output mints must be the pool assets");
            const [reserves, lpSupply] = await Promise.all([this.sdk.getReserves(pool), this.sdk.getLpSupply(pool)]);
            const reserveIn = direction === 0 ? reserves.a : reserves.b;
            const reserveOut = direction === 0 ? reserves.b : reserves.a;
            const amountOut = swapOutputPreservingLpClaims(reserveIn, reserveOut, input.amountIn, pool.feeBps, lpSupply);
            if (amountOut < input.minAmountOut)
                throw new Error("Slippage exceeded");
            const witnessValue = await witness.getWitness(input.pool, note.commitment);
            const nullifierValue = nullifier(input.pool, input.inputMint, this.spendSecret, note.randomness);
            const changeAmount = note.amount - input.amountIn;
            const changeRandomness = changeAmount > 0n ? cryptoRandom(32) : new Uint8Array(32);
            const changeCommitment = changeAmount > 0n ? noteCommitment(input.pool, input.inputMint, changeAmount, this.ownerCommitment, changeRandomness) : new Uint8Array(32);
            const outputRandomness = cryptoRandom(32);
            const outputCommitment = noteCommitment(input.pool, input.outputMint, amountOut, this.ownerCommitment, outputRandomness);
            const changeNote = changeAmount > 0n ? this.localNote(input.pool, input.inputMint, changeAmount, changeRandomness, changeCommitment) : undefined;
            const outputNote = this.localNote(input.pool, input.outputMint, amountOut, outputRandomness, outputCommitment);
            await this.sdk.validatePrivateTransactionReady([
                ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
                privateSwapIx(this.sdk.wallet.publicKey, pool, stateAccount, direction, witnessValue.root, witnessValue.rootSequence, witnessValue.generation, nullifierValue, input.amountIn, amountOut, changeAmount, changeCommitment, outputCommitment, new Uint8Array(256), this.sdk.programId),
            ]);
            const journal = this.journal();
            if (journal)
                await journal.updateOperation(operationId, { metadata: { amountOut: amountOut.toString(), nullifier: key(nullifierValue), changeCommitment: key(changeCommitment), outputCommitment: key(outputCommitment) }, outputNotes: [...(changeNote ? [changeNote] : []), outputNote] });
            const proofInput = { pool: input.pool, assetIn: input.inputMint, assetOut: input.outputMint, root: witnessValue.root, rootSequence: witnessValue.rootSequence, generation: witnessValue.generation, nullifier: nullifierValue, reserveIn, reserveOut, feeBps: pool.feeBps, amountIn: input.amountIn, amountOut, changeAmount, changeCommitment, outputCommitment, direction, swapNonce: pool.swapNonce, inputSpendSecret: this.spendSecret, inputRandomness: note.randomness, witness: witnessValue, changeSpendSecret: this.spendSecret, changeRandomness, outputSpendSecret: this.spendSecret, outputRandomness };
            const result = await prover.provePrivateSwap(proofInput);
            const expected = encodePrivateSwapPublicInputs(proofInput);
            if (!Buffer.from(result.publicInputs).equals(Buffer.from(expected)))
                throw new Error("Prover returned mismatched private-swap public inputs");
            const outcome = await this.sdk.buildAndSendOutcome([
                ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
                privateSwapIx(this.sdk.wallet.publicKey, pool, stateAccount, direction, witnessValue.root, witnessValue.rootSequence, witnessValue.generation, nullifierValue, input.amountIn, amountOut, changeAmount, changeCommitment, outputCommitment, result.proof, this.sdk.programId),
            ], {
                requireVersioned: true,
                onPrepared: async (transaction, lastValidBlockHeight) => { const journal = this.journal(); if (journal)
                    await journal.markPrepared(operationId, transaction, lastValidBlockHeight); },
                onSubmitted: async (signature) => this.submitted(operationId, signature, note),
            });
            if (outcome.status === "finalized-success") {
                await this.finalized(operationId, note, [...(changeNote ? [changeNote] : []), outputNote]);
                return outcome.signature;
            }
            if (outcome.status === "finalized-failed") {
                await this.fail(operationId, note, String(outcome.error), journaled);
                throw new Error(`Private swap transaction failed: ${String(outcome.error)}`);
            }
            await this.unknown(operationId, outcome.reason, outcome.signature);
            throw new Error(`Private swap transaction outcome is unknown: ${outcome.reason}`);
        }
        catch (error) {
            if (!String(error).includes("outcome is unknown") && !String(error).includes("TransactionUnknownError"))
                await this.fail(operationId, reserved ? note : undefined, String(error), journaled);
            throw error;
        }
    }
    localNote(pool, asset, amount, randomness, commitment) {
        return { pool, asset, amount, ownerCommitment: this.ownerCommitment, randomness, commitment, encryptedPayload: encryptNote(encodeNote(pool, asset, amount, this.ownerCommitment, randomness), this.viewKey, pool, asset, commitment), state: "available" };
    }
    async recoverShieldedNotes(pool) {
        const provider = this.witnessProvider;
        if (!provider?.getShieldEvents || !provider.getSpentNullifiers)
            throw new Error("The configured witness provider does not support authenticated shield recovery");
        const stateAccount = await this.sdk.getShieldedState(pool);
        const spentNullifiers = new Set((await provider.getSpentNullifiers(pool)).map(value => key(value)));
        const existing = new Map((await this.getNotes()).filter(note => note.pool.equals(pool)).map(note => [key(note.commitment), note]));
        const events = await provider.getShieldEvents(pool);
        const decoded = [];
        for (const event of events) {
            const mint = event.asset === 0 ? stateAccount.tokenAMint : event.asset === 1 ? stateAccount.tokenBMint : undefined;
            if (!mint)
                throw new Error("Invalid shield asset in recovery history");
            const note = decryptNotePayload(event.encryptedNote, this.viewKey, pool, mint, event.commitment);
            if (!same(note.ownerCommitment, this.ownerCommitment))
                continue;
            decoded.push({ event, mint, randomness: note.randomness, ownerCommitment: note.ownerCommitment, amount: note.amount, nullifier: nullifier(pool, mint, this.spendSecret, note.randomness) });
        }
        const getMultipleAccountsInfo = this.sdk.connection.getMultipleAccountsInfo?.bind(this.sdk.connection);
        if (decoded.length && !getMultipleAccountsInfo)
            throw new Error("RPC does not support finalized spent-nullifier verification");
        const spentDiscriminator = accountDiscriminator("SpentNullifier");
        for (let offset = 0; offset < decoded.length; offset += 100) {
            const batch = decoded.slice(offset, offset + 100);
            const addresses = batch.map(value => pda.spent(pool, value.nullifier, this.sdk.programId)[0]);
            const accounts = await getMultipleAccountsInfo(addresses, "finalized");
            if (accounts.length !== batch.length)
                throw new Error("RPC returned an incomplete spent-nullifier response");
            for (let index = 0; index < accounts.length; index++) {
                const account = accounts[index];
                if (!account)
                    continue;
                const data = account.data;
                if (!account.owner.equals(this.sdk.programId) || data.length !== 73 || !data.subarray(0, 8).equals(spentDiscriminator) || !data.subarray(8, 40).equals(pool.toBuffer()) || !data.subarray(40, 72).equals(Buffer.from(batch[index].nullifier)) || data[72] !== 1)
                    throw new Error("Invalid spent-nullifier account");
                spentNullifiers.add(key(batch[index].nullifier));
            }
        }
        const recovered = [];
        for (const candidate of decoded) {
            const { event, mint } = candidate;
            const consumed = spentNullifiers.has(key(candidate.nullifier));
            const note = { pool, asset: mint, amount: candidate.amount, ownerCommitment: candidate.ownerCommitment, randomness: candidate.randomness, commitment: event.commitment, encryptedPayload: event.encryptedNote, leafIndex: event.index, state: consumed ? "spent" : "available" };
            const current = existing.get(key(note.commitment));
            if (!current)
                await this.store.saveNote(note);
            else if (consumed && state(current) !== "spent") {
                if (state(current) === "available")
                    await this.store.reserveNote(current.commitment, cryptoRandom(32), this.ownerCommitment);
                await this.store.markSpent(current.commitment);
            }
            recovered.push(note);
        }
        return recovered;
    }
    async reconcilePending() {
        const journal = this.journal();
        if (!journal)
            return [];
        const pending = await journal.getPendingOperations();
        for (const operation of pending) {
            const signature = operation.signature ?? operation.metadata.signature ?? (operation.signedTransaction ? transactionSignatureFromBytes(operation.signedTransaction) : undefined);
            if (!signature) {
                if (operation.state === "intent") {
                    if (operation.inputCommitment) {
                        try {
                            await this.store.releaseReservation(operation.inputCommitment, operation.id);
                        }
                        catch { /* The composite reservation may not have committed. */ }
                    }
                    try {
                        await journal.markOperationFailed(operation.id, "Operation had no submitted transaction signature");
                    }
                    catch { /* Retry on the next reconciliation pass. */ }
                }
                continue;
            }
            if (!operation.signature && !operation.metadata.signature) {
                try {
                    await journal.updateOperation(operation.id, { metadata: { signature } });
                }
                catch { /* Keep the operation pending for the next reconciliation pass. */ }
            }
            const outcome = await this.sdk.reconcileTransaction(signature, operation.lastValidBlockHeight === undefined ? undefined : Number(operation.lastValidBlockHeight));
            if (outcome.status === "finalized-success") {
                const eventName = operation.kind === "shield" ? "ShieldedNoteAppended" : operation.kind === "unshield" ? "Unshielded" : "PrivateSwapped";
                const needles = Object.values(operation.metadata).filter(value => /^[0-9a-f]{64}$/i.test(value)).map(value => Uint8Array.from(Buffer.from(value, "hex")));
                if (!(await this.sdk.hasFinalizedProgramEvent(signature, eventName, needles))) {
                    await journal.markOperationUnknown(operation.id, "Finalized transaction has no authenticated matching event");
                    continue;
                }
                if (operation.inputCommitment)
                    await this.store.markSpent(operation.inputCommitment, operation.id);
                for (const note of operation.outputNotes)
                    await this.store.saveNote(note);
                await journal.markOperationFinalized(operation.id);
            }
            else if (outcome.status === "finalized-failed") {
                if (operation.inputCommitment)
                    await this.store.releaseReservation(operation.inputCommitment, operation.id);
                await journal.markOperationFailed(operation.id, String(outcome.error));
            }
            else {
                await journal.markOperationUnknown(operation.id, outcome.reason);
            }
        }
        return journal.getPendingOperations();
    }
}
