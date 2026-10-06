import { createHash } from "node:crypto";
import { PublicKey, Transaction, TransactionMessage, VersionedTransaction, } from "@solana/web3.js";
import { ASSOCIATED_TOKEN_PROGRAM_ID, createAssociatedTokenAccountIdempotentInstruction, getAccount, getAssociatedTokenAddressSync, getMint, TOKEN_PROGRAM_ID, } from "@solana/spl-token";
import { accountDiscriminator, PROGRAM_ID } from "./encoding.js";
import { decodePool, decodeProtocolConfig, decodeShieldedState, decodeTreeState } from "./accounts.js";
import { pda } from "./pda.js";
import { addLiquidity as addLiquidityIx, initializePool, initializeShieldedState, removeLiquidity as removeLiquidityIx, rolloverTree, swap as swapIx } from "./instructions.js";
import { TREE_CAPACITY } from "./merkle.js";
import { OnChainPagedMerkleWitnessProvider } from "./archive.js";
import { authenticatedShieldedEvents } from "./witness.js";
import { swapOutputPreservingLpClaims } from "./math.js";
import { keyHierarchy, ownerCommitment } from "./crypto.js";
import { EncryptedFileNoteStore } from "./store.js";
import { ShieldedWallet } from "./wallet.js";
const FINALIZED = "finalized";
const MAX_U64 = 0xffffffffffffffffn;
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function encodeBase58(value) {
    let number = BigInt(`0x${Buffer.from(value).toString("hex")}`);
    let output = "";
    while (number > 0n) {
        const remainder = Number(number % 58n);
        output = BASE58[remainder] + output;
        number /= 58n;
    }
    let leading = 0;
    while (leading < value.length && value[leading] === 0)
        leading++;
    return "1".repeat(leading) + output;
}
function signedSignature(transaction) {
    const signature = transaction instanceof VersionedTransaction ? transaction.signatures[0] : transaction.signature;
    if (!signature || signature.every(byte => byte === 0))
        return undefined;
    return encodeBase58(signature);
}
export function transactionSignatureFromBytes(serialized) {
    try {
        return signedSignature(VersionedTransaction.deserialize(serialized));
    }
    catch {
        try {
            return signedSignature(Transaction.from(Buffer.from(serialized)));
        }
        catch {
            return undefined;
        }
    }
}
export class LookupTableRequiredError extends Error {
    constructor() { super("A validated versioned lookup table is required for private proof transactions"); this.name = "LookupTableRequiredError"; }
}
export class TransactionFailedError extends Error {
    outcome;
    constructor(outcome) {
        super(`Transaction finalized with an execution error: ${String(outcome.error)}`);
        this.outcome = outcome;
        this.name = "TransactionFailedError";
    }
}
export class TransactionUnknownError extends Error {
    outcome;
    constructor(outcome) {
        super(`Transaction outcome is unknown: ${outcome.reason}`);
        this.outcome = outcome;
        this.name = "TransactionUnknownError";
    }
}
export class Lethenymous {
    connection;
    wallet;
    programId;
    witnessProvider;
    lookupTables;
    lookupTableCache = new Map();
    lookupTableLoads = new Map();
    constructor(config) {
        this.connection = config.connection;
        this.wallet = config.wallet;
        this.programId = config.programId ?? PROGRAM_ID;
        this.witnessProvider = config.witnessProvider ?? new OnChainPagedMerkleWitnessProvider(this.connection, this.programId);
        this.lookupTables = (config.lookupTables ?? []).map(value => value instanceof PublicKey ? { address: value } : value);
    }
    async account(address, kind) {
        const info = await this.connection.getAccountInfo(address, FINALIZED);
        if (!info)
            throw new Error(`Account not found: ${address.toBase58()}`);
        if (!info.owner.equals(this.programId))
            throw new Error(`Account is not owned by configured program: ${address.toBase58()}`);
        if (info.data.length < 8 || !info.data.subarray(0, 8).equals(accountDiscriminator(kind)))
            throw new Error(`Invalid ${kind} account discriminator: ${address.toBase58()}`);
        return info.data.subarray(8);
    }
    async getPool(address) {
        return decodePool(await this.account(address, "Pool"), address);
    }
    async getShieldedState(pool) {
        const state = decodeShieldedState(await this.account(pda.shielded(pool, this.programId)[0], "ShieldedState"));
        if (!state.pool.equals(pool))
            throw new Error("Shielded state does not match pool");
        return state;
    }
    async getTree(pool) {
        return (await this.getActiveTree(pool)).tree;
    }
    async getTreeAt(address, pool) {
        const tree = decodeTreeState(await this.account(address, "TreeState"));
        if (pool && !tree.pool.equals(pool))
            throw new Error("Tree does not match pool");
        if (!address.equals(pda.tree(tree.pool, tree.generation, this.programId)[0]))
            throw new Error("Tree generation/PDA mismatch");
        return tree;
    }
    async getTreeByGeneration(pool, generation) {
        return this.getTreeAt(pda.tree(pool, generation, this.programId)[0], pool);
    }
    async getActiveTree(pool) {
        const state = await this.getShieldedState(pool);
        const tree = await this.getTreeAt(state.tree, pool);
        return { address: state.tree, tree, state };
    }
    async ensureTreeCapacity(pool, requiredLeaves) {
        for (let attempt = 0; attempt < 3; attempt++) {
            const active = await this.getActiveTree(pool);
            const remaining = TREE_CAPACITY - active.tree.nextIndex;
            if (remaining < 0n)
                throw new Error("Invalid active tree capacity");
            if (remaining >= BigInt(requiredLeaves))
                return active;
            try {
                await this.buildAndSend([rolloverTree(this.wallet.publicKey, pool, active.tree.generation, this.programId)]);
            }
            catch (error) {
                const refreshed = await this.getActiveTree(pool);
                if (refreshed.tree.generation <= active.tree.generation)
                    throw error;
            }
        }
        throw new Error("Active tree kept changing during rollover; retry from finalized state");
    }
    async getProtocolConfig() {
        return decodeProtocolConfig(await this.account(pda.protocolConfig(this.programId)[0], "ProtocolConfig"));
    }
    async getReserves(pool) {
        const [a, b] = await Promise.all([
            getAccount(this.connection, pool.tokenAVault, FINALIZED, TOKEN_PROGRAM_ID),
            getAccount(this.connection, pool.tokenBVault, FINALIZED, TOKEN_PROGRAM_ID),
        ]);
        if (!a.mint.equals(pool.tokenAMint) || !b.mint.equals(pool.tokenBMint))
            throw new Error("Pool vault mint mismatch");
        return { a: a.amount, b: b.amount };
    }
    async getLpSupply(pool) {
        return (await getMint(this.connection, pool.lpMint, FINALIZED, TOKEN_PROGRAM_ID)).supply;
    }
    async validatedTables(instructions) {
        if (!this.lookupTables.length)
            return [];
        const slot = await this.connection.getSlot(FINALIZED);
        const tables = [];
        for (const config of this.lookupTables) {
            const key = config.address.toBase58();
            let entry = this.lookupTableCache.get(key)?.slot === slot ? this.lookupTableCache.get(key) : undefined;
            if (!entry) {
                let load = this.lookupTableLoads.get(key);
                if (!load) {
                    load = (async () => {
                        const response = await this.connection.getAddressLookupTable(config.address, { commitment: FINALIZED });
                        const value = response.value;
                        if (!value)
                            throw new Error(`Configured address lookup table is unavailable: ${config.address.toBase58()}`);
                        if (!value.key.equals(config.address))
                            throw new Error(`Configured address lookup table returned the wrong account: ${config.address.toBase58()}`);
                        const responseSlot = response.context?.slot ?? slot;
                        if (!Number.isSafeInteger(responseSlot) || responseSlot < 0)
                            throw new Error("Configured address lookup table returned an invalid context slot");
                        return { slot: responseSlot, table: value };
                    })();
                    this.lookupTableLoads.set(key, load);
                }
                try {
                    entry = await load;
                    this.lookupTableCache.set(key, entry);
                }
                finally {
                    if (this.lookupTableLoads.get(key) === load)
                        this.lookupTableLoads.delete(key);
                }
            }
            const value = entry.table;
            const validationSlot = entry.slot;
            const state = value.state;
            const lastExtendedSlotStartIndex = state.lastExtendedSlotStartIndex ?? state.addresses.length;
            if (BigInt(state.lastExtendedSlot) > BigInt(validationSlot) || (BigInt(state.lastExtendedSlot) === BigInt(validationSlot) && lastExtendedSlotStartIndex < state.addresses.length))
                throw new Error("Configured address lookup table is not active at finalized slot");
            if (state.deactivationSlot !== MAX_U64 && state.deactivationSlot <= BigInt(validationSlot))
                throw new Error("Configured address lookup table is deactivated");
            if (config.expectedAuthority !== undefined) {
                const actual = state.authority ?? null;
                if ((actual === null) !== (config.expectedAuthority === null) || (actual && !actual.equals(config.expectedAuthority)))
                    throw new Error("Configured address lookup table authority mismatch");
            }
            if (config.expectedAddresses) {
                const actual = new Set(state.addresses.map(address => address.toBase58()));
                const expected = new Set(config.expectedAddresses.map(address => address.toBase58()));
                if (expected.size !== config.expectedAddresses.length || actual.size !== expected.size)
                    throw new Error("Configured address lookup table contents differ from the expected deployment");
                for (const address of expected)
                    if (!actual.has(address))
                        throw new Error("Configured address lookup table is missing an expected address");
            }
            tables.push(value);
        }
        return tables;
    }
    async buildAndSendOutcome(instructions, options = {}) {
        if (options.requireVersioned && !this.lookupTables.length)
            throw new LookupTableRequiredError();
        const latest = await this.connection.getLatestBlockhash(FINALIZED);
        const tables = await this.validatedTables(instructions);
        let raw;
        if (tables.length) {
            if (!this.wallet.signVersionedTransaction)
                throw new Error("Wallet adapter must implement signVersionedTransaction when lookup tables are configured");
            const message = new TransactionMessage({ payerKey: this.wallet.publicKey, recentBlockhash: latest.blockhash, instructions }).compileToV0Message(tables);
            raw = await this.wallet.signVersionedTransaction(new VersionedTransaction(message));
        }
        else {
            if (options.requireVersioned)
                throw new LookupTableRequiredError();
            const transaction = new Transaction();
            transaction.feePayer = this.wallet.publicKey;
            transaction.recentBlockhash = latest.blockhash;
            transaction.lastValidBlockHeight = latest.lastValidBlockHeight;
            transaction.add(...instructions);
            raw = await this.wallet.signTransaction(transaction);
        }
        const serialized = raw.serialize();
        if (serialized.length > 1232)
            throw new Error(`Transaction exceeds Solana packet limit: ${serialized.length} > 1232`);
        if (options.onPrepared)
            await options.onPrepared(serialized, BigInt(latest.lastValidBlockHeight));
        let signature;
        try {
            signature = await this.connection.sendRawTransaction(serialized);
        }
        catch (error) {
            signature = signedSignature(raw);
            if (!signature)
                throw new Error(`Transaction submission failed before a signature was returned: ${String(error)}`);
            if (options.onSubmitted) {
                try {
                    await options.onSubmitted(signature);
                }
                catch { /* The transaction remains unknown and must not release local state. */ }
            }
            return { status: "unknown", signature, reason: "Transaction submission acknowledgement failed after signing" };
        }
        if (options.onSubmitted) {
            try {
                await options.onSubmitted(signature);
            }
            catch {
                return { status: "unknown", signature, reason: "Transaction submitted; local submission state could not be journaled" };
            }
        }
        try {
            const confirmation = await this.connection.confirmTransaction({ signature, blockhash: latest.blockhash, lastValidBlockHeight: latest.lastValidBlockHeight }, FINALIZED);
            if (confirmation.value.err !== null)
                return { status: "finalized-failed", signature, error: confirmation.value.err };
            return { status: "finalized-success", signature };
        }
        catch (error) {
            return this.reconcileTransaction(signature, latest.lastValidBlockHeight, String(error));
        }
    }
    async reconcileTransaction(signature, lastValidBlockHeight, reason = "confirmation did not complete") {
        try {
            const status = (await this.connection.getSignatureStatuses([signature], { searchTransactionHistory: true })).value[0];
            if (status?.confirmationStatus === "finalized")
                return status.err == null
                    ? { status: "finalized-success", signature }
                    : { status: "finalized-failed", signature, error: status.err };
            const transaction = await this.connection.getTransaction(signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
            if (transaction?.meta?.err !== null && transaction?.meta?.err !== undefined)
                return { status: "finalized-failed", signature, error: transaction.meta.err };
            if (transaction?.meta && transaction.meta.err === null)
                return { status: "finalized-success", signature };
            if (status == null && lastValidBlockHeight !== undefined && await this.connection.getBlockHeight(FINALIZED) > lastValidBlockHeight)
                return { status: "finalized-failed", signature, error: new Error("Blockhash expired before finalization") };
            return { status: "unknown", signature, reason };
        }
        catch {
            return { status: "unknown", signature, reason: "Transaction outcome could not be reconciled" };
        }
    }
    async hasFinalizedProgramEvent(signature, name, needles = []) {
        const transaction = await this.connection.getTransaction(signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
        if (!transaction || transaction.meta?.err !== null && transaction.meta?.err !== undefined)
            return false;
        const discriminator = createHash("sha256").update(`event:${name}`).digest().subarray(0, 8);
        const stack = [];
        for (const log of transaction.meta?.logMessages ?? []) {
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
            if (!log.startsWith("Program data: ") || stack.at(-1) !== this.programId.toBase58())
                continue;
            const data = Buffer.from(log.slice("Program data: ".length), "base64");
            if (!data.subarray(0, 8).equals(discriminator))
                continue;
            if (needles.every(needle => data.includes(Buffer.from(needle))))
                return true;
        }
        return false;
    }
    async getFinalizedShieldedEvents(signature) {
        const tx = await this.connection.getTransaction(signature, { commitment: "finalized", maxSupportedTransactionVersion: 0 });
        if (!tx || tx.transaction.signatures[0] !== signature)
            throw new Error("Finalized transaction unavailable or signature mismatch");
        return authenticatedShieldedEvents(tx, this.programId);
    }
    async buildAndSend(instructions, options = {}) {
        const outcome = await this.buildAndSendOutcome(instructions, options);
        if (outcome.status === "finalized-success")
            return outcome.signature;
        if (outcome.status === "finalized-failed")
            throw new TransactionFailedError(outcome);
        throw new TransactionUnknownError(outcome);
    }
    async initializePool(a, b, feeBps, creator = this.wallet.publicKey) {
        return this.buildAndSend([initializePool(this.wallet.publicKey, this.wallet.publicKey, creator, a, b, feeBps, this.programId)]);
    }
    async initializeShieldedState(pool) {
        const state = await this.getPool(pool);
        return this.buildAndSend([initializeShieldedState(this.wallet.publicKey, pool, { pool, tokenAMint: state.tokenAMint, tokenBMint: state.tokenBMint }, this.programId)]);
    }
    async ata(mint, owner, allowOwnerOffCurve = false) {
        const address = getAssociatedTokenAddressSync(mint, owner, allowOwnerOffCurve, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
        const info = await this.connection.getAccountInfo(address, FINALIZED);
        if (!info)
            return { address, create: createAssociatedTokenAccountIdempotentInstruction(this.wallet.publicKey, address, owner, mint, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID) };
        if (!info.owner.equals(TOKEN_PROGRAM_ID))
            throw new Error("Existing ATA is not owned by the classic token program");
        const account = await getAccount(this.connection, address, FINALIZED, TOKEN_PROGRAM_ID);
        if (!account.mint.equals(mint) || !account.owner.equals(owner))
            throw new Error("Existing ATA has the wrong mint or authority");
        return { address };
    }
    async addLiquidity(poolAddress, amountA, amountB, minLp = 0n) {
        const pool = await this.getPool(poolAddress);
        const [a, b, lp] = await Promise.all([this.ata(pool.tokenAMint, this.wallet.publicKey), this.ata(pool.tokenBMint, this.wallet.publicKey), this.ata(pool.lpMint, this.wallet.publicKey)]);
        return this.buildAndSend([a.create, b.create, lp.create, addLiquidityIx(this.wallet.publicKey, pool, a.address, b.address, lp.address, amountA, amountB, minLp, this.programId)].filter(Boolean));
    }
    async removeLiquidity(poolAddress, lpAmount, minA = 0n, minB = 0n) {
        const pool = await this.getPool(poolAddress);
        const [a, b, lp] = await Promise.all([this.ata(pool.tokenAMint, this.wallet.publicKey), this.ata(pool.tokenBMint, this.wallet.publicKey), this.ata(pool.lpMint, this.wallet.publicKey)]);
        return this.buildAndSend([a.create, b.create, removeLiquidityIx(this.wallet.publicKey, pool, a.address, b.address, lp.address, lpAmount, minA, minB, this.programId)].filter(Boolean));
    }
    async quote(poolAddress, direction, amountIn) {
        const pool = await this.getPool(poolAddress);
        const [reserves, supply] = await Promise.all([this.getReserves(pool), this.getLpSupply(pool)]);
        return swapOutputPreservingLpClaims(direction === "AToB" ? reserves.a : reserves.b, direction === "AToB" ? reserves.b : reserves.a, amountIn, pool.feeBps, supply);
    }
    async swap(poolAddress, direction, amountIn, minAmountOut) {
        const pool = await this.getPool(poolAddress);
        const [a, b] = await Promise.all([this.ata(pool.tokenAMint, this.wallet.publicKey), this.ata(pool.tokenBMint, this.wallet.publicKey)]);
        return this.buildAndSend([a.create, b.create, swapIx(this.wallet.publicKey, pool, a.address, b.address, direction === "AToB" ? 0 : 1, amountIn, minAmountOut, this.programId)].filter(Boolean));
    }
    async ensureAta(mint, owner = this.wallet.publicKey, allowOwnerOffCurve = false) {
        return (await this.ata(mint, owner, allowOwnerOffCurve)).address;
    }
    async ensureAtas(mintOwnerPairs) {
        const entries = await Promise.all(mintOwnerPairs.map(entry => this.ata(entry.mint, entry.owner, entry.allowOwnerOffCurve ?? false)));
        const missing = entries.flatMap(entry => entry.create ? [entry.create] : []);
        if (missing.length)
            await this.buildAndSend(missing);
        return entries.map(entry => entry.address);
    }
    assertPrivateTransactionReady() {
        if (!this.lookupTables.length || !this.wallet.signVersionedTransaction)
            throw new LookupTableRequiredError();
    }
    async validatePrivateTransactionReady(instructions) {
        this.assertPrivateTransactionReady();
        const tables = await this.validatedTables(instructions);
        const message = new TransactionMessage({ payerKey: this.wallet.publicKey, recentBlockhash: PublicKey.default.toBase58(), instructions }).compileToV0Message(tables);
        const size = new VersionedTransaction(message).serialize().length;
        if (size > 1232)
            throw new Error(`Private transaction exceeds Solana packet limit: ${size} > 1232; configure a sufficient static pool LUT`);
    }
    shieldedWallet(seed, prover, options = {}) {
        const noteStore = options.noteStore ?? (options.storagePath ? EncryptedFileNoteStore.fromSeed(options.storagePath, seed, ownerCommitment(keyHierarchy(seed).spendSecret)) : undefined);
        if (!noteStore)
            throw new Error("A persistent encrypted NoteStore is required; pass storagePath or noteStore");
        return new ShieldedWallet(this, seed, prover, this.witnessProvider, noteStore);
    }
}
