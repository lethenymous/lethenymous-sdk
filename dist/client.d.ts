import { Connection, PublicKey, TransactionInstruction } from "@solana/web3.js";
import type { ClientConfig, MerkleWitnessProvider, NoteStore, PoolState, ProtocolConfig, ShieldedState, TransactionOutcome, TreeState, WalletAdapter, Prover, Direction } from "./types.js";
import { ShieldedWallet } from "./wallet.js";
export declare function transactionSignatureFromBytes(serialized: Uint8Array): string | undefined;
export declare class LookupTableRequiredError extends Error {
    constructor();
}
export declare class TransactionFailedError extends Error {
    readonly outcome: Extract<TransactionOutcome, {
        status: "finalized-failed";
    }>;
    constructor(outcome: Extract<TransactionOutcome, {
        status: "finalized-failed";
    }>);
}
export declare class TransactionUnknownError extends Error {
    readonly outcome: Extract<TransactionOutcome, {
        status: "unknown";
    }>;
    constructor(outcome: Extract<TransactionOutcome, {
        status: "unknown";
    }>);
}
export interface SendOptions {
    requireVersioned?: boolean;
    onPrepared?: (signedTransaction: Uint8Array, lastValidBlockHeight: bigint) => Promise<void>;
    onSubmitted?: (signature: string) => Promise<void>;
}
export interface ShieldedWalletOptions {
    noteStore?: NoteStore;
    storagePath?: string;
}
export declare class Lethenymous {
    readonly connection: Connection;
    readonly wallet: WalletAdapter;
    readonly programId: PublicKey;
    readonly witnessProvider?: MerkleWitnessProvider;
    private readonly lookupTables;
    private readonly lookupTableCache;
    private readonly lookupTableLoads;
    constructor(config: ClientConfig);
    private account;
    getPool(address: PublicKey): Promise<PoolState>;
    getShieldedState(pool: PublicKey): Promise<ShieldedState>;
    getTree(pool: PublicKey): Promise<TreeState>;
    getProtocolConfig(): Promise<ProtocolConfig>;
    getReserves(pool: PoolState): Promise<{
        a: bigint;
        b: bigint;
    }>;
    getLpSupply(pool: PoolState): Promise<bigint>;
    private validatedTables;
    buildAndSendOutcome(instructions: TransactionInstruction[], options?: SendOptions): Promise<TransactionOutcome>;
    reconcileTransaction(signature: string, lastValidBlockHeight?: number, reason?: string): Promise<TransactionOutcome>;
    hasFinalizedProgramEvent(signature: string, name: string, needles?: Uint8Array[]): Promise<boolean>;
    buildAndSend(instructions: TransactionInstruction[], options?: SendOptions): Promise<string>;
    initializePool(a: PublicKey, b: PublicKey, feeBps: number, creator?: PublicKey): Promise<string>;
    initializeShieldedState(pool: PublicKey): Promise<string>;
    private ata;
    addLiquidity(poolAddress: PublicKey, amountA: bigint, amountB: bigint, minLp?: bigint): Promise<string>;
    removeLiquidity(poolAddress: PublicKey, lpAmount: bigint, minA?: bigint, minB?: bigint): Promise<string>;
    quote(poolAddress: PublicKey, direction: Direction, amountIn: bigint): Promise<bigint>;
    swap(poolAddress: PublicKey, direction: Direction, amountIn: bigint, minAmountOut: bigint): Promise<string>;
    ensureAta(mint: PublicKey, owner?: PublicKey, allowOwnerOffCurve?: boolean): Promise<PublicKey>;
    ensureAtas(mintOwnerPairs: Array<{
        mint: PublicKey;
        owner: PublicKey;
        allowOwnerOffCurve?: boolean;
    }>): Promise<PublicKey[]>;
    assertPrivateTransactionReady(): void;
    validatePrivateTransactionReady(instructions: TransactionInstruction[]): Promise<void>;
    shieldedWallet(seed: Uint8Array, prover?: Prover, options?: ShieldedWalletOptions): ShieldedWallet;
}
