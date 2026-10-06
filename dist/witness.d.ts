import { PublicKey, type Connection, type VersionedTransactionResponse } from "@solana/web3.js";
import type { MerkleCheckpointStore, MerkleWitness, MerkleWitnessProvider, TreeState } from "./types.js";
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
    outputGeneration: bigint;
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
export interface TreeRolloverEvent {
    kind: "rollover";
    pool: PublicKey;
    previousTree: PublicKey;
    previousGeneration: bigint;
    previousFinalRoot: Uint8Array;
    newTree: PublicKey;
    newGeneration: bigint;
    signature: string;
    slot: number;
}
export type HistoryEvent = ShieldedAppendEvent | UnshieldEvent | TreeRolloverEvent;
export type MerkleReconstructionErrorCode = "INVALID_CHECKPOINT" | "HISTORY_GAP" | "HISTORY_RPC" | "GENERATION_MISMATCH" | "SEQUENCE_GAP" | "ROOT_MISMATCH" | "TRANSACTION_MISSING" | "FAILED_TRANSACTION" | "DUPLICATE_EVENT" | "INVALID_TREE";
export declare class MerkleReconstructionError extends Error {
    readonly code: MerkleReconstructionErrorCode;
    constructor(code: MerkleReconstructionErrorCode, message: string);
}
export interface MerkleReplayMetrics {
    generationLoads: number;
    validatedLeaves: number;
    replayedAppends: number;
    serializedAppends: number;
    sealedWrites: number;
    activeDeltaWrites: number;
    manifestWrites: number;
    historyTransactions: number;
    nullifierReads: number;
    nullifierWrites: number;
    serializedBytes: number;
}
export declare function authenticatedShieldedEvents(transaction: VersionedTransactionResponse, programId: PublicKey): HistoryEvent[];
export declare function parseShieldedEvent(data: Buffer, signature: string, slot: number): HistoryEvent | undefined;
export declare class RpcMerkleWitnessProvider implements MerkleWitnessProvider {
    private readonly connection;
    private readonly programId;
    private readonly getTree;
    private readonly checkpointStore?;
    private readonly getGenerationTree?;
    private readonly states;
    private readonly syncing;
    private genesisHash?;
    private readonly blobs;
    private readonly historical;
    private readonly metrics;
    getReplayMetrics(): MerkleReplayMetrics;
    constructor(connection: Connection, programId: PublicKey, getTree: (pool: PublicKey) => Promise<TreeState>, checkpointStore?: MerkleCheckpointStore | undefined, getGenerationTree?: ((pool: PublicKey, generation: bigint) => Promise<TreeState>) | undefined);
    private getGenesisIdentity;
    private identity;
    private loadCheckpoint;
    private collectRows;
    private transaction;
    private historicalTree;
    private poolCheckpointBytes;
    private storageKey;
    private read;
    private immutable;
    private putBlob;
    private readBlob;
    private generationIdentity;
    private initial;
    private assertGenerationObject;
    private snapshot;
    private loadGeneration;
    private sealedGeneration;
    private recoverVolatileGeneration;
    private publish;
    private manifest;
    private compareSummary;
    private activeState;
    private nullifier;
    private flushNullifiers;
    private syncPool;
    private load;
    getShieldEvents(pool: PublicKey): Promise<ShieldAppendEvent[]>;
    getSpentNullifiers(pool: PublicKey): Promise<Uint8Array[]>;
    getWitness(pool: PublicKey, commitment: Uint8Array, generation?: bigint): Promise<MerkleWitness>;
}
