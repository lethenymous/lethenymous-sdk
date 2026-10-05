import { PublicKey, type Connection } from "@solana/web3.js";
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
export type MerkleReconstructionErrorCode = "INVALID_CHECKPOINT" | "HISTORY_GAP" | "HISTORY_RPC" | "GENERATION_MISMATCH" | "SEQUENCE_GAP" | "ROOT_MISMATCH" | "TRANSACTION_MISSING" | "FAILED_TRANSACTION" | "DUPLICATE_EVENT" | "INVALID_TREE";
export declare class MerkleReconstructionError extends Error {
    readonly code: MerkleReconstructionErrorCode;
    constructor(code: MerkleReconstructionErrorCode, message: string);
}
export declare class RpcMerkleWitnessProvider implements MerkleWitnessProvider {
    private readonly connection;
    private readonly programId;
    private readonly getTree;
    private readonly checkpointStore?;
    private readonly states;
    private readonly syncing;
    private genesisHash?;
    constructor(connection: Connection, programId: PublicKey, getTree: (pool: PublicKey) => Promise<TreeState>, checkpointStore?: MerkleCheckpointStore | undefined);
    private getGenesisIdentity;
    private identity;
    private loadCheckpoint;
    private collectRows;
    private transaction;
    private syncPool;
    private load;
    getShieldEvents(pool: PublicKey): Promise<ShieldAppendEvent[]>;
    getSpentNullifiers(pool: PublicKey): Promise<Uint8Array[]>;
    getWitness(pool: PublicKey, commitment: Uint8Array): Promise<MerkleWitness>;
}
