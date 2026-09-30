import { PublicKey, type Connection } from "@solana/web3.js";
import type { MerkleWitness, MerkleWitnessProvider, TreeState } from "./types.js";
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
export declare class RpcMerkleWitnessProvider implements MerkleWitnessProvider {
    private readonly connection;
    private readonly programId;
    private readonly getTree;
    private readonly appends;
    private readonly spentNullifiers;
    private readonly loadedNext;
    constructor(connection: Connection, programId: PublicKey, getTree: (pool: PublicKey) => Promise<TreeState>);
    getShieldEvents(pool: PublicKey): Promise<ShieldAppendEvent[]>;
    private load;
    getSpentNullifiers(pool: PublicKey): Promise<Uint8Array[]>;
    private storeAppend;
    getWitness(pool: PublicKey, commitment: Uint8Array): Promise<MerkleWitness>;
}
