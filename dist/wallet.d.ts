import { PublicKey } from "@solana/web3.js";
import type { JournaledNoteStore, MerkleWitnessProvider, Note, NoteStore, OperationRecord, Prover, ShieldParams } from "./types.js";
import { type Lethenymous } from "./client.js";
export declare class InMemoryNoteStore implements JournaledNoteStore {
    private readonly notes;
    private readonly operations;
    getNotes(ownerCommitment?: Uint8Array): Promise<Note[]>;
    saveNote(input: Note): Promise<void>;
    reserveNote(commitment: Uint8Array, operationId: Uint8Array, owner: Uint8Array): Promise<Note>;
    reserveNoteAndBegin(commitment: Uint8Array, operationId: Uint8Array, owner: Uint8Array, operation: OperationRecord): Promise<Note>;
    markSubmitted(commitment: Uint8Array, operationId: Uint8Array, signature: string): Promise<void>;
    markSpent(commitment: Uint8Array, operationId?: Uint8Array): Promise<void>;
    releaseReservation(commitment: Uint8Array, operationId?: Uint8Array): Promise<void>;
    beginOperation(operation: OperationRecord): Promise<void>;
    updateOperation(id: Uint8Array, patch: Partial<Pick<OperationRecord, "metadata" | "outputNotes">>): Promise<void>;
    markPrepared(id: Uint8Array, signedTransaction: Uint8Array, lastValidBlockHeight: bigint): Promise<void>;
    markOperationSubmitted(id: Uint8Array, signature: string): Promise<void>;
    markOperationFinalized(id: Uint8Array): Promise<void>;
    markOperationFailed(id: Uint8Array, reason: string): Promise<void>;
    markOperationUnknown(id: Uint8Array, reason: string): Promise<void>;
    getPendingOperations(): Promise<OperationRecord[]>;
}
export declare class ShieldedWallet {
    private readonly sdk;
    private readonly prover;
    private readonly witnessProvider;
    readonly spendSecret: Uint8Array;
    readonly viewKey: Uint8Array;
    readonly ownerCommitment: Uint8Array;
    private readonly store;
    constructor(sdk: Lethenymous, seed: Uint8Array, prover: Prover | undefined, witnessProvider: MerkleWitnessProvider | undefined, store: NoteStore);
    private journal;
    addNote(note: Note): Promise<void>;
    getNotes(): Promise<Note[]>;
    getPrivateBalance(input: {
        pool: PublicKey;
        mint: PublicKey;
    }): Promise<bigint>;
    private requireBackend;
    private select;
    private begin;
    private reserveAndBegin;
    private fail;
    private unknown;
    private submitted;
    private finalized;
    shield(input: ShieldParams): Promise<{
        signature: string;
        note: Note;
    }>;
    unshield(input: {
        pool: PublicKey;
        mint: PublicKey;
        amount: bigint;
        recipient: PublicKey;
    }): Promise<string>;
    privateSend(input: {
        pool: PublicKey;
        mint: PublicKey;
        amount: bigint;
        recipient: PublicKey;
    }): Promise<string>;
    privateSwap(input: {
        pool: PublicKey;
        inputMint: PublicKey;
        outputMint: PublicKey;
        amountIn: bigint;
        minAmountOut: bigint;
    }): Promise<string>;
    private localNote;
    recoverShieldedNotes(pool: PublicKey): Promise<Note[]>;
    reconcilePending(): Promise<OperationRecord[]>;
}
