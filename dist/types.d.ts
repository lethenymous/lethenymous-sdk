import type { Connection, PublicKey, Signer, Transaction, TransactionInstruction, VersionedTransaction } from "@solana/web3.js";
export type Asset = "A" | "B";
export type Direction = "AToB" | "BToA";
export type Hash32 = Uint8Array;
export interface WalletAdapter {
    publicKey: PublicKey;
    signTransaction<T extends Transaction>(tx: T): Promise<T>;
    signVersionedTransaction?(tx: VersionedTransaction): Promise<VersionedTransaction>;
}
export interface LookupTableConfig {
    address: PublicKey;
    expectedAddresses?: PublicKey[];
    expectedAuthority?: PublicKey | null;
}
export interface ClientConfig {
    connection: Connection;
    wallet: WalletAdapter;
    programId?: PublicKey;
    witnessProvider?: MerkleWitnessProvider;
    lookupTables?: Array<PublicKey | LookupTableConfig>;
}
export interface PoolState {
    address: PublicKey;
    authority: PublicKey;
    tokenAMint: PublicKey;
    tokenBMint: PublicKey;
    tokenAVault: PublicKey;
    tokenBVault: PublicKey;
    protocolFeeVaultA: PublicKey;
    protocolFeeVaultB: PublicKey;
    creatorFeeVaultA: PublicKey;
    creatorFeeVaultB: PublicKey;
    creatorFeeRecipient: PublicKey;
    lpMint: PublicKey;
    feeBps: number;
    bump: number;
    version: number;
    swapNonce: bigint;
}
export interface ShieldedState {
    pool: PublicKey;
    tokenAMint: PublicKey;
    tokenBMint: PublicKey;
    custodyA: PublicKey;
    custodyB: PublicKey;
    tree: PublicKey;
    bump: number;
    version: number;
}
export interface TreeState {
    pool: PublicKey;
    generation: bigint;
    nextIndex: bigint;
    sequence: bigint;
    frontier: Uint8Array[];
    frontierPresent: number[];
    emptySubtrees: Uint8Array[];
    roots: Uint8Array[];
    rootSequences: bigint[];
    rootGenerations: bigint[];
}
export interface ProtocolConfig {
    authority: PublicKey;
    feeRecipient: PublicKey;
    bump: number;
    version: number;
}
export interface BuiltTransaction {
    instructions: TransactionInstruction[];
    signers?: Signer[];
}
export interface MerkleWitness {
    index: bigint;
    siblings: Uint8Array[];
    root: Uint8Array;
    rootSequence: bigint;
    generation: bigint;
}
export interface MerkleWitnessProvider {
    getWitness(pool: PublicKey, commitment: Uint8Array): Promise<MerkleWitness>;
}
/** Implementations must authenticate checkpoint bytes and make replacement writes crash-safe. */
export interface MerkleCheckpointStore {
    loadMerkleCheckpoint(identity: string): Promise<Uint8Array | undefined>;
    saveMerkleCheckpoint(identity: string, checkpoint: Uint8Array): Promise<void>;
}
export type NoteState = "available" | "reserved" | "submitted" | "spent";
export interface Note {
    pool: PublicKey;
    asset: PublicKey;
    amount: bigint;
    ownerCommitment: Uint8Array;
    randomness: Uint8Array;
    commitment: Uint8Array;
    encryptedPayload?: Uint8Array;
    leafIndex?: bigint;
    state?: NoteState;
    operationId?: Uint8Array;
    transactionSignature?: string;
    spent?: boolean;
}
export interface NoteStore {
    getNotes(ownerCommitment?: Uint8Array): Promise<Note[]>;
    saveNote(note: Note): Promise<void>;
    reserveNote(commitment: Uint8Array, operationId: Uint8Array, ownerCommitment: Uint8Array): Promise<Note>;
    markSubmitted(commitment: Uint8Array, operationId: Uint8Array, signature: string): Promise<void>;
    markSpent(commitment: Uint8Array, operationId?: Uint8Array): Promise<void>;
    releaseReservation(commitment: Uint8Array, operationId?: Uint8Array): Promise<void>;
}
export type OperationKind = "shield" | "unshield" | "private_swap";
export type OperationState = "intent" | "prepared" | "submitted" | "finalized" | "failed" | "unknown";
export interface OperationRecord {
    id: Uint8Array;
    kind: OperationKind;
    state: OperationState;
    pool: PublicKey;
    inputCommitment?: Uint8Array;
    signature?: string;
    lastValidBlockHeight?: bigint;
    signedTransaction?: Uint8Array;
    metadata: Record<string, string>;
    outputNotes: Note[];
}
export interface JournaledNoteStore extends NoteStore {
    reserveNoteAndBegin(commitment: Uint8Array, operationId: Uint8Array, ownerCommitment: Uint8Array, operation: OperationRecord): Promise<Note>;
    beginOperation(operation: OperationRecord): Promise<void>;
    updateOperation(id: Uint8Array, patch: Partial<Pick<OperationRecord, "metadata" | "outputNotes">>): Promise<void>;
    markPrepared(id: Uint8Array, signedTransaction: Uint8Array, lastValidBlockHeight: bigint): Promise<void>;
    markOperationSubmitted(id: Uint8Array, signature: string): Promise<void>;
    markOperationFinalized(id: Uint8Array): Promise<void>;
    markOperationFailed(id: Uint8Array, reason: string): Promise<void>;
    markOperationUnknown(id: Uint8Array, reason: string): Promise<void>;
    getPendingOperations(): Promise<OperationRecord[]>;
}
export interface Prover {
    proveUnshield(input: UnshieldProverInput): Promise<{
        proof: Uint8Array;
        publicInputs: Uint8Array;
    }>;
    provePrivateSwap(input: PrivateSwapProverInput): Promise<{
        proof: Uint8Array;
        publicInputs: Uint8Array;
    }>;
}
export interface UnshieldProverInput {
    pool: PublicKey;
    asset: PublicKey;
    root: Uint8Array;
    rootSequence: bigint;
    generation: bigint;
    nullifier: Uint8Array;
    amount: bigint;
    recipient: PublicKey;
    spendSecret: Uint8Array;
    randomness: Uint8Array;
    witness: MerkleWitness;
}
export interface PrivateSwapProverInput {
    pool: PublicKey;
    assetIn: PublicKey;
    assetOut: PublicKey;
    root: Uint8Array;
    rootSequence: bigint;
    generation: bigint;
    nullifier: Uint8Array;
    reserveIn: bigint;
    reserveOut: bigint;
    feeBps: number;
    amountIn: bigint;
    amountOut: bigint;
    changeAmount: bigint;
    changeCommitment: Uint8Array;
    outputCommitment: Uint8Array;
    direction: number;
    swapNonce: bigint;
    inputSpendSecret: Uint8Array;
    inputRandomness: Uint8Array;
    witness: MerkleWitness;
    changeSpendSecret: Uint8Array;
    changeRandomness: Uint8Array;
    outputSpendSecret: Uint8Array;
    outputRandomness: Uint8Array;
}
export interface ShieldParams {
    pool: PublicKey;
    mint: PublicKey;
    amount: bigint;
}
export interface RecipientParams extends ShieldParams {
    recipient: PublicKey;
}
export type TransactionOutcome = {
    status: "finalized-success";
    signature: string;
} | {
    status: "finalized-failed";
    signature: string;
    error: unknown;
} | {
    status: "unknown";
    signature: string;
    reason: string;
};
