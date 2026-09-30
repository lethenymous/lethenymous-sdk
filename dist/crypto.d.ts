import { PublicKey } from "@solana/web3.js";
export declare const NOTE_PLAINTEXT_LENGTH = 145;
export declare const NOTE_PAYLOAD_LENGTH: number;
export declare function hash2(a: Uint8Array, b: Uint8Array): Uint8Array;
export declare function keyHierarchy(seed: Uint8Array): {
    spendSecret: Uint8Array<ArrayBufferLike>;
    viewKey: Uint8Array<ArrayBufferLike>;
    storageKey: Uint8Array<ArrayBufferLike>;
};
export declare function noteStoreKey(seed: Uint8Array): Uint8Array;
export declare function ownerCommitment(spend: Uint8Array): Uint8Array;
export declare function noteCommitment(pool: PublicKey, asset: PublicKey, amount: bigint, owner: Uint8Array, randomness: Uint8Array): Uint8Array;
export declare function nullifier(pool: PublicKey, asset: PublicKey, spend: Uint8Array, randomness: Uint8Array): Uint8Array;
export declare function encodeNote(pool: PublicKey, asset: PublicKey, amount: bigint, owner: Uint8Array, randomness: Uint8Array): Buffer;
export interface DecryptedNote {
    pool: PublicKey;
    asset: PublicKey;
    amount: bigint;
    ownerCommitment: Uint8Array;
    randomness: Uint8Array;
}
export declare function encryptNote(note: Buffer, viewKey: Uint8Array, pool: PublicKey, asset: PublicKey, commitment: Uint8Array): Buffer;
export declare function decryptNotePayload(payload: Uint8Array, viewKey: Uint8Array, pool: PublicKey, asset: PublicKey, commitment: Uint8Array): DecryptedNote;
export declare function cryptoRandom(length: number): Uint8Array;
