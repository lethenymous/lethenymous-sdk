import { PublicKey, type Connection } from "@solana/web3.js";
import type { MerkleWitness, MerkleWitnessProvider } from "./types.js";
export declare const PAGE_DEPTH = 12, LEAVES_PER_PAGE = 4096, PAGES_PER_GENERATION = 16;
export declare const PAGE_DIRECTORY_LEN = 1122, LEAF_PAGE_HEADER_LEN = 597, LEAF_PAGE_MAX_LEN = 131669;
export declare class MerkleArchiveError extends Error {
    constructor(message: string);
}
export declare function subtree(leaves: Uint8Array[], depth: number, index?: number): {
    root: Uint8Array;
    siblings: Uint8Array[];
};
/** Always fetches the whole generation; no history, indexer or checkpoints. */
export declare class OnChainPagedMerkleWitnessProvider implements MerkleWitnessProvider {
    private readonly connection;
    private readonly programId;
    constructor(connection: Connection, programId?: PublicKey);
    getWitness(pool: PublicKey, commitment: Uint8Array, generation?: bigint, leafIndex?: bigint): Promise<MerkleWitness>;
}
