import type { TreeState } from "./types.js";
export declare const TREE_DEPTH = 16, ROOT_HISTORY = 32, TREE_CAPACITY: bigint;
export declare function rootFromTree(tree: TreeState): Uint8Array;
export declare function verifyPath(leaf: Uint8Array, index: bigint, siblings: Uint8Array[], root: Uint8Array): boolean;
