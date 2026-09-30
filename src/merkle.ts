import { hash2 } from "./crypto.js"; import type { TreeState } from "./types.js";
export const TREE_DEPTH=16, ROOT_HISTORY=32, TREE_CAPACITY=1n<<16n;
export function rootFromTree(tree:TreeState):Uint8Array { if(tree.nextIndex===TREE_CAPACITY){if(tree.frontierPresent[15]!==1)throw new Error("Invalid terminal tree");return tree.frontier[15];} let node=tree.emptySubtrees[0]; for(let i=0;i<TREE_DEPTH;i++) node=((tree.nextIndex>>BigInt(i))&1n)===1n?hash2(tree.frontier[i],node):hash2(node,tree.emptySubtrees[i]); return node; }
export function verifyPath(leaf:Uint8Array,index:bigint,siblings:Uint8Array[],root:Uint8Array):boolean { let n=leaf; for(let i=0;i<TREE_DEPTH;i++) n=((index>>BigInt(i))&1n)===0n?hash2(n,siblings[i]):hash2(siblings[i],n); return Buffer.from(n).equals(Buffer.from(root)); }
