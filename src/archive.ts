import { createHash } from "node:crypto";
import { PublicKey, type AccountInfo, type Connection } from "@solana/web3.js";
import { accountDiscriminator, PROGRAM_ID } from "./encoding.js";
import { decodeTreeState } from "./accounts.js";
import { hash2 } from "./crypto.js";
import { rootFromTree, verifyPath, TREE_CAPACITY } from "./merkle.js";
import { pda } from "./pda.js";
import type { MerkleWitness, MerkleWitnessProvider } from "./types.js";

export const PAGE_DEPTH = 12, LEAVES_PER_PAGE = 4096, PAGES_PER_GENERATION = 16;
export const PAGE_DIRECTORY_LEN = 1106, LEAF_PAGE_HEADER_LEN = 597, LEAF_PAGE_MAX_LEN = 131669;
const MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const same = (a: Uint8Array, b: Uint8Array) => Buffer.from(a).equals(Buffer.from(b));
const sha = (a: Uint8Array) => createHash("sha256").update(a).digest();
const canonical = (a: Uint8Array) => a.length === 32 && BigInt(`0x${Buffer.from(a).toString("hex")}`) < MODULUS;

export class MerkleArchiveError extends Error {
  constructor(message: string) { super(message); this.name = "MerkleArchiveError"; }
}
function requireArchive(condition: unknown, message: string): asserts condition {
  if (!condition) throw new MerkleArchiveError(message);
}
function owned(info: AccountInfo<Buffer> | null, program: PublicKey, kind: string): Buffer {
  requireArchive(info && !info.executable && info.owner.equals(program), `${kind} is missing or has an invalid owner`);
  requireArchive(info.data.subarray(0, 8).equals(accountDiscriminator(kind)), `${kind} discriminator mismatch`);
  return info.data;
}

export function subtree(leaves: Uint8Array[], depth: number, index?: number): { root: Uint8Array; siblings: Uint8Array[] } {
  const empties = [new Uint8Array(32)];
  for (let h = 0; h < depth; h++) empties.push(Uint8Array.from(hash2(empties[h], empties[h])));
  let nodes: Uint8Array[] = leaves.map(v => Uint8Array.from(v)), position = index ?? 0;
  const siblings: Uint8Array[] = [];
  for (let h = 0; h < depth; h++) {
    if (index !== undefined) siblings.push(nodes[position ^ 1] ?? empties[h]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2) next.push(hash2(nodes[i], nodes[i + 1] ?? empties[h]));
    nodes = next; position >>= 1;
  }
  return { root: nodes[0] ?? empties[depth], siblings };
}

/** Always fetches the whole generation; no history, indexer or checkpoints. */
export class OnChainPagedMerkleWitnessProvider implements MerkleWitnessProvider {
  constructor(private readonly connection: Connection, private readonly programId: PublicKey = PROGRAM_ID) {}

  async getWitness(pool: PublicKey, commitment: Uint8Array, generation = 0n, leafIndex?: bigint): Promise<MerkleWitness> {
    requireArchive(canonical(commitment), "Invalid commitment");
    const treeAddress = pda.tree(pool, generation, this.programId)[0];
    const [directoryAddress, directoryBump] = pda.pageDirectory(pool, generation, this.programId);
    const pageAddresses = Array.from({ length: 16 }, (_, i) => pda.leafPage(pool, generation, i, this.programId));
    // One batched request gives a coherent finalized bank snapshot and hides
    // which page/index the wallet is interested in.
    const accounts = await this.connection.getMultipleAccountsInfo([treeAddress, directoryAddress, ...pageAddresses.map(p => p[0])], "finalized");
    requireArchive(accounts.length === 18, "Incomplete generation account response");
    const tree = decodeTreeState(owned(accounts[0], this.programId, "TreeState").subarray(8));
    requireArchive(tree.pool.equals(pool) && tree.generation === generation && tree.nextIndex <= TREE_CAPACITY && tree.sequence === tree.nextIndex, "TreeState binding/counters mismatch");
    const slot = Number(tree.sequence % 32n), root = rootFromTree(tree);
    requireArchive(tree.rootSequences[slot] === tree.sequence && tree.rootGenerations[slot] === generation && same(root, tree.roots[slot]), "TreeState root history mismatch");
    const directory = owned(accounts[1], this.programId, "PageDirectory");
    requireArchive(directory.length === PAGE_DIRECTORY_LEN && new PublicKey(directory.subarray(8, 40)).equals(pool) && new PublicKey(directory.subarray(40, 72)).equals(treeAddress) && directory.readBigUInt64LE(72) === generation && directory[1104] === directoryBump && directory[1105] === 1, "PageDirectory binding/version/length mismatch");
    const roots = Array.from({ length: 16 }, (_, i) => directory.subarray(80 + i * 32, 112 + i * 32));
    requireArchive(roots.every(canonical) && same(subtree(roots, 4).root, root), "Directory is not bound to the generation root");
    const pages: Uint8Array[][] = [], emptyPageRoot = subtree([], 12).root;
    for (let page = 0; page < 16; page++) {
      const expectedCount = Number(tree.nextIndex > BigInt(page * 4096) ? (tree.nextIndex - BigInt(page * 4096) > 4096n ? 4096n : tree.nextIndex - BigInt(page * 4096)) : 0n);
      const info = accounts[page + 2], expectedHash = directory.subarray(592 + page * 32, 624 + page * 32);
      if (!info || info.owner.equals(PublicKey.default) && info.data.length === 0) {
        requireArchive(expectedCount === 0 && same(roots[page], emptyPageRoot) && same(expectedHash, sha(new Uint8Array())), "Required populated LeafPage is missing");
        pages.push([]); continue;
      }
      const data = owned(info, this.programId, "LeafPage");
      requireArchive(data.length >= LEAF_PAGE_HEADER_LEN && data.length <= LEAF_PAGE_MAX_LEN && data.length === LEAF_PAGE_HEADER_LEN + expectedCount * 32, "LeafPage length/count mismatch");
      requireArchive(new PublicKey(data.subarray(8, 40)).equals(pool) && new PublicKey(data.subarray(40, 72)).equals(treeAddress) && data.readBigUInt64LE(72) === generation && data[80] === page && data.readUInt16LE(81) === expectedCount && data[83] === pageAddresses[page][1] && data[84] === 1, "LeafPage binding/index/version mismatch");
      requireArchive(same(sha(data.subarray(0,LEAF_PAGE_HEADER_LEN)), expectedHash), "LeafPage content digest mismatch");
      for(let chunk=0;chunk<16;chunk++) {
        const start=LEAF_PAGE_HEADER_LEN+chunk*256*32,end=Math.min(start+256*32,data.length);
        requireArchive(same(sha(start>=data.length?new Uint8Array():data.subarray(start,end)),data.subarray(85+chunk*32,117+chunk*32)), "LeafPage commitment chunk digest mismatch");
      }
      const leaves = Array.from({ length: expectedCount }, (_, i) => data.subarray(LEAF_PAGE_HEADER_LEN + i * 32, LEAF_PAGE_HEADER_LEN + (i+1) * 32));
      requireArchive(leaves.every(canonical) && same(subtree(leaves, 12).root, roots[page]), "LeafPage commitments disagree with directory");
      pages.push(leaves);
    }
    if (leafIndex === undefined) {
      const indices: bigint[] = [];
      for (let page = 0; page < 16; page++) for (let i = 0; i < pages[page].length; i++) if (same(pages[page][i], commitment)) indices.push(BigInt(page * 4096 + i));
      requireArchive(indices.length === 1, indices.length ? "Commitment has ambiguous duplicate indices" : "Commitment is absent from generation archive");
      leafIndex = indices[0];
    }
    requireArchive(leafIndex >= 0n && leafIndex < tree.nextIndex, "Leaf index outside populated archive");
    const page = Number(leafIndex >> 12n), offset = Number(leafIndex & 4095n);
    requireArchive(same(pages[page][offset], commitment), "Stored leaf does not match note commitment");
    const siblings = [...subtree(pages[page], 12, offset).siblings, ...subtree(roots, 4, page).siblings];
    requireArchive(siblings.length === 16 && verifyPath(commitment, leafIndex, siblings, root), "Paged witness fails global depth-16 verification");
    return { index: leafIndex, siblings, root, rootSequence: tree.sequence, generation };
  }
}
