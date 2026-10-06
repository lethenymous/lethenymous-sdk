import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { accountDiscriminator, OnChainPagedMerkleWitnessProvider, pda, subtree } from "../dist/index.js";
import { programId, pool, bytesFor, emptyTree, append } from "./witness-fixtures.mjs";
const sha=b=>createHash("sha256").update(b).digest();
const u64=v=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(v);return b;};
function encodeTree(t){return Buffer.concat([accountDiscriminator("TreeState"),t.pool.toBuffer(),u64(t.generation),u64(t.nextIndex),u64(t.sequence),...t.frontier,Buffer.from(t.frontierPresent),...t.emptySubtrees,...t.roots,...t.rootSequences.map(u64),...t.rootGenerations.map(u64)]);}
export function pageFixture(count=3,generation=0n,duplicate=false,customLeaves){
  const tree=emptyTree(generation),leaves=[];let rng=84932n;
  for(let i=0;i<count;i++){rng=(rng*6364136223846793005n+1n)&0xffffffffffffffffn;const b=Buffer.alloc(32);b.writeBigUInt64BE(rng,24);leaves.push(customLeaves?.[i]??(duplicate?bytesFor(91):b));append(tree,leaves.at(-1));}
  const treeAddress=pda.tree(pool,generation,programId)[0],[dirAddress,dirBump]=pda.pageDirectory(pool,generation,programId);
  const pages=[],roots=[],hashes=[];
  for(let page=0;page<16;page++){
    const part=leaves.slice(page*4096,(page+1)*4096);roots.push(subtree(part,12).root);
    if(!part.length){pages.push(null);hashes.push(sha(Buffer.alloc(0)));continue;}
    const [address,bump]=pda.leafPage(pool,generation,page,programId);
    const chunkHashes=Array.from({length:16},(_,chunk)=>sha(Buffer.concat(part.slice(chunk*256,(chunk+1)*256))));
    const header=Buffer.concat([accountDiscriminator("LeafPage"),pool.toBuffer(),treeAddress.toBuffer(),u64(generation),Buffer.from([page]),Buffer.from([part.length&255,part.length>>8]),Buffer.from([bump,1]),...chunkHashes]);
    assert.equal(header.length,597);const data=Buffer.concat([header,...part]);hashes.push(sha(header));
    pages.push({owner:programId,executable:false,data,lamports:999999});
  }
  const directory=Buffer.concat([accountDiscriminator("PageDirectory"),pool.toBuffer(),treeAddress.toBuffer(),u64(generation),...roots,...hashes,Buffer.from(Array.from({length:16},(_,i)=>pda.leafPage(pool,generation,i,programId)[1])),Buffer.from([dirBump,2])]);assert.equal(directory.length,1122);
  const accounts=[{owner:programId,executable:false,data:encodeTree(tree),lamports:999999},{owner:programId,executable:false,data:directory,lamports:999999},...pages];
  const expected=[treeAddress,dirAddress,...Array.from({length:16},(_,i)=>pda.leafPage(pool,generation,i,programId)[0])];
  const requests=[];
  const forbidden=()=>{throw new Error("history/indexer/checkpoint request forbidden");};
  const connection={getSignaturesForAddress:forbidden,getTransaction:forbidden,getMultipleAccountsInfo:async(keys,finality)=>{assert.equal(finality,"finalized");assert.deepEqual(keys.map(k=>k.toBase58()),expected.map(k=>k.toBase58()));requests.push(keys);return accounts;}};
  const provider=new OnChainPagedMerkleWitnessProvider(connection,programId);
  return{tree,leaves,accounts,expected,requests,provider,generation,connection};
}
