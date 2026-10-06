import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { PublicKey } from "@solana/web3.js";
import { accountDiscriminator, OnChainPagedMerkleWitnessProvider, MerkleArchiveError, pda, subtree, rootFromTree, verifyPath, LEAF_PAGE_HEADER_LEN, LEAF_PAGE_MAX_LEN } from "../dist/index.js";
import { programId, pool, bytesFor, emptyTree, append } from "./witness-fixtures.mjs";

const sha=b=>createHash("sha256").update(b).digest();
const u64=v=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(v);return b;};
function encodeTree(t){return Buffer.concat([accountDiscriminator("TreeState"),t.pool.toBuffer(),u64(t.generation),u64(t.nextIndex),u64(t.sequence),...t.frontier,Buffer.from(t.frontierPresent),...t.emptySubtrees,...t.roots,...t.rootSequences.map(u64),...t.rootGenerations.map(u64)]);}
export function pageFixture(count=3,generation=0n,duplicate=false){
  const tree=emptyTree(generation),leaves=[];let rng=84932n;
  for(let i=0;i<count;i++){rng=(rng*6364136223846793005n+1n)&0xffffffffffffffffn;const b=Buffer.alloc(32);b.writeBigUInt64BE(rng,24);leaves.push(duplicate?bytesFor(91):b);append(tree,leaves.at(-1));}
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
  const directory=Buffer.concat([accountDiscriminator("PageDirectory"),pool.toBuffer(),treeAddress.toBuffer(),u64(generation),...roots,...hashes,Buffer.from([dirBump,1])]);assert.equal(directory.length,1106);
  const accounts=[{owner:programId,executable:false,data:encodeTree(tree),lamports:999999},{owner:programId,executable:false,data:directory,lamports:999999},...pages];
  const expected=[treeAddress,dirAddress,...Array.from({length:16},(_,i)=>pda.leafPage(pool,generation,i,programId)[0])];
  const requests=[];
  const forbidden=()=>{throw new Error("history/indexer/checkpoint request forbidden");};
  const connection={getSignaturesForAddress:forbidden,getTransaction:forbidden,getMultipleAccountsInfo:async(keys,finality)=>{assert.equal(finality,"finalized");assert.deepEqual(keys.map(k=>k.toBase58()),expected.map(k=>k.toBase58()));requests.push(keys);return accounts;}};
  const provider=new OnChainPagedMerkleWitnessProvider(connection,programId);
  return{tree,leaves,accounts,expected,requests,provider,generation};
}

test("normal paged witnesses use only one full-generation canonical account batch",async()=>{
  const f=pageFixture(17,7n);for(const i of [0,8,16]){const w=await f.provider.getWitness(pool,f.leaves[i],7n,BigInt(i));assert.equal(w.siblings.length,16);assert.equal(w.index,BigInt(i));assert(verifyPath(f.leaves[i],w.index,w.siblings,w.root));assert.deepEqual(Buffer.from(w.root),Buffer.from(rootFromTree(f.tree)));}
  assert(f.requests.every(keys=>keys.length===18));
});
test("missing index recovers by account scan and duplicate commitments fail closed",async()=>{
  const f=pageFixture(5,0n);assert.equal((await f.provider.getWitness(pool,f.leaves[3],0n)).index,3n);
  await assert.rejects(()=>f.provider.getWitness(pool,bytesFor(99),0n),/absent/);
  const d=pageFixture(2,0n,true);await assert.rejects(()=>d.provider.getWitness(pool,d.leaves[0],0n),/ambiguous/);
  assert.equal((await d.provider.getWitness(pool,d.leaves[0],0n,1n)).index,1n);
});
test("page boundaries remain one global depth16 generation membership set",async()=>{
  const f=pageFixture(8193,2n);for(const i of [0,1,4094,4095,4096,4097,8191,8192]){const w=await f.provider.getWitness(pool,f.leaves[i],2n,BigInt(i));assert.equal(w.index,BigInt(i));assert.equal(w.siblings.length,16);assert(verifyPath(f.leaves[i],w.index,w.siblings,w.root));}
  assert.equal(f.accounts[2].data.length,LEAF_PAGE_MAX_LEN);assert.equal(f.accounts[4].data.length,LEAF_PAGE_HEADER_LEN+32);
});
test("all directory/page binding, ownership, size, count and byte corruptions are rejected",async()=>{
  const changes=[
    f=>{f.accounts[1].owner=PublicKey.default;},
    f=>{f.accounts[1].data[0]^=1;},
    f=>{f.accounts[1].data[8]^=1;},
    f=>{f.accounts[1].data[40]^=1;},
    f=>{f.accounts[1].data[72]^=1;},
    f=>{f.accounts[1].data[80]^=1;},
    f=>{f.accounts[1].data[1105]=2;},
    f=>{f.accounts[2].owner=PublicKey.default;},
    f=>{f.accounts[2].data[0]^=1;},
    f=>{f.accounts[2].data[8]^=1;},
    f=>{f.accounts[2].data[40]^=1;},
    f=>{f.accounts[2].data[72]^=1;},
    f=>{f.accounts[2].data[80]=1;},
    f=>{f.accounts[2].data.writeUInt16LE(4097,81);},
    f=>{f.accounts[2].data.writeUInt16LE(1,81);},
    f=>{f.accounts[2].data[84]=2;},
    f=>{f.accounts[2].data=f.accounts[2].data.subarray(0,f.accounts[2].data.length-1);},
    f=>{f.accounts[2].data[597]^=1;},
    f=>{f.accounts[2]=null;},
  ];
  for(const alter of changes){const f=pageFixture(3,1n);alter(f);await assert.rejects(()=>f.provider.getWitness(pool,f.leaves[0],1n,0n),e=>e instanceof MerkleArchiveError||/TreeState/.test(e.message));}
});
test("populated missing pages are never silently interpreted as empty",async()=>{
  const f=pageFixture(4097,0n);f.accounts[3]=null;
  await assert.rejects(()=>f.provider.getWitness(pool,f.leaves[0],0n,0n),/populated LeafPage is missing/);
});
test("missing archive for legacy populated TreeState is an explicit migration failure",async()=>{
  const f=pageFixture(1,0n);f.accounts[1]=null;
  await assert.rejects(()=>f.provider.getWitness(pool,f.leaves[0],0n),/PageDirectory is missing/);
});
