import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";
import { MerkleArchiveError, rootFromTree, verifyPath, LEAF_PAGE_HEADER_LEN, LEAF_PAGE_MAX_LEN } from "../dist/index.js";
import { pool, bytesFor } from "./witness-fixtures.mjs";
import { pageFixture } from "./paged-fixtures.mjs";

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
    f=>{f.accounts[1].data[1121]=3;},
    f=>{f.accounts[1].data[1104]^=1;},
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
