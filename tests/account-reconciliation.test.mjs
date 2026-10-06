import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicKey } from "@solana/web3.js";
import { EncryptedFileNoteStore, ShieldedWallet, accountDiscriminator, keyHierarchy, ownerCommitment, noteCommitment, nullifier, pda } from "../dist/index.js";
import { pageFixture } from "./paged-fixtures.mjs";
import { pool, programId, bytesFor } from "./witness-fixtures.mjs";
const hex=b=>Buffer.from(b).toString("hex"),seed=new Uint8Array(32).fill(44),owner=ownerCommitment(keyHierarchy(seed).spendSecret);
const assetA=new PublicKey(new Uint8Array(32).fill(71)),assetB=new PublicKey(new Uint8Array(32).fill(72));
const note=(amount,asset,random,generation)=>{const randomness=new Uint8Array(32).fill(random);return{pool,asset,amount,generation,ownerCommitment:owner,randomness,commitment:noteCommitment(pool,asset,amount,owner,randomness)};};

for (const scenario of ["shield","one-output","same-page","cross-page","duplicate","missing","wrong-generation","noncontiguous","missing-spend"]) {
  test(`account-only encrypted restart recovery: ${scenario}`,async()=>{
    const directory=await mkdtemp(join(tmpdir(),"pending-accounts-"));
    try {
      const path=join(directory,"notes"),store=EncryptedFileNoteStore.fromSeed(path,seed,owner),id=new Uint8Array(32).fill(50);
      const shield=scenario==="shield",one=scenario==="one-output",input=note(6000n,assetA,51,0n),output=note(2000n,assetB,52,4n),change=note(4000n,assetA,53,4n);
      const outputs=shield?[note(6000n,assetA,54,4n)]:one?[output]:[change,output];
      const nf=nullifier(pool,assetA,keyHierarchy(seed).spendSecret,input.randomness);
      const metadata=shield?{asset:assetA.toBase58(),amount:"6000",commitment:hex(outputs[0].commitment),outputGeneration:"4"}:{assetIn:assetA.toBase58(),assetOut:assetB.toBase58(),amountIn:one?"6000":"2000",amountOut:"2000",nullifier:hex(nf),changeCommitment:hex(one?new Uint8Array(32):change.commitment),outputCommitment:hex(output.commitment),outputGeneration:"4"};
      const operation={id,kind:shield?"shield":"private_swap",state:"intent",pool,metadata,outputNotes:outputs,inputCommitment:shield?undefined:input.commitment};
      if(shield)await store.beginOperation(operation);else{await store.saveNote(input);await store.reserveNoteAndBegin(input.commitment,id,owner,operation);await store.markSubmitted(input.commitment,id,"retained-signature");}
      await store.markOperationSubmitted(id,"retained-signature");
      // The chain state below represents completed settlement; the local final
      // event/index write is deliberately dropped, leaving only authenticated
      // preimages and expected generation in the encrypted submitted record.
      const start=scenario==="cross-page"?4095:2;
      const leaves=Array.from({length:start},()=>bytesFor(1));leaves.push(...outputs.map(n=>n.commitment));
      if(scenario==="duplicate")leaves.push(outputs[0].commitment);
      if(scenario==="missing")leaves.pop();
      if(scenario==="noncontiguous")leaves.splice(start+1,0,bytesFor(2));
      const fixture=pageFixture(leaves.length,scenario==="wrong-generation"?5n:4n,false,leaves);
      const spent={owner:programId,executable:false,data:Buffer.concat([accountDiscriminator("SpentNullifier"),pool.toBuffer(),Buffer.from(nf),Buffer.from([1])]),lamports:1};
      let historicalCalls=0;
      const forbidden=()=>{historicalCalls++;throw new Error("history disabled");};
      const connection={getTransaction:forbidden,getSignaturesForAddress:forbidden,getMultipleAccountsInfo:async(keys,finality)=>{
        if(keys.length===1){assert(keys[0].equals(pda.spent(pool,nf,programId)[0]));return[scenario==="missing-spend"?null:spent];}
        if(scenario==="wrong-generation")return Array(18).fill(null);
        return fixture.connection.getMultipleAccountsInfo(keys,finality);
      }};
      const sdk={programId,connection,reconcileTransaction:forbidden,hasFinalizedProgramEvent:forbidden,getFinalizedShieldedEvents:forbidden};
      const reopen=()=>new ShieldedWallet(sdk,seed,undefined,undefined,EncryptedFileNoteStore.fromSeed(path,seed,owner));
      const wallet=reopen(),pending=await wallet.reconcilePending();
      const failure=["duplicate","missing","wrong-generation","noncontiguous","missing-spend"].includes(scenario);
      if(failure){assert.equal(pending.length,1);assert.equal((await wallet.getNotes()).length,shield?0:1);}
      else {
        assert.equal(pending.length,0);assert.equal(historicalCalls,0);
        const restored=await reopen().getNotes(),published=restored.filter(n=>!n.spent);
        assert.equal(published.length,outputs.length);
        for(let i=0;i<outputs.length;i++){const n=published.find(n=>hex(n.commitment)===hex(outputs[i].commitment));assert.equal(n.generation,4n);assert.equal(n.leafIndex,BigInt(start+i));}
        assert.equal((await reopen().reconcilePending()).length,0);assert.equal((await reopen().getNotes()).length,restored.length);
      }
    }finally{await rm(directory,{recursive:true,force:true});}
  });
}
