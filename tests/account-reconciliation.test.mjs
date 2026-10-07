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

const scenarios=["shield","shield-spent","shield-malformed","one-output","one-output-spent","same-page","same-page-change-spent","same-page-output-spent","same-page-both-spent","cross-page","cross-page-change-spent","cross-page-output-spent","cross-page-both-spent","duplicate","missing","wrong-generation","noncontiguous","missing-spend","wrong-owner","wrong-pool","wrong-nullifier","wrong-discriminator","wrong-version","wrong-size","executable","prefunded-system","fetch-failure","incomplete-response","undefined-response","malformed-second","spent-after-membership","partial-publication","spent-publication-retry","event-fallback-spent","event-fallback-malformed"];
for (const scenario of scenarios) {
  test(`account-only encrypted restart recovery: ${scenario}`,async()=>{
    const directory=await mkdtemp(join(tmpdir(),"pending-accounts-"));
    try {
      const path=join(directory,"notes"),store=EncryptedFileNoteStore.fromSeed(path,seed,owner),id=new Uint8Array(32).fill(50);
      const shield=scenario.startsWith("shield"),one=scenario.startsWith("one-output")||scenario.startsWith("event-fallback"),input=note(6000n,assetA,51,0n),output=note(2000n,assetB,52,4n),change=note(4000n,assetA,53,4n);
      const outputs=shield?[note(6000n,assetA,54,4n)]:one?[output]:[change,output];
      const nf=nullifier(pool,assetA,keyHierarchy(seed).spendSecret,input.randomness);
      const metadata=shield?{asset:assetA.toBase58(),amount:"6000",commitment:hex(outputs[0].commitment),outputGeneration:"4"}:{assetIn:assetA.toBase58(),assetOut:assetB.toBase58(),amountIn:one?"6000":"2000",amountOut:"2000",nullifier:hex(nf),changeCommitment:hex(one?new Uint8Array(32):change.commitment),outputCommitment:hex(output.commitment),outputGeneration:"4"};
      const operation={id,kind:shield?"shield":"private_swap",state:"intent",pool,metadata,outputNotes:outputs,inputCommitment:shield?undefined:input.commitment};
      if(shield)await store.beginOperation(operation);else{await store.saveNote(input);await store.reserveNoteAndBegin(input.commitment,id,owner,operation);await store.markSubmitted(input.commitment,id,"retained-signature");}
      await store.markOperationSubmitted(id,"retained-signature");
      // The chain state below represents completed settlement; the local final
      // event/index write is deliberately dropped, leaving only authenticated
      // preimages and expected generation in the encrypted submitted record.
      const start=scenario.startsWith("cross-page")?4095:2;
      const leaves=Array.from({length:start},()=>bytesFor(1));leaves.push(...outputs.map(n=>n.commitment));
      if(scenario==="duplicate")leaves.push(outputs[0].commitment);
      if(scenario==="missing")leaves.pop();
      if(scenario==="noncontiguous")leaves.splice(start+1,0,bytesFor(2));
      const fixture=pageFixture(leaves.length,scenario==="wrong-generation"?5n:4n,false,leaves);
      const spent={owner:programId,executable:false,data:Buffer.concat([accountDiscriminator("SpentNullifier"),pool.toBuffer(),Buffer.from(nf),Buffer.from([1])]),lamports:1};
      const outputNfs=outputs.map(n=>nullifier(pool,n.asset,keyHierarchy(seed).spendSecret,n.randomness));
      const outputAddresses=outputNfs.map(nf=>pda.spent(pool,nf,programId)[0]);
      const consumed=new Set();
      if(scenario==="shield-spent"||scenario==="one-output-spent"||scenario.endsWith("change-spent")||["partial-publication","spent-publication-retry","event-fallback-spent"].includes(scenario))consumed.add(0);
      if(scenario.endsWith("output-spent"))consumed.add(1);
      if(scenario.endsWith("both-spent")||scenario==="malformed-second")consumed.add(0).add(1);
      const malformed=["shield-malformed","wrong-owner","wrong-pool","wrong-nullifier","wrong-discriminator","wrong-version","wrong-size","executable","prefunded-system","malformed-second","event-fallback-malformed"].includes(scenario);
      let outputReads=0,membershipReads=0,proofCalls=0;
      let historicalCalls=0;
      const forbidden=()=>{historicalCalls++;throw new Error("history disabled");};
      const connection={getTransaction:forbidden,getSignaturesForAddress:forbidden,getMultipleAccountsInfo:async(keys,finality)=>{
        assert.equal(finality,"finalized");
        if(keys.length===1&&keys[0].equals(pda.spent(pool,nf,programId)[0]))return[scenario==="missing-spend"?null:spent];
        if(keys.length===18){
          membershipReads++;
          if(scenario.startsWith("event-fallback"))throw new Error("archive transport temporarily unavailable");
          if(scenario==="wrong-generation")return Array(18).fill(null);
          const accounts=await fixture.connection.getMultipleAccountsInfo(keys,finality);
          if(scenario==="spent-after-membership"&&membershipReads===outputs.length)consumed.add(0);
          return accounts;
        }
        assert.deepEqual(keys.map(k=>k.toBase58()),outputAddresses.map(k=>k.toBase58()));outputReads++;
        if(scenario==="fetch-failure"&&outputReads===1)throw new Error("spent-state RPC unavailable");
        if(scenario==="incomplete-response")return[];
        if(scenario==="undefined-response")return Array(outputs.length);
        return outputNfs.map((nf,i)=>{
          if(!consumed.has(i)&&!(malformed&&i===0))return null;
          const account={...spent,data:Buffer.concat([accountDiscriminator("SpentNullifier"),pool.toBuffer(),Buffer.from(nf),Buffer.from([1])])};
          if(i===1&&scenario==="malformed-second")account.data[40]^=1;
          if(i===0){
            if(["wrong-owner","event-fallback-malformed"].includes(scenario))account.owner=PublicKey.default;
            if(scenario==="wrong-pool")account.data[8]^=1;
            if(scenario==="wrong-nullifier")account.data[40]^=1;
            if(["wrong-discriminator","shield-malformed"].includes(scenario))account.data[0]^=1;
            if(scenario==="wrong-version")account.data[72]=2;
            if(scenario==="wrong-size")account.data=account.data.subarray(0,72);
            if(scenario==="executable")account.executable=true;
            if(scenario==="prefunded-system"){account.owner=PublicKey.default;account.data=Buffer.alloc(0);}
          }
          return account;
        });
      }};
      const sdk={programId,connection,assertPrivateTransactionReady(){},reconcileTransaction:forbidden,hasFinalizedProgramEvent:forbidden,getFinalizedShieldedEvents:forbidden};
      if(scenario.startsWith("event-fallback")){
        sdk.reconcileTransaction=async()=>{historicalCalls++;return{status:"finalized-success",signature:"retained-signature"};};sdk.hasFinalizedProgramEvent=async()=>true;
        sdk.getFinalizedShieldedEvents=async()=>[{kind:"swap",pool,nullifier:nf,outputCommitment:output.commitment,changeCommitment:new Uint8Array(32),amountOut:output.amount,outputGeneration:4n,outputIndex:BigInt(start)}];
      }
      const prover={proveUnshield:async()=>{proofCalls++;throw new Error("must not prove a spent note");}},witness={getWitness:async()=>{throw new Error("must not request spent-note witness");}};
      const reopen=()=>new ShieldedWallet(sdk,seed,prover,witness,EncryptedFileNoteStore.fromSeed(path,seed,owner));
      if(scenario==="partial-publication")await store.saveNote({...outputs[0],leafIndex:BigInt(start),state:"available"});
      let wallet=reopen();
      if(scenario==="spent-publication-retry"){
        const retryStore=EncryptedFileNoteStore.fromSeed(path,seed,owner);retryStore.markOperationFinalized=async()=>{throw new Error("crash after publishing spent output");};
        wallet=new ShieldedWallet(sdk,seed,prover,witness,retryStore);
        assert.equal((await wallet.reconcilePending()).length,1);assert((await wallet.getNotes()).find(n=>hex(n.commitment)===hex(outputs[0].commitment)).spent);
        // Even a stale absent RPC response after this crash cannot unspend the
        // journal's already persisted consumed state.
        consumed.clear();wallet=reopen();
      }
      let pending=await wallet.reconcilePending();
      const failure=["duplicate","missing","wrong-generation","noncontiguous","missing-spend","incomplete-response","undefined-response"].includes(scenario)||malformed;
      if(scenario==="fetch-failure"){
        assert.equal(pending.length,1);assert.equal((await wallet.getNotes()).length,1);assert.equal(historicalCalls,0);
        pending=await reopen().reconcilePending();
      }
      if(failure){assert.equal(pending.length,1);assert.equal((await wallet.getNotes()).length,shield?0:1);}
      else {
        assert.equal(pending.length,0);if(!scenario.startsWith("event-fallback"))assert.equal(historicalCalls,0);
        const restored=await reopen().getNotes(),published=restored.filter(n=>outputs.some(o=>hex(o.commitment)===hex(n.commitment)));
        assert.equal(published.length,outputs.length);
        for(let i=0;i<outputs.length;i++){
          const n=published.find(n=>hex(n.commitment)===hex(outputs[i].commitment)),isSpent=consumed.has(i)||(scenario==="spent-publication-retry"&&i===0);
          assert.equal(n.generation,4n);assert.equal(n.leafIndex,BigInt(start+i));assert.equal(n.spent,isSpent);assert.equal(n.state,isSpent?"spent":"available");
          assert.equal(await reopen().getPrivateBalance({pool,mint:n.asset}),isSpent?0n:n.amount);
          if(isSpent){
            const fresh=EncryptedFileNoteStore.fromSeed(path,seed,owner);await assert.rejects(()=>fresh.reserveNote(n.commitment,new Uint8Array(32).fill(99),owner),/not available/);
            for(let attempt=0;attempt<2;attempt++)await assert.rejects(()=>reopen().unshield({pool,mint:n.asset,amount:n.amount,recipient:PublicKey.default}),/Insufficient private balance/);
          }
        }
        assert.equal(proofCalls,0);
        assert.equal((await reopen().reconcilePending()).length,0);assert.equal((await reopen().getNotes()).length,restored.length);
      }
    }finally{await rm(directory,{recursive:true,force:true});}
  });
}
