// Actual SBF settlement accounts supplied over private stdin by ProgramTest.
// Drop final publication, reopen the encrypted journal twice, forbid history.
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { PublicKey } from "@solana/web3.js";
import { EncryptedFileNoteStore, ShieldedWallet, keyHierarchy, ownerCommitment } from "../dist/index.js";
let input="";for await(const chunk of process.stdin)input+=chunk;const f=JSON.parse(input);
const b=h=>Uint8Array.from(Buffer.from(h,"hex")),hex=b=>Buffer.from(b).toString("hex"),seed=b(f.seed),owner=ownerCommitment(keyHierarchy(seed).spendSecret),programId=new PublicKey(f.programId),pool=new PublicKey(f.pool);
const decode=n=>({pool,asset:new PublicKey(n.asset),amount:BigInt(n.amount),generation:BigInt(n.generation),randomness:b(n.randomness),commitment:b(n.commitment),ownerCommitment:owner});
const outputs=f.outputs.map(decode),spentInput=f.input?decode(f.input):undefined;
const signature=f.signature??"retained-local-signature";
const directory=f.journalDirectory??await mkdtemp(join(tmpdir(),"sbf-pending-offline-"));
try {
  const path=join(directory,"journal"),store=EncryptedFileNoteStore.fromSeed(path,seed,owner),id=new Uint8Array(32).fill(88);
  if(!f.journalDirectory){
  const metadata=f.kind==="shield"?{asset:outputs[0].asset.toBase58(),amount:outputs[0].amount.toString(),commitment:hex(outputs[0].commitment),outputGeneration:outputs[0].generation.toString()}:{assetIn:spentInput.asset.toBase58(),assetOut:outputs.at(-1).asset.toBase58(),amountIn:(spentInput.amount-(outputs.length===2?outputs[0].amount:0n)).toString(),amountOut:outputs.at(-1).amount.toString(),changeCommitment:outputs.length===2?hex(outputs[0].commitment):hex(new Uint8Array(32)),outputCommitment:hex(outputs.at(-1).commitment),nullifier:f.nullifier,outputGeneration:outputs[0].generation.toString()};
  const operation={id,kind:f.kind,pool,state:"intent",inputCommitment:spentInput?.commitment,outputNotes:outputs,metadata};
  if(spentInput){await store.saveNote(spentInput);await store.reserveNoteAndBegin(spentInput.commitment,id,owner,operation);await store.markSubmitted(spentInput.commitment,id,signature);}else await store.beginOperation(operation);
  await store.markOperationSubmitted(id,signature);
  }
  if(f.prepareOnly){process.stdout.write(JSON.stringify({journalDirectory:directory}));}
  else {
  const accounts=new Map(f.accounts.map(a=>[a.address,a]));let historyCalls=0;
  const forbidden=()=>{historyCalls++;throw new Error("Historical transaction/event API forbidden");};
  const connection={getTransaction:forbidden,getSignaturesForAddress:forbidden,getMultipleAccountsInfo:async(addresses,commitment)=>{assert.equal(commitment,"finalized");assert([1,2,18].includes(addresses.length));return addresses.map(k=>{const a=accounts.get(k.toBase58());return a?{owner:new PublicKey(a.owner),data:Buffer.from(a.data,"hex"),lamports:a.lamports,executable:a.executable}:null;});}};
  let proofCalls=0;
  const sdk={programId,connection,assertPrivateTransactionReady(){},reconcileTransaction:forbidden,getFinalizedShieldedEvents:forbidden,hasFinalizedProgramEvent:forbidden};
  const prover={proveUnshield:async()=>{proofCalls++;throw new Error("spent note reached prover");}},witness={getWitness:async()=>{throw new Error("spent note reached witness provider");}};
  const reopen=()=>new ShieldedWallet(sdk,seed,prover,witness,EncryptedFileNoteStore.fromSeed(path,seed,owner));
  assert.equal((await reopen().reconcilePending()).length,0);assert.equal(historyCalls,0);
  const notes=await reopen().getNotes();
  for(let i=0;i<outputs.length;i++){const n=notes.find(n=>hex(n.commitment)===hex(outputs[i].commitment)),spent=(f.consumedIndices??[]).includes(i);assert.equal(n.generation,outputs[i].generation);assert.equal(n.leafIndex,BigInt(f.indices[i]));assert.equal(n.spent,spent);assert.equal(n.state,spent?"spent":"available");assert.equal(await reopen().getPrivateBalance({pool,mint:n.asset}),spent?0n:n.amount);if(spent){await assert.rejects(()=>EncryptedFileNoteStore.fromSeed(path,seed,owner).reserveNote(n.commitment,new Uint8Array(32).fill(99),owner),/not available/);for(let attempt=0;attempt<2;attempt++)await assert.rejects(()=>reopen().unshield({pool,mint:n.asset,amount:n.amount,recipient:PublicKey.default}),/Insufficient private balance/);}}
  assert.equal(proofCalls,0);
  assert.equal((await reopen().reconcilePending()).length,0);assert.equal((await reopen().getNotes()).length,notes.length);
  process.stdout.write(JSON.stringify({kind:f.kind,recoveredIndices:f.indices,recoveredStates:outputs.map(o=>notes.find(n=>hex(n.commitment)===hex(o.commitment)).state),historyCalls,proofCalls,restartIdempotent:true}));
  }
} finally {if(!f.prepareOnly)await rm(directory,{recursive:true,force:true});}
