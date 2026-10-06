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
const directory=await mkdtemp(join(tmpdir(),"sbf-pending-offline-"));
try {
  const path=join(directory,"journal"),store=EncryptedFileNoteStore.fromSeed(path,seed,owner),id=new Uint8Array(32).fill(88);
  const metadata=f.kind==="shield"?{asset:outputs[0].asset.toBase58(),amount:outputs[0].amount.toString(),commitment:hex(outputs[0].commitment),outputGeneration:outputs[0].generation.toString()}:{assetIn:spentInput.asset.toBase58(),assetOut:outputs.at(-1).asset.toBase58(),amountIn:(spentInput.amount-(outputs.length===2?outputs[0].amount:0n)).toString(),amountOut:outputs.at(-1).amount.toString(),changeCommitment:outputs.length===2?hex(outputs[0].commitment):hex(new Uint8Array(32)),outputCommitment:hex(outputs.at(-1).commitment),nullifier:f.nullifier,outputGeneration:outputs[0].generation.toString()};
  const operation={id,kind:f.kind,pool,state:"intent",inputCommitment:spentInput?.commitment,outputNotes:outputs,metadata};
  if(spentInput){await store.saveNote(spentInput);await store.reserveNoteAndBegin(spentInput.commitment,id,owner,operation);await store.markSubmitted(spentInput.commitment,id,"retained-local-signature");}else await store.beginOperation(operation);
  await store.markOperationSubmitted(id,"retained-local-signature");
  const accounts=new Map(f.accounts.map(a=>[a.address,a]));let historyCalls=0;
  const forbidden=()=>{historyCalls++;throw new Error("Historical transaction/event API forbidden");};
  const connection={getTransaction:forbidden,getSignaturesForAddress:forbidden,getMultipleAccountsInfo:async(addresses,commitment)=>{assert.equal(commitment,"finalized");assert([1,18].includes(addresses.length));return addresses.map(k=>{const a=accounts.get(k.toBase58());return a?{owner:new PublicKey(a.owner),data:Buffer.from(a.data,"hex"),lamports:a.lamports,executable:a.executable}:null;});}};
  const sdk={programId,connection,reconcileTransaction:forbidden,getFinalizedShieldedEvents:forbidden,hasFinalizedProgramEvent:forbidden};
  const reopen=()=>new ShieldedWallet(sdk,seed,undefined,undefined,EncryptedFileNoteStore.fromSeed(path,seed,owner));
  assert.equal((await reopen().reconcilePending()).length,0);assert.equal(historyCalls,0);
  const notes=await reopen().getNotes();
  for(let i=0;i<outputs.length;i++){const n=notes.find(n=>hex(n.commitment)===hex(outputs[i].commitment));assert.equal(n.generation,outputs[i].generation);assert.equal(n.leafIndex,BigInt(f.indices[i]));}
  assert.equal((await reopen().reconcilePending()).length,0);assert.equal((await reopen().getNotes()).length,notes.length);
  process.stdout.write(JSON.stringify({kind:f.kind,recoveredIndices:f.indices,historyCalls,restartIdempotent:true}));
} finally {await rm(directory,{recursive:true,force:true});}
