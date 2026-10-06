import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AddressLookupTableAccount, ComputeBudgetProgram, Keypair, PublicKey, TransactionMessage, VersionedTransaction } from "@solana/web3.js";
import { accountDiscriminator, encodePrivateSwapPublicInputs, encodeUnshieldPublicInputs, EncryptedFileNoteStore, InMemoryNoteStore, keyHierarchy, noteCommitment, ownerCommitment, ShieldedWallet, Lethenymous, PROGRAM_ID, TREE_CAPACITY, parseShieldedEvent, pda, privateSwap, rolloverTree, shield, shieldFee, unshield } from "../dist/index.js";

const key = v => new PublicKey(new Uint8Array(32).fill(v));
const zero = new Uint8Array(32);
const u64 = v => { const b=Buffer.alloc(8);b.writeBigUInt64LE(v);return b; };
const id = n => createHash("sha256").update(`event:${n}`).digest().subarray(0,8);
const pool = { address:key(1),tokenAMint:key(2),tokenBMint:key(3),lpMint:key(4),tokenAVault:key(5),tokenBVault:key(6),protocolFeeVaultA:key(7),protocolFeeVaultB:key(8),creatorFeeVaultA:key(9),creatorFeeVaultB:key(10) };
const state = { pool:pool.address,tree:pda.tree(pool.address,4n)[0],custodyA:key(11),custodyB:key(12) };
const nf = Uint8Array.from(zero);nf[31]=1;

test("Gen0 stays byte-identical and Gen1/Gen2 use LE u64 seeds",()=>{
  assert.deepEqual(pda.tree(pool.address,0n),PublicKey.findProgramAddressSync([Buffer.from("tree"),pool.address.toBuffer()],PROGRAM_ID));
  assert.deepEqual(pda.tree(pool.address,PROGRAM_ID),pda.tree(pool.address,0n));
  for(const g of [1n,2n])assert.deepEqual(pda.tree(pool.address,g),PublicKey.findProgramAddressSync([Buffer.from("tree"),pool.address.toBuffer(),u64(g)],PROGRAM_ID));
  assert.throws(()=>pda.tree(pool.address,-1n));
  assert.throws(()=>pda.tree(pool.address,1n<<64n));
});

test("shield fee preserves Rust floor semantics at u64 boundaries",()=>{
  for(const [a,f] of [[1n,0n],[1999n,0n],[2000n,1n],[100000000n,50000n],[0xffffffffffffffffn,9223372036854775n]])assert.equal(shieldFee(a),f);
  assert.throws(()=>shieldFee(-1n));assert.throws(()=>shieldFee(1n<<64n));
});

test("legacy notes deliberately normalize to Gen0",async()=>{
  const store=new InMemoryNoteStore();
  await store.saveNote({pool:pool.address,asset:pool.tokenAMint,amount:10n,ownerCommitment:zero,randomness:zero,commitment:nf});
  assert.equal((await store.getNotes())[0].generation,0n);
});

test("a finalized failed status never becomes a successful recovered spend",async()=>{
  const error={InstructionError:[0,{Custom:6033}]};
  const sdk=new Lethenymous({connection:{getSignatureStatuses:async()=>({value:[{confirmationStatus:"finalized",err:error}]}),getTransaction:async()=>{throw new Error("should not reinterpret a known finalized failure");}},wallet:{publicKey:key(15),signTransaction:async tx=>tx}});
  const outcome=await sdk.reconcileTransaction("failed-signature");assert.equal(outcome.status,"finalized-failed");assert.deepEqual(outcome.error,error);
});

test("private builders bind historical input generation and active output pointer",()=>{
  const payer=key(15), recipient=key(16),proof=new Uint8Array(256);
  const swap=privateSwap(payer,pool,state,0,nf,1n,0n,nf,100n,200n,1n,nf,nf,proof,PROGRAM_ID,{generation:4n,nextIndex:0n});
  assert(swap.keys[3].pubkey.equals(pda.tree(pool.address,0n)[0]));assert.equal(swap.keys[3].isWritable,false);
  assert(swap.keys[4].pubkey.equals(state.tree));assert.equal(swap.keys[4].isWritable,true);
  const withdraw=unshield(payer,pool,state,0,100n,nf,1n,1n,nf,recipient,key(17),key(18),proof,new Uint8Array(320));
  assert(withdraw.keys[3].pubkey.equals(pda.tree(pool.address,1n)[0]));assert.equal(withdraw.keys[3].isWritable,false);
  assert(withdraw.keys[11].pubkey.equals(pda.spent(pool.address,nf)[0]));
  const deposit=shield(payer,pool,state,1,2000n,nf,nf,new Uint8Array(186),key(17),key(18),PROGRAM_ID,{generation:4n,nextIndex:0n});assert(deposit.keys[10].pubkey.equals(pool.protocolFeeVaultB));
});

function swapEvent(change,outputGeneration){
  const fields=[id("PrivateSwapped"),pool.address.toBuffer(),Buffer.from([0]),u64(100n),u64(200n),Buffer.from(nf),u64(1n),u64(0n),Buffer.from(nf),Buffer.from(change?nf:zero),Buffer.from(nf),Buffer.from([change?1:0]),...(change?[u64(0n)]:[]),u64(change?1n:0n)];
  if(outputGeneration!==undefined)fields.push(u64(outputGeneration));return Buffer.concat(fields);
}

test("legacy/new PrivateSwapped layouts preserve input and output meanings",()=>{
  for(const change of [false,true]){
    const old=parseShieldedEvent(swapEvent(change),"s",1);assert.equal(old.generation,0n);assert.equal(old.outputGeneration,0n);
    const updated=parseShieldedEvent(swapEvent(change,4n),"s",1);assert.equal(updated.generation,0n);assert.equal(updated.outputGeneration,4n);
  }
  assert.throws(()=>parseShieldedEvent(Buffer.concat([swapEvent(false),Buffer.from([0])]),"s",1));
});

test("TreeRolledOver layout is strict and preserves final root identifiers",()=>{
  const data=Buffer.concat([id("TreeRolledOver"),pool.address.toBuffer(),pda.tree(pool.address,0n)[0].toBuffer(),u64(0n),Buffer.from(nf),pda.tree(pool.address,1n)[0].toBuffer(),u64(1n)]);
  const event=parseShieldedEvent(data,"roll",10);assert.equal(event.newGeneration,1n);assert(event.previousTree.equals(pda.tree(pool.address,0n)[0]));
  assert.throws(()=>parseShieldedEvent(data.subarray(0,151),"s",1));
});

test("capacity rollover refetch handles another caller winning the race",async()=>{
  const sdk=new Lethenymous({connection:{},wallet:{publicKey:key(15),signTransaction:async tx=>tx}});
  let call=0;let attempts=0;
  sdk.getActiveTree=async()=>++call===1?{state,tree:{generation:4n,nextIndex:TREE_CAPACITY-1n},address:state.tree}:{state:{...state,tree:pda.tree(pool.address,5n)[0]},tree:{generation:5n,nextIndex:0n},address:pda.tree(pool.address,5n)[0]};
  sdk.buildAndSend=async()=>{attempts++;throw new Error("stale current tree");};
  assert.equal((await sdk.ensureTreeCapacity(pool.address,2)).tree.generation,5n);assert.equal(attempts,1);
});

test("capacity does not guess success when rollover fails without pointer advance",async()=>{
  const sdk=new Lethenymous({connection:{},wallet:{publicKey:key(15),signTransaction:async tx=>tx}});
  sdk.getActiveTree=async()=>({state,tree:{generation:4n,nextIndex:TREE_CAPACITY},address:state.tree});sdk.buildAndSend=async()=>{throw new Error("unknown outcome");};
  await assert.rejects(()=>sdk.ensureTreeCapacity(pool.address,1),/unknown outcome/);
});

test("active tree discovery uses the pointer and rejects forged pool/generation pairing",async()=>{
  const address=pda.tree(pool.address,2n)[0];
  const treeData=Buffer.alloc(2672);accountDiscriminator("TreeState").copy(treeData);pool.address.toBuffer().copy(treeData,8);treeData.writeBigUInt64LE(2n,40);
  const stateData=Buffer.concat([accountDiscriminator("ShieldedState"),pool.address.toBuffer(),pool.tokenAMint.toBuffer(),pool.tokenBMint.toBuffer(),state.custodyA.toBuffer(),state.custodyB.toBuffer(),address.toBuffer(),Buffer.from([1,1])]);
  const sdk=new Lethenymous({connection:{getAccountInfo:async k=>({owner:PROGRAM_ID,data:k.equals(pda.shielded(pool.address)[0])?stateData:treeData})},wallet:{publicKey:key(15),signTransaction:async tx=>tx}});
  assert.equal((await sdk.getActiveTree(pool.address)).tree.generation,2n);
  treeData.writeBigUInt64LE(1n,40);await assert.rejects(()=>sdk.getActiveTree(pool.address),/generation\/PDA/);
  treeData.writeBigUInt64LE(2n,40);key(19).toBuffer().copy(treeData,8);await assert.rejects(()=>sdk.getActiveTree(pool.address),/match pool/);
});

function walletFixture(amount=10000n){
  const seed=new Uint8Array(32).fill(40),keys=keyHierarchy(seed),owner=ownerCommitment(keys.spendSecret),randomness=new Uint8Array(32).fill(41),store=new InMemoryNoteStore();
  const note={pool:pool.address,asset:pool.tokenAMint,amount,ownerCommitment:owner,randomness,commitment:noteCommitment(pool.address,pool.tokenAMint,amount,owner,randomness),generation:0n};
  const submitted=[];let capacities=0;
  const sdk={programId:PROGRAM_ID,wallet:{publicKey:Keypair.generate().publicKey},connection:{},assertPrivateTransactionReady(){},validatePrivateTransactionReady:async()=>{},getPool:async()=>({...pool,feeBps:100,swapNonce:0n}),getShieldedState:async()=>state,ensureTreeCapacity:async()=>{const generation=++capacities===1?3n:4n;return{tree:{generation,nextIndex:0n},state:{...state,tree:pda.tree(pool.address,generation)[0]}};},getReserves:async()=>({a:1000000n,b:2000000n}),getLpSupply:async()=>1000000n,ensureAtas:async()=>[key(17),key(18)],buildAndSendOutcome:async(ixs,options)=>{submitted.push(ixs);await options.onSubmitted("unit-signature");return{status:"finalized-success",signature:"unit-signature"};}};
  const witness={getWitness:async()=>({generation:0n,index:0n,rootSequence:1n,root:nf,siblings:Array.from({length:16},()=>zero)})};
  return {seed,store,note,sdk,witness,submitted};
}

test("wallet orchestration keeps Gen0 proof input and records current output generation after a race",async()=>{
  const f=walletFixture();await f.store.saveNote(f.note);let statement;
  const prover={provePrivateSwap:async i=>{statement=i;return{proof:new Uint8Array(256),publicInputs:encodePrivateSwapPublicInputs(i)};}};
  f.sdk.getFinalizedShieldedEvents=async()=>[{kind:"swap",pool:pool.address,nullifier:statement.nullifier,changeCommitment:statement.changeCommitment,outputCommitment:statement.outputCommitment,amountOut:statement.amountOut,generation:0n,outputGeneration:4n,changeIndex:0n,outputIndex:1n}];
  const wallet=new ShieldedWallet(f.sdk,f.seed,prover,f.witness,f.store);
  await wallet.privateSwap({pool:pool.address,inputMint:pool.tokenAMint,outputMint:pool.tokenBMint,amountIn:6000n,minAmountOut:1n});
  assert.equal(statement.generation,0n);assert.equal(statement.witness.generation,0n);
  assert.equal("outputGeneration"in statement,false);
  const notes=await wallet.getNotes();assert(notes.find(n=>n.amount===10000n).spent);
  assert.equal(notes.find(n=>n.amount===4000n&&!n.spent).generation,4n);assert.equal(notes.find(n=>n.asset.equals(pool.tokenBMint)).generation,4n);
  assert.equal(notes.find(n=>n.amount===4000n&&!n.spent).leafIndex,0n);assert.equal(notes.find(n=>n.asset.equals(pool.tokenBMint)).leafIndex,1n);
  const ix=f.submitted[0][1];assert(ix.keys[3].pubkey.equals(pda.tree(pool.address,0n)[0]));assert(ix.keys[4].pubkey.equals(pda.tree(pool.address,4n)[0]));
});

test("encrypted pending swap recovers exact finalized generation and page-boundary indices after restart",async()=>{
  const directory=await mkdtemp(join(tmpdir(),"archive-index-recovery-"));
  try {
    const f=walletFixture(),path=join(directory,"journal");let statement;
    const store=EncryptedFileNoteStore.fromSeed(path,f.seed,f.note.ownerCommitment);await store.saveNote(f.note);
    const prover={provePrivateSwap:async i=>{statement=i;return{proof:new Uint8Array(256),publicInputs:encodePrivateSwapPublicInputs(i)};}};
    f.sdk.getFinalizedShieldedEvents=async()=>{throw new Error("event RPC temporarily unavailable");};
    const wallet=new ShieldedWallet(f.sdk,f.seed,prover,f.witness,store);
    await assert.rejects(()=>wallet.privateSwap({pool:pool.address,inputMint:pool.tokenAMint,outputMint:pool.tokenBMint,amountIn:6000n,minAmountOut:1n}),/outcome is unknown/);
    assert.equal((await store.getNotes()).length,1);assert.equal((await store.getPendingOperations())[0].state,"unknown");
    const reopened=EncryptedFileNoteStore.fromSeed(path,f.seed,f.note.ownerCommitment);
    const returning=new ShieldedWallet(f.sdk,f.seed,prover,f.witness,reopened);
    f.sdk.reconcileTransaction=async()=>({status:"finalized-success",signature:"unit-signature"});f.sdk.hasFinalizedProgramEvent=async()=>true;
    const event={kind:"swap",pool:pool.address,nullifier:statement.nullifier,changeCommitment:statement.changeCommitment,outputCommitment:statement.outputCommitment,amountOut:statement.amountOut,generation:0n,outputGeneration:4n,changeIndex:4095n,outputIndex:4096n};
    // Ambiguous events must leave reservations and output publication pending.
    f.sdk.getFinalizedShieldedEvents=async()=>[event,event];
    assert.equal((await returning.reconcilePending()).length,1);assert.equal((await reopened.getNotes()).length,1);
    f.sdk.getFinalizedShieldedEvents=async()=>[event];
    assert.equal((await returning.reconcilePending()).length,0);
    const fresh=EncryptedFileNoteStore.fromSeed(path,f.seed,f.note.ownerCommitment),notes=await fresh.getNotes();
    assert.equal(notes.length,3);assert(notes.find(n=>n.amount===10000n).spent);
    assert.equal(notes.find(n=>n.amount===4000n).leafIndex,4095n);assert.equal(notes.find(n=>n.asset.equals(pool.tokenBMint)).leafIndex,4096n);
    assert(notes.filter(n=>!n.spent).every(n=>n.generation===4n));
  } finally {await rm(directory,{recursive:true,force:true});}
});

test("old-generation unshield and Private Send use the historical membership account",async()=>{
  for(const method of ["unshield","privateSend"]){const f=walletFixture(3000n);await f.store.saveNote(f.note);let statement;
    const prover={proveUnshield:async i=>{statement=i;return{proof:new Uint8Array(256),publicInputs:encodeUnshieldPublicInputs(i)};}};
    const wallet=new ShieldedWallet(f.sdk,f.seed,prover,f.witness,f.store);
    await wallet[method]({pool:pool.address,mint:pool.tokenAMint,amount:3000n,recipient:Keypair.generate().publicKey});
    assert.equal(statement.generation,0n);assert(f.submitted[0][1].keys[3].pubkey.equals(pda.tree(pool.address,0n)[0]));assert((await wallet.getNotes())[0].spent);
  }
});

test("all v0 flows fit with dynamic trees excluded from a static pool LUT",()=>{
  const payer=Keypair.generate().publicKey,recipient=key(16);
  const addresses=[pool.address,pool.tokenAMint,pool.tokenBMint,pool.lpMint,pool.tokenAVault,pool.tokenBVault,pool.protocolFeeVaultA,pool.protocolFeeVaultB,pool.creatorFeeVaultA,pool.creatorFeeVaultB,pda.shielded(pool.address)[0],state.custodyA,state.custodyB];
  const table=new AddressLookupTableAccount({key:key(30),state:{deactivationSlot:0xffffffffffffffffn,lastExtendedSlot:1,lastExtendedSlotStartIndex:0,addresses}});
  const size=ixs=>new VersionedTransaction(new TransactionMessage({payerKey:payer,recentBlockhash:key(31).toBase58(),instructions:ixs}).compileToV0Message([table])).serialize().length;
  const swap=(change,index=0n)=>[ComputeBudgetProgram.setComputeUnitLimit({units:1400000}),privateSwap(payer,pool,state,0,nf,100n,1n,nf,100n,200n,change?1n:0n,change?nf:zero,nf,new Uint8Array(256),PROGRAM_ID,{generation:4n,nextIndex:index})];
  const withdraw=[ComputeBudgetProgram.setComputeUnitLimit({units:500000}),unshield(payer,pool,state,1,200n,nf,100n,1n,nf,recipient,key(17),key(18),new Uint8Array(256),new Uint8Array(320))];
  const flows={privateSwapWithChange:size(swap(true)),privateSwapWithoutChange:size(swap(false)),privateSwapCrossPage:size(swap(true,4095n)),unshield:size(withdraw),privateSend:size(withdraw),shield:size([shield(payer,pool,state,0,2000n,nf,nf,new Uint8Array(186),key(17),key(18),PROGRAM_ID,{generation:4n,nextIndex:0n})]),rollover:size([rolloverTree(payer,pool.address,4n)])};
  for(const [name,bytes]of Object.entries(flows)){console.log(`generation_transaction_bytes ${name}=${bytes}`);assert(bytes<=1232,`${name} too large: ${bytes}`);}
  for(const g of [1n,4n,5n])assert(!addresses.some(a=>a.equals(pda.tree(pool.address,g)[0])));
});
