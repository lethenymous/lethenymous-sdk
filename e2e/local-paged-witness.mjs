// Local SBF integration bridge: stdin contains accounts fetched from BanksClient
// and private test note metadata. No history/indexer/checkpoint input is accepted.
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PublicKey } from "@solana/web3.js";
import { EncryptedFileNoteStore, OnChainPagedMerkleWitnessProvider, keyHierarchy, ownerCommitment } from "../dist/index.js";

let input="";for await(const chunk of process.stdin)input+=chunk;
const fixture=JSON.parse(input);
const bytes=h=>Uint8Array.from(Buffer.from(h,"hex"));
const seed=bytes(fixture.seed),owner=ownerCommitment(keyHierarchy(seed).spendSecret);
const note={pool:new PublicKey(fixture.note.pool),asset:new PublicKey(fixture.note.asset),amount:BigInt(fixture.note.amount),ownerCommitment:owner,randomness:bytes(fixture.note.randomness),commitment:bytes(fixture.note.commitment),generation:BigInt(fixture.note.generation),leafIndex:fixture.note.leafIndex==null?undefined:BigInt(fixture.note.leafIndex)};
const directory=await mkdtemp(join(tmpdir(),"paged-offline-wallet-"));
try {
  const path=join(directory,"encrypted-wallet");
  const store=EncryptedFileNoteStore.fromSeed(path,seed,owner);await store.saveNote(note);
  // A new store/provider represents returning with only normal encrypted note
  // state. There are no SDK Merkle sidecars or archived event lists.
  const restored=EncryptedFileNoteStore.fromSeed(path,seed,owner);const owned=(await restored.getNotes())[0];
  const accounts=new Map(fixture.accounts.map(a=>[a.address,a]));
  const forbidden=()=>{throw new Error("Historical RPC/checkpoint access is forbidden");};
  let fetched=0;
  const connection={getSignaturesForAddress:forbidden,getTransaction:forbidden,getMultipleAccountsInfo:async(addresses,commitment)=>{
    if(addresses.length!==18||commitment!=="finalized")throw new Error("Privacy batch or finality mismatch");fetched+=addresses.length;
    return addresses.map(key=>{const a=accounts.get(key.toBase58());return a?{owner:new PublicKey(a.owner),executable:a.executable,data:Buffer.from(a.data,"hex"),lamports:a.lamports,rentEpoch:0}:null;});
  }};
  const provider=new OnChainPagedMerkleWitnessProvider(connection,new PublicKey(fixture.programId));
  const witness=await provider.getWitness(owned.pool,owned.commitment,owned.generation,owned.leafIndex);
  if(fetched!==18||witness.siblings.length!==16)throw new Error("Account-only witness invariant failed");
  process.stdout.write(JSON.stringify({index:witness.index.toString(),generation:witness.generation.toString(),rootSequence:witness.rootSequence.toString(),root:Buffer.from(witness.root).toString("hex"),siblings:witness.siblings.map(b=>Buffer.from(b).toString("hex"))}));
} finally {await rm(directory,{recursive:true,force:true});}
