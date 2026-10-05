import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import {
  EncryptedFileNoteStore,
  Lethenymous,
  PROGRAM_ID,
  RpcMerkleWitnessProvider,
  keyHierarchy,
  ownerCommitment,
} from "../dist/index.js";
import { lookupTableConfig } from "./fixture.mjs";

const env = process.env;
const rpcUrl = env.E2E_RPC_URL ?? "https://api.devnet.solana.com";
const programId = new PublicKey(env.E2E_PROGRAM_ID ?? PROGRAM_ID);
const pool = new PublicKey(env.E2E_POOL ?? "EV9QP9oDHdMna6jhSygVgZrCNK1tj8jQxoHgnmPWs53K");
const expand = value => value?.startsWith("~/") ? resolve(homedir(), value.slice(2)) : resolve(value);
const payerPath = expand(env.E2E_PAYER_KEYPAIR ?? "~/.config/solana/id.json");
const seedHex = env.E2E_SEED_HEX;
if (!seedHex || !/^[0-9a-fA-F]{64}$/.test(seedHex)) throw new Error("E2E_SEED_HEX must be a 32-byte seed");
if (!env.E2E_NOTE_STORE) throw new Error("E2E_NOTE_STORE is required");
const noteStorePath = expand(env.E2E_NOTE_STORE);

const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(await readFile(payerPath, "utf8"))));
const seed = Uint8Array.from(Buffer.from(seedHex, "hex"));
const owner = ownerCommitment(keyHierarchy(seed).spendSecret);
const noteStore = EncryptedFileNoteStore.fromSeed(noteStorePath, seed, owner);
const connection = new Connection(rpcUrl, "confirmed");
const wallet = {
  publicKey: payer.publicKey,
  signTransaction: async transaction => { transaction.partialSign(payer); return transaction; },
  signVersionedTransaction: async transaction => { transaction.sign([payer]); return transaction; },
};
let sdk;
const witnessProvider = new RpcMerkleWitnessProvider(connection, programId, poolAddress => sdk.getTree(poolAddress), noteStore);
sdk = new Lethenymous({
  connection,
  wallet,
  programId,
  witnessProvider,
  lookupTables: env.E2E_LOOKUP_TABLE ? [lookupTableConfig(new PublicKey(env.E2E_LOOKUP_TABLE), payer.publicKey)] : [],
});
const shielded = sdk.shieldedWallet(seed, undefined, { noteStore });
const before = await shielded.getNotes();
const pendingBefore = await noteStore.getPendingOperations();
assert.equal(pendingBefore.length, 0, "fresh process found pending operations before reconciliation");
for (const note of before) await witnessProvider.getWitness(pool, note.commitment);
const pendingAfter = await shielded.reconcilePending();
assert.equal(pendingAfter.length, 0, "reconciliation left pending operations");
const after = await shielded.getNotes();
assert.equal(after.length, before.length, "recovery changed the local note count");
const tree = await sdk.getTree(pool);
console.log(JSON.stringify({
  result: "PASS",
  verifiedNotes: after.length,
  persistentNotes: after.length,
  availableNotes: after.filter(note => note.state === "available").length,
  spentNotes: after.filter(note => note.state === "spent").length,
  treeSequence: tree.sequence.toString(),
  treeNextIndex: tree.nextIndex.toString(),
  checkpoint: "reloaded and authenticated",
  reconciliation: "no pending operations",
}, null, 2));
