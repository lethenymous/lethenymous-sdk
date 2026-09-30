import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";
import { InMemoryNoteStore, ProductionProver, ShieldedWallet, keyHierarchy, ownerCommitment } from "../dist/index.js";

const key = new PublicKey(new Uint8Array(32).fill(9));
const sdk = { wallet: { publicKey: key } };
const owner = ownerCommitment(keyHierarchy(new Uint8Array(32).fill(7)).spendSecret);
const note = { pool: key, asset: new PublicKey(new Uint8Array(32).fill(8)), amount: 10n, ownerCommitment: owner, randomness: new Uint8Array(32).fill(3), commitment: new Uint8Array(32).fill(1) };

test("private operations fail closed without both production backends", async () => {
  const wallet = new ShieldedWallet(sdk, new Uint8Array(32).fill(7), undefined, undefined, new InMemoryNoteStore());
  wallet.addNote(note);
  await assert.rejects(() => wallet.privateSend({ pool: key, mint: key, amount: 10n, recipient: key }), /production prover/);
});

test("ShieldedWallet refuses an omitted note store", () => {
  assert.throws(() => new ShieldedWallet(sdk, new Uint8Array(32).fill(7), undefined, undefined), /explicit NoteStore/);
});

test("unshield rejects partial note consumption", async () => {
  const wallet = new ShieldedWallet({ ...sdk, assertPrivateTransactionReady: () => {}, validatePrivateTransactionReady: async () => {} }, new Uint8Array(32).fill(7), { proveUnshield: async () => { throw new Error("must not prove"); }, provePrivateSwap: async () => { throw new Error("must not prove"); } }, { getWitness: async () => { throw new Error("must not witness"); } }, new InMemoryNoteStore());
  wallet.addNote(note);
  await assert.rejects(() => wallet.unshield({ pool: key, mint: note.asset, amount: 3n, recipient: key }), /complete note/);
});

test("production prover rejects an unauthenticated executable before proving", async () => {
  const prover = new ProductionProver({ executablePath: "/does/not/exist", privateSwapPkPath: "/does/not/exist", unshieldPkPath: "/does/not/exist" });
  const zero = new Uint8Array(32); const witness = { index: 0n, siblings: Array.from({ length: 16 }, () => zero), root: zero, rootSequence: 0n, generation: 0n };
  await assert.rejects(() => prover.proveUnshield({ pool: key, asset: key, root: zero, rootSequence: 0n, generation: 0n, nullifier: zero, amount: 1n, recipient: key, spendSecret: zero, randomness: zero, witness }), /authenticated|ENOENT|regular file/);
});

test("in-memory note store requires reservation before marking notes spent", async () => {
  const store = new InMemoryNoteStore(); const operation = new Uint8Array(32).fill(4); await store.saveNote(note); await store.reserveNote(note.commitment, operation, owner); await store.markSubmitted(note.commitment, operation, "sig"); await store.markSpent(note.commitment, operation); assert.equal((await store.getNotes())[0].spent, true);
});
