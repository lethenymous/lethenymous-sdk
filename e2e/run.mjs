import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { getAccount, getAssociatedTokenAddressSync } from "@solana/spl-token";
import {
  Lethenymous, ProductionProver,
  RpcMerkleWitnessProvider, EncryptedFileNoteStore, PROGRAM_ID, keyHierarchy, ownerCommitment, pda, nullifier,
} from "../dist/index.js";

const env = process.env;
const rpcUrl = env.E2E_RPC_URL ?? "https://api.devnet.solana.com";
const programId = new PublicKey(env.E2E_PROGRAM_ID ?? PROGRAM_ID);
const poolAddress = env.E2E_POOL && new PublicKey(env.E2E_POOL);
if (!poolAddress) throw new Error("E2E_POOL must identify an isolated deployed pool");
const expand = p => p?.startsWith("~/") ? resolve(homedir(), p.slice(2)) : resolve(p);
const payerPath = expand(env.E2E_PAYER_KEYPAIR ?? "~/.config/solana/id.json");
const bobPath = env.E2E_BOB_KEYPAIR && expand(env.E2E_BOB_KEYPAIR);
const seedHex = env.E2E_SEED_HEX;
if (!bobPath || !seedHex || !/^[0-9a-fA-F]{64}$/.test(seedHex)) throw new Error("E2E_BOB_KEYPAIR and a 32-byte E2E_SEED_HEX are required");
if (!env.E2E_NOTE_STORE) throw new Error("E2E_NOTE_STORE must identify an encrypted persistent note-store path");
const keypair = bytes => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(bytes)));
const payer = keypair(await readFile(payerPath, "utf8"));
const bob = keypair(await readFile(bobPath, "utf8"));
const seed = Uint8Array.from(Buffer.from(seedHex, "hex"));
const noteStorePath = expand(env.E2E_NOTE_STORE);
const noteStore = EncryptedFileNoteStore.fromSeed(noteStorePath, seed, ownerCommitment(keyHierarchy(seed).spendSecret));
const connection = new Connection(rpcUrl, "confirmed");
const walletAdapter = { publicKey: payer.publicKey, signTransaction: async tx => { tx.partialSign(payer); return tx; }, signVersionedTransaction: async tx => { tx.sign([payer]); return tx; } };
let sdk;
const witnessProvider = new RpcMerkleWitnessProvider(connection, programId, pool => sdk.getTree(pool), noteStore);
sdk = new Lethenymous({ connection, wallet: walletAdapter, programId, witnessProvider, lookupTables: env.E2E_LOOKUP_TABLE ? [new PublicKey(env.E2E_LOOKUP_TABLE)] : [] });
const prover = new ProductionProver({
  executablePath: expand(env.E2E_PROVER_BIN ?? "audit/tooling/production-prover/target/release/production-prover"),
  privateSwapPkPath: expand(env.E2E_PRIVATE_SWAP_PK ?? "artifacts/production-groth16-v1/private_swap_pk.production.bin"),
  unshieldPkPath: expand(env.E2E_UNSHIELD_PK ?? "artifacts/production-groth16-v1/unshield_pk.production.bin"),
});
const shielded = sdk.shieldedWallet(seed, prover, { noteStore });
const report = [];
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b));
async function token(address) { return (await getAccount(connection, address, "finalized")).amount; }
async function finalized(signature) { await connection.confirmTransaction(signature, "finalized"); return signature; }
async function root(pool) { const tree = await sdk.getTree(pool); return { tree, value: tree.roots[Number(tree.sequence % 32n)] }; }
async function checkWitness(note) { const w = await witnessProvider.getWitness(note.pool, note.commitment); const current = await root(note.pool); assert.equal(w.rootSequence, current.tree.sequence); assert(same(w.root, current.value)); return w; }
function record(name, signatures) { report.push({ name, result: "PASS", transaction: signatures }); }

const program = await connection.getAccountInfo(programId, "finalized");
assert(program?.executable, "deployed program is not executable");
const pool = await sdk.getPool(poolAddress);
assert(pool.tokenAMint && pool.tokenBMint);
const state = await sdk.getShieldedState(poolAddress);
const treeBefore = await sdk.getTree(poolAddress);
assert(state.tree.equals(pda.tree(poolAddress, programId)[0]));
assert(state.custodyA.equals(pda.custodyA(poolAddress, programId)[0]));
assert(state.custodyB.equals(pda.custodyB(poolAddress, programId)[0]));
assert(pool.tokenAVault.equals(pda.vaultA(poolAddress, programId)[0]));
assert(pool.tokenBVault.equals(pda.vaultB(poolAddress, programId)[0]));
const reserves = await sdk.getReserves(pool);
assert.equal(reserves.a, (await token(pool.tokenAVault)));
assert.equal(reserves.b, (await token(pool.tokenBVault)));
const payerA = getAssociatedTokenAddressSync(pool.tokenAMint, payer.publicKey);
const payerB = getAssociatedTokenAddressSync(pool.tokenBMint, payer.publicKey);
assert((await token(payerA)) >= 2900n, "payer needs at least 2900 Asset A for the lifecycle");
console.log(JSON.stringify({ preflight: "PASS", rpc: rpcUrl, program: programId.toBase58(), pool: poolAddress.toBase58(), treeSequence: treeBefore.sequence.toString() }));

async function shieldNote(amount) {
  const beforeA = await token(payerA), beforeCustody = await token(state.custodyA), beforeRoot = await root(poolAddress);
  const result = await shielded.shield({ pool: poolAddress, mint: pool.tokenAMint, amount });
  await finalized(result.signature);
  assert.equal((await token(payerA)) + amount, beforeA);
  assert.equal((await token(state.custodyA)), beforeCustody + amount);
  const afterRoot = await root(poolAddress); assert(afterRoot.tree.sequence > beforeRoot.tree.sequence);
  const witness = await checkWitness(result.note); result.note.leafIndex = witness.index;
  return result;
}

const first = await shieldNote(1000n); record("Shield", [first.signature]);
const beforeSwap = await root(poolAddress);
const swapSignature = await shielded.privateSwap({ pool: poolAddress, inputMint: pool.tokenAMint, outputMint: pool.tokenBMint, amountIn: 600n, minAmountOut: 1n });
await finalized(swapSignature);
const notesAfterSwap = await shielded.getNotes();
assert(notesAfterSwap.some(n => n.spent && same(n.commitment, first.note.commitment)));
const change = notesAfterSwap.find(n => n.asset.equals(pool.tokenAMint) && !n.spent && n.amount === 400n);
const output = notesAfterSwap.find(n => n.asset.equals(pool.tokenBMint) && !n.spent);
assert(change && output);
const swapWitness = await checkWitness(change); await checkWitness(output);
assert(swapWitness.rootSequence > beforeSwap.tree.sequence);
const inputNullifier = nullifier(poolAddress, pool.tokenAMint, shielded.spendSecret, first.note.randomness);
assert((await connection.getAccountInfo(pda.spent(poolAddress, inputNullifier, programId)[0], "finalized")) !== null);
record("Private Swap", [swapSignature]);
const beforeUnshield = await token(state.custodyB), beforeAliceB = await token(getAssociatedTokenAddressSync(pool.tokenBMint, payer.publicKey));
const unshieldSignature = await shielded.unshield({ pool: poolAddress, mint: pool.tokenBMint, amount: output.amount, recipient: payer.publicKey });
await finalized(unshieldSignature);
assert.equal(await token(state.custodyB), beforeUnshield - output.amount);
assert.equal(await token(getAssociatedTokenAddressSync(pool.tokenBMint, payer.publicKey)), beforeAliceB + output.amount);
record("Unshield", [unshieldSignature]);

const direct = await shieldNote(700n);
const bobA = getAssociatedTokenAddressSync(pool.tokenAMint, bob.publicKey);
const beforeBobA = (await connection.getAccountInfo(bobA, "finalized")) ? await token(bobA) : 0n;
const directSend = await shielded.privateSend({ pool: poolAddress, mint: pool.tokenAMint, amount: direct.note.amount, recipient: bob.publicKey });
await finalized(directSend);
assert.equal(await token(bobA), beforeBobA + direct.note.amount);
record("Private Send", [directSend]);

const routed = await shieldNote(1200n);
const routeSwap = await shielded.privateSwap({ pool: poolAddress, inputMint: pool.tokenAMint, outputMint: pool.tokenBMint, amountIn: routed.note.amount, minAmountOut: 1n });
await finalized(routeSwap);
const routeOutput = (await shielded.getNotes()).find(n => n.asset.equals(pool.tokenBMint) && !n.spent);
assert(routeOutput);
const beforeBobB = (await connection.getAccountInfo(getAssociatedTokenAddressSync(pool.tokenBMint, bob.publicKey), "finalized")) ? await token(getAssociatedTokenAddressSync(pool.tokenBMint, bob.publicKey)) : 0n;
const routeSend = await shielded.privateSend({ pool: poolAddress, mint: pool.tokenBMint, amount: routeOutput.amount, recipient: bob.publicKey });
await finalized(routeSend);
assert.equal(await token(getAssociatedTokenAddressSync(pool.tokenBMint, bob.publicKey)), beforeBobB + routeOutput.amount);
record("Private Swap -> Private Send", [routeSwap, routeSend]);

if (env.E2E_FULL === "1") {
  const full = await shieldNote(1200n);
  const firstHop = await shielded.privateSwap({ pool: poolAddress, inputMint: pool.tokenAMint, outputMint: pool.tokenBMint, amountIn: full.note.amount, minAmountOut: 1n });
  await finalized(firstHop);
  const hopB = (await shielded.getNotes()).find(n => n.asset.equals(pool.tokenBMint) && !n.spent);
  assert(hopB);
  const secondHop = await shielded.privateSwap({ pool: poolAddress, inputMint: pool.tokenBMint, outputMint: pool.tokenAMint, amountIn: hopB.amount, minAmountOut: 1n });
  await finalized(secondHop);
  const hopA = (await shielded.getNotes()).find(n => n.asset.equals(pool.tokenAMint) && !n.spent);
  assert(hopA);
  const finalUnshield = await shielded.unshield({ pool: poolAddress, mint: pool.tokenAMint, amount: hopA.amount, recipient: payer.publicKey });
  await finalized(finalUnshield);
  record("Full lifecycle", [full.signature, firstHop, secondHop, finalUnshield]);
}

console.log(JSON.stringify({ flows: report, payer: payer.publicKey.toBase58(), bob: bob.publicKey.toBase58(), pool: poolAddress.toBase58() }, null, 2));
