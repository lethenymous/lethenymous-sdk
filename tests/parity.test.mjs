import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey } from "@solana/web3.js";
import { keyHierarchy, ownerCommitment, noteCommitment, nullifier, encodeNote } from "../dist/index.js";
import { feeBreakdown, swapOutput } from "../dist/index.js";
import { pda, PROGRAM_ID, initializePool, encodeUnshieldPublicInputs, encodePrivateSwapPublicInputs } from "../dist/index.js";

test("shielded cryptography matches shielded-core vectors", () => {
  const keys = keyHierarchy(new Uint8Array(32).fill(7));
  const pool = new PublicKey(new Uint8Array(32).fill(1));
  const asset = new PublicKey(new Uint8Array(32).fill(2));
  const randomness = new Uint8Array(32).fill(3);
  const owner = ownerCommitment(keys.spendSecret);
  assert.equal(Buffer.from(keys.spendSecret).toString("hex"), "f74ed2759cecb7ded8915baf4c4212a7f5a6774aa373d48479bcf9c3e1a5ccd8");
  assert.equal(Buffer.from(keys.viewKey).toString("hex"), "e282026459da50900150e9cf9e52d0993450010c865e82d4ca1ad9acefe0b0e0");
  assert.equal(Buffer.from(owner).toString("hex"), "0af34a0ab940e3dd0187ebb955ab02eeb484672b44bc4accfbddf55087c11eee");
  assert.equal(Buffer.from(noteCommitment(pool, asset, 42n, owner, randomness)).toString("hex"), "20df330c1f6d20aa2028112596e992d11208c8a203103043c15966620bf7bff1");
  assert.equal(Buffer.from(nullifier(pool, asset, keys.spendSecret, randomness)).toString("hex"), "00e453bfa5322de50bcd6b12394f9ecea943d01418c2ed8e325a97a69707da94");
  assert.equal(encodeNote(pool, asset, 42n, owner, randomness).subarray(0, 9).toString("hex"), "025a4b43504d4d0003");
});

test("CPMM arithmetic uses exact integer semantics", () => {
  assert.equal(swapOutput(10_000n, 10_000n, 1_000n, 100), 900n);
  assert.deepEqual(feeBreakdown(1_000n, 100), { totalFee: 10n, protocolFee: 5n, creatorFee: 2n, lpFee: 3n, pricingInput: 990n });
});

test("PDA seeds and instruction discriminator are stable", () => {
  const a = new PublicKey(new Uint8Array(32).fill(1));
  const b = new PublicKey(new Uint8Array(32).fill(2));
  const [pool] = pda.pool(a, b, 100);
  const ix = initializePool(pool, pool, pool, a, b, 100);
  assert.equal(ix.programId.toBase58(), PROGRAM_ID.toBase58());
  assert.equal(ix.data.length, 10);
  assert.equal(ix.keys.length, 17);
});

test("production public-input buffers have the frozen circuit sizes", () => {
  const zero = new Uint8Array(32); const a = new PublicKey(new Uint8Array(32).fill(1));
  assert.equal(encodeUnshieldPublicInputs({ pool: a, asset: a, root: zero, nullifier: zero, amount: 1n, recipient: a }).length, 320);
  assert.equal(encodePrivateSwapPublicInputs({ pool: a, assetIn: a, assetOut: a, root: zero, rootSequence: 0n, generation: 0n, nullifier: zero, reserveIn: 1n, reserveOut: 1n, feeBps: 100, amountIn: 1n, amountOut: 1n, changeAmount: 0n, changeCommitment: zero, outputCommitment: zero, direction: 0, swapNonce: 0n }).length, 704);
});
