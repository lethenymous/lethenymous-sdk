import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY } from "@solana/web3.js";
import * as builders from "../dist/instructions.js";
import { PROGRAM_ID, TOKEN_PROGRAM_ID } from "../dist/index.js";

const idlPath = process.env.LETHENYMOUS_CORE_IDL ?? new URL("../../zkCPMM/idl/zkcpmm.json", import.meta.url);
const idl = existsSync(idlPath) ? JSON.parse(readFileSync(idlPath, "utf8")) : undefined;
const pk = n => new PublicKey(new Uint8Array(32).fill(n));
const le = (n, size = 8) => { const b = Buffer.alloc(size); size === 8 ? b.writeBigUInt64LE(BigInt(n)) : b.writeUInt16LE(n); return b; };
const derive = (...seeds) => PublicKey.findProgramAddressSync(seeds, PROGRAM_ID)[0];
const a = pk(1), b = pk(2), payer = pk(20), authority = pk(21), creator = pk(22);
const poolAddress = derive(Buffer.from("pool"), a.toBuffer(), b.toBuffer(), le(100, 2));
const address = seed => derive(Buffer.from(seed), poolAddress.toBuffer());
const tree = g => g === 0n ? address("tree") : derive(Buffer.from("tree"), poolAddress.toBuffer(), le(g));
const directory = g => derive(Buffer.from("page-dir"), poolAddress.toBuffer(), le(g));
const page = (g, i) => derive(Buffer.from("leaf-page"), poolAddress.toBuffer(), le(g), Buffer.from([i]));
const pool = { address: poolAddress, tokenAMint: a, tokenBMint: b, tokenAVault: address("vault-a"), tokenBVault: address("vault-b"), lpMint: address("lp"), protocolFeeVaultA: address("protocol-fee-a"), protocolFeeVaultB: address("protocol-fee-b"), creatorFeeVaultA: address("creator-fee-a"), creatorFeeVaultB: address("creator-fee-b") };
const state = { tree: tree(2n), custodyA: address("custody-a"), custodyB: address("custody-b"), tokenAMint: a, tokenBMint: b };
const zero = new Uint8Array(32), proof = new Uint8Array(256), nf = new Uint8Array(32).fill(1);
const canonical = {
  payer, authority, pool_creator: creator, pool: poolAddress, token_a_mint: a, token_b_mint: b,
  token_a_vault: pool.tokenAVault, token_b_vault: pool.tokenBVault, lp_vault_a: pool.tokenAVault, lp_vault_b: pool.tokenBVault,
  lp_mint: pool.lpMint, lp_lock: address("lp-lock"), shielded_state: address("shielded"), custody_a: state.custodyA, custody_b: state.custodyB,
  protocol_fee_vault_a: pool.protocolFeeVaultA, protocol_fee_vault_b: pool.protocolFeeVaultB, creator_fee_vault_a: pool.creatorFeeVaultA, creator_fee_vault_b: pool.creatorFeeVaultB,
  provider: pk(23), provider_a: pk(24), provider_b: pk(25), provider_lp: pk(26), trader: pk(27), trader_a: pk(28), trader_b: pk(29),
  depositor: pk(30), depositor_a: pk(31), depositor_b: pk(32), recipient: pk(33), recipient_a: pk(34), recipient_b: pk(35),
  tree: state.tree, input_tree: tree(0n), output_tree: state.tree, page_directory: directory(2n), first_output_page: page(2n, 0),
  current_tree: tree(2n), next_tree: tree(3n), next_directory: directory(3n),
  spent_nullifier: derive(Buffer.from("spent"), poolAddress.toBuffer(), Buffer.from(nf)), token_program: TOKEN_PROGRAM_ID, system_program: SystemProgram.programId, rent: SYSVAR_RENT_PUBKEY,
};
const cases = [
  ["initialize_pool", builders.initializePool(payer, authority, creator, a, b, 100)],
  ["initialize_shielded_state", builders.initializeShieldedState(payer, poolAddress, state), { tree: tree(0n), page_directory: directory(0n) }],
  ["add_liquidity", builders.addLiquidity(canonical.provider, pool, canonical.provider_a, canonical.provider_b, canonical.provider_lp, 1n, 2n, 1n)],
  ["remove_liquidity", builders.removeLiquidity(canonical.provider, pool, canonical.provider_a, canonical.provider_b, canonical.provider_lp, 1n, 1n, 1n)],
  ["swap", builders.swap(canonical.trader, pool, canonical.trader_a, canonical.trader_b, 0, 1n, 1n)],
  ["rollover_tree", builders.rolloverTree(payer, poolAddress, 2n)],
  ...[0, 1].map(asset => ["shield", builders.shield(canonical.depositor, pool, state, asset, 1n, zero, zero, new Uint8Array(186), canonical.depositor_a, canonical.depositor_b, PROGRAM_ID, { generation: 2n, nextIndex: 4096n }), { protocol_fee_vault: asset === 0 ? pool.protocolFeeVaultA : pool.protocolFeeVaultB }, [["page_directory", directory(2n)], ["leaf_page", page(2n, 1)], ["system_program", SystemProgram.programId]]]),
  ["unshield", builders.unshield(payer, pool, state, 0, 1n, zero, 1n, 0n, nf, canonical.recipient, canonical.recipient_a, canonical.recipient_b, proof, new Uint8Array(320)), { tree: tree(0n) }],
  ...[0n, 1n].flatMap(change => [0n, 4095n].map(nextIndex => ["private_swap", builders.privateSwap(payer, pool, state, 0, zero, 1n, 0n, nf, 1n, 1n, change, zero, nf, proof, PROGRAM_ID, { generation: 2n, nextIndex }), { first_output_page: page(2n, Number(nextIndex >> 12n)) }, [["token_program", TOKEN_PROGRAM_ID], ["system_program", SystemProgram.programId], ["spent_nullifier", canonical.spent_nullifier], ...(change && nextIndex === 4095n ? [["second_output_page", page(2n, 1)]] : [])]])),
];

test("RC-03 all supported builders match authoritative IDL and manual remaining-account constraints", { skip: !idl && "Set LETHENYMOUS_CORE_IDL to the project-owned Core IDL" }, () => {
  assert.equal(idl.address, PROGRAM_ID.toBase58());
  assert.equal(new Set(cases.map(([name]) => name)).size, Object.keys(builders).filter(name => typeof builders[name] === "function").length);
  for (const [name, ix, overrides = {}, remaining = []] of cases) {
    const definition = idl.instructions.find(i => i.name === name);
    assert(definition, name);
    assert.deepEqual(ix.data.subarray(0, 8), Buffer.from(definition.discriminator), `${name} discriminator`);
    assert(ix.programId.equals(new PublicKey(idl.address)));
    const expected = { ...canonical, ...overrides };
    assert.equal(ix.keys.length, definition.accounts.length + remaining.length, `${name} account count`);
    definition.accounts.forEach((account, i) => {
      const actual = ix.keys[i], label = `${name}.${account.name}`;
      assert(actual.pubkey.equals(account.address ? new PublicKey(account.address) : expected[account.name]), `${label} address/order`);
      // PrivateSwap's unchecked payer is explicitly required to sign by the handler.
      const signer = account.signer === true || name === "private_swap" && account.name === "payer";
      assert.equal(actual.isSigner, signer, `${label} signer`);
      assert.equal(actual.isWritable, account.writable === true, `${label} writable`);
    });
    remaining.forEach(([name, address], i) => {
      const actual = ix.keys[definition.accounts.length + i];
      assert(actual.pubkey.equals(address), `${name} remaining address/order`);
      assert.equal(actual.isSigner, false);
      assert.equal(actual.isWritable, !name.endsWith("program"));
    });
  }
});
