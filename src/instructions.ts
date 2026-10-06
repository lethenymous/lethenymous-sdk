import {
  AccountMeta,
  PublicKey,
  SYSVAR_RENT_PUBKEY,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, PROGRAM_ID, discriminator, concat, pubkey, u16, u64, vec, bytes32, enumByte } from "./encoding.js";
import { pda } from "./pda.js";
import type { PoolState, ShieldedState } from "./types.js";

const meta = (pubkey: PublicKey, isSigner = false, isWritable = false): AccountMeta => ({ pubkey, isSigner, isWritable });
const ro = (key: PublicKey) => meta(key);
const rw = (key: PublicKey) => meta(key, false, true);
const signer = (key: PublicKey) => meta(key, true, true);

function ix(name: string, args: Buffer, accounts: AccountMeta[], programId: PublicKey): TransactionInstruction {
  return new TransactionInstruction({ programId, keys: accounts, data: concat(discriminator(name), args) });
}

export function rolloverTree(payer: PublicKey, pool: PublicKey, currentGeneration: bigint, programId: PublicKey = PROGRAM_ID): TransactionInstruction {
  return ix("rollover_tree", u64(currentGeneration + 1n), [
    signer(payer), ro(pool), rw(pda.shielded(pool, programId)[0]), ro(pda.tree(pool, currentGeneration, programId)[0]),
    rw(pda.tree(pool, currentGeneration + 1n, programId)[0]), ro(SystemProgram.programId),
  ], programId);
}

export function initializePool(
  payer: PublicKey,
  authority: PublicKey,
  creator: PublicKey,
  a: PublicKey,
  b: PublicKey,
  feeBps: number,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  if (Buffer.compare(a.toBuffer(), b.toBuffer()) >= 0) throw new Error("Mints must be ordered");
  const [pool] = pda.pool(a, b, feeBps, programId);
  return ix("initialize_pool", u16(feeBps), [
    signer(payer), signer(authority), ro(creator), ro(a), ro(b), rw(pool),
    rw(pda.vaultA(pool, programId)[0]), rw(pda.vaultB(pool, programId)[0]),
    rw(pda.protocolFeeA(pool, programId)[0]), rw(pda.protocolFeeB(pool, programId)[0]),
    rw(pda.creatorFeeA(pool, programId)[0]), rw(pda.creatorFeeB(pool, programId)[0]),
    rw(pda.lpMint(pool, programId)[0]), rw(pda.lpLock(pool, programId)[0]),
    ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId), ro(SYSVAR_RENT_PUBKEY),
  ], programId);
}

export function initializeShieldedState(
  payer: PublicKey,
  pool: PublicKey,
  state?: ShieldedState,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  const s = state ?? { tokenAMint: PublicKey.default, tokenBMint: PublicKey.default } as ShieldedState;
  return ix("initialize_shielded_state", Buffer.alloc(0), [
    signer(payer), ro(pool), ro(s.tokenAMint), ro(s.tokenBMint),
    rw(pda.shielded(pool, programId)[0]), rw(pda.tree(pool, programId)[0]),
    rw(pda.custodyA(pool, programId)[0]), rw(pda.custodyB(pool, programId)[0]),
    ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId), ro(SYSVAR_RENT_PUBKEY),
  ], programId);
}

export function addLiquidity(
  provider: PublicKey,
  pool: PoolState,
  providerA: PublicKey,
  providerB: PublicKey,
  providerLp: PublicKey,
  a: bigint,
  b: bigint,
  minLp: bigint,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  return ix("add_liquidity", concat(u64(a), u64(b), u64(minLp)), [
    signer(provider), rw(pool.address), ro(pool.tokenAMint), ro(pool.tokenBMint),
    rw(pool.tokenAVault), rw(pool.tokenBVault), rw(pool.lpMint), rw(pda.lpLock(pool.address, programId)[0]),
    rw(providerA), rw(providerB), rw(providerLp), ro(TOKEN_PROGRAM_ID),
  ], programId);
}

export function shield(
  depositor: PublicKey,
  pool: PoolState,
  state: ShieldedState,
  asset: number,
  amount: bigint,
  owner: Uint8Array,
  randomness: Uint8Array,
  encrypted: Uint8Array,
  depositorA: PublicKey,
  depositorB: PublicKey,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  return ix("shield", concat(enumByte(asset), u64(amount), bytes32(owner), bytes32(randomness), vec(encrypted)), [
    signer(depositor), ro(pool.address), rw(pda.shielded(pool.address, programId)[0]), rw(state.tree),
    ro(pool.tokenAMint), ro(pool.tokenBMint), rw(state.custodyA), rw(state.custodyB),
    rw(depositorA), rw(depositorB), rw(asset === 0 ? pool.protocolFeeVaultA : pool.protocolFeeVaultB), ro(TOKEN_PROGRAM_ID),
  ], programId);
}

export function removeLiquidity(
  provider: PublicKey,
  pool: PoolState,
  providerA: PublicKey,
  providerB: PublicKey,
  providerLp: PublicKey,
  lpAmount: bigint,
  minA: bigint,
  minB: bigint,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  return ix("remove_liquidity", concat(u64(lpAmount), u64(minA), u64(minB)), [
    signer(provider), rw(pool.address), ro(pool.tokenAMint), ro(pool.tokenBMint),
    rw(pool.tokenAVault), rw(pool.tokenBVault), rw(pool.lpMint), rw(providerA), rw(providerB),
    rw(providerLp), ro(TOKEN_PROGRAM_ID),
  ], programId);
}

export function swap(
  trader: PublicKey,
  pool: PoolState,
  traderA: PublicKey,
  traderB: PublicKey,
  direction: number,
  amountIn: bigint,
  minAmountOut: bigint,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  return ix("swap", concat(enumByte(direction), u64(amountIn), u64(minAmountOut)), [
    signer(trader), rw(pool.address), ro(pool.tokenAMint), ro(pool.tokenBMint),
    rw(pool.tokenAVault), rw(pool.tokenBVault), ro(pool.lpMint),
    rw(pool.protocolFeeVaultA), rw(pool.protocolFeeVaultB), rw(pool.creatorFeeVaultA), rw(pool.creatorFeeVaultB),
    rw(traderA), rw(traderB), ro(TOKEN_PROGRAM_ID),
  ], programId);
}

export function unshield(
  payer: PublicKey,
  pool: PoolState,
  state: ShieldedState,
  asset: number,
  amount: bigint,
  root: Uint8Array,
  rootSequence: bigint,
  generation: bigint,
  nullifierValue: Uint8Array,
  recipient: PublicKey,
  recipientA: PublicKey,
  recipientB: PublicKey,
  proof: Uint8Array,
  publicInputs: Uint8Array,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  return ix("unshield", concat(enumByte(asset), bytes32(root), u64(rootSequence), u64(generation), u64(amount), bytes32(nullifierValue), vec(proof), vec(publicInputs)), [
    signer(payer), ro(pool.address), ro(pda.shielded(pool.address, programId)[0]), ro(pda.tree(pool.address, generation, programId)[0]),
    ro(pool.tokenAMint), ro(pool.tokenBMint), rw(state.custodyA), rw(state.custodyB), ro(recipient),
    rw(recipientA), rw(recipientB), rw(pda.spent(pool.address, nullifierValue, programId)[0]),
    ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId),
  ], programId);
}

export function privateSwap(
  payer: PublicKey,
  pool: PoolState,
  state: ShieldedState,
  direction: number,
  root: Uint8Array,
  rootSequence: bigint,
  generation: bigint,
  nullifierValue: Uint8Array,
  amountIn: bigint,
  amountOut: bigint,
  changeAmount: bigint,
  changeCommitment: Uint8Array,
  outputCommitment: Uint8Array,
  proof: Uint8Array,
  programId: PublicKey = PROGRAM_ID,
): TransactionInstruction {
  return ix("private_swap", concat(enumByte(direction), bytes32(root), u64(rootSequence), u64(generation), bytes32(nullifierValue), u64(amountIn), u64(amountOut), u64(changeAmount), bytes32(changeCommitment), bytes32(outputCommitment), vec(proof)), [
    signer(payer), rw(pool.address), rw(pda.shielded(pool.address, programId)[0]), ro(pda.tree(pool.address, generation, programId)[0]), rw(state.tree),
    rw(pool.tokenAMint), rw(pool.tokenBMint), ro(pool.lpMint), rw(pool.tokenAVault), rw(pool.tokenBVault),
    rw(pool.protocolFeeVaultA), rw(pool.protocolFeeVaultB), rw(pool.creatorFeeVaultA), rw(pool.creatorFeeVaultB),
    rw(state.custodyA), rw(state.custodyB), ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId),
    rw(pda.spent(pool.address, nullifierValue, programId)[0]),
  ], programId);
}
