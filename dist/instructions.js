import { PublicKey, SYSVAR_RENT_PUBKEY, SystemProgram, TransactionInstruction, } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, PROGRAM_ID, discriminator, concat, u16, u64, vec, bytes32, enumByte } from "./encoding.js";
import { pda } from "./pda.js";
const meta = (pubkey, isSigner = false, isWritable = false) => ({ pubkey, isSigner, isWritable });
const ro = (key) => meta(key);
const rw = (key) => meta(key, false, true);
const signer = (key) => meta(key, true, true);
function ix(name, args, accounts, programId) {
    return new TransactionInstruction({ programId, keys: accounts, data: concat(discriminator(name), args) });
}
export function rolloverTree(payer, pool, currentGeneration, programId = PROGRAM_ID) {
    return ix("rollover_tree", u64(currentGeneration + 1n), [
        signer(payer), ro(pool), rw(pda.shielded(pool, programId)[0]), ro(pda.tree(pool, currentGeneration, programId)[0]),
        rw(pda.tree(pool, currentGeneration + 1n, programId)[0]), ro(SystemProgram.programId),
    ], programId);
}
export function initializePool(payer, authority, creator, a, b, feeBps, programId = PROGRAM_ID) {
    if (Buffer.compare(a.toBuffer(), b.toBuffer()) >= 0)
        throw new Error("Mints must be ordered");
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
export function initializeShieldedState(payer, pool, state, programId = PROGRAM_ID) {
    const s = state ?? { tokenAMint: PublicKey.default, tokenBMint: PublicKey.default };
    return ix("initialize_shielded_state", Buffer.alloc(0), [
        signer(payer), ro(pool), ro(s.tokenAMint), ro(s.tokenBMint),
        rw(pda.shielded(pool, programId)[0]), rw(pda.tree(pool, programId)[0]),
        rw(pda.custodyA(pool, programId)[0]), rw(pda.custodyB(pool, programId)[0]),
        ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId), ro(SYSVAR_RENT_PUBKEY),
    ], programId);
}
export function addLiquidity(provider, pool, providerA, providerB, providerLp, a, b, minLp, programId = PROGRAM_ID) {
    return ix("add_liquidity", concat(u64(a), u64(b), u64(minLp)), [
        signer(provider), rw(pool.address), ro(pool.tokenAMint), ro(pool.tokenBMint),
        rw(pool.tokenAVault), rw(pool.tokenBVault), rw(pool.lpMint), rw(pda.lpLock(pool.address, programId)[0]),
        rw(providerA), rw(providerB), rw(providerLp), ro(TOKEN_PROGRAM_ID),
    ], programId);
}
export function shield(depositor, pool, state, asset, amount, owner, randomness, encrypted, depositorA, depositorB, programId = PROGRAM_ID) {
    return ix("shield", concat(enumByte(asset), u64(amount), bytes32(owner), bytes32(randomness), vec(encrypted)), [
        signer(depositor), ro(pool.address), rw(pda.shielded(pool.address, programId)[0]), rw(state.tree),
        ro(pool.tokenAMint), ro(pool.tokenBMint), rw(state.custodyA), rw(state.custodyB),
        rw(depositorA), rw(depositorB), rw(asset === 0 ? pool.protocolFeeVaultA : pool.protocolFeeVaultB), ro(TOKEN_PROGRAM_ID),
    ], programId);
}
export function removeLiquidity(provider, pool, providerA, providerB, providerLp, lpAmount, minA, minB, programId = PROGRAM_ID) {
    return ix("remove_liquidity", concat(u64(lpAmount), u64(minA), u64(minB)), [
        signer(provider), rw(pool.address), ro(pool.tokenAMint), ro(pool.tokenBMint),
        rw(pool.tokenAVault), rw(pool.tokenBVault), rw(pool.lpMint), rw(providerA), rw(providerB),
        rw(providerLp), ro(TOKEN_PROGRAM_ID),
    ], programId);
}
export function swap(trader, pool, traderA, traderB, direction, amountIn, minAmountOut, programId = PROGRAM_ID) {
    return ix("swap", concat(enumByte(direction), u64(amountIn), u64(minAmountOut)), [
        signer(trader), rw(pool.address), ro(pool.tokenAMint), ro(pool.tokenBMint),
        rw(pool.tokenAVault), rw(pool.tokenBVault), ro(pool.lpMint),
        rw(pool.protocolFeeVaultA), rw(pool.protocolFeeVaultB), rw(pool.creatorFeeVaultA), rw(pool.creatorFeeVaultB),
        rw(traderA), rw(traderB), ro(TOKEN_PROGRAM_ID),
    ], programId);
}
export function unshield(payer, pool, state, asset, amount, root, rootSequence, generation, nullifierValue, recipient, recipientA, recipientB, proof, publicInputs, programId = PROGRAM_ID) {
    return ix("unshield", concat(enumByte(asset), bytes32(root), u64(rootSequence), u64(generation), u64(amount), bytes32(nullifierValue), vec(proof), vec(publicInputs)), [
        signer(payer), ro(pool.address), ro(pda.shielded(pool.address, programId)[0]), ro(pda.tree(pool.address, generation, programId)[0]),
        ro(pool.tokenAMint), ro(pool.tokenBMint), rw(state.custodyA), rw(state.custodyB), ro(recipient),
        rw(recipientA), rw(recipientB), rw(pda.spent(pool.address, nullifierValue, programId)[0]),
        ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId),
    ], programId);
}
export function privateSwap(payer, pool, state, direction, root, rootSequence, generation, nullifierValue, amountIn, amountOut, changeAmount, changeCommitment, outputCommitment, proof, programId = PROGRAM_ID) {
    return ix("private_swap", concat(enumByte(direction), bytes32(root), u64(rootSequence), u64(generation), bytes32(nullifierValue), u64(amountIn), u64(amountOut), u64(changeAmount), bytes32(changeCommitment), bytes32(outputCommitment), vec(proof)), [
        signer(payer), rw(pool.address), rw(pda.shielded(pool.address, programId)[0]), ro(pda.tree(pool.address, generation, programId)[0]), rw(state.tree),
        rw(pool.tokenAMint), rw(pool.tokenBMint), ro(pool.lpMint), rw(pool.tokenAVault), rw(pool.tokenBVault),
        rw(pool.protocolFeeVaultA), rw(pool.protocolFeeVaultB), rw(pool.creatorFeeVaultA), rw(pool.creatorFeeVaultB),
        rw(state.custodyA), rw(state.custodyB), ro(TOKEN_PROGRAM_ID), ro(SystemProgram.programId),
        rw(pda.spent(pool.address, nullifierValue, programId)[0]),
    ], programId);
}
