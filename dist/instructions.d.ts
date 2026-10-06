import { PublicKey, TransactionInstruction } from "@solana/web3.js";
import type { PoolState, ShieldedState } from "./types.js";
export interface ArchiveAppendContext {
    generation: bigint;
    nextIndex: bigint;
}
export declare function rolloverTree(payer: PublicKey, pool: PublicKey, currentGeneration: bigint, programId?: PublicKey): TransactionInstruction;
export declare function initializePool(payer: PublicKey, authority: PublicKey, creator: PublicKey, a: PublicKey, b: PublicKey, feeBps: number, programId?: PublicKey): TransactionInstruction;
export declare function initializeShieldedState(payer: PublicKey, pool: PublicKey, state?: ShieldedState, programId?: PublicKey): TransactionInstruction;
export declare function addLiquidity(provider: PublicKey, pool: PoolState, providerA: PublicKey, providerB: PublicKey, providerLp: PublicKey, a: bigint, b: bigint, minLp: bigint, programId?: PublicKey): TransactionInstruction;
export declare function shield(depositor: PublicKey, pool: PoolState, state: ShieldedState, asset: number, amount: bigint, owner: Uint8Array, randomness: Uint8Array, encrypted: Uint8Array, depositorA: PublicKey, depositorB: PublicKey, programId?: PublicKey, archive?: ArchiveAppendContext): TransactionInstruction;
export declare function removeLiquidity(provider: PublicKey, pool: PoolState, providerA: PublicKey, providerB: PublicKey, providerLp: PublicKey, lpAmount: bigint, minA: bigint, minB: bigint, programId?: PublicKey): TransactionInstruction;
export declare function swap(trader: PublicKey, pool: PoolState, traderA: PublicKey, traderB: PublicKey, direction: number, amountIn: bigint, minAmountOut: bigint, programId?: PublicKey): TransactionInstruction;
export declare function unshield(payer: PublicKey, pool: PoolState, state: ShieldedState, asset: number, amount: bigint, root: Uint8Array, rootSequence: bigint, generation: bigint, nullifierValue: Uint8Array, recipient: PublicKey, recipientA: PublicKey, recipientB: PublicKey, proof: Uint8Array, publicInputs: Uint8Array, programId?: PublicKey): TransactionInstruction;
export declare function privateSwap(payer: PublicKey, pool: PoolState, state: ShieldedState, direction: number, root: Uint8Array, rootSequence: bigint, generation: bigint, nullifierValue: Uint8Array, amountIn: bigint, amountOut: bigint, changeAmount: bigint, changeCommitment: Uint8Array, outputCommitment: Uint8Array, proof: Uint8Array, programId?: PublicKey, archive?: ArchiveAppendContext): TransactionInstruction;
