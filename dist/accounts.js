import { Reader } from "./encoding.js";
import { PublicKey } from "@solana/web3.js";
export function decodePool(data, address) {
    if (data.length !== 364)
        throw new Error("Invalid Pool account length");
    const r = new Reader(data);
    return {
        address: address ?? PublicKey.default,
        authority: r.pubkey(),
        tokenAMint: r.pubkey(),
        tokenBMint: r.pubkey(),
        tokenAVault: r.pubkey(),
        tokenBVault: r.pubkey(),
        protocolFeeVaultA: r.pubkey(),
        protocolFeeVaultB: r.pubkey(),
        creatorFeeVaultA: r.pubkey(),
        creatorFeeVaultB: r.pubkey(),
        creatorFeeRecipient: r.pubkey(),
        lpMint: r.pubkey(),
        feeBps: r.u16(),
        bump: r.u8(),
        version: r.u8(),
        swapNonce: r.u64(),
    };
}
export function decodeShieldedState(data) {
    if (data.length !== 194)
        throw new Error("Invalid ShieldedState account length");
    const r = new Reader(data);
    return {
        pool: r.pubkey(),
        tokenAMint: r.pubkey(),
        tokenBMint: r.pubkey(),
        custodyA: r.pubkey(),
        custodyB: r.pubkey(),
        tree: r.pubkey(),
        bump: r.u8(),
        version: r.u8(),
    };
}
export function decodeProtocolConfig(data) {
    if (data.length !== 66)
        throw new Error("Invalid ProtocolConfig account length");
    const r = new Reader(data);
    return {
        authority: r.pubkey(),
        feeRecipient: r.pubkey(),
        bump: r.u8(),
        version: r.u8(),
    };
}
export function decodeTreeState(data) {
    if (data.length !== 2664)
        throw new Error("Invalid TreeState account length");
    const r = new Reader(data);
    const pool = r.pubkey(), generation = r.u64(), nextIndex = r.u64(), sequence = r.u64();
    const frontier = Array.from({ length: 16 }, () => r.bytes(32));
    const frontierPresent = Array.from({ length: 16 }, () => r.u8());
    const emptySubtrees = Array.from({ length: 17 }, () => r.bytes(32));
    const roots = Array.from({ length: 32 }, () => r.bytes(32));
    const rootSequences = Array.from({ length: 32 }, () => r.u64());
    const rootGenerations = Array.from({ length: 32 }, () => r.u64());
    return {
        pool,
        generation,
        nextIndex,
        sequence,
        frontier,
        frontierPresent,
        emptySubtrees,
        roots,
        rootSequences,
        rootGenerations,
    };
}
