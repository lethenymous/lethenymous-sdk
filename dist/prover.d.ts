import type { PrivateSwapProverInput, Prover, UnshieldProverInput } from "./types.js";
export declare const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export declare const PRODUCTION_ARTIFACT_SHA256: {
    readonly privateSwapPk: "26f9aaa5ff0924bc5c1d4a6fc618f70147d4f8b6d76acdfca3eabbd704cf51f5";
    readonly unshieldPk: "156b0759e8819cb529c59249fbef6e075651655c8f8361f97616a8a1fc981563";
};
export declare function encodeUnshieldPublicInputs(input: Pick<UnshieldProverInput, "pool" | "asset" | "root" | "nullifier" | "amount" | "recipient">): Uint8Array;
export declare function encodePrivateSwapPublicInputs(input: Pick<PrivateSwapProverInput, "pool" | "assetIn" | "assetOut" | "root" | "rootSequence" | "generation" | "nullifier" | "reserveIn" | "reserveOut" | "feeBps" | "amountIn" | "amountOut" | "changeAmount" | "changeCommitment" | "outputCommitment" | "direction" | "swapNonce">): Uint8Array;
export interface ProductionProverConfig {
    executablePath: string;
    privateSwapPkPath: string;
    unshieldPkPath: string;
    timeoutMs?: number;
}
export declare class ProductionProver implements Prover {
    private readonly config;
    constructor(config: ProductionProverConfig);
    proveUnshield(input: UnshieldProverInput): Promise<{
        proof: Uint8Array;
        publicInputs: Uint8Array;
    }>;
    provePrivateSwap(input: PrivateSwapProverInput): Promise<{
        proof: Uint8Array;
        publicInputs: Uint8Array;
    }>;
}
