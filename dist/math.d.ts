export declare const FEE_DENOMINATOR = 10000n;
export declare const MINIMUM_LIQUIDITY = 1000n;
export declare const SHIELD_FEE_BPS = 5n;
export declare function shieldFee(amount: bigint): bigint;
export interface FeeBreakdown {
    totalFee: bigint;
    protocolFee: bigint;
    creatorFee: bigint;
    lpFee: bigint;
    pricingInput: bigint;
}
export declare function validateFeeTier(feeBps: number): void;
export declare function feeBreakdown(amountIn: bigint, feeBps: number): FeeBreakdown;
export declare function minimumLpClaimReserve(totalLp: bigint, lockedLp?: bigint): bigint;
export declare function swapOutput(reserveIn: bigint, reserveOut: bigint, amountIn: bigint, feeBps: number): bigint;
export declare function swapOutputPreservingLpClaims(reserveIn: bigint, reserveOut: bigint, amountIn: bigint, feeBps: number, totalLp: bigint, lockedLp?: bigint): bigint;
export declare function initialLp(a: bigint, b: bigint): bigint;
export declare function proportional(amount: bigint, lp: bigint, supply: bigint): bigint;
export declare function optimalDeposit(maxA: bigint, maxB: bigint, reserveA: bigint, reserveB: bigint): [bigint, bigint];
export declare function sqrt(n: bigint): bigint;
