export const FEE_DENOMINATOR = 10000n;
export const MINIMUM_LIQUIDITY = 1000n;
export function validateFeeTier(feeBps) {
    if (!Number.isInteger(feeBps) || ![100, 200, 300].includes(feeBps))
        throw new Error("Invalid fee tier");
}
export function feeBreakdown(amountIn, feeBps) {
    if (amountIn <= 0n)
        throw new Error("Amount must be positive");
    validateFeeTier(feeBps);
    const totalFee = amountIn * BigInt(feeBps) / FEE_DENOMINATOR;
    const protocolFee = totalFee * 5000n / 10000n;
    const creatorFee = totalFee * 2000n / 10000n;
    return {
        totalFee,
        protocolFee,
        creatorFee,
        lpFee: totalFee - protocolFee - creatorFee,
        pricingInput: amountIn - totalFee,
    };
}
function ceilDiv(numerator, denominator) {
    if (numerator <= 0n || denominator <= 0n)
        throw new Error("Insufficient liquidity");
    return (numerator - 1n) / denominator + 1n;
}
export function minimumLpClaimReserve(totalLp, lockedLp = MINIMUM_LIQUIDITY) {
    if (lockedLp <= 0n || lockedLp >= totalLp)
        throw new Error("Insufficient liquidity");
    return [ceilDiv(totalLp, lockedLp), ceilDiv(totalLp, totalLp - lockedLp)].reduce((a, b) => a > b ? a : b);
}
export function swapOutput(reserveIn, reserveOut, amountIn, feeBps) {
    if (reserveIn <= 0n || reserveOut <= 0n)
        throw new Error("Zero reserve");
    const fee = feeBreakdown(amountIn, feeBps);
    const effective = fee.pricingInput * FEE_DENOMINATOR;
    const denominator = reserveIn * FEE_DENOMINATOR + effective;
    const output = reserveOut * effective / denominator;
    if (output <= 0n || output >= reserveOut)
        throw new Error("Invalid output");
    return output;
}
export function swapOutputPreservingLpClaims(reserveIn, reserveOut, amountIn, feeBps, totalLp, lockedLp = MINIMUM_LIQUIDITY) {
    const output = swapOutput(reserveIn, reserveOut, amountIn, feeBps);
    if (reserveOut - output < minimumLpClaimReserve(totalLp, lockedLp)) {
        throw new Error("Reserve is too low for LP claims");
    }
    return output;
}
export function initialLp(a, b) {
    return sqrt(a * b);
}
export function proportional(amount, lp, supply) {
    if (supply <= 0n || lp > supply)
        throw new Error("Insufficient liquidity");
    return amount * lp / supply;
}
export function optimalDeposit(maxA, maxB, reserveA, reserveB) {
    if (maxA <= 0n || maxB <= 0n || reserveA <= 0n || reserveB <= 0n)
        throw new Error("Zero amount");
    const b = maxA * reserveB / reserveA;
    return b <= maxB ? [maxA, b] : [maxB * reserveA / reserveB, maxB];
}
export function sqrt(n) {
    if (n < 0n)
        throw new Error("Negative square root");
    if (n < 2n)
        return n;
    let x = n;
    let y = (x + 1n) / 2n;
    while (y < x) {
        x = y;
        y = (x + n / x) / 2n;
    }
    return x;
}
