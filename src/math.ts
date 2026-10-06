export const FEE_DENOMINATOR = 10_000n;
export const MINIMUM_LIQUIDITY = 1_000n;
export const SHIELD_FEE_BPS = 5n;
export function shieldFee(amount: bigint): bigint {
  if (typeof amount !== "bigint" || amount < 0n || amount > 0xffffffffffffffffn) throw new Error("Shield amount must be a u64 bigint");
  return amount * SHIELD_FEE_BPS / FEE_DENOMINATOR;
}

export interface FeeBreakdown {
  totalFee: bigint;
  protocolFee: bigint;
  creatorFee: bigint;
  lpFee: bigint;
  pricingInput: bigint;
}

export function validateFeeTier(feeBps: number): void {
  if (!Number.isInteger(feeBps) || ![100, 200, 300].includes(feeBps)) throw new Error("Invalid fee tier");
}

export function feeBreakdown(amountIn: bigint, feeBps: number): FeeBreakdown {
  if (amountIn <= 0n) throw new Error("Amount must be positive");
  validateFeeTier(feeBps);
  const totalFee = amountIn * BigInt(feeBps) / FEE_DENOMINATOR;
  const protocolFee = totalFee * 5_000n / 10_000n;
  const creatorFee = totalFee * 2_000n / 10_000n;
  return {
    totalFee,
    protocolFee,
    creatorFee,
    lpFee: totalFee - protocolFee - creatorFee,
    pricingInput: amountIn - totalFee,
  };
}

function ceilDiv(numerator: bigint, denominator: bigint): bigint {
  if (numerator <= 0n || denominator <= 0n) throw new Error("Insufficient liquidity");
  return (numerator - 1n) / denominator + 1n;
}

export function minimumLpClaimReserve(totalLp: bigint, lockedLp = MINIMUM_LIQUIDITY): bigint {
  if (lockedLp <= 0n || lockedLp >= totalLp) throw new Error("Insufficient liquidity");
  return [ceilDiv(totalLp, lockedLp), ceilDiv(totalLp, totalLp - lockedLp)].reduce((a, b) => a > b ? a : b);
}

export function swapOutput(reserveIn: bigint, reserveOut: bigint, amountIn: bigint, feeBps: number): bigint {
  if (reserveIn <= 0n || reserveOut <= 0n) throw new Error("Zero reserve");
  const fee = feeBreakdown(amountIn, feeBps);
  const effective = fee.pricingInput * FEE_DENOMINATOR;
  const denominator = reserveIn * FEE_DENOMINATOR + effective;
  const output = reserveOut * effective / denominator;
  if (output <= 0n || output >= reserveOut) throw new Error("Invalid output");
  return output;
}

export function swapOutputPreservingLpClaims(
  reserveIn: bigint,
  reserveOut: bigint,
  amountIn: bigint,
  feeBps: number,
  totalLp: bigint,
  lockedLp = MINIMUM_LIQUIDITY,
): bigint {
  const output = swapOutput(reserveIn, reserveOut, amountIn, feeBps);
  if (reserveOut - output < minimumLpClaimReserve(totalLp, lockedLp)) {
    throw new Error("Reserve is too low for LP claims");
  }
  return output;
}

export function initialLp(a: bigint, b: bigint): bigint {
  return sqrt(a * b);
}

export function proportional(amount: bigint, lp: bigint, supply: bigint): bigint {
  if (supply <= 0n || lp > supply) throw new Error("Insufficient liquidity");
  return amount * lp / supply;
}

export function optimalDeposit(maxA: bigint, maxB: bigint, reserveA: bigint, reserveB: bigint): [bigint, bigint] {
  if (maxA <= 0n || maxB <= 0n || reserveA <= 0n || reserveB <= 0n) throw new Error("Zero amount");
  const b = maxA * reserveB / reserveA;
  return b <= maxB ? [maxA, b] : [maxB * reserveA / reserveB, maxB];
}

export function sqrt(n: bigint): bigint {
  if (n < 0n) throw new Error("Negative square root");
  if (n < 2n) return n;
  let x = n;
  let y = (x + 1n) / 2n;
  while (y < x) {
    x = y;
    y = (x + n / x) / 2n;
  }
  return x;
}
