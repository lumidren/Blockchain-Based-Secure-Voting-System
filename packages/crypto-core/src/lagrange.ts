/** Lagrange coefficients at x = 0 over Z_L for a set of distinct trustee indices (1-based). */
import { L, mod, modInv } from "./babyjub.js";

export function lagrangeCoefficients(indices: readonly number[]): bigint[] {
  const set = new Set(indices);
  if (set.size !== indices.length) throw new Error("duplicate indices");
  return indices.map((j) => {
    let num = 1n;
    let den = 1n;
    for (const m of indices) {
      if (m === j) continue;
      if (m <= 0 || j <= 0) throw new Error("indices must be positive");
      num = (num * BigInt(m)) % L;
      den = (den * mod(BigInt(m) - BigInt(j), L)) % L;
    }
    return (num * modInv(den, L)) % L;
  });
}

/** Evaluate Σ coeff_k · x^k mod L (Horner). */
export function evalPoly(coeffs: readonly bigint[], x: bigint): bigint {
  let acc = 0n;
  for (let k = coeffs.length - 1; k >= 0; k--) acc = (acc * x + (coeffs[k] as bigint)) % L;
  return acc;
}
