/**
 * Exponential ElGamal on Baby Jubjub.
 *   Enc(m; r) = (r·G, m·G + r·PK)
 * Decryption yields m·G; the exponent is recovered with baby-step giant-step.
 */
import { G, IDENTITY, L, add, mul, negate, randomScalar, type Point, pointEquals, isOnCurve } from "./babyjub.js";

export interface Ciphertext {
  readonly c1: Point;
  readonly c2: Point;
}

export const ZERO_CIPHERTEXT: Ciphertext = Object.freeze({ c1: IDENTITY, c2: IDENTITY });

export interface KeyPair {
  readonly secret: bigint;
  readonly publicKey: Point;
}

export function generateKeyPair(): KeyPair {
  const secret = randomScalar();
  return { secret, publicKey: mul(G, secret) };
}

export function publicKeyFromSecret(secret: bigint): Point {
  return mul(G, secret);
}

export function encrypt(pk: Point, m: bigint, r: bigint = randomScalar()): Ciphertext {
  if (r <= 0n || r >= L) throw new Error("randomness must be in [1, L)");
  if (!isOnCurve(pk)) throw new Error("public key not on curve");
  const c1 = mul(G, r);
  const c2 = add(mul(G, m), mul(pk, r));
  return { c1, c2 };
}

export function addCiphertexts(a: Ciphertext, b: Ciphertext): Ciphertext {
  return { c1: add(a.c1, b.c1), c2: add(a.c2, b.c2) };
}

export function sumCiphertexts(list: readonly Ciphertext[]): Ciphertext {
  return list.reduce(addCiphertexts, ZERO_CIPHERTEXT);
}

/** M = C2 − x·C1 (still a group element). */
export function decryptToPoint(ct: Ciphertext, secret: bigint): Point {
  return add(ct.c2, negate(mul(ct.c1, secret)));
}

/** Partial decryption D = s·C1 for a trustee share s. */
export function partialDecrypt(c1: Point, share: bigint): Point {
  return mul(c1, share);
}

/** Combine partial decryptions with Lagrange coefficients: X = Σ λ_j D_j; M = C2 − X. */
export function combinePartials(c2: Point, partials: readonly Point[], lambdas: readonly bigint[]): Point {
  if (partials.length !== lambdas.length) throw new Error("length mismatch");
  let x: Point = IDENTITY;
  for (let i = 0; i < partials.length; i++) x = add(x, mul(partials[i] as Point, lambdas[i] as bigint));
  return add(c2, negate(x));
}

/**
 * Baby-step giant-step for m with m·G == target and 0 ≤ m ≤ maxM.
 * Table size ≈ sqrt(maxM); returns undefined when no solution exists in range.
 */
export function discreteLog(target: Point, maxM: number): bigint | undefined {
  if (maxM < 0) throw new Error("maxM must be non-negative");
  if (pointEquals(target, IDENTITY)) return 0n;
  const m = Math.ceil(Math.sqrt(maxM + 1)) + 1;
  const table = new Map<string, number>();
  let cur: Point = IDENTITY;
  for (let j = 0; j < m; j++) {
    table.set(`${cur.x},${cur.y}`, j);
    cur = add(cur, G);
  }
  const giant = negate(mul(G, BigInt(m)));
  let gamma = target;
  for (let i = 0; i <= m; i++) {
    const j = table.get(`${gamma.x},${gamma.y}`);
    if (j !== undefined) {
      const result = BigInt(i) * BigInt(m) + BigInt(j);
      if (result <= BigInt(maxM)) return result;
      return undefined;
    }
    gamma = add(gamma, giant);
  }
  return undefined;
}

export function decrypt(ct: Ciphertext, secret: bigint, maxM: number): bigint | undefined {
  return discreteLog(decryptToPoint(ct, secret), maxM);
}
