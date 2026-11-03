/**
 * Baby Jubjub twisted Edwards curve arithmetic over the BN254 scalar field.
 *
 *   a·x² + y² = 1 + d·x²·y²,  a = 168700, d = 168696
 *
 * `a` is a quadratic residue and `d` is a non-residue, so the addition law is complete: the
 * formulas below are valid for every pair of points, including doubling and the identity.
 * The same formulas are implemented on-chain in contracts/src/libraries/BabyJubJub.sol; the
 * projective variants here exist so that test vectors can be produced for the Solidity code.
 */

import { sha256 } from "@noble/hashes/sha256";
import { bytesToBigIntBE, bigIntToBytesBE, utf8 } from "./encoding.js";

/** BN254 scalar field modulus (coordinate field of Baby Jubjub). */
export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
/** Curve coefficient a. */
export const A = 168700n;
/** Curve coefficient d. */
export const D = 168696n;
/** Prime order of the large subgroup. */
export const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
/** Cofactor. */
export const COFACTOR = 8n;

export interface Point {
  readonly x: bigint;
  readonly y: bigint;
}

export interface ProjectivePoint {
  readonly X: bigint;
  readonly Y: bigint;
  readonly Z: bigint;
}

/** circomlib Base8: generator of the prime-order subgroup. */
export const G: Point = Object.freeze({
  x: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
});

/** Neutral element. */
export const IDENTITY: Point = Object.freeze({ x: 0n, y: 1n });

export function mod(a: bigint, m: bigint = P): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

export function modPow(base: bigint, exp: bigint, m: bigint = P): bigint {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/** Modular inverse by Fermat (m prime). Throws on zero. */
export function modInv(a: bigint, m: bigint = P): bigint {
  const r = mod(a, m);
  if (r === 0n) throw new Error("modInv: division by zero");
  return modPow(r, m - 2n, m);
}

/** Legendre symbol: 1 if x is a non-zero square mod P, -1 if non-square, 0 if zero. */
export function legendre(x: bigint): -1 | 0 | 1 {
  const r = modPow(x, (P - 1n) / 2n);
  if (r === 0n) return 0;
  return r === 1n ? 1 : -1;
}

/** Tonelli–Shanks square root mod P. Returns undefined when x is a non-residue. */
export function sqrtMod(x: bigint): bigint | undefined {
  const n = mod(x);
  if (n === 0n) return 0n;
  if (legendre(n) !== 1) return undefined;
  // P - 1 = Q · 2^S with Q odd
  let q = P - 1n;
  let s = 0n;
  while ((q & 1n) === 0n) {
    q >>= 1n;
    s += 1n;
  }
  // find a non-residue z
  let z = 2n;
  while (legendre(z) !== -1) z += 1n;
  let m = s;
  let c = modPow(z, q);
  let t = modPow(n, q);
  let r = modPow(n, (q + 1n) / 2n);
  while (t !== 1n) {
    let i = 0n;
    let tt = t;
    while (tt !== 1n) {
      tt = (tt * tt) % P;
      i += 1n;
      if (i === m) return undefined;
    }
    const b = modPow(c, 1n << (m - i - 1n));
    m = i;
    c = (b * b) % P;
    t = (t * c) % P;
    r = (r * b) % P;
  }
  return r;
}

export function isOnCurve(p: Point): boolean {
  const { x, y } = p;
  if (x < 0n || x >= P || y < 0n || y >= P) return false;
  const xx = (x * x) % P;
  const yy = (y * y) % P;
  const lhs = (A * xx + yy) % P;
  const rhs = (1n + ((D * xx) % P) * yy) % P;
  return lhs === rhs;
}

export function pointEquals(p: Point, q: Point): boolean {
  return p.x === q.x && p.y === q.y;
}

export function isIdentity(p: Point): boolean {
  return p.x === 0n && p.y === 1n;
}

export function negate(p: Point): Point {
  return { x: mod(-p.x), y: p.y };
}

/** Complete affine addition (one field inversion, via projective coordinates). */
export function add(p: Point, q: Point): Point {
  return toAffine(projAdd(toProjective(p), toProjective(q)));
}

export function sub(p: Point, q: Point): Point {
  return add(p, negate(q));
}

export function double(p: Point): Point {
  return add(p, p);
}

/** Scalar multiplication (projective double-and-add, one inversion). Not constant-time: inputs are public or local. */
export function mul(p: Point, k: bigint): Point {
  return toAffine(projMul(toProjective(p), mod(k, L)));
}

/** Scalar multiplication with the full scalar (no reduction mod L), used to cross-check circuits. */
export function mulUnreduced(p: Point, k: bigint): Point {
  if (k < 0n) throw new Error("negative scalar");
  return toAffine(projMulUnreduced(toProjective(p), k));
}

/** True if p is on the curve and in the prime-order subgroup. */
export function inSubgroup(p: Point): boolean {
  if (!isOnCurve(p)) return false;
  return isIdentity(mul(p, L));
}

// ---------------------------------------------------------------------------------------------
// Projective coordinates (X : Y : Z) with x = X/Z, y = Y/Z — mirror of the Solidity library.
// Formulas "add-2008-bbjlp" / "dbl-2008-bbjlp" from the Explicit-Formulas Database.
// ---------------------------------------------------------------------------------------------

export const PROJECTIVE_IDENTITY: ProjectivePoint = Object.freeze({ X: 0n, Y: 1n, Z: 1n });

export function toProjective(p: Point): ProjectivePoint {
  return { X: p.x, Y: p.y, Z: 1n };
}

export function toAffine(p: ProjectivePoint): Point {
  if (p.Z === 1n) return { x: p.X, y: p.Y };
  const zi = modInv(p.Z);
  return { x: (p.X * zi) % P, y: (p.Y * zi) % P };
}

export function projAdd(p: ProjectivePoint, q: ProjectivePoint): ProjectivePoint {
  const a = (p.Z * q.Z) % P;
  const b = (a * a) % P;
  const c = (p.X * q.X) % P;
  const d = (p.Y * q.Y) % P;
  const e = (((D * c) % P) * d) % P;
  const f = mod(b - e);
  const g = (b + e) % P;
  const x3 = (((a * f) % P) * mod(((p.X + p.Y) % P) * ((q.X + q.Y) % P) - c - d)) % P;
  const y3 = (((a * g) % P) * mod(d - A * c)) % P;
  const z3 = (f * g) % P;
  return { X: x3, Y: y3, Z: z3 };
}

export function projDouble(p: ProjectivePoint): ProjectivePoint {
  const b = (((p.X + p.Y) % P) * ((p.X + p.Y) % P)) % P;
  const c = (p.X * p.X) % P;
  const d = (p.Y * p.Y) % P;
  const e = (A * c) % P;
  const f = (e + d) % P;
  const h = (p.Z * p.Z) % P;
  const j = mod(f - 2n * h);
  const x3 = (mod(b - c - d) * j) % P;
  const y3 = (f * mod(e - d)) % P;
  const z3 = (f * j) % P;
  return { X: x3, Y: y3, Z: z3 };
}

export function projMul(p: ProjectivePoint, k: bigint): ProjectivePoint {
  return projMulUnreduced(p, mod(k, L));
}

export function projMulUnreduced(p: ProjectivePoint, k: bigint): ProjectivePoint {
  let e = k;
  let result = PROJECTIVE_IDENTITY;
  let base = p;
  while (e > 0n) {
    if (e & 1n) result = projAdd(result, base);
    base = projDouble(base);
    e >>= 1n;
  }
  return result;
}

// ---------------------------------------------------------------------------------------------
// Randomness and encoding
// ---------------------------------------------------------------------------------------------

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** Uniform scalar in [1, L) by rejection sampling. */
export function randomScalar(): bigint {
  for (;;) {
    const v = bytesToBigIntBE(randomBytes(32));
    const candidate = v >> 5n; // 251 bits, same bit-length as L
    if (candidate >= 1n && candidate < L) return candidate;
  }
}

/** Uniform field element in [1, P) by rejection sampling (for identity secrets). */
export function randomFieldElement(): bigint {
  for (;;) {
    const v = bytesToBigIntBE(randomBytes(32)) >> 2n; // 254 bits
    if (v >= 1n && v < P) return v;
  }
}

/**
 * Deterministic "nothing up my sleeve" second generator H with unknown discrete log w.r.t. G.
 * x = SHA-256("VeriVote/H/v1" ‖ counter) mod P, first x with a square RHS, smaller root, times the cofactor.
 */
export function deriveH(): { point: Point; counter: number } {
  for (let counter = 0; counter < 10_000; counter++) {
    const input = new Uint8Array([...utf8("VeriVote/H/v1"), ...bigIntToBytesBE(BigInt(counter), 4)]);
    const x = mod(bytesToBigIntBE(sha256(input)));
    const xx = (x * x) % P;
    const num = mod(1n - A * xx);
    const den = mod(1n - D * xx);
    if (den === 0n) continue;
    const rhs = (num * modInv(den)) % P;
    const root = sqrtMod(rhs);
    if (root === undefined) continue;
    const y = root < P - root ? root : P - root;
    const base = { x, y };
    if (!isOnCurve(base)) continue;
    const h = mulUnreduced(base, COFACTOR);
    if (isIdentity(h)) continue;
    return { point: h, counter };
  }
  throw new Error("deriveH: no point found");
}

/** Pedersen second generator, derived by {@link deriveH} and pinned by test. */
export const H: Point = deriveH().point;
