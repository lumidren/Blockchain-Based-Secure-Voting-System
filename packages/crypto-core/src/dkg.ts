/**
 * Pedersen VSS distributed key generation with Feldman reveal (GJKR-style, abort on reveal failure).
 * Trustee indices are 1-based. All scalar arithmetic is mod L (the Baby Jubjub subgroup order).
 */
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { gcm } from "@noble/ciphers/aes";
import {
  G,
  H,
  IDENTITY,
  L,
  add,
  inSubgroup,
  mul,
  pointEquals,
  randomScalar,
  type Point,
} from "./babyjub.js";
import { evalPoly } from "./lagrange.js";
import { bigIntToBytesBE, bytesToBigIntBE, concatBytes, utf8 } from "./encoding.js";

export interface DealerSecrets {
  readonly coeffsA: bigint[]; // a_{i,0..t-1}
  readonly coeffsB: bigint[]; // b_{i,0..t-1}
}

export interface Deal {
  readonly dealerIndex: number;
  readonly pedersen: Point[]; // C_{i,k} = a_k G + b_k H
  readonly feldman: Point[]; // A_{i,k} = a_k G (kept secret until the reveal phase)
  readonly shares: SharePair[]; // index j-1 holds (s_{i,j}, s'_{i,j})
  readonly encryptedShares: Uint8Array[]; // ECIES to each trustee's encryption key
}

export interface SharePair {
  readonly s: bigint;
  readonly sPrime: bigint;
}

export interface DkgParams {
  readonly n: number;
  readonly t: number;
  readonly electionId: bigint;
}

export function validateParams(p: DkgParams): void {
  if (!Number.isInteger(p.n) || !Number.isInteger(p.t)) throw new Error("n and t must be integers");
  if (p.t < 2 || p.t > p.n || p.n > 32) throw new Error("require 2 ≤ t ≤ n ≤ 32");
}

export function samplePolynomial(t: number): bigint[] {
  return Array.from({ length: t }, () => randomScalar());
}

/** Dealer i creates its contribution. `encryptionKeys[j-1]` is EK_j. */
export function deal(
  params: DkgParams,
  dealerIndex: number,
  encryptionKeys: readonly Point[],
  secrets: DealerSecrets = { coeffsA: samplePolynomial(params.t), coeffsB: samplePolynomial(params.t) },
): Deal {
  validateParams(params);
  if (dealerIndex < 1 || dealerIndex > params.n) throw new Error("dealer index out of range");
  if (encryptionKeys.length !== params.n) throw new Error("need one encryption key per trustee");
  const { coeffsA, coeffsB } = secrets;
  if (coeffsA.length !== params.t || coeffsB.length !== params.t) throw new Error("polynomial degree mismatch");
  const pedersen = coeffsA.map((a, k) => add(mul(G, a), mul(H, coeffsB[k] as bigint)));
  const feldman = coeffsA.map((a) => mul(G, a));
  const shares: SharePair[] = [];
  const encryptedShares: Uint8Array[] = [];
  for (let j = 1; j <= params.n; j++) {
    const pair = { s: evalPoly(coeffsA, BigInt(j)), sPrime: evalPoly(coeffsB, BigInt(j)) };
    shares.push(pair);
    encryptedShares.push(encryptShare(encryptionKeys[j - 1] as Point, pair, params.electionId, dealerIndex, j));
  }
  return { dealerIndex, pedersen, feldman, shares, encryptedShares };
}

/** Σ_k C_k · j^k */
export function evalCommitments(commitments: readonly Point[], j: number): Point {
  let acc: Point = IDENTITY;
  let jk = 1n;
  for (const c of commitments) {
    acc = add(acc, mul(c, jk));
    jk = (jk * BigInt(j)) % L;
  }
  return acc;
}

/** s·G + s'·H == Σ C_k j^k */
export function verifyPedersenShare(j: number, pair: SharePair, pedersen: readonly Point[]): boolean {
  if (!pedersen.every(inSubgroup)) return false;
  const lhs = add(mul(G, pair.s), mul(H, pair.sPrime));
  return pointEquals(lhs, evalCommitments(pedersen, j));
}

/** s·G == Σ A_k j^k */
export function verifyFeldmanShare(j: number, s: bigint, feldman: readonly Point[]): boolean {
  if (!feldman.every(inSubgroup)) return false;
  return pointEquals(mul(G, s), evalCommitments(feldman, j));
}

/** Trustee j combines the shares received from every qualified dealer. */
export function combineShares(shares: readonly bigint[]): bigint {
  return shares.reduce((acc, s) => (acc + s) % L, 0n);
}

/** PK = Σ_{i∈QUAL} A_{i,0}; combined[k] = Σ_i A_{i,k}. */
export function combineFeldman(feldmanByDealer: readonly (readonly Point[])[]): { publicKey: Point; combined: Point[] } {
  if (feldmanByDealer.length === 0) throw new Error("no qualified dealers");
  const t = (feldmanByDealer[0] as readonly Point[]).length;
  const combined: Point[] = Array.from({ length: t }, () => IDENTITY);
  for (const fel of feldmanByDealer) {
    if (fel.length !== t) throw new Error("inconsistent commitment lengths");
    for (let k = 0; k < t; k++) combined[k] = add(combined[k] as Point, fel[k] as Point);
  }
  return { publicKey: combined[0] as Point, combined };
}

/** S_j = Σ_k combined_k · j^k = s_j·G */
export function verificationKey(combined: readonly Point[], j: number): Point {
  return evalCommitments(combined, j);
}

// ------------------------------------------------------------------------------------------
// ECIES share delivery: R = e·G, Z = e·EK_j, key = HKDF-SHA256(Z.x, salt, info), AES-256-GCM.
// Layout: R.x(32) ‖ R.y(32) ‖ iv(12) ‖ ciphertext(64) ‖ tag(16) = 156 bytes.
// ------------------------------------------------------------------------------------------

const SALT = utf8("VeriVote/DKG/v1");

function info(electionId: bigint, i: number, j: number): Uint8Array {
  return concatBytes(bigIntToBytesBE(electionId, 32), bigIntToBytesBE(BigInt(i), 4), bigIntToBytesBE(BigInt(j), 4));
}

function deriveKey(shared: Point, electionId: bigint, i: number, j: number): Uint8Array {
  return hkdf(sha256, bigIntToBytesBE(shared.x, 32), SALT, info(electionId, i, j), 32);
}

export function encryptShare(ek: Point, pair: SharePair, electionId: bigint, i: number, j: number, e: bigint = randomScalar()): Uint8Array {
  if (!inSubgroup(ek)) throw new Error("encryption key not in subgroup");
  const r = mul(G, e);
  const shared = mul(ek, e);
  const key = deriveKey(shared, electionId, i, j);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const aad = info(electionId, i, j);
  const plaintext = concatBytes(bigIntToBytesBE(pair.s, 32), bigIntToBytesBE(pair.sPrime, 32));
  const ct = gcm(key, iv, aad).encrypt(plaintext); // ciphertext ‖ tag
  return concatBytes(bigIntToBytesBE(r.x, 32), bigIntToBytesBE(r.y, 32), iv, ct);
}

export function decryptShare(ekSecret: bigint, blob: Uint8Array, electionId: bigint, i: number, j: number): SharePair {
  if (blob.length !== 156) throw new Error("malformed share blob");
  const r = { x: bytesToBigIntBE(blob.subarray(0, 32)), y: bytesToBigIntBE(blob.subarray(32, 64)) };
  if (!inSubgroup(r)) throw new Error("ephemeral key not in subgroup");
  const iv = blob.subarray(64, 76);
  const ct = blob.subarray(76);
  const shared = mul(r, ekSecret);
  const key = deriveKey(shared, electionId, i, j);
  const pt = gcm(key, iv, info(electionId, i, j)).decrypt(ct);
  const s = bytesToBigIntBE(pt.subarray(0, 32));
  const sPrime = bytesToBigIntBE(pt.subarray(32, 64));
  if (s >= L || sPrime >= L) throw new Error("share out of range");
  return { s, sPrime };
}

/** Full local simulation of the protocol — used by tests and the load-test harness. */
export function simulateDkg(params: DkgParams, encryptionSecrets: readonly bigint[]) {
  validateParams(params);
  const eks = encryptionSecrets.map((k) => mul(G, k));
  const deals = Array.from({ length: params.n }, (_, i) => deal(params, i + 1, eks));
  for (const d of deals) {
    for (let j = 1; j <= params.n; j++) {
      const pair = decryptShare(encryptionSecrets[j - 1] as bigint, d.encryptedShares[j - 1] as Uint8Array, params.electionId, d.dealerIndex, j);
      if (!verifyPedersenShare(j, pair, d.pedersen)) throw new Error(`pedersen check failed for dealer ${d.dealerIndex}, trustee ${j}`);
      if (!verifyFeldmanShare(j, pair.s, d.feldman)) throw new Error(`feldman check failed for dealer ${d.dealerIndex}, trustee ${j}`);
    }
  }
  const { publicKey, combined } = combineFeldman(deals.map((d) => d.feldman));
  const shares = Array.from({ length: params.n }, (_, jIdx) => combineShares(deals.map((d) => (d.shares[jIdx] as SharePair).s)));
  const verificationKeys = Array.from({ length: params.n }, (_, jIdx) => verificationKey(combined, jIdx + 1));
  return { deals, publicKey, combined, shares, verificationKeys };
}
