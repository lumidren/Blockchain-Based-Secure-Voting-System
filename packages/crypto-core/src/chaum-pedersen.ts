/**
 * Chaum–Pedersen proof of discrete-log equality used for partial decryptions:
 *   prove log_G(S) = log_{C1}(D) (= s) without revealing s.
 * Fiat–Shamir challenge: keccak256(abi.encodePacked(DST, electionId, slot, S, C1, D, A, B)) mod L,
 * byte-for-byte the computation in contracts/src/libraries/ChaumPedersen.sol.
 */
import { keccak_256 } from "@noble/hashes/sha3";
import { G, L, add, mul, pointEquals, randomScalar, type Point, inSubgroup } from "./babyjub.js";
import { bytesToBigIntBE, packWords, utf8 } from "./encoding.js";

export const CP_DOMAIN: bigint = bytesToBigIntBE(keccak_256(utf8("VeriVote/CP/v1")));

export interface ChaumPedersenProof {
  readonly a: Point;
  readonly b: Point;
  readonly z: bigint;
}

export function challenge(electionId: bigint, slot: number, s: Point, c1: Point, d: Point, a: Point, b: Point): bigint {
  const words = [CP_DOMAIN, electionId, BigInt(slot), s.x, s.y, c1.x, c1.y, d.x, d.y, a.x, a.y, b.x, b.y];
  return bytesToBigIntBE(keccak_256(packWords(words))) % L;
}

export function prove(
  share: bigint,
  verificationKey: Point,
  c1: Point,
  electionId: bigint,
  slot: number,
  w: bigint = randomScalar(),
): { d: Point; proof: ChaumPedersenProof } {
  const d = mul(c1, share);
  const a = mul(G, w);
  const b = mul(c1, w);
  const e = challenge(electionId, slot, verificationKey, c1, d, a, b);
  const z = (w + e * share) % L;
  return { d, proof: { a, b, z } };
}

export function verify(
  verificationKey: Point,
  c1: Point,
  d: Point,
  proof: ChaumPedersenProof,
  electionId: bigint,
  slot: number,
): boolean {
  if (proof.z < 0n || proof.z >= L) return false;
  if (!inSubgroup(d) || !inSubgroup(proof.a) || !inSubgroup(proof.b)) return false;
  const e = challenge(electionId, slot, verificationKey, c1, d, proof.a, proof.b);
  const lhs1 = mul(G, proof.z);
  const rhs1 = add(proof.a, mul(verificationKey, e));
  if (!pointEquals(lhs1, rhs1)) return false;
  const lhs2 = mul(c1, proof.z);
  const rhs2 = add(proof.b, mul(d, e));
  return pointEquals(lhs2, rhs2);
}
