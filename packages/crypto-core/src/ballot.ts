/** Ballot encoding, encryption, hashing and Benaloh audit records. */
import { keccak_256 } from "@noble/hashes/sha3";
import { randomScalar, type Point, pointEquals } from "./babyjub.js";
import { encrypt, type Ciphertext } from "./elgamal.js";
import { bytesToBigIntBE, packWords } from "./encoding.js";

export interface EncryptedBallot {
  readonly k: number;
  readonly choice: number;
  readonly m: bigint[];
  readonly r: bigint[];
  readonly ciphertexts: Ciphertext[];
}

export function oneHot(choice: number, k: number): bigint[] {
  if (!Number.isInteger(choice) || choice < 0 || choice >= k) throw new Error("choice out of range");
  return Array.from({ length: k }, (_, i) => (i === choice ? 1n : 0n));
}

export function encryptBallot(pk: Point, choice: number, k: number, numCandidates: number, randomness?: readonly bigint[]): EncryptedBallot {
  if (numCandidates < 2 || numCandidates > k) throw new Error("numCandidates must be in [2, k]");
  if (choice >= numCandidates) throw new Error("choice must address an active candidate");
  const m = oneHot(choice, k);
  const r = randomness ? [...randomness] : Array.from({ length: k }, () => randomScalar());
  if (r.length !== k) throw new Error("randomness length mismatch");
  const ciphertexts = m.map((mi, i) => encrypt(pk, mi, r[i] as bigint));
  return { k, choice, m, r, ciphertexts };
}

/** keccak256(abi.encodePacked(c1[0].x, c1[0].y, …, c2[K-1].y)) as a 256-bit integer. */
export function ballotHashFull(ciphertexts: readonly Ciphertext[]): bigint {
  const words: bigint[] = [];
  for (const c of ciphertexts) words.push(c.c1.x, c.c1.y);
  for (const c of ciphertexts) words.push(c.c2.x, c.c2.y);
  return bytesToBigIntBE(keccak_256(packWords(words)));
}

/** The 224-bit truncation stored on-chain (top 224 bits of the keccak output). */
export function ballotHash224(ciphertexts: readonly Ciphertext[]): bigint {
  return ballotHashFull(ciphertexts) >> 32n;
}

/** Benaloh audit record revealed by the client when the voter chooses "audit" instead of "cast". */
export interface AuditRecord {
  readonly electionId: bigint;
  readonly publicKey: Point;
  readonly numCandidates: number;
  readonly k: number;
  readonly choice: number;
  readonly r: bigint[];
  readonly ciphertexts: Ciphertext[];
  readonly ballotHash: bigint;
}

export function makeAuditRecord(electionId: bigint, pk: Point, numCandidates: number, ballot: EncryptedBallot): AuditRecord {
  return {
    electionId,
    publicKey: pk,
    numCandidates,
    k: ballot.k,
    choice: ballot.choice,
    r: ballot.r,
    ciphertexts: ballot.ciphertexts,
    ballotHash: ballotHashFull(ballot.ciphertexts),
  };
}

/** Independent re-encryption check of an audit record. */
export function verifyAuditRecord(rec: AuditRecord): { ok: boolean; reason?: string } {
  let re: EncryptedBallot;
  try {
    re = encryptBallot(rec.publicKey, rec.choice, rec.k, rec.numCandidates, rec.r);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
  for (let i = 0; i < rec.k; i++) {
    const a = re.ciphertexts[i] as Ciphertext;
    const b = rec.ciphertexts[i];
    if (!b || !pointEquals(a.c1, b.c1) || !pointEquals(a.c2, b.c2)) return { ok: false, reason: `slot ${i} does not re-encrypt to the committed ciphertext` };
  }
  if (ballotHashFull(rec.ciphertexts) !== rec.ballotHash) return { ok: false, reason: "ballot hash mismatch" };
  return { ok: true };
}
