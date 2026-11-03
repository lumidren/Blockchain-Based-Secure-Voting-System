import { beforeAll, describe, expect, it } from "vitest";
import { initCrypto, poseidon2 } from "./poseidon.js";
import { PoseidonMerkleTree, computeRoot, verifyMerkleProof, zeroHashes } from "./merkle.js";
import { generateIdentity, identityCommitment, nullifierFor } from "./identity.js";
import { encryptBallot, ballotHash224, ballotHashFull, makeAuditRecord, verifyAuditRecord } from "./ballot.js";
import { generateKeyPair } from "./elgamal.js";
import { parsePublicSignals, serializePublicSignals, publicSignalCount } from "./prover.js";

beforeAll(async () => {
  await initCrypto();
});

describe("Poseidon Merkle tree", () => {
  it("empty tree root equals the depth-th zero hash", () => {
    const t = new PoseidonMerkleTree(20);
    expect(t.root).toBe(zeroHashes(20)[20]);
    expect(zeroHashes(20)[1]).toBe(poseidon2(0n, 0n));
  });
  it("proofs verify and roots are recomputable from leaves", () => {
    const t = new PoseidonMerkleTree(20);
    const ids = Array.from({ length: 37 }, () => generateIdentity());
    for (const id of ids) t.insert(id.commitment);
    expect(t.leafCount).toBe(37);
    for (const idx of [0, 1, 17, 36]) {
      const proof = t.proof(idx);
      expect(verifyMerkleProof(proof)).toBe(true);
      expect(proof.pathElements.length).toBe(20);
    }
    const tampered = { ...t.proof(5), leaf: 42n };
    expect(verifyMerkleProof(tampered)).toBe(false);
    expect(computeRoot(t.leaves, 20)).toBe(t.root);
  });
  it("small depth tree matches manual hashing", () => {
    const t = new PoseidonMerkleTree(2, [1n, 2n, 3n]);
    const expected = poseidon2(poseidon2(1n, 2n), poseidon2(3n, 0n));
    expect(t.root).toBe(expected);
  });
});

describe("identity and ballot helpers", () => {
  it("commitment and nullifier are Poseidon of the right arity", () => {
    const id = generateIdentity();
    expect(identityCommitment(id.secret)).toBe(id.commitment);
    expect(nullifierFor(id.secret, 7n)).not.toBe(nullifierFor(id.secret, 8n));
  });
  it("ballot hash truncation and audit record verification", () => {
    const kp = generateKeyPair();
    const b = encryptBallot(kp.publicKey, 1, 4, 3);
    expect(b.m).toEqual([0n, 1n, 0n, 0n]);
    expect(ballotHash224(b.ciphertexts)).toBe(ballotHashFull(b.ciphertexts) >> 32n);
    const rec = makeAuditRecord(9n, kp.publicKey, 3, b);
    expect(verifyAuditRecord(rec).ok).toBe(true);
    const lying = { ...rec, choice: 2 };
    expect(verifyAuditRecord(lying).ok).toBe(false);
    expect(() => encryptBallot(kp.publicKey, 3, 4, 3)).toThrow();
  });
  it("public signal layout round-trips", () => {
    const kp = generateKeyPair();
    const b = encryptBallot(kp.publicKey, 0, 4, 2);
    const ps = {
      k: 4,
      ciphertexts: b.ciphertexts,
      nullifier: 11n,
      root: 22n,
      electionId: 33n,
      publicKey: kp.publicKey,
      numCandidates: 2n,
      voteIndex: 0n,
    };
    const ser = serializePublicSignals(ps);
    expect(ser.length).toBe(publicSignalCount(4));
    const back = parsePublicSignals(ser.map(String));
    expect(back.nullifier).toBe(11n);
    expect(back.ciphertexts[3]!.c2.y).toBe(b.ciphertexts[3]!.c2.y);
    expect(back.publicKey.x).toBe(kp.publicKey.x);
  });
});
