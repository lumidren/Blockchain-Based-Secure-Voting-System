import { describe, expect, it } from "vitest";
import { G, L, mul, pointEquals, randomScalar } from "./babyjub.js";
import { combinePartials, discreteLog, encrypt, partialDecrypt, sumCiphertexts } from "./elgamal.js";
import { lagrangeCoefficients } from "./lagrange.js";
import * as cp from "./chaum-pedersen.js";
import { deal, decryptShare, simulateDkg, verifyFeldmanShare, verifyPedersenShare, type SharePair } from "./dkg.js";

const electionId = 123456789n;

describe("Pedersen/Feldman DKG", () => {
  it("5 trustees, threshold 3: shares verify, keys combine, any 3 reconstruct", () => {
    const params = { n: 5, t: 3, electionId };
    const ekSecrets = Array.from({ length: 5 }, () => randomScalar());
    const sim = simulateDkg(params, ekSecrets);
    expect(sim.deals.length).toBe(5);
    // verification keys are s_j·G
    for (let j = 1; j <= 5; j++) {
      expect(pointEquals(mul(G, sim.shares[j - 1]!), sim.verificationKeys[j - 1]!)).toBe(true);
    }
    // any 3 trustees reconstruct the secret behind PK
    for (const subset of [[1, 2, 3], [2, 4, 5], [1, 3, 5]]) {
      const lambdas = lagrangeCoefficients(subset);
      const secret = subset.reduce((acc, j, i) => (acc + lambdas[i]! * sim.shares[j - 1]!) % L, 0n);
      expect(pointEquals(mul(G, secret), sim.publicKey)).toBe(true);
    }
    // two trustees cannot (sanity: wrong lambdas for a 2-subset don't reconstruct)
    const lambdas2 = lagrangeCoefficients([1, 2]);
    const wrong = (lambdas2[0]! * sim.shares[0]! + lambdas2[1]! * sim.shares[1]!) % L;
    expect(pointEquals(mul(G, wrong), sim.publicKey)).toBe(false);
  });

  it("threshold decryption of a homomorphic tally with Chaum–Pedersen proofs", () => {
    const params = { n: 5, t: 3, electionId };
    const ekSecrets = Array.from({ length: 5 }, () => randomScalar());
    const sim = simulateDkg(params, ekSecrets);
    const votes = [1n, 0n, 1n, 1n, 1n, 0n, 1n]; // 5 yes
    const tally = sumCiphertexts(votes.map((m) => encrypt(sim.publicKey, m)));
    const subset = [1, 3, 4];
    const partials = subset.map((j) => {
      const { d, proof } = cp.prove(sim.shares[j - 1]!, sim.verificationKeys[j - 1]!, tally.c1, electionId, 0);
      expect(cp.verify(sim.verificationKeys[j - 1]!, tally.c1, d, proof, electionId, 0)).toBe(true);
      expect(cp.verify(sim.verificationKeys[j - 1]!, tally.c1, d, proof, electionId, 1)).toBe(false);
      expect(pointEquals(d, partialDecrypt(tally.c1, sim.shares[j - 1]!))).toBe(true);
      return d;
    });
    const m = combinePartials(tally.c2, partials, lagrangeCoefficients(subset));
    expect(discreteLog(m, votes.length)).toBe(5n);
  });

  it("detects a dealer that sends an inconsistent share", () => {
    const params = { n: 3, t: 2, electionId };
    const ekSecrets = [randomScalar(), randomScalar(), randomScalar()];
    const eks = ekSecrets.map((k) => mul(G, k));
    const d = deal(params, 1, eks);
    const good = decryptShare(ekSecrets[1]!, d.encryptedShares[1]!, electionId, 1, 2);
    expect(verifyPedersenShare(2, good, d.pedersen)).toBe(true);
    expect(verifyFeldmanShare(2, good.s, d.feldman)).toBe(true);
    const bad: SharePair = { s: (good.s + 1n) % L, sPrime: good.sPrime };
    expect(verifyPedersenShare(2, bad, d.pedersen)).toBe(false);
    expect(verifyFeldmanShare(2, bad.s, d.feldman)).toBe(false);
    // wrong recipient cannot decrypt (AES-GCM authentication fails)
    expect(() => decryptShare(ekSecrets[2]!, d.encryptedShares[1]!, electionId, 1, 2)).toThrow();
    // wrong context (i, j) fails too
    expect(() => decryptShare(ekSecrets[1]!, d.encryptedShares[1]!, electionId, 1, 3)).toThrow();
  });

  it("rejects invalid parameters", () => {
    expect(() => simulateDkg({ n: 2, t: 3, electionId }, [1n, 2n])).toThrow();
    expect(() => simulateDkg({ n: 3, t: 1, electionId }, [1n, 2n, 3n])).toThrow();
  });
});
