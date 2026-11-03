import { describe, expect, it } from "vitest";
import { G, IDENTITY, add, mul, pointEquals, randomScalar } from "./babyjub.js";
import { addCiphertexts, combinePartials, decrypt, decryptToPoint, discreteLog, encrypt, generateKeyPair, partialDecrypt, sumCiphertexts } from "./elgamal.js";
import { lagrangeCoefficients, evalPoly } from "./lagrange.js";

describe("exponential ElGamal", () => {
  it("round-trips small messages", () => {
    const kp = generateKeyPair();
    for (const m of [0n, 1n, 2n, 17n, 1000n]) {
      const ct = encrypt(kp.publicKey, m);
      expect(decrypt(ct, kp.secret, 2000)).toBe(m);
    }
  });
  it("is additively homomorphic", () => {
    const kp = generateKeyPair();
    const cts = [1n, 0n, 1n, 1n, 0n, 1n].map((m) => encrypt(kp.publicKey, m));
    const sum = sumCiphertexts(cts);
    expect(decrypt(sum, kp.secret, 10)).toBe(4n);
    expect(decrypt(addCiphertexts(cts[0]!, cts[2]!), kp.secret, 10)).toBe(2n);
  });
  it("rejects zero or out-of-range randomness", () => {
    const kp = generateKeyPair();
    expect(() => encrypt(kp.publicKey, 1n, 0n)).toThrow();
  });
  it("BSGS finds exponents up to the bound and reports out-of-range", () => {
    expect(discreteLog(IDENTITY, 10)).toBe(0n);
    expect(discreteLog(mul(G, 12345n), 20000)).toBe(12345n);
    expect(discreteLog(mul(G, 20000n), 20000)).toBe(20000n);
    expect(discreteLog(mul(G, 30000n), 20000)).toBeUndefined();
  });
  it("threshold decryption with Lagrange-combined partials matches direct decryption", () => {
    // secret x shared with a degree-2 polynomial among 5 trustees
    const coeffs = [randomScalar(), randomScalar(), randomScalar()];
    const x = coeffs[0]!;
    const pk = mul(G, x);
    const shares = [1, 2, 3, 4, 5].map((j) => evalPoly(coeffs, BigInt(j)));
    const ct = sumCiphertexts([1n, 1n, 0n, 1n].map((m) => encrypt(pk, m)));
    const subset = [2, 4, 5];
    const lambdas = lagrangeCoefficients(subset);
    const partials = subset.map((j) => partialDecrypt(ct.c1, shares[j - 1]!));
    const m = combinePartials(ct.c2, partials, lambdas);
    expect(pointEquals(m, decryptToPoint(ct, x))).toBe(true);
    expect(discreteLog(m, 10)).toBe(3n);
    // reconstructed secret equals x
    const rec = subset.reduce((acc, j, i) => (acc + lambdas[i]! * shares[j - 1]!) % 2736030358979909402780800718157159386076813972158567259200215660948447373041n, 0n);
    expect(rec).toBe(x);
    expect(pointEquals(add(IDENTITY, pk), pk)).toBe(true);
  });
});
