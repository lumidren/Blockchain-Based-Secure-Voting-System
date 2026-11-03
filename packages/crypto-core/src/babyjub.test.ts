import { describe, expect, it, beforeAll } from "vitest";
import { buildBabyjub } from "circomlibjs";
import {
  A,
  D,
  G,
  H,
  IDENTITY,
  L,
  P,
  add,
  deriveH,
  double,
  inSubgroup,
  isOnCurve,
  legendre,
  mul,
  negate,
  pointEquals,
  projAdd,
  projDouble,
  projMul,
  randomScalar,
  sqrtMod,
  toAffine,
  toProjective,
  type Point,
} from "./babyjub.js";

interface CircomBabyjub {
  Base8: [Uint8Array, Uint8Array];
  F: { toObject(v: Uint8Array): bigint; e(v: bigint): Uint8Array };
  mulPointEscalar(p: [Uint8Array, Uint8Array], e: bigint): [Uint8Array, Uint8Array];
  addPoint(a: [Uint8Array, Uint8Array], b: [Uint8Array, Uint8Array]): [Uint8Array, Uint8Array];
}

let ref: CircomBabyjub;
const toRef = (p: Point): [Uint8Array, Uint8Array] => [ref.F.e(p.x), ref.F.e(p.y)];
const fromRef = (p: [Uint8Array, Uint8Array]): Point => ({ x: ref.F.toObject(p[0]), y: ref.F.toObject(p[1]) });

beforeAll(async () => {
  ref = (await buildBabyjub()) as CircomBabyjub;
});

describe("curve parameters", () => {
  it("a is a square and d is not, so the addition law is complete", () => {
    expect(legendre(A)).toBe(1);
    expect(legendre(D)).toBe(-1);
  });
  it("G is on the curve, in the prime subgroup, and matches circomlib Base8", () => {
    expect(isOnCurve(G)).toBe(true);
    expect(inSubgroup(G)).toBe(true);
    expect(pointEquals(G, fromRef(ref.Base8))).toBe(true);
    expect(pointEquals(mul(G, L), IDENTITY)).toBe(true);
  });
  it("H is deterministic, in the subgroup and pinned", () => {
    const { point, counter } = deriveH();
    expect(pointEquals(point, H)).toBe(true);
    expect(inSubgroup(H)).toBe(true);
    expect(pointEquals(H, G)).toBe(false);
    expect(counter).toBeGreaterThanOrEqual(0);
  });
});

describe("affine arithmetic vs circomlib", () => {
  it("scalar multiplication agrees on random scalars", () => {
    for (let i = 0; i < 20; i++) {
      const k = randomScalar();
      const ours = mul(G, k);
      const theirs = fromRef(ref.mulPointEscalar(ref.Base8, k));
      expect(pointEquals(ours, theirs)).toBe(true);
    }
  });
  it("addition agrees, including doubling and identity", () => {
    const p = mul(G, randomScalar());
    const q = mul(G, randomScalar());
    expect(pointEquals(add(p, q), fromRef(ref.addPoint(toRef(p), toRef(q))))).toBe(true);
    expect(pointEquals(double(p), fromRef(ref.addPoint(toRef(p), toRef(p))))).toBe(true);
    expect(pointEquals(add(p, IDENTITY), p)).toBe(true);
    expect(pointEquals(add(p, negate(p)), IDENTITY)).toBe(true);
  });
  it("mul is linear: (a+b)G = aG + bG", () => {
    const a = randomScalar();
    const b = randomScalar();
    expect(pointEquals(mul(G, (a + b) % L), add(mul(G, a), mul(G, b)))).toBe(true);
  });
});

describe("projective arithmetic mirrors affine", () => {
  it("add/double/mul round-trip through projective coordinates", () => {
    const p = mul(G, randomScalar());
    const q = mul(G, randomScalar());
    expect(pointEquals(toAffine(projAdd(toProjective(p), toProjective(q))), add(p, q))).toBe(true);
    expect(pointEquals(toAffine(projDouble(toProjective(p))), double(p))).toBe(true);
    expect(pointEquals(toAffine(projAdd(toProjective(p), toProjective(p))), double(p))).toBe(true);
    const k = randomScalar();
    expect(pointEquals(toAffine(projMul(toProjective(p), k)), mul(p, k))).toBe(true);
    // identity handling
    expect(pointEquals(toAffine(projAdd(toProjective(p), { X: 0n, Y: 1n, Z: 1n })), p)).toBe(true);
    expect(pointEquals(toAffine(projAdd(toProjective(p), toProjective(negate(p)))), IDENTITY)).toBe(true);
  });
});

describe("field helpers", () => {
  it("sqrtMod finds roots and rejects non-residues", () => {
    for (let i = 0; i < 10; i++) {
      const x = randomScalar();
      const sq = (x * x) % P;
      const r = sqrtMod(sq);
      expect(r).toBeDefined();
      expect(((r as bigint) * (r as bigint)) % P).toBe(sq);
    }
    expect(sqrtMod(D)).toBeUndefined();
  });
});
