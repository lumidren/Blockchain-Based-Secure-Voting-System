/**
 * Groth16 prover/verifier wrapper around snarkjs and the public-signal layout of circuits/src/ballot.circom.
 * Works in Node (paths or buffers) and in browsers (fetched buffers, run inside a Web Worker).
 */
import * as snarkjs from "snarkjs";
import type { Point } from "./babyjub.js";
import type { Ciphertext } from "./elgamal.js";
import type { MerkleProof } from "./merkle.js";
import type { EncryptedBallot } from "./ballot.js";

export interface Groth16Proof {
  readonly pi_a: [string, string, string];
  readonly pi_b: [[string, string], [string, string], [string, string]];
  readonly pi_c: [string, string, string];
  readonly protocol: "groth16";
  readonly curve: "bn128";
}

export interface BallotWitnessInput {
  readonly secret: bigint;
  readonly merkleProof: MerkleProof;
  readonly ballot: EncryptedBallot;
  readonly electionId: bigint;
  readonly publicKey: Point;
  readonly numCandidates: number;
  readonly voteIndex: number;
}

export interface BallotPublicSignals {
  readonly k: number;
  readonly ciphertexts: Ciphertext[];
  readonly nullifier: bigint;
  readonly root: bigint;
  readonly electionId: bigint;
  readonly publicKey: Point;
  readonly numCandidates: bigint;
  readonly voteIndex: bigint;
}

export interface SolidityProof {
  readonly a: [bigint, bigint];
  readonly b: [[bigint, bigint], [bigint, bigint]];
  readonly c: [bigint, bigint];
}

export type ArtifactSource = string | Uint8Array | { type: "mem"; data: Uint8Array };

export function witnessInput(input: BallotWitnessInput): Record<string, unknown> {
  const { merkleProof, ballot } = input;
  return {
    sk: input.secret.toString(),
    pathElements: merkleProof.pathElements.map(String),
    pathIndices: merkleProof.pathIndices.map(String),
    m: ballot.m.map(String),
    r: ballot.r.map(String),
    root: merkleProof.root.toString(),
    electionId: input.electionId.toString(),
    pk: [input.publicKey.x.toString(), input.publicKey.y.toString()],
    numCandidates: String(input.numCandidates),
    voteIndex: String(input.voteIndex),
  };
}

/** Number of public signals for a K-slot circuit: 4K ciphertext coordinates + nullifier + 6 public inputs. */
export function publicSignalCount(k: number): number {
  return 4 * k + 7;
}

export function parsePublicSignals(signals: readonly (string | bigint)[]): BallotPublicSignals {
  const n = signals.length;
  if ((n - 7) % 4 !== 0 || n < 7 + 8) throw new Error(`unexpected public signal count ${n}`);
  const k = (n - 7) / 4;
  const s = signals.map((v) => BigInt(v));
  const ciphertexts: Ciphertext[] = [];
  for (let i = 0; i < k; i++) {
    ciphertexts.push({
      c1: { x: s[2 * i] as bigint, y: s[2 * i + 1] as bigint },
      c2: { x: s[2 * k + 2 * i] as bigint, y: s[2 * k + 2 * i + 1] as bigint },
    });
  }
  const base = 4 * k;
  return {
    k,
    ciphertexts,
    nullifier: s[base] as bigint,
    root: s[base + 1] as bigint,
    electionId: s[base + 2] as bigint,
    publicKey: { x: s[base + 3] as bigint, y: s[base + 4] as bigint },
    numCandidates: s[base + 5] as bigint,
    voteIndex: s[base + 6] as bigint,
  };
}

export function serializePublicSignals(ps: BallotPublicSignals): bigint[] {
  const out: bigint[] = [];
  for (const c of ps.ciphertexts) out.push(c.c1.x, c.c1.y);
  for (const c of ps.ciphertexts) out.push(c.c2.x, c.c2.y);
  out.push(ps.nullifier, ps.root, ps.electionId, ps.publicKey.x, ps.publicKey.y, ps.numCandidates, ps.voteIndex);
  return out;
}

/** Convert a snarkjs proof to the (a, b, c) layout expected by the generated Solidity verifier. */
export function toSolidityProof(proof: Groth16Proof): SolidityProof {
  return {
    a: [BigInt(proof.pi_a[0]), BigInt(proof.pi_a[1])],
    // snarkjs' Solidity calldata swaps the inner coordinates of pi_b
    b: [
      [BigInt(proof.pi_b[0][1]), BigInt(proof.pi_b[0][0])],
      [BigInt(proof.pi_b[1][1]), BigInt(proof.pi_b[1][0])],
    ],
    c: [BigInt(proof.pi_c[0]), BigInt(proof.pi_c[1])],
  };
}

export function fromSolidityProof(p: SolidityProof): Groth16Proof {
  return {
    pi_a: [p.a[0].toString(), p.a[1].toString(), "1"],
    pi_b: [
      [p.b[0][1].toString(), p.b[0][0].toString()],
      [p.b[1][1].toString(), p.b[1][0].toString()],
      ["1", "0"],
    ],
    pi_c: [p.c[0].toString(), p.c[1].toString(), "1"],
    protocol: "groth16",
    curve: "bn128",
  };
}

export interface ProveResult {
  readonly proof: Groth16Proof;
  readonly publicSignals: string[];
  readonly parsed: BallotPublicSignals;
  readonly timings: { witnessMs: number; proveMs: number };
}

/**
 * Generate a Groth16 proof. `wasm` and `zkey` may be file paths (Node) or byte buffers (browser).
 * `onProgress` receives coarse stage updates; snarkjs does not expose finer-grained progress.
 */
export async function proveBallot(
  input: BallotWitnessInput,
  wasm: ArtifactSource,
  zkey: ArtifactSource,
  onProgress?: (stage: "witness" | "prove" | "done", elapsedMs: number) => void,
): Promise<ProveResult> {
  const t0 = performance.now();
  onProgress?.("witness", 0);
  const wtns = { type: "mem" } as { type: "mem"; data?: Uint8Array };
  await snarkjs.wtns.calculate(witnessInput(input), normalizeSource(wasm), wtns);
  const t1 = performance.now();
  onProgress?.("prove", t1 - t0);
  const { proof, publicSignals } = await snarkjs.groth16.prove(normalizeSource(zkey), wtns as { type: "mem"; data: Uint8Array });
  const t2 = performance.now();
  onProgress?.("done", t2 - t0);
  return {
    proof: proof as Groth16Proof,
    publicSignals: publicSignals as string[],
    parsed: parsePublicSignals(publicSignals as string[]),
    timings: { witnessMs: t1 - t0, proveMs: t2 - t1 },
  };
}

export async function verifyBallotProof(vkey: object, publicSignals: readonly (string | bigint)[], proof: Groth16Proof): Promise<boolean> {
  return snarkjs.groth16.verify(vkey, publicSignals.map(String), proof);
}

function normalizeSource(src: ArtifactSource): string | { type: "mem"; data: Uint8Array } {
  if (typeof src === "string") return src;
  if (src instanceof Uint8Array) return { type: "mem", data: src };
  return src;
}
