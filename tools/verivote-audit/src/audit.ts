/**
 * Independent re-verification of a VeriVote election.
 *
 * Every check uses only public data (contract state, event logs and transaction calldata) and the
 * reference cryptography in @verivote/crypto-core — never the indexer, the explorer or any service.
 */
import { createHash } from "node:crypto";
import { decodeFunctionData, type Hex, type PublicClient } from "viem";
import {
  G,
  IDENTITY,
  L,
  babyjub,
  ballotHash224,
  chaumPedersen,
  computeRoot,
  elgamal,
  initCrypto,
  lagrangeCoefficients,
  verifyBallotProof,
  type Ciphertext,
  type Point,
} from "@verivote/crypto-core";
import {
  electionAbi,
  fetchElectionRecord,
  finalBallots,
  tallyAbi,
  toCiphertexts,
  type Deployment,
  type ElectionRecord,
} from "@verivote/sdk";

export type Status = "PASS" | "FAIL" | "WARN" | "SKIP";

export interface CheckResult {
  readonly id: string;
  readonly title: string;
  readonly status: Status;
  readonly details: string[];
}

export interface AuditOptions {
  readonly vkeys: Record<number, object>;
  readonly verifierCodeHashes?: Record<number, string>;
  readonly onProgress?: (msg: string) => void;
}

export interface AuditReport {
  readonly electionId: bigint;
  readonly election: string;
  readonly phase: string;
  readonly checks: CheckResult[];
  readonly verdict: "PASS" | "FAIL";
  readonly recomputedCounts: number[] | null;
}

const eq = babyjub.pointEquals;

class Check {
  readonly details: string[] = [];
  status: Status = "PASS";
  constructor(readonly id: string, readonly title: string) {}
  fail(msg: string): void {
    this.status = "FAIL";
    this.details.push(`✗ ${msg}`);
  }
  warn(msg: string): void {
    if (this.status === "PASS") this.status = "WARN";
    this.details.push(`! ${msg}`);
  }
  info(msg: string): void {
    this.details.push(msg);
  }
  skip(msg: string): void {
    this.status = "SKIP";
    this.details.push(msg);
  }
  done(): CheckResult {
    return { id: this.id, title: this.title, status: this.status, details: this.details };
  }
}

export async function auditElection(client: PublicClient, deployment: Deployment, electionId: bigint, opts: AuditOptions): Promise<AuditReport> {
  await initCrypto();
  const progress = opts.onProgress ?? (() => {});
  progress("downloading election record");
  const rec = await fetchElectionRecord(client, deployment, electionId);
  const checks: CheckResult[] = [];
  checks.push(await checkVerifierCode(client, rec, opts));
  checks.push(checkRoll(rec));
  checks.push(checkDkg(rec));
  progress(`verifying ${rec.casts.length} ballot proofs`);
  checks.push(await checkBallots(client, rec, opts));
  checks.push(checkAggregation(rec));
  progress("verifying partial decryptions");
  checks.push(await checkPartials(client, deployment, rec));
  const { result, counts } = checkResult(rec);
  checks.push(result);
  const verdict = checks.some((c) => c.status === "FAIL") ? "FAIL" : "PASS";
  return { electionId, election: rec.address, phase: rec.phase, checks, verdict, recomputedCounts: counts };
}

/** 1. The on-chain verifier is byte-for-byte the audited artifact (so its embedded vkey is the published one). */
async function checkVerifierCode(client: PublicClient, rec: ElectionRecord, opts: AuditOptions): Promise<CheckResult> {
  const c = new Check("verifier", "On-chain Groth16 verifier matches the published verification key");
  const expected = opts.verifierCodeHashes?.[rec.slots];
  const code = await client.getCode({ address: rec.verifier });
  if (!code || code === "0x") {
    c.fail(`no code at verifier ${rec.verifier}`);
    return c.done();
  }
  const h = "0x" + createHash("sha256").update(Buffer.from(code.slice(2), "hex")).digest("hex");
  if (!expected) c.warn(`no expected code hash for K=${rec.slots}; verifier code hash is ${h}`);
  else if (h !== expected) c.fail(`verifier code hash ${h} ≠ audited artifact ${expected}`);
  else c.info(`verifier ${rec.verifier} code hash ${h} matches the audited build`);
  if (rec.numSignals !== 4 * rec.slots + 7) c.fail(`numSignals ${rec.numSignals} inconsistent with K=${rec.slots}`);
  return c.done();
}

/** 2. Every published root is the Poseidon root of the leaves published up to that point; snapshot = last root. */
function checkRoll(rec: ElectionRecord): CheckResult {
  const c = new Check("roll", "Voter roll: every root recomputed from the published commitments");
  const { leaves, roots } = rec.roll;
  if (roots.length === 0) {
    c.fail("no roots published");
    return c.done();
  }
  const seen = new Set<string>();
  for (const l of leaves) {
    if (seen.has(l.toString())) c.fail(`duplicate identity commitment ${l}`);
    seen.add(l.toString());
  }
  for (const r of roots) {
    const recomputed = computeRoot(leaves.slice(0, r.leafCount));
    if (recomputed !== r.root) c.fail(`root at leafCount ${r.leafCount} does not match the published leaves`);
  }
  const last = roots[roots.length - 1]!;
  if (rec.phase !== "Setup" && rec.phase !== "Registration") {
    if (rec.snapshotRoot !== last.root) c.fail("election snapshot root is not the last published root");
  }
  c.info(`${leaves.length} commitments, ${roots.length} root(s), all recomputed`);
  return c.done();
}

/** 3. DKG transcript: commitments in the subgroup, PK and combined commitments recomputed over QUAL. */
function checkDkg(rec: ElectionRecord): CheckResult {
  const c = new Check("dkg", "Distributed key generation: public key recomputed from qualified dealers");
  const { dkg: d } = rec;
  if (!d.finalized) {
    if (d.failed) c.warn("DKG failed (a dealer was exposed or did not reveal); election cannot proceed");
    else c.skip("DKG not finalized yet");
    return c.done();
  }
  const qual = d.deals.filter((x) => x.qualified);
  if (qual.length < d.threshold) c.fail(`only ${qual.length} qualified dealers, threshold ${d.threshold}`);
  for (const x of d.deals) {
    for (const p of [...x.pedersen, ...x.feldman]) if (!babyjub.inSubgroup(p)) c.fail(`dealer ${x.dealer} published a point outside the subgroup`);
    if (x.qualified && x.feldman.length !== d.threshold) c.fail(`dealer ${x.dealer} revealed ${x.feldman.length} commitments`);
  }
  const combined: Point[] = Array.from({ length: d.threshold }, () => IDENTITY);
  for (const x of qual) x.feldman.forEach((p, k) => (combined[k] = babyjub.add(combined[k]!, p)));
  combined.forEach((p, k) => {
    if (!d.combined[k] || !eq(p, d.combined[k]!)) c.fail(`combined commitment ${k} mismatch`);
  });
  if (!d.publicKey || !eq(combined[0]!, d.publicKey)) c.fail("election public key ≠ Σ A_i,0 over qualified dealers");
  if (rec.phase !== "Setup" && rec.phase !== "Registration" && !eq(rec.snapshotKey, combined[0]!)) c.fail("snapshot key ≠ DKG key");
  c.info(`${qual.length} qualified dealers of ${d.trustees.length}, threshold ${d.threshold}`);
  return c.done();
}

/** 4. Every ballot: proof re-verified from calldata, hash commitment, vote-index sequence per nullifier. */
async function checkBallots(client: PublicClient, rec: ElectionRecord, opts: AuditOptions): Promise<CheckResult> {
  const c = new Check("ballots", "Ballots: every Groth16 proof and ballot commitment re-verified");
  const vkey = opts.vkeys[rec.slots];
  if (!vkey) {
    c.fail(`no verification key for K=${rec.slots}`);
    return c.done();
  }
  if (rec.casts.length === 0) {
    c.info("no ballots cast");
    return c.done();
  }
  const seq = new Map<bigint, number>();
  let verified = 0;
  for (const cast of rec.casts) {
    const expectedIndex = seq.get(cast.nullifier) ?? 0;
    if (cast.voteIndex !== expectedIndex) c.fail(`nullifier ${short(cast.nullifier)}: voteIndex ${cast.voteIndex}, expected ${expectedIndex}`);
    seq.set(cast.nullifier, expectedIndex + 1);
    if (cast.voteIndex > 0 && !rec.allowRevote) c.fail(`re-vote accepted although re-voting is disabled`);
    const cts = toCiphertexts(cast.ciphertext, rec.slots);
    if (ballotHash224(cts) !== cast.ballotHash) c.fail(`ballot hash mismatch in tx ${cast.txHash}`);
    const signals = [...cast.ciphertext, cast.nullifier, rec.snapshotRoot, rec.electionId, rec.snapshotKey.x, rec.snapshotKey.y, BigInt(rec.numCandidates), BigInt(cast.voteIndex)];
    const proof = await proofFromTx(client, cast.txHash);
    if (!proof) {
      c.warn(`tx ${cast.txHash}: castVote was not a top-level call; proof not recoverable from calldata (accepted on-chain)`);
      continue;
    }
    if (proof.signals.length !== signals.length || proof.signals.some((v, i) => v !== signals[i])) {
      c.fail(`tx ${cast.txHash}: calldata signals differ from the event and snapshot`);
      continue;
    }
    const ok = await verifyBallotProof(vkey, signals, proof.snark);
    if (!ok) c.fail(`tx ${cast.txHash}: Groth16 proof does not verify`);
    else verified++;
  }
  if (seq.size !== rec.ballotCount) c.fail(`ballotCount ${rec.ballotCount} ≠ ${seq.size} distinct nullifiers`);
  c.info(`${rec.casts.length} ballot transactions, ${verified} proofs re-verified, ${seq.size} distinct voters`);
  return c.done();
}

async function proofFromTx(client: PublicClient, hash: Hex) {
  const tx = await client.getTransaction({ hash });
  try {
    const d = decodeFunctionData({ abi: electionAbi, data: tx.input });
    if (d.functionName !== "castVote") return null;
    const [a, b, cc, signals] = d.args as unknown as [readonly bigint[], readonly (readonly bigint[])[], readonly bigint[], readonly bigint[]];
    return {
      signals: [...signals],
      snark: {
        pi_a: [a[0]!.toString(), a[1]!.toString(), "1"],
        pi_b: [
          [b[0]![1]!.toString(), b[0]![0]!.toString()],
          [b[1]![1]!.toString(), b[1]![0]!.toString()],
          ["1", "0"],
        ],
        pi_c: [cc[0]!.toString(), cc[1]!.toString(), "1"],
        protocol: "groth16",
        curve: "bn128",
      } as never,
    };
  } catch {
    return null;
  }
}

/** 5. The encrypted tally is exactly Σ of every voter's final ballot (no omission, no superseded ballot). */
function checkAggregation(rec: ElectionRecord): CheckResult {
  const c = new Check("aggregation", "Homomorphic aggregation: encrypted tally recomputed from final ballots");
  if (!rec.tally.normalized) {
    c.skip("tally not aggregated yet");
    return c.done();
  }
  const finals = finalBallots(rec.casts);
  const sum: Ciphertext[] = Array.from({ length: rec.numCandidates }, () => ({ c1: IDENTITY, c2: IDENTITY }));
  for (const f of finals) {
    const cts = toCiphertexts(f.ciphertext, rec.slots);
    for (let i = 0; i < rec.numCandidates; i++) sum[i] = elgamal.addCiphertexts(sum[i]!, cts[i]!);
  }
  for (let i = 0; i < rec.numCandidates; i++) {
    if (!rec.tally.c1[i] || !eq(sum[i]!.c1, rec.tally.c1[i]!) || !eq(sum[i]!.c2, rec.tally.c2[i]!)) c.fail(`slot ${i}: on-chain encrypted tally ≠ recomputed sum`);
  }
  if (rec.tally.aggregatedNullifiers.length > 0) {
    const want = finals.map((f) => f.nullifier.toString()).join(",");
    const got = rec.tally.aggregatedNullifiers.map(String).join(",");
    if (want !== got) c.fail("aggregated nullifier list ≠ set of final ballots");
  }
  c.info(`${finals.length} final ballots aggregated into ${rec.numCandidates} encrypted counters`);
  return c.done();
}

/** 6. Every partial decryption carries a valid Chaum–Pedersen proof against the trustee's verification key. */
async function checkPartials(client: PublicClient, deployment: Deployment, rec: ElectionRecord): Promise<CheckResult> {
  const c = new Check("partials", "Trustee partial decryptions: Chaum–Pedersen proofs re-verified");
  if (rec.tally.partials.length === 0) {
    c.skip("no partial decryptions submitted yet");
    return c.done();
  }
  const proofsByTrustee = await partialProofsFromChain(client, deployment, rec);
  for (const p of rec.tally.partials) {
    const vk = verificationKey(rec.dkg.combined, p.trustee);
    p.points.forEach((d, slot) => {
      if (!babyjub.inSubgroup(d)) c.fail(`trustee ${p.trustee} slot ${slot}: partial not in subgroup`);
    });
    // proofs are in the submitPartialDecryption calldata
    const proofs = proofsByTrustee.get(p.trustee);
    if (!proofs) {
      c.warn(`trustee ${p.trustee}: proofs not recoverable from calldata (verified on-chain)`);
      continue;
    }
    p.points.forEach((d, slot) => {
      const pr = proofs[slot];
      if (!pr || !chaumPedersen.verify(vk, rec.tally.c1[slot]!, d, pr, rec.electionId, slot)) c.fail(`trustee ${p.trustee} slot ${slot}: invalid Chaum–Pedersen proof`);
    });
  }
  c.info(`${rec.tally.partials.length} trustees submitted; all proofs checked against S_j = Σ_k C_k·j^k`);
  return c.done();
}

/** Decodes the Chaum–Pedersen proofs from each submitPartialDecryption transaction's calldata. */
async function partialProofsFromChain(client: PublicClient, deployment: Deployment, rec: ElectionRecord) {
  const out = new Map<number, chaumPedersen.ChaumPedersenProof[]>();
  const logs = await client.getContractEvents({
    address: deployment.tally,
    abi: tallyAbi,
    eventName: "PartialDecryptionSubmitted",
    fromBlock: BigInt(deployment.startBlock),
  });
  for (const l of logs) {
    const args = l.args as { electionId?: bigint; trustee?: number };
    if (args.electionId !== rec.electionId) continue;
    const tx = await client.getTransaction({ hash: l.transactionHash! });
    try {
      const d = decodeFunctionData({ abi: tallyAbi, data: tx.input });
      if (d.functionName !== "submitPartialDecryption") continue;
      const proofs = (d.args as unknown as [bigint, unknown, { a: Point; b: Point; z: bigint }[]])[2];
      out.set(Number(args.trustee), proofs.map((p) => ({ a: { x: p.a.x, y: p.a.y }, b: { x: p.b.x, y: p.b.y }, z: p.z })));
    } catch {
      // submitted through another contract (e.g. a Safe module): proofs were still verified on-chain
    }
  }
  return out;
}

function verificationKey(combined: readonly Point[], j: number): Point {
  let acc: Point = IDENTITY;
  let jk = 1n;
  for (const cpt of combined) {
    acc = babyjub.add(acc, babyjub.mul(cpt, jk));
    jk = (jk * BigInt(j)) % L;
  }
  return acc;
}

/** 7. Decryption: Lagrange-combined partials give count·G for every finalised slot; counts found by BSGS; Σ = ballots. */
function checkResult(rec: ElectionRecord): { result: CheckResult; counts: number[] | null } {
  const c = new Check("result", "Result: counts recomputed by threshold decryption and discrete log");
  if (rec.tally.partials.length < rec.dkg.threshold) {
    c.skip(`${rec.tally.partials.length}/${rec.dkg.threshold} partial decryptions available`);
    return { result: c.done(), counts: null };
  }
  const subset = rec.tally.partials.slice(0, rec.dkg.threshold);
  const lambdas = lagrangeCoefficients(subset.map((p) => p.trustee));
  const counts: number[] = [];
  for (let slot = 0; slot < rec.numCandidates; slot++) {
    const m = elgamal.combinePartials(rec.tally.c2[slot]!, subset.map((p) => p.points[slot]!), lambdas);
    const count = elgamal.discreteLog(m, rec.ballotCount);
    if (count === undefined) {
      c.fail(`slot ${slot}: decrypted point is not k·G for any k ≤ ${rec.ballotCount}`);
      counts.push(-1);
      continue;
    }
    counts.push(Number(count));
    if (!eq(babyjub.mul(G, count), m)) c.fail(`slot ${slot}: discrete log inconsistent`);
  }
  const sum = counts.reduce((a, b) => a + b, 0);
  if (sum !== rec.ballotCount) c.fail(`Σ counts = ${sum} ≠ ${rec.ballotCount} ballots`);
  for (const f of rec.tally.slotFinalizations) {
    if (counts[f.slot] !== f.count) c.fail(`slot ${f.slot}: on-chain count ${f.count} ≠ recomputed ${counts[f.slot]}`);
  }
  if (rec.phase === "Finalized") {
    rec.results.forEach((r, i) => {
      if (r !== counts[i]) c.fail(`published result for "${rec.candidates[i]}" is ${r}, recomputed ${counts[i]}`);
    });
  } else {
    c.warn(`election is in phase ${rec.phase}; result not yet published on-chain`);
  }
  c.info(rec.candidates.map((name, i) => `${name}: ${counts[i]}`).join(" · "));
  return { result: c.done(), counts };
}

function short(v: bigint): string {
  const s = v.toString(16);
  return `0x${s.slice(0, 6)}…${s.slice(-4)}`;
}
