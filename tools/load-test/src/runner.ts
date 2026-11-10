/**
 * Runs a complete VeriVote election against a local chain (Anvil), exercising the real code paths:
 * factory → registrar batches → trustee DKG (trustee library) → voter proofs (snarkjs, worker pool) →
 * submission (relayer HTTP or direct) → re-votes → aggregation → threshold decryption → verivote-audit.
 */
import { Worker } from "node:worker_threads";
import { cpus } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  defineChain,
  http,
  parseEventLogs,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { mnemonicToAccount, nonceManager } from "viem/accounts";
import {
  PoseidonMerkleTree,
  elgamal,
  encryptBallot,
  generateIdentity,
  initCrypto,
  lagrangeCoefficients,
  toSolidityProof,
  witnessInput,
  type Identity,
  type Point,
} from "@verivote/crypto-core";
import { electionAbi, finalBallots, loadDeployment, tallyAbi, veriVoteFactoryAbi, voterRegistryAbi, fetchElectionRecord, type Deployment } from "@verivote/sdk";
import * as trustee from "@verivote/trustee-cli";
import { auditElection, type AuditReport } from "@verivote/audit";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../../..");
/** Anvil's public development mnemonic (test accounts only — never use on a real network). */
const ANVIL_MNEMONIC = "test test test test test test test test test test test junk";

export interface RunOptions {
  rpc: string;
  deploymentFile: string;
  voters: number;
  trustees: number;
  threshold: number;
  slots: 4 | 8;
  candidates: string[];
  revoteFraction: number;
  relayerUrl?: string;
  workers?: number;
  log?: (msg: string) => void;
}

export interface RunResult {
  electionId: bigint;
  election: Address;
  expected: number[];
  onChain: number[];
  audit: AuditReport;
  timings: Record<string, number>;
  proofMs: number[];
  submitMs: number[];
  gas: { castVoteAvg: number; castVoteMax: number; castVoteSamples: number };
}

const account = (i: number) => mnemonicToAccount(ANVIL_MNEMONIC, { addressIndex: i, nonceManager });

export async function runElection(o: RunOptions): Promise<RunResult> {
  const log = o.log ?? (() => {});
  const timings: Record<string, number> = {};
  const lap = (() => {
    let last = performance.now();
    return (name: string) => {
      const now = performance.now();
      timings[name] = Math.round(now - last);
      last = now;
    };
  })();

  await initCrypto();
  const deployment: Deployment = loadDeployment(JSON.parse(readFileSync(o.deploymentFile, "utf8")));
  const chain = defineChain({
    id: deployment.chainId,
    name: "anvil",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [o.rpc] } },
  });
  const transport = http(o.rpc, { batch: false, timeout: 120_000 });
  const pub = createPublicClient({ chain, transport }) as PublicClient;
  const test = createTestClient({ chain, transport, mode: "anvil" });
  const wallet = (i: number) => createWalletClient({ chain, transport, account: account(i) });
  const admin = wallet(0);
  const registrar = wallet(2);
  const trusteeWallets = Array.from({ length: o.trustees }, (_, i) => wallet(3 + i));
  const submitter = wallet(3 + o.trustees);

  const now = async () => Number((await pub.getBlock()).timestamp);
  const warpTo = async (t: number) => {
    const cur = await now();
    if (t > cur) await test.increaseTime({ seconds: t - cur });
    await test.mine({ blocks: 1 });
  };
  const write = async (w: ReturnType<typeof wallet>, address: Address, abi: unknown, functionName: string, args: readonly unknown[]) => {
    const hash = await w.writeContract({ address, abi, functionName, args, chain } as never);
    const r = await pub.waitForTransactionReceipt({ hash });
    if (r.status !== "success") throw new Error(`${functionName} reverted`);
    return r;
  };

  // ---------------------------------------------------------------- create
  const t0 = await now();
  const sched = {
    registrationStart: t0 + 60,
    dkg: [t0 + 300, t0 + 600, t0 + 900, t0 + 1200, t0 + 1500, t0 + 1800],
    votingStart: t0 + 1900,
    votingEnd: t0 + 1900 + 3600,
    tallyDeadline: t0 + 1900 + 3600 + 3600,
  };
  const createRcpt = await write(admin, deployment.factory, veriVoteFactoryAbi, "createElection", [
    {
      admin: admin.account.address,
      registrar: registrar.account.address,
      title: `Demo election (${o.voters} voters)`,
      metadataURI: "ipfs://verivote-demo",
      candidates: o.candidates,
      slots: o.slots,
      allowRevote: true,
      registrationStart: BigInt(sched.registrationStart),
      votingStart: BigInt(sched.votingStart),
      votingEnd: BigInt(sched.votingEnd),
      tallyDeadline: BigInt(sched.tallyDeadline),
      trustees: trusteeWallets.map((w) => w.account.address),
      threshold: o.threshold,
      dkgSchedule: sched.dkg.map(BigInt),
    },
  ]);
  const created = parseEventLogs({ abi: veriVoteFactoryAbi, logs: createRcpt.logs, eventName: "ElectionCreated" })[0]!;
  const electionId = created.args.electionId;
  const election = created.args.election;
  log(`election ${electionId} at ${election}`);
  lap("create");

  // ---------------------------------------------------------------- registration
  await warpTo(sched.registrationStart);
  await write(admin, election, electionAbi, "advance", []);
  const voters: Identity[] = Array.from({ length: o.voters }, () => generateIdentity());
  const tree = new PoseidonMerkleTree(20);
  const BATCH = 1000;
  for (let i = 0; i < voters.length; i += BATCH) {
    const batch = voters.slice(i, i + BATCH).map((v) => v.commitment);
    tree.insertMany(batch);
    await write(registrar, deployment.registry, voterRegistryAbi, "publishRoot", [electionId, tree.root, batch, tree.leafCount]);
  }
  log(`roll published: ${tree.leafCount} commitments, root ${tree.root.toString(16).slice(0, 12)}…`);
  lap("registration");

  // ---------------------------------------------------------------- DKG with the trustee library
  const ctxs = trusteeWallets.map((w) => ({ publicClient: pub, wallet: w as never, deployment }) as trustee.Ctx);
  const states = trusteeWallets.map((w) => ({ version: 1 as const, address: w.account.address, elections: {} }) as trustee.TrusteeState);
  const secrets = await Promise.all(ctxs.map((c, i) => trustee.prepare(c, states[i]!, electionId)));
  for (let i = 0; i < ctxs.length; i++) await trustee.registerKey(ctxs[i]!, secrets[i]!);
  await warpTo(sched.dkg[0]! + 1);
  for (let i = 0; i < ctxs.length; i++) await trustee.deal(ctxs[i]!, secrets[i]!);
  await warpTo(sched.dkg[1]! + 1);
  for (let i = 0; i < ctxs.length; i++) {
    const r = await trustee.verifyShares(ctxs[i]!, secrets[i]!, BigInt(deployment.startBlock));
    if (r.complained.length) log(`trustee ${i + 1} complained about ${r.complained}`);
  }
  await warpTo(sched.dkg[3]! + 1);
  for (let i = 0; i < ctxs.length; i++) await trustee.reveal(ctxs[i]!, secrets[i]!);
  await warpTo(sched.dkg[4]! + 1);
  for (let i = 0; i < ctxs.length; i++) {
    const exposed = await trustee.checkReveals(ctxs[i]!, secrets[i]!);
    if (exposed.length) throw new Error(`trustee ${i + 1} exposed ${exposed}`);
  }
  await warpTo(sched.dkg[5]! + 1);
  await trustee.finalizeDkg(ctxs[0]!, electionId);
  for (let i = 0; i < ctxs.length; i++) await trustee.computeShare(ctxs[i]!, secrets[i]!);
  log(`DKG finalized: ${o.threshold}-of-${o.trustees}`);
  lap("dkg");

  await warpTo(sched.votingStart);
  await write(admin, election, electionAbi, "advance", []);
  const [pkx, pky] = (await pub.readContract({ address: election, abi: electionAbi, functionName: "snapshotKey" })) as readonly [bigint, bigint];
  const pk: Point = { x: pkx, y: pky };
  lap("toVoting");

  // ---------------------------------------------------------------- voting
  const numCandidates = o.candidates.length;
  const choices = voters.map(() => Math.floor(Math.random() * numCandidates));
  const revoters = new Set<number>();
  for (let i = 0; i < voters.length; i++) if (Math.random() < o.revoteFraction) revoters.add(i);
  const finalChoice = [...choices];
  interface Job { voter: number; choice: number; voteIndex: number }
  const jobs: Job[] = voters.map((_, i) => ({ voter: i, choice: choices[i]!, voteIndex: 0 }));
  for (const v of revoters) {
    const c = Math.floor(Math.random() * numCandidates);
    finalChoice[v] = c;
    jobs.push({ voter: v, choice: c, voteIndex: 1 });
  }

  const k = o.slots;
  const art = {
    wasmPath: resolve(repo, `circuits/build/ballot_k${k}/ballot_k${k}_js/ballot_k${k}.wasm`),
    zkeyPath: resolve(repo, `circuits/build/ballot_k${k}/ballot_k${k}_final.zkey`),
  };
  const nWorkers = Math.max(1, o.workers ?? Math.min(cpus().length - 2, 12));
  const pool = Array.from({ length: nWorkers }, () => new Worker(resolve(here, "prover-worker.mjs"), { workerData: art }));
  const proofMs: number[] = [];
  const submitMs: number[] = [];
  const castGas: bigint[] = [];

  const prove = (w: Worker, id: number, input: Record<string, unknown>) =>
    new Promise<{ proof: never; publicSignals: string[]; ms: number }>((resolveP, reject) => {
      const onMsg = (m: { id: number; error?: string; proof: never; publicSignals: string[]; ms: number }) => {
        if (m.id !== id) return;
        w.off("message", onMsg);
        if (m.error) reject(new Error(m.error));
        else resolveP(m);
      };
      w.on("message", onMsg);
      w.postMessage({ id, input });
    });

  const submit = async (proof: ReturnType<typeof toSolidityProof>, signals: bigint[]): Promise<Hex> => {
    const t = performance.now();
    let hash: Hex;
    if (o.relayerUrl) {
      const res = await fetch(`${o.relayerUrl}/v1/relay`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          election,
          proof: { a: proof.a.map(String), b: proof.b.map((r) => r.map(String)), c: proof.c.map(String) },
          signals: signals.map(String),
        }),
      });
      const body = (await res.json()) as { txHash?: Hex; error?: string };
      if (!res.ok || !body.txHash) throw new Error(`relayer: ${body.error ?? res.status}`);
      hash = body.txHash;
    } else {
      hash = await submitter.writeContract({ address: election, abi: electionAbi, functionName: "castVote", args: [proof.a, proof.b, proof.c, signals], chain, gas: 1_500_000n } as never);
    }
    submitMs.push(performance.now() - t);
    return hash;
  };

  // first votes and re-votes are separate waves: a re-vote must land after the first vote (voteIndex order)
  const runWave = async (wave: Job[]) => {
    const hashes: Hex[] = [];
    let next = 0;
    let done = 0;
    const lastLog = { t: performance.now() };
    await Promise.all(
      pool.map(async (w, wi) => {
        for (;;) {
          const idx = next++;
          if (idx >= wave.length) return;
          const job = wave[idx]!;
          const ballot = encryptBallot(pk, job.choice, k, numCandidates);
          const input = witnessInput({
            secret: voters[job.voter]!.secret,
            merkleProof: tree.proof(job.voter),
            ballot,
            electionId,
            publicKey: pk,
            numCandidates,
            voteIndex: job.voteIndex,
          });
          const res = await prove(w, wi * 1_000_000 + idx, input);
          proofMs.push(res.ms);
          hashes.push(await submit(toSolidityProof(res.proof as never), res.publicSignals.map(BigInt)));
          done++;
          if (performance.now() - lastLog.t > 10_000) {
            lastLog.t = performance.now();
            log(`  ${done}/${wave.length} ballots proven and submitted`);
          }
        }
      }),
    );
    // confirm every transaction
    for (const h of hashes) {
      const r = await pub.waitForTransactionReceipt({ hash: h, timeout: 300_000 });
      if (r.status !== "success") throw new Error(`castVote reverted: ${h}`);
      castGas.push(r.gasUsed);
    }
  };
  await runWave(jobs.filter((j) => j.voteIndex === 0));
  lap("votingFirst");
  await runWave(jobs.filter((j) => j.voteIndex === 1));
  lap("votingRevotes");
  for (const w of pool) await w.terminate();
  log(`${jobs.length} ballots cast (${revoters.size} re-votes)`);

  // ---------------------------------------------------------------- tally
  await warpTo(sched.votingEnd);
  await write(admin, election, electionAbi, "advance", []);
  const rec = await fetchElectionRecord(pub, deployment, electionId);
  const finals = finalBallots(rec.casts);
  for (let i = 0; i < finals.length; i += 128) {
    const batch = finals.slice(i, i + 128).map((f) => ({ nullifier: f.nullifier, ciphertext: f.ciphertext }));
    await write(admin, deployment.tally, tallyAbi, "aggregate", [electionId, batch]);
  }
  await write(admin, deployment.tally, tallyAbi, "normalize", [electionId]);
  lap("aggregate");

  for (let i = 0; i < o.threshold; i++) await trustee.submitPartialDecryption(ctxs[i]!, secrets[i]!);
  const [, c2] = (await pub.readContract({ address: deployment.tally, abi: tallyAbi, functionName: "encryptedTally", args: [electionId] })) as readonly [
    { x: bigint; y: bigint }[],
    { x: bigint; y: bigint }[],
  ];
  const subset = Array.from({ length: o.threshold }, (_, i) => i + 1);
  const lambdas = lagrangeCoefficients(subset);
  const partials = await Promise.all(
    subset.map((j) => pub.readContract({ address: deployment.tally, abi: tallyAbi, functionName: "partialDecryptions", args: [electionId, j] }) as Promise<{ x: bigint; y: bigint }[]>),
  );
  for (let slot = 0; slot < numCandidates; slot++) {
    const m = elgamal.combinePartials(c2[slot]!, partials.map((p) => p[slot]!), lambdas);
    const count = elgamal.discreteLog(m, voters.length);
    if (count === undefined) throw new Error(`slot ${slot}: discrete log not found`);
    await write(admin, deployment.tally, tallyAbi, "finalizeSlot", [electionId, slot, Number(count), subset]);
  }
  lap("decrypt");

  const onChain = ((await pub.readContract({ address: election, abi: electionAbi, functionName: "results" })) as readonly number[]).map(Number);
  const expected = Array.from({ length: numCandidates }, () => 0);
  finalChoice.forEach((c) => expected[c]!++);

  // ---------------------------------------------------------------- independent audit
  const vkeys = { [k]: JSON.parse(readFileSync(resolve(repo, `circuits/build/ballot_k${k}/ballot_k${k}_vkey.json`), "utf8")) };
  const hashesFile = resolve(repo, "tools/verivote-audit/dist/artifacts/verifier-code-hashes.json");
  let verifierCodeHashes: Record<number, string> | undefined;
  try {
    verifierCodeHashes = JSON.parse(readFileSync(hashesFile, "utf8"));
  } catch {
    verifierCodeHashes = undefined;
  }
  const audit = await auditElection(pub, deployment, electionId, { vkeys, ...(verifierCodeHashes ? { verifierCodeHashes } : {}) });
  lap("audit");

  const gasNums = castGas.map(Number);
  return {
    electionId,
    election,
    expected,
    onChain,
    audit,
    timings,
    proofMs,
    submitMs,
    gas: {
      castVoteAvg: Math.round(gasNums.reduce((a, b) => a + b, 0) / Math.max(1, gasNums.length)),
      castVoteMax: Math.max(0, ...gasNums),
      castVoteSamples: gasNums.length,
    },
  };
}
