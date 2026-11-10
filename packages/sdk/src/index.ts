/**
 * @verivote/sdk — chain access for VeriVote.
 *
 * `fetchElectionRecord` reconstructs everything that is public about one election purely from contract
 * state and event logs. It is the single source of data for the audit CLI, the indexer and the explorer, so
 * all three see exactly the same facts.
 */
import {
  type Address,
  type Hex,
  type PublicClient,
  type Log,
  getAddress,
  parseEventLogs,
} from "viem";
import type { Ciphertext, Point } from "@verivote/crypto-core";
import { electionAbi, tallyAbi, trusteeCoordinatorAbi, veriVoteFactoryAbi, voterRegistryAbi } from "./abi/index.js";

export * from "./abi/index.js";

export interface Deployment {
  chainId: number;
  name: string;
  factory: Address;
  registry: Address;
  coordinator: Address;
  tally: Address;
  timelock: Address;
  verifiers: Record<string, Address>;
  electionImplementation: Address;
  startBlock: number;
}

export const PHASES = ["Setup", "Registration", "Voting", "Tallying", "Finalized", "Aborted"] as const;
export type PhaseName = (typeof PHASES)[number];

export interface CastRecord {
  nullifier: bigint;
  voteIndex: number;
  ballotHash: bigint;
  ciphertext: bigint[];
  blockNumber: bigint;
  txHash: Hex;
  logIndex: number;
}

export interface DealRecord {
  dealer: number;
  pedersen: Point[];
  feldman: Point[];
  encryptedShares: Hex[];
  disqualified: boolean;
  qualified: boolean;
}

export interface ElectionRecord {
  electionId: bigint;
  address: Address;
  title: string;
  metadataURI: string;
  candidates: string[];
  slots: number;
  numCandidates: number;
  allowRevote: boolean;
  phase: PhaseName;
  paused: boolean;
  schedule: { registrationStart: number; votingStart: number; votingEnd: number; tallyDeadline: number };
  snapshotRoot: bigint;
  snapshotKey: Point;
  ballotCount: number;
  results: number[];
  roll: { leaves: bigint[]; roots: { root: bigint; leafCount: number; blockNumber: bigint }[] };
  dkg: {
    trustees: Address[];
    threshold: number;
    finalized: boolean;
    failed: boolean;
    publicKey: Point | null;
    combined: Point[];
    encryptionKeys: (Point | null)[];
    deals: DealRecord[];
  };
  casts: CastRecord[];
  tally: {
    normalized: boolean;
    finalized: boolean;
    aggregatedCount: number;
    c1: Point[];
    c2: Point[];
    partials: { trustee: number; points: Point[] }[];
    slotFinalizations: { slot: number; count: number; trustees: number[] }[];
    aggregatedNullifiers: bigint[];
  };
  verifier: Address;
  numSignals: number;
}

const pt = (p: { x: bigint; y: bigint }): Point => ({ x: p.x, y: p.y });

async function logsInRange(client: PublicClient, address: Address, fromBlock: bigint, toBlock: bigint, step = 9_000n): Promise<Log[]> {
  const out: Log[] = [];
  for (let start = fromBlock; start <= toBlock; start += step) {
    const end = start + step - 1n > toBlock ? toBlock : start + step - 1n;
    out.push(...(await client.getLogs({ address, fromBlock: start, toBlock: end })));
  }
  return out;
}

/** Loads every public fact about an election from chain state and logs. */
export async function fetchElectionRecord(
  client: PublicClient,
  deployment: Deployment,
  electionId: bigint,
  opts: { toBlock?: bigint } = {},
): Promise<ElectionRecord> {
  const toBlock = opts.toBlock ?? (await client.getBlockNumber());
  const fromBlock = BigInt(deployment.startBlock);
  const address = (await client.readContract({
    address: deployment.factory,
    abi: veriVoteFactoryAbi,
    functionName: "electionAddress",
    args: [electionId],
  })) as Address;
  if (address === "0x0000000000000000000000000000000000000000") throw new Error(`unknown election ${electionId}`);
  const e = { address, abi: electionAbi } as const;
  const read = <T>(functionName: string, args: readonly unknown[] = []) =>
    client.readContract({ ...e, functionName, args, blockNumber: toBlock } as never) as Promise<T>;

  const [title, metadataURI, candidates, slots, numCandidates, allowRevote, phase, paused, schedule, snapshotRoot, snapshotKey, ballotCount, results, verifier, numSignals] =
    await Promise.all([
      read<string>("title"),
      read<string>("metadataURI"),
      read<string[]>("candidates"),
      read<number>("slots"),
      read<number>("numCandidates"),
      read<boolean>("allowRevote"),
      read<number>("phase"),
      read<boolean>("paused"),
      read<readonly [bigint, bigint, bigint, bigint]>("schedule"),
      read<bigint>("snapshotRoot"),
      read<readonly [bigint, bigint]>("snapshotKey"),
      read<number>("ballotCount"),
      read<number[]>("results"),
      read<Address>("verifier"),
      read<number>("numSignals"),
    ]);

  // ---- events ----
  const [electionLogs, registryLogs, coordLogs, tallyLogs] = await Promise.all([
    logsInRange(client, address, fromBlock, toBlock),
    logsInRange(client, deployment.registry, fromBlock, toBlock),
    logsInRange(client, deployment.coordinator, fromBlock, toBlock),
    logsInRange(client, deployment.tally, fromBlock, toBlock),
  ]);

  const casts: CastRecord[] = parseEventLogs({ abi: electionAbi, logs: electionLogs, eventName: "BallotCast" }).map((l) => ({
    nullifier: l.args.nullifier,
    voteIndex: Number(l.args.voteIndex),
    ballotHash: l.args.ballotHash,
    ciphertext: [...l.args.ciphertext],
    blockNumber: l.blockNumber,
    txHash: l.transactionHash,
    logIndex: l.logIndex,
  }));

  const leavesEvents = parseEventLogs({ abi: voterRegistryAbi, logs: registryLogs, eventName: "LeavesAppended" })
    .filter((l) => l.args.electionId === electionId)
    .sort((a, b) => a.args.startIndex - b.args.startIndex);
  const leaves: bigint[] = [];
  for (const l of leavesEvents) {
    if (l.args.startIndex !== leaves.length) throw new Error(`gap in leaf stream at ${leaves.length}`);
    leaves.push(...l.args.leaves);
  }
  const roots = parseEventLogs({ abi: voterRegistryAbi, logs: registryLogs, eventName: "RootPublished" })
    .filter((l) => l.args.electionId === electionId)
    .map((l) => ({ root: l.args.root, leafCount: Number(l.args.leafCount), blockNumber: l.blockNumber }));

  // ---- DKG ----
  const c = { address: deployment.coordinator, abi: trusteeCoordinatorAbi } as const;
  const readC = <T>(functionName: string, args: readonly unknown[]) =>
    client.readContract({ ...c, functionName, args, blockNumber: toBlock } as never) as Promise<T>;
  const trustees = await readC<Address[]>("trustees", [electionId]);
  const threshold = await readC<number>("threshold", [electionId]);
  const finalized = await readC<boolean>("isFinalized", [electionId]);
  const [failed] = await readC<readonly [boolean, number]>("isFailed", [electionId]);
  const combined = (await readC<{ x: bigint; y: bigint }[]>("combinedCommitments", [electionId])).map(pt);
  const delivered = parseEventLogs({ abi: trusteeCoordinatorAbi, logs: coordLogs, eventName: "SharesDelivered" }).filter(
    (l) => l.args.electionId === electionId,
  );
  const deals: DealRecord[] = [];
  const encryptionKeys: (Point | null)[] = [];
  for (let i = 1; i <= trustees.length; i++) {
    const ek = await readC<{ x: bigint; y: bigint }>("encryptionKey", [electionId, i]);
    encryptionKeys.push(ek.y === 0n ? null : pt(ek));
    const [dealt, , disqualified, , qualified] = await readC<readonly [boolean, boolean, boolean, number, boolean]>("dealerState", [electionId, i]);
    if (!dealt) continue;
    const pedersen = (await readC<{ x: bigint; y: bigint }[]>("pedersenCommitments", [electionId, i])).map(pt);
    const feldman = (await readC<{ x: bigint; y: bigint }[]>("feldmanCommitments", [electionId, i])).map(pt);
    const shares = delivered.find((l) => l.args.dealer === i);
    deals.push({ dealer: i, pedersen, feldman, encryptedShares: shares ? [...shares.args.encryptedShares] : [], disqualified, qualified });
  }

  // ---- tally ----
  const t = { address: deployment.tally, abi: tallyAbi } as const;
  const status = (await client.readContract({ ...t, functionName: "status", args: [electionId], blockNumber: toBlock })) as readonly [
    number, boolean, boolean, number, number, number, bigint,
  ];
  const [c1, c2] = (await client.readContract({ ...t, functionName: "encryptedTally", args: [electionId], blockNumber: toBlock })) as readonly [
    { x: bigint; y: bigint }[],
    { x: bigint; y: bigint }[],
  ];
  const partials = parseEventLogs({ abi: tallyAbi, logs: tallyLogs, eventName: "PartialDecryptionSubmitted" })
    .filter((l) => l.args.electionId === electionId)
    .map((l) => {
      const flat = l.args.partials;
      const points: Point[] = [];
      for (let i = 0; i < flat.length; i += 2) points.push({ x: flat[i]!, y: flat[i + 1]! });
      return { trustee: Number(l.args.trustee), points };
    });
  const slotFinalizations = parseEventLogs({ abi: tallyAbi, logs: tallyLogs, eventName: "SlotFinalized" })
    .filter((l) => l.args.electionId === electionId)
    .map((l) => ({ slot: Number(l.args.slot), count: Number(l.args.count), trustees: l.args.trustees.map(Number) }));
  // the aggregation calldata is the authoritative list of aggregated ballots
  const aggregatedNullifiers: bigint[] = [];
  const aggTxs = parseEventLogs({ abi: tallyAbi, logs: tallyLogs, eventName: "BallotsAggregated" }).filter((l) => l.args.electionId === electionId);
  for (const l of aggTxs) {
    const tx = await client.getTransaction({ hash: l.transactionHash });
    const { decodeFunctionData } = await import("viem");
    try {
      const decoded = decodeFunctionData({ abi: tallyAbi, data: tx.input });
      if (decoded.functionName === "aggregate") {
        for (const b of (decoded.args as unknown as [bigint, { nullifier: bigint }[]])[1]) aggregatedNullifiers.push(b.nullifier);
      }
    } catch {
      // aggregated through a contract (e.g. a Safe): fall back to the event's count only
    }
  }

  return {
    electionId,
    address: getAddress(address),
    title,
    metadataURI,
    candidates: [...candidates],
    slots: Number(slots),
    numCandidates: Number(numCandidates),
    allowRevote,
    phase: PHASES[Number(phase)]!,
    paused,
    schedule: {
      registrationStart: Number(schedule[0]),
      votingStart: Number(schedule[1]),
      votingEnd: Number(schedule[2]),
      tallyDeadline: Number(schedule[3]),
    },
    snapshotRoot,
    snapshotKey: { x: snapshotKey[0], y: snapshotKey[1] },
    ballotCount: Number(ballotCount),
    results: results.map(Number),
    roll: { leaves, roots },
    dkg: {
      trustees: [...trustees],
      threshold: Number(threshold),
      finalized,
      failed,
      publicKey: finalized ? combined[0] ?? null : null,
      combined,
      encryptionKeys,
      deals,
    },
    casts,
    tally: {
      normalized: status[1],
      finalized: status[2],
      aggregatedCount: Number(status[5]),
      c1: c1.map(pt),
      c2: c2.map(pt),
      partials,
      slotFinalizations,
      aggregatedNullifiers,
    },
    verifier: getAddress(verifier),
    numSignals: Number(numSignals),
  };
}

/** Latest ballot of every nullifier, sorted by nullifier (the order Tally.aggregate requires). */
export function finalBallots(casts: readonly CastRecord[]): CastRecord[] {
  const latest = new Map<bigint, CastRecord>();
  for (const c of casts) {
    const prev = latest.get(c.nullifier);
    if (!prev || c.voteIndex > prev.voteIndex) latest.set(c.nullifier, c);
  }
  return [...latest.values()].sort((a, b) => (a.nullifier < b.nullifier ? -1 : a.nullifier > b.nullifier ? 1 : 0));
}

/** Splits the circuit's ciphertext words into per-slot ciphertexts. */
export function toCiphertexts(words: readonly bigint[], slots: number): Ciphertext[] {
  if (words.length !== 4 * slots) throw new Error("ciphertext length mismatch");
  return Array.from({ length: slots }, (_, i) => ({
    c1: { x: words[2 * i]!, y: words[2 * i + 1]! },
    c2: { x: words[2 * slots + 2 * i]!, y: words[2 * slots + 2 * i + 1]! },
  }));
}

export function loadDeployment(json: unknown): Deployment {
  const d = json as Deployment;
  for (const k of ["factory", "registry", "coordinator", "tally"] as const) {
    if (!d[k] || !/^0x[0-9a-fA-F]{40}$/.test(d[k])) throw new Error(`deployment.${k} missing or invalid`);
  }
  return { ...d, startBlock: Number(d.startBlock ?? 0) };
}
