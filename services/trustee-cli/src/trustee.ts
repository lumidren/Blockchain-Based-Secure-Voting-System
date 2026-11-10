/**
 * Trustee protocol logic, independent of the CLI so that the demo, load test and web client reuse it.
 * Every step reads public data from the contracts, does its local computation, and submits one transaction.
 */
import type { Account, Address, Chain, Hex, PublicClient, Transport, WalletClient } from "viem";
import { parseEventLogs } from "viem";
import {
  G,
  L,
  babyjub,
  chaumPedersen,
  dkg,
  bytesToHex,
  hexToBytes,
  type Point,
  type DealerSecrets,
  type SharePair,
} from "@verivote/crypto-core";
import { tallyAbi, trusteeCoordinatorAbi, type Deployment } from "@verivote/sdk";

/** Everything a trustee must keep secret, stored encrypted in the keystore. */
export interface TrusteeState {
  readonly version: 1;
  readonly address: Address;
  readonly elections: Record<string, ElectionSecrets>;
}

export interface ElectionSecrets {
  electionId: bigint;
  index: number;
  n: number;
  t: number;
  encryptionSecret: bigint;
  dealer?: DealerSecrets;
  /** pairs received from each dealer (1-based dealer index as key) */
  received: Record<string, SharePair>;
  /** dealers this trustee complained about */
  complained: number[];
  share?: bigint;
  verificationKey?: Point;
  partialsSubmitted?: boolean;
}

export type Wallet = WalletClient<Transport, Chain, Account>;

export interface Ctx {
  readonly publicClient: PublicClient;
  readonly wallet: Wallet;
  readonly deployment: Deployment;
  readonly log?: (msg: string) => void;
}

const coord = (ctx: Ctx) => ({ address: ctx.deployment.coordinator, abi: trusteeCoordinatorAbi }) as const;

async function send(ctx: Ctx, functionName: string, args: readonly unknown[], address?: Address, abi?: unknown): Promise<Hex> {
  const target = address ? { address, abi } : coord(ctx);
  const { request } = await ctx.publicClient.simulateContract({
    ...(target as { address: Address; abi: typeof trusteeCoordinatorAbi }),
    functionName,
    args,
    account: ctx.wallet.account,
  } as never);
  const hash = await ctx.wallet.writeContract(request as never);
  const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") throw new Error(`${functionName} reverted (${hash})`);
  ctx.log?.(`${functionName} ✓ ${hash} (gas ${receipt.gasUsed})`);
  return hash;
}

async function read<T>(ctx: Ctx, functionName: string, args: readonly unknown[]): Promise<T> {
  return ctx.publicClient.readContract({ ...coord(ctx), functionName, args } as never) as Promise<T>;
}

const P = (p: { x: bigint; y: bigint }): Point => ({ x: p.x, y: p.y });

/** Creates the per-election secrets (encryption key) for this trustee. */
export async function prepare(ctx: Ctx, state: TrusteeState, electionId: bigint): Promise<ElectionSecrets> {
  const key = electionId.toString();
  const existing = state.elections[key];
  if (existing) return existing;
  const index = await read<number>(ctx, "trusteeIndex", [electionId, ctx.wallet.account.address]);
  if (index === 0) throw new Error("this account is not a trustee of the election");
  const n = await read<number>(ctx, "trusteeCount", [electionId]);
  const t = await read<number>(ctx, "threshold", [electionId]);
  const secrets: ElectionSecrets = {
    electionId,
    index,
    n,
    t,
    encryptionSecret: babyjub.randomScalar(),
    received: {},
    complained: [],
  };
  state.elections[key] = secrets;
  return secrets;
}

export async function registerKey(ctx: Ctx, s: ElectionSecrets): Promise<Hex> {
  const ek = babyjub.mul(G, s.encryptionSecret);
  return send(ctx, "registerKey", [s.electionId, { x: ek.x, y: ek.y }]);
}

/** Deals Pedersen commitments and encrypted shares to every trustee that registered a key. */
export async function deal(ctx: Ctx, s: ElectionSecrets): Promise<Hex> {
  const eks: (Point | null)[] = [];
  for (let j = 1; j <= s.n; j++) {
    const ek = await read<{ x: bigint; y: bigint }>(ctx, "encryptionKey", [s.electionId, j]);
    eks.push(ek.y === 0n ? null : P(ek));
  }
  s.dealer ??= { coeffsA: dkg.samplePolynomial(s.t), coeffsB: dkg.samplePolynomial(s.t) };
  // inactive trustees get an empty blob; use G as a placeholder key for the local computation only
  const keysForDeal = eks.map((k) => k ?? G);
  const d = dkg.deal({ n: s.n, t: s.t, electionId: s.electionId }, s.index, keysForDeal, s.dealer);
  const blobs = d.encryptedShares.map((b, i) => (eks[i] ? bytesToHex(b) : ("0x" as Hex)));
  // keep our own pair locally (we are also a recipient)
  s.received[String(s.index)] = d.shares[s.index - 1]!;
  return send(ctx, "deal", [s.electionId, d.pedersen.map((p) => ({ x: p.x, y: p.y })), blobs]);
}

/** Decrypts and verifies the pairs dealt to this trustee; files a complaint for every bad one. */
export async function verifyShares(ctx: Ctx, s: ElectionSecrets, fromBlock: bigint): Promise<{ ok: number[]; complained: number[] }> {
  const logs = await ctx.publicClient.getLogs({ address: ctx.deployment.coordinator, fromBlock, toBlock: "latest" });
  const delivered = parseEventLogs({ abi: trusteeCoordinatorAbi, logs, eventName: "SharesDelivered" }).filter((l) => l.args.electionId === s.electionId);
  const ok: number[] = [];
  const complained: number[] = [];
  for (const l of delivered) {
    const i = Number(l.args.dealer);
    if (i === s.index) {
      ok.push(i);
      continue;
    }
    const pedersen = (await read<{ x: bigint; y: bigint }[]>(ctx, "pedersenCommitments", [s.electionId, i])).map(P);
    let valid = false;
    try {
      const blob = hexToBytes(l.args.encryptedShares[s.index - 1]!);
      const pair = dkg.decryptShare(s.encryptionSecret, blob, s.electionId, i, s.index);
      valid = dkg.verifyPedersenShare(s.index, pair, pedersen);
      if (valid) s.received[String(i)] = pair;
    } catch {
      valid = false;
    }
    if (valid) ok.push(i);
    else if (!s.complained.includes(i)) {
      await send(ctx, "complain", [s.electionId, i]);
      s.complained.push(i);
      complained.push(i);
    }
  }
  return { ok, complained };
}

/** Answers complaints against this trustee by publishing the disputed pair (verified on-chain). */
export async function answerComplaints(ctx: Ctx, s: ElectionSecrets): Promise<number[]> {
  if (!s.dealer) return [];
  const answered: number[] = [];
  for (let j = 1; j <= s.n; j++) {
    const state = await read<number>(ctx, "complaintState", [s.electionId, s.index, j]);
    if (state !== 1) continue; // 1 = Open
    const pair = { s: evalPoly(s.dealer.coeffsA, j), sPrime: evalPoly(s.dealer.coeffsB, j) };
    await send(ctx, "justify", [s.electionId, j, pair.s, pair.sPrime]);
    answered.push(j);
  }
  return answered;
}

export async function reveal(ctx: Ctx, s: ElectionSecrets): Promise<Hex> {
  if (!s.dealer) throw new Error("nothing dealt");
  const feldman = s.dealer.coeffsA.map((a) => babyjub.mul(G, a));
  return send(ctx, "reveal", [s.electionId, feldman.map((p) => ({ x: p.x, y: p.y }))]);
}

/** Checks every revealed dealer's Feldman commitments against the received pair; exposes inconsistent ones. */
export async function checkReveals(ctx: Ctx, s: ElectionSecrets): Promise<number[]> {
  const exposed: number[] = [];
  for (const [dealerKey, pair] of Object.entries(s.received)) {
    const i = Number(dealerKey);
    if (i === s.index) continue;
    const [, revealed] = await read<readonly [boolean, boolean, boolean, number, boolean]>(ctx, "dealerState", [s.electionId, i]);
    if (!revealed) continue;
    const feldman = (await read<{ x: bigint; y: bigint }[]>(ctx, "feldmanCommitments", [s.electionId, i])).map(P);
    if (!dkg.verifyFeldmanShare(s.index, pair.s, feldman)) {
      await send(ctx, "exposeReveal", [s.electionId, i, pair.s, pair.sPrime]);
      exposed.push(i);
    }
  }
  return exposed;
}

export async function finalizeDkg(ctx: Ctx, electionId: bigint): Promise<Hex | null> {
  if (await read<boolean>(ctx, "isFinalized", [electionId])) return null;
  return send(ctx, "finalize", [electionId]);
}

/** Combines the pairs of qualified dealers into this trustee's share and checks it against S_j on-chain. */
export async function computeShare(ctx: Ctx, s: ElectionSecrets): Promise<bigint> {
  let share = 0n;
  for (let i = 1; i <= s.n; i++) {
    const [, , , , qualified] = await read<readonly [boolean, boolean, boolean, number, boolean]>(ctx, "dealerState", [s.electionId, i]);
    if (!qualified) continue;
    const pair = s.received[String(i)];
    if (!pair) throw new Error(`missing share from qualified dealer ${i}`);
    share = (share + pair.s) % L;
  }
  const vk = P(await read<{ x: bigint; y: bigint }>(ctx, "verificationKey", [s.electionId, s.index]));
  if (!babyjub.pointEquals(babyjub.mul(G, share), vk)) throw new Error("combined share does not match the on-chain verification key");
  s.share = share;
  s.verificationKey = vk;
  return share;
}

/** Partial decryption of the normalised tally with one Chaum–Pedersen proof per active slot. */
export async function submitPartialDecryption(ctx: Ctx, s: ElectionSecrets): Promise<Hex> {
  if (s.share === undefined || !s.verificationKey) throw new Error("share not computed");
  const [c1] = (await ctx.publicClient.readContract({
    address: ctx.deployment.tally,
    abi: tallyAbi,
    functionName: "encryptedTally",
    args: [s.electionId],
  })) as readonly [{ x: bigint; y: bigint }[], { x: bigint; y: bigint }[]];
  const partials: Point[] = [];
  const proofs: { a: Point; b: Point; z: bigint }[] = [];
  c1.forEach((c, slot) => {
    const { d, proof } = chaumPedersen.prove(s.share!, s.verificationKey!, P(c), s.electionId, slot);
    if (!chaumPedersen.verify(s.verificationKey!, P(c), d, proof, s.electionId, slot)) throw new Error("self-check of proof failed");
    partials.push(d);
    proofs.push(proof);
  });
  const hash = await send(
    ctx,
    "submitPartialDecryption",
    [s.electionId, partials.map((p) => ({ x: p.x, y: p.y })), proofs.map((p) => ({ a: { x: p.a.x, y: p.a.y }, b: { x: p.b.x, y: p.b.y }, z: p.z }))],
    ctx.deployment.tally,
    tallyAbi,
  );
  s.partialsSubmitted = true;
  return hash;
}

function evalPoly(coeffs: readonly bigint[], x: number): bigint {
  let acc = 0n;
  for (let k = coeffs.length - 1; k >= 0; k--) acc = (acc * BigInt(x) + coeffs[k]!) % L;
  return acc;
}
