/**
 * Quickstart demo: a full election with 5 trustees (threshold 3) and 100 voters on the local chain, followed
 * by an independent audit. Usage: pnpm --filter @verivote/load-test demo [-- --voters 100 --relayer http://…]
 */
import { parseArgs } from "node:util";
import { resolve } from "node:path";
import { runElection } from "./runner.js";

const { values } = parseArgs({
  options: {
    rpc: { type: "string", default: process.env.VERIVOTE_RPC_URL ?? "http://127.0.0.1:8545" },
    deployment: { type: "string", default: resolve(import.meta.dirname, "../../../contracts/deployments/local.json") },
    voters: { type: "string", default: "100" },
    relayer: { type: "string" },
    slots: { type: "string", default: "4" },
  },
});

const started = performance.now();
const res = await runElection({
  rpc: values.rpc!,
  deploymentFile: values.deployment!,
  voters: Number(values.voters),
  trustees: 5,
  threshold: 3,
  slots: Number(values.slots) as 4 | 8,
  candidates: ["Ada Lovelace", "Alan Turing", "Grace Hopper"],
  revoteFraction: 0.1,
  ...(values.relayer ? { relayerUrl: values.relayer } : {}),
  log: (m) => console.log(m),
});

console.log("\nResult");
res.onChain.forEach((n, i) => console.log(`  candidate ${i + 1}: ${n} (expected ${res.expected[i]})`));
console.log(`\nAudit verdict: ${res.audit.verdict}`);
for (const c of res.audit.checks) console.log(`  [${c.status}] ${c.title}`);
console.log(`\nTotal ${(performance.now() - started) / 1000 | 0} s · castVote gas avg ${res.gas.castVoteAvg}`);
const ok = res.audit.verdict === "PASS" && res.onChain.every((n, i) => n === res.expected[i]);
process.exit(ok ? 0 : 1);
