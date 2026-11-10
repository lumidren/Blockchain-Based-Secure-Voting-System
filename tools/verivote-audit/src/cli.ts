#!/usr/bin/env node
/**
 * verivote-audit — universal verifiability for VeriVote elections.
 *
 *   verivote-audit election --rpc <url> --deployment deployments/sepolia.json --election <id> [--json report.json]
 *   verivote-audit challenge --record audit-record.json     (Benaloh cast-or-audit check)
 *   verivote-audit receipt   --rpc <url> --deployment … --election <id> --nullifier <n> --hash <ballotHash>
 *
 * Exit code 0 = PASS, 1 = FAIL, 2 = usage / connection error.
 */
import { Command } from "commander";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, http } from "viem";
import { loadDeployment, fetchElectionRecord } from "@verivote/sdk";
import { initCrypto, parseBig, stringifyBig, verifyAuditRecord, type AuditRecord } from "@verivote/crypto-core";
import { auditElection, type AuditReport } from "./audit.js";

const here = dirname(fileURLToPath(import.meta.url));
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: number, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const STATUS = { PASS: paint(32, "PASS"), FAIL: paint(31, "FAIL"), WARN: paint(33, "WARN"), SKIP: paint(90, "SKIP") } as const;

function artifactsDir(custom?: string): string {
  if (custom) return custom;
  const bundled = resolve(here, "artifacts");
  if (existsSync(bundled)) return bundled;
  return resolve(here, "../dist/artifacts");
}

function loadVkeys(dir: string): Record<number, object> {
  const out: Record<number, object> = {};
  for (const k of [4, 8]) {
    const f = resolve(dir, `ballot_k${k}_vkey.json`);
    if (existsSync(f)) out[k] = JSON.parse(readFileSync(f, "utf8"));
  }
  return out;
}

function print(report: AuditReport): void {
  console.log(`\nVeriVote audit — election ${report.electionId}`);
  console.log(`contract ${report.election} · phase ${report.phase}\n`);
  for (const c of report.checks) {
    console.log(`  [${STATUS[c.status]}] ${c.title}`);
    for (const d of c.details) console.log(`         ${d}`);
  }
  console.log(`\n  Verdict: ${report.verdict === "PASS" ? paint(32, "PASS") : paint(31, "FAIL")}\n`);
}

const program = new Command().name("verivote-audit").description("Independently re-verify a VeriVote election from public chain data");

program
  .command("election")
  .requiredOption("--election <id>", "election id")
  .option("--rpc <url>", "JSON-RPC endpoint", process.env.VERIVOTE_RPC_URL ?? "http://127.0.0.1:8545")
  .option("--deployment <file>", "deployment manifest", process.env.VERIVOTE_DEPLOYMENT ?? "contracts/deployments/local.json")
  .option("--artifacts <dir>", "directory with ballot_k*_vkey.json and verifier-code-hashes.json")
  .option("--json <file>", "also write the machine-readable report")
  .action(async (o: { election: string; rpc: string; deployment: string; artifacts?: string; json?: string }) => {
    const deployment = loadDeployment(JSON.parse(readFileSync(o.deployment, "utf8")));
    const dir = artifactsDir(o.artifacts);
    const hashesFile = resolve(dir, "verifier-code-hashes.json");
    const client = createPublicClient({ transport: http(o.rpc) });
    const report = await auditElection(client as never, deployment, BigInt(o.election), {
      vkeys: loadVkeys(dir),
      verifierCodeHashes: existsSync(hashesFile) ? JSON.parse(readFileSync(hashesFile, "utf8")) : undefined,
      onProgress: (m) => process.stderr.write(`… ${m}\n`),
    });
    print(report);
    if (o.json) writeFileSync(o.json, stringifyBig(report, 2));
    process.exit(report.verdict === "PASS" ? 0 : 1);
  });

program
  .command("challenge")
  .description("check a Benaloh audit record: the revealed randomness must re-encrypt to the displayed ballot")
  .requiredOption("--record <file>")
  .action(async (o: { record: string }) => {
    await initCrypto();
    const rec = parseBig<AuditRecord>(readFileSync(o.record, "utf8"));
    const res = verifyAuditRecord(rec);
    if (res.ok) {
      console.log(`[${STATUS.PASS}] the client encrypted choice #${rec.choice + 1} honestly (ballot ${rec.ballotHash.toString(16).slice(0, 16)}…)`);
      console.log("         This ballot is now spoiled. Return to the voting app and cast a fresh one.");
      process.exit(0);
    }
    console.log(`[${STATUS.FAIL}] ${res.reason} — do not use this voting client`);
    process.exit(1);
  });

program
  .command("receipt")
  .description("individual verifiability: check that a receipt's ballot is the one that will be (or was) counted")
  .requiredOption("--election <id>")
  .requiredOption("--nullifier <n>")
  .requiredOption("--hash <ballotHash>", "224-bit ballot hash from the receipt (decimal or 0x hex)")
  .option("--rpc <url>", "JSON-RPC endpoint", process.env.VERIVOTE_RPC_URL ?? "http://127.0.0.1:8545")
  .option("--deployment <file>", "deployment manifest", process.env.VERIVOTE_DEPLOYMENT ?? "contracts/deployments/local.json")
  .action(async (o: { election: string; nullifier: string; hash: string; rpc: string; deployment: string }) => {
    const deployment = loadDeployment(JSON.parse(readFileSync(o.deployment, "utf8")));
    const client = createPublicClient({ transport: http(o.rpc) });
    const rec = await fetchElectionRecord(client as never, deployment, BigInt(o.election));
    const nullifier = BigInt(o.nullifier);
    const hash = BigInt(o.hash);
    const mine = rec.casts.filter((c) => c.nullifier === nullifier).sort((a, b) => a.voteIndex - b.voteIndex);
    const match = mine.find((c) => c.ballotHash === hash);
    if (!match) {
      console.log(`[${STATUS.FAIL}] no ballot with this hash was recorded for the nullifier`);
      process.exit(1);
    }
    const latest = mine[mine.length - 1]!;
    if (latest.ballotHash !== hash) {
      console.log(`[${STATUS.WARN}] this ballot was recorded (tx ${match.txHash}) but a later ballot (#${latest.voteIndex}) replaced it`);
      process.exit(1);
    }
    console.log(`[${STATUS.PASS}] your ballot is recorded in tx ${match.txHash} (block ${match.blockNumber}) and is the one that counts`);
    if (rec.tally.aggregatedNullifiers.length > 0) {
      const included = rec.tally.aggregatedNullifiers.includes(nullifier);
      console.log(`[${included ? STATUS.PASS : STATUS.FAIL}] ${included ? "it is included in the aggregated tally" : "it is MISSING from the aggregated tally"}`);
      process.exit(included ? 0 : 1);
    }
    process.exit(0);
  });

program.parseAsync().catch((e: Error) => {
  console.error(`error: ${e.message}`);
  process.exit(2);
});
