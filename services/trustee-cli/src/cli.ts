#!/usr/bin/env node
/**
 * verivote-trustee — command-line client for election trustees.
 *
 *   verivote-trustee init        --keystore k.json --account-key-env TRUSTEE_PK
 *   verivote-trustee dkg         --election <id>  (runs every DKG step whose window is open, idempotently)
 *   verivote-trustee decrypt     --election <id>
 *   verivote-trustee status      --election <id>
 *   verivote-trustee rotate-password
 *   verivote-trustee export-backup --out backup.json
 *
 * Secrets: the keystore password comes from $VERIVOTE_KEYSTORE_PASSWORD or an interactive prompt; the
 * Ethereum account key from the env variable named by --account-key-env (never from a flag, so it does not
 * end up in shell history). With --pkcs11-module the keystore key is additionally wrapped by an HSM/YubiKey.
 */
import { Command } from "commander";
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { createPublicClient, createWalletClient, http, type Hex, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { loadDeployment } from "@verivote/sdk";
import { FileKeystore, identityWrapper, type KeyWrapper } from "./keystore/file-keystore.js";
import { pkcs11Wrapper } from "./keystore/pkcs11-keystore.js";
import * as T from "./trustee.js";

const program = new Command()
  .name("verivote-trustee")
  .description("VeriVote trustee client")
  .option("--rpc <url>", "JSON-RPC endpoint", process.env.VERIVOTE_RPC_URL ?? "http://127.0.0.1:8545")
  .option("--deployment <file>", "deployment manifest", process.env.VERIVOTE_DEPLOYMENT ?? "contracts/deployments/local.json")
  .option("--keystore <file>", "encrypted keystore", "trustee.keystore.json")
  .option("--account-key-env <name>", "environment variable holding the trustee account private key", "TRUSTEE_PRIVATE_KEY")
  .option("--pkcs11-module <path>", "PKCS#11 module for HSM/YubiKey key wrapping")
  .option("--pkcs11-label <label>", "label of the token secret key", "verivote-trustee")
  .option("--pkcs11-pin-env <name>", "environment variable holding the token PIN", "VERIVOTE_PKCS11_PIN");

async function password(confirm = false): Promise<string> {
  const env = process.env.VERIVOTE_KEYSTORE_PASSWORD;
  if (env) return env;
  const ask = (q: string) =>
    new Promise<string>((resolve) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
      process.stdout.write(q);
      rl.question("", (a) => {
        rl.close();
        process.stdout.write("\n");
        resolve(a);
      });
    });
  const p = await ask("Keystore password: ");
  if (confirm && (await ask("Repeat password: ")) !== p) throw new Error("passwords do not match");
  return p;
}

function wrapper(): KeyWrapper {
  const o = program.opts();
  if (!o.pkcs11Module) return identityWrapper;
  const pin = process.env[o.pkcs11PinEnv];
  if (!pin) throw new Error(`set $${o.pkcs11PinEnv} to the token PIN`);
  return pkcs11Wrapper({ module: o.pkcs11Module, pin, label: o.pkcs11Label });
}

async function context(): Promise<T.Ctx> {
  const o = program.opts();
  const deployment = loadDeployment(JSON.parse(readFileSync(o.deployment, "utf8")));
  const key = process.env[o.accountKeyEnv] as Hex | undefined;
  if (!key) throw new Error(`set $${o.accountKeyEnv} to the trustee account private key`);
  const chain = defineChain({
    id: deployment.chainId,
    name: deployment.name,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [o.rpc] } },
  });
  const account = privateKeyToAccount(key);
  return {
    deployment,
    publicClient: createPublicClient({ chain, transport: http(o.rpc) }) as T.Ctx["publicClient"],
    wallet: createWalletClient({ chain, transport: http(o.rpc), account }),
    log: (m) => console.log(`  ${m}`),
  };
}

async function keystore(confirm = false): Promise<FileKeystore<T.TrusteeState>> {
  return new FileKeystore<T.TrusteeState>(program.opts().keystore, await password(confirm), wrapper());
}

program
  .command("init")
  .description("create an empty encrypted keystore for this trustee account")
  .action(async () => {
    const ctx = await context();
    const ks = await keystore(true);
    if (ks.exists()) throw new Error(`${ks.path} already exists`);
    await ks.save({ version: 1, address: ctx.wallet.account.address, elections: {} });
    console.log(`keystore created: ${ks.path}`);
  });

program
  .command("dkg")
  .description("run every DKG step whose time window is currently open (safe to re-run)")
  .requiredOption("--election <id>")
  .option("--from-block <n>", "first block to scan for share deliveries", "0")
  .action(async (o: { election: string; fromBlock: string }) => {
    const ctx = await context();
    const ks = await keystore();
    const state = await ks.load();
    const id = BigInt(o.election);
    const s = await T.prepare(ctx, state, id);
    await ks.save(state);
    const schedule = (await ctx.publicClient.readContract({
      address: ctx.deployment.coordinator,
      abi: (await import("@verivote/sdk")).trusteeCoordinatorAbi,
      functionName: "schedule",
      args: [id],
    })) as readonly bigint[];
    const now = BigInt((await ctx.publicClient.getBlock()).timestamp);
    const step = async (name: string, fn: () => Promise<unknown>) => {
      try {
        console.log(`• ${name}`);
        await fn();
      } catch (e) {
        console.log(`  skipped: ${(e as Error).message.split("\n")[0]}`);
      } finally {
        await ks.save(state);
      }
    };
    if (now <= schedule[0]!) await step("register encryption key", () => T.registerKey(ctx, s));
    else if (now <= schedule[1]!) await step("deal", () => T.deal(ctx, s));
    else if (now <= schedule[2]!) await step("verify received shares", () => T.verifyShares(ctx, s, BigInt(o.fromBlock)));
    else if (now <= schedule[3]!) await step("answer complaints", () => T.answerComplaints(ctx, s));
    else if (now <= schedule[4]!) {
      await step("verify received shares", () => T.verifyShares(ctx, s, BigInt(o.fromBlock)));
      await step("reveal", () => T.reveal(ctx, s));
    } else if (now <= schedule[5]!) await step("check reveals", () => T.checkReveals(ctx, s));
    else {
      await step("finalize", () => T.finalizeDkg(ctx, id));
      await step("compute share", () => T.computeShare(ctx, s));
    }
  });

program
  .command("decrypt")
  .description("submit the partial decryption of the aggregated tally with Chaum-Pedersen proofs")
  .requiredOption("--election <id>")
  .action(async (o: { election: string }) => {
    const ctx = await context();
    const ks = await keystore();
    const state = await ks.load();
    const s = state.elections[o.election];
    if (!s) throw new Error("no secrets for this election in the keystore");
    if (s.share === undefined) await T.computeShare(ctx, s);
    await T.submitPartialDecryption(ctx, s);
    await ks.save(state);
  });

program
  .command("status")
  .requiredOption("--election <id>")
  .action(async (o: { election: string }) => {
    const ks = await keystore();
    const state = await ks.load();
    const s = state.elections[o.election];
    if (!s) return console.log("not participating in this election");
    console.log(
      JSON.stringify(
        {
          trusteeIndex: s.index,
          threshold: `${s.t}-of-${s.n}`,
          dealt: Boolean(s.dealer),
          sharesReceivedFrom: Object.keys(s.received).map(Number),
          complainedAbout: s.complained,
          shareComputed: s.share !== undefined,
          partialDecryptionSubmitted: Boolean(s.partialsSubmitted),
        },
        null,
        2,
      ),
    );
  });

program
  .command("rotate-password")
  .description("re-encrypt the keystore under a new password (old file kept as .bak)")
  .action(async () => {
    const ks = await keystore();
    process.env.VERIVOTE_KEYSTORE_PASSWORD = "";
    const next = await password(true);
    await ks.changePassword(next);
    console.log("password changed");
  });

program
  .command("export-backup")
  .description("copy the encrypted keystore for offline backup (it stays encrypted)")
  .requiredOption("--out <file>")
  .action(async (o: { out: string }) => {
    const ks = await keystore();
    await ks.load(); // proves the password is right before backing up
    copyFileSync(ks.path, o.out);
    writeFileSync(`${o.out}.sha256`, (await import("node:crypto")).createHash("sha256").update(readFileSync(o.out)).digest("hex") + "\n");
    console.log(`backup written to ${o.out}`);
  });

program.parseAsync().catch((e: Error) => {
  console.error(`error: ${e.message}`);
  process.exit(1);
});
