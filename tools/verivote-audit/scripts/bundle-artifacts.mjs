// Copies the verification keys and the expected verifier runtime-bytecode hashes into dist/artifacts so the
// published CLI is self-contained. Auditors can (and should) rebuild them from source and compare.
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const out = resolve(here, "../dist/artifacts");
mkdirSync(out, { recursive: true });
const hashes = {};
for (const k of [4, 8]) {
  const vkey = resolve(root, `circuits/build/ballot_k${k}/ballot_k${k}_vkey.json`);
  if (existsSync(vkey)) copyFileSync(vkey, resolve(out, `ballot_k${k}_vkey.json`));
  const art = resolve(root, `contracts/out/Groth16VerifierK${k}.sol/Groth16VerifierK${k}.json`);
  if (existsSync(art)) {
    const code = JSON.parse(readFileSync(art, "utf8")).deployedBytecode.object;
    hashes[k] = "0x" + createHash("sha256").update(Buffer.from(code.replace(/^0x/, ""), "hex")).digest("hex");
  }
}
writeFileSync(resolve(out, "verifier-code-hashes.json"), JSON.stringify(hashes, null, 2));
console.log("artifacts bundled:", Object.keys(hashes).map((k) => `K=${k}`).join(", "));
