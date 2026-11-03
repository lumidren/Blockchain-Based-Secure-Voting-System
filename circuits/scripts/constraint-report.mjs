// Reports constraint counts for every built circuit and regression-checks them against constraints.json.
// Usage: node scripts/constraint-report.mjs [--update]
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const names = ["ballot_k4", "ballot_k8"];
const update = process.argv.includes("--update");
const pinnedPath = resolve(root, "constraints.json");
const pinned = existsSync(pinnedPath) ? JSON.parse(readFileSync(pinnedPath, "utf8")) : {};
const report = {};
let failed = false;

for (const name of names) {
  const r1cs = resolve(root, "build", name, `${name}.r1cs`);
  if (!existsSync(r1cs)) {
    console.log(`skip ${name}: not built`);
    continue;
  }
  const info = await snarkjs.r1cs.info(r1cs);
  const zkey = resolve(root, "build", name, `${name}_final.zkey`);
  report[name] = {
    constraints: info.nConstraints,
    variables: info.nVars,
    publicInputs: info.nPubInputs,
    outputs: info.nOutputs,
    privateInputs: info.nPrvInputs,
    zkeyBytes: existsSync(zkey) ? statSync(zkey).size : null,
  };
  console.log(
    `${name}: ${info.nConstraints} constraints, ${info.nVars} variables, ${info.nPubInputs} public inputs, ${info.nOutputs} outputs`,
  );
  if (!update && pinned[name] && pinned[name].constraints !== info.nConstraints) {
    console.error(
      `REGRESSION: ${name} constraints changed ${pinned[name].constraints} -> ${info.nConstraints} (run with --update if intended)`,
    );
    failed = true;
  }
}
if (update) {
  writeFileSync(pinnedPath, JSON.stringify(report, null, 2) + "\n");
  console.log(`wrote ${pinnedPath}`);
}
process.exit(failed ? 1 : 0);
