// Worker thread that generates ballot proofs single-threaded, so a pool of N workers uses N cores without
// snarkjs spawning nested workers. The proving key is read once per worker.
import { parentPort, workerData } from "node:worker_threads";
import { readFileSync } from "node:fs";
import * as snarkjs from "snarkjs";

const { wasmPath, zkeyPath } = workerData;
const wasm = new Uint8Array(readFileSync(wasmPath));
const zkey = new Uint8Array(readFileSync(zkeyPath));

parentPort.on("message", async (job) => {
  const t0 = performance.now();
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      job.input,
      { type: "mem", data: wasm },
      { type: "mem", data: zkey },
      undefined,
      { singleThread: true },
      { singleThread: true },
    );
    parentPort.postMessage({ id: job.id, proof, publicSignals, ms: performance.now() - t0 });
  } catch (e) {
    parentPort.postMessage({ id: job.id, error: e instanceof Error ? e.message : String(e), ms: performance.now() - t0 });
  }
});
