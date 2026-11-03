/**
 * Poseidon hash with circomlib parameters (the same constants used by circuits/src).
 * circomlibjs initialises asynchronously; call {@link initCrypto} once at startup.
 */
import { buildPoseidon } from "circomlibjs";

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & { F: { toObject(v: Uint8Array): bigint } };

let poseidonFn: PoseidonFn | undefined;
let initPromise: Promise<void> | undefined;

export async function initCrypto(): Promise<void> {
  if (poseidonFn) return;
  if (!initPromise) {
    initPromise = (async () => {
      poseidonFn = (await buildPoseidon()) as unknown as PoseidonFn;
    })();
  }
  await initPromise;
}

export function isCryptoReady(): boolean {
  return poseidonFn !== undefined;
}

/** Poseidon over 1..16 inputs. Requires {@link initCrypto}. */
export function poseidon(inputs: readonly bigint[]): bigint {
  if (!poseidonFn) throw new Error("crypto-core not initialised: await initCrypto() first");
  if (inputs.length < 1 || inputs.length > 16) throw new Error("poseidon supports 1..16 inputs");
  return poseidonFn.F.toObject(poseidonFn([...inputs]));
}

export function poseidon1(a: bigint): bigint {
  return poseidon([a]);
}

export function poseidon2(a: bigint, b: bigint): bigint {
  return poseidon([a, b]);
}
