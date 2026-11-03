declare module "snarkjs" {
  export namespace groth16 {
    function prove(
      zkey: string | { type: "mem"; data: Uint8Array },
      witness: string | { type: "mem"; data: Uint8Array },
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    function fullProve(
      input: Record<string, unknown>,
      wasm: string | { type: "mem"; data: Uint8Array },
      zkey: string | { type: "mem"; data: Uint8Array },
    ): Promise<{ proof: unknown; publicSignals: string[] }>;
    function verify(vkey: object, publicSignals: string[], proof: unknown): Promise<boolean>;
    function exportSolidityCallData(proof: unknown, publicSignals: string[]): Promise<string>;
  }
  export namespace wtns {
    function calculate(
      input: Record<string, unknown>,
      wasm: string | { type: "mem"; data: Uint8Array },
      wtns: string | { type: "mem"; data?: Uint8Array },
    ): Promise<void>;
    function check(r1cs: string, wtns: string | { type: "mem"; data: Uint8Array }, logger?: unknown): Promise<boolean>;
  }
  export namespace zKey {
    function exportVerificationKey(zkey: string | { type: "mem"; data: Uint8Array }): Promise<object>;
  }
  export namespace r1cs {
    function info(r1cs: string, logger?: unknown): Promise<{ nConstraints: number; nVars: number; nOutputs: number; nPubInputs: number; nPrvInputs: number }>;
  }
}

declare module "circomlibjs" {
  export function buildPoseidon(): Promise<unknown>;
  export function buildBabyjub(): Promise<unknown>;
}
