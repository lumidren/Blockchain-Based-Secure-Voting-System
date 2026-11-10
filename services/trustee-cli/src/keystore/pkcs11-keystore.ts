/**
 * HSM / YubiKey key wrapping.
 *
 * The password-derived key is additionally passed through an HMAC-SHA256 operation performed *inside* a
 * PKCS#11 token with a non-exportable secret key (`CKK_GENERIC_SECRET`, `CKA_EXTRACTABLE = false`):
 *
 *   wrappedKey = HMAC_token(passwordKey)
 *
 * so a stolen keystore file plus the password is useless without the physical token. The operation is driven
 * through OpenSC's `pkcs11-tool`, which works with YubiKey (YKCS11), SoftHSM2, Nitrokey and cloud HSMs that
 * expose PKCS#11, without a native Node addon.
 *
 * Provisioning (once per trustee, documented in docs/RUNBOOK.md §2.3):
 *   pkcs11-tool --module <lib> --login --keygen --key-type GENERIC:32 --label verivote-trustee \
 *               --usage-sign --sensitive --private
 *
 * This adapter is exercised in CI against SoftHSM2; it is not exercised on developer machines without a token.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { KeyWrapper } from "./file-keystore.js";

export interface Pkcs11Options {
  /** Path to the PKCS#11 module (e.g. libykcs11.so, softhsm2.dll). */
  readonly module: string;
  readonly pin: string;
  readonly label: string;
  readonly slot?: string;
  readonly tool?: string;
}

export function pkcs11Wrapper(opts: Pkcs11Options): KeyWrapper {
  const tool = opts.tool ?? "pkcs11-tool";
  const run = (input: Uint8Array): Uint8Array => {
    const dir = mkdtempSync(join(tmpdir(), "verivote-p11-"));
    const inFile = join(dir, "in.bin");
    const outFile = join(dir, "out.bin");
    try {
      writeFileSync(inFile, input, { mode: 0o600 });
      const args = [
        "--module", opts.module,
        "--login", "--pin", opts.pin,
        "--sign", "--mechanism", "SHA256-HMAC",
        "--label", opts.label,
        "--input-file", inFile,
        "--output-file", outFile,
      ];
      if (opts.slot) args.push("--slot", opts.slot);
      const res = spawnSync(tool, args, { encoding: "utf8" });
      if (res.status !== 0) throw new Error(`pkcs11-tool failed: ${res.stderr || res.error?.message || "unknown error"}`);
      const out = new Uint8Array(readFileSync(outFile));
      if (out.length !== 32) throw new Error("unexpected HMAC length from token");
      return out;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  return {
    kind: "pkcs11",
    wrap: async (key) => run(key),
    // HMAC is deterministic, so unwrap is the same token operation applied to the same password-derived key
    unwrap: async (key) => run(key),
  };
}
