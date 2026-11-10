/**
 * Password-protected trustee keystore.
 *
 *   key  = Argon2id(password, salt, m = 64 MiB, t = 3, p = 1, 32 bytes)
 *   blob = AES-256-GCM(key, iv, aad = header JSON, plaintext = state JSON)
 *
 * The header (format version, KDF parameters, salt, iv) is authenticated as AAD, so downgrading the KDF
 * parameters or swapping the salt is detected. Every write is atomic (temp file + rename) and the previous
 * version is kept as `<file>.bak` for recovery.
 */
import { argon2id } from "@noble/hashes/argon2";
import { gcm } from "@noble/ciphers/aes";
import { existsSync, readFileSync, renameSync, writeFileSync, copyFileSync } from "node:fs";
import { bytesToHex, hexToBytes, parseBig, stringifyBig } from "@verivote/crypto-core";

export interface KdfParams {
  readonly algorithm: "argon2id";
  readonly m: number; // KiB
  readonly t: number;
  readonly p: number;
  readonly salt: string; // hex
}

export interface KeystoreHeader {
  readonly format: "verivote-trustee-keystore";
  readonly version: 1;
  readonly kdf: KdfParams;
  readonly cipher: "aes-256-gcm";
  readonly iv: string; // hex
  /** "file" = key derived from password only; "pkcs11" = password-derived key additionally wrapped by an HSM */
  readonly protection: "file" | "pkcs11";
}

export interface KeystoreFile {
  readonly header: KeystoreHeader;
  readonly ciphertext: string; // hex
}

/** Minimum KDF cost accepted when opening a keystore (protects against parameter downgrade). */
export const MIN_KDF = { m: 19_456, t: 2, p: 1 } as const; // OWASP 2023 minimum for Argon2id
export const DEFAULT_KDF = { m: 65_536, t: 3, p: 1 } as const;

function rand(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export function deriveKey(password: string, kdf: KdfParams): Uint8Array {
  if (kdf.algorithm !== "argon2id") throw new Error("unsupported KDF");
  if (kdf.m < MIN_KDF.m || kdf.t < MIN_KDF.t || kdf.p < MIN_KDF.p) throw new Error("KDF parameters below the accepted minimum");
  if (password.length < 12) throw new Error("password must be at least 12 characters");
  return argon2id(new TextEncoder().encode(password), hexToBytes(kdf.salt), { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: 32 });
}

function aad(header: KeystoreHeader): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(header));
}

/** Optional extra wrapping step (HSM / YubiKey). The identity wrapper is used for plain file keystores. */
export interface KeyWrapper {
  readonly kind: "file" | "pkcs11";
  wrap(key: Uint8Array): Promise<Uint8Array>;
  unwrap(key: Uint8Array): Promise<Uint8Array>;
}

export const identityWrapper: KeyWrapper = {
  kind: "file",
  wrap: async (k) => k,
  unwrap: async (k) => k,
};

export async function encryptState<T>(
  state: T,
  password: string,
  wrapper: KeyWrapper = identityWrapper,
  kdfCost: { m: number; t: number; p: number } = DEFAULT_KDF,
): Promise<KeystoreFile> {
  const header: KeystoreHeader = {
    format: "verivote-trustee-keystore",
    version: 1,
    kdf: { algorithm: "argon2id", ...kdfCost, salt: bytesToHex(rand(16)).slice(2) },
    cipher: "aes-256-gcm",
    iv: bytesToHex(rand(12)).slice(2),
    protection: wrapper.kind,
  };
  const key = await wrapper.wrap(deriveKey(password, header.kdf));
  const pt = new TextEncoder().encode(stringifyBig(state));
  const ct = gcm(key, hexToBytes(header.iv), aad(header)).encrypt(pt);
  key.fill(0);
  return { header, ciphertext: bytesToHex(ct).slice(2) };
}

export async function decryptState<T>(file: KeystoreFile, password: string, wrapper: KeyWrapper = identityWrapper): Promise<T> {
  const { header } = file;
  if (header.format !== "verivote-trustee-keystore" || header.version !== 1) throw new Error("unknown keystore format");
  if (header.protection !== wrapper.kind) throw new Error(`keystore requires the "${header.protection}" key wrapper`);
  const key = await wrapper.wrap(deriveKey(password, header.kdf));
  try {
    const pt = gcm(key, hexToBytes(header.iv), aad(header)).decrypt(hexToBytes(file.ciphertext));
    return parseBig<T>(new TextDecoder().decode(pt));
  } catch {
    throw new Error("wrong password or corrupted keystore");
  } finally {
    key.fill(0);
  }
}

export class FileKeystore<T> {
  constructor(
    readonly path: string,
    private readonly password: string,
    private readonly wrapper: KeyWrapper = identityWrapper,
    private readonly kdfCost: { m: number; t: number; p: number } = DEFAULT_KDF,
  ) {}

  exists(): boolean {
    return existsSync(this.path);
  }

  async load(): Promise<T> {
    const file = JSON.parse(readFileSync(this.path, "utf8")) as KeystoreFile;
    return decryptState<T>(file, this.password, this.wrapper);
  }

  async save(state: T): Promise<void> {
    const file = await encryptState(state, this.password, this.wrapper, this.kdfCost);
    if (existsSync(this.path)) copyFileSync(this.path, `${this.path}.bak`);
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  /** Re-encrypts under a new password (key rotation / handover). */
  async changePassword(newPassword: string): Promise<FileKeystore<T>> {
    const state = await this.load();
    const next = new FileKeystore<T>(this.path, newPassword, this.wrapper, this.kdfCost);
    await next.save(state);
    return next;
  }
}
