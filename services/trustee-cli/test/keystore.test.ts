import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileKeystore, decryptState, encryptState, MIN_KDF, type KeyWrapper } from "../src/keystore/file-keystore.js";

// Use the minimum accepted Argon2id cost to keep the test fast; production uses DEFAULT_KDF (64 MiB, t=3).
const FAST = { m: MIN_KDF.m, t: MIN_KDF.t, p: 1 };
const PW = "correct horse battery staple";
const state = { version: 1, share: 123456789012345678901234567890n, nested: { list: [1n, 2n] } };

describe("file keystore (Argon2id + AES-256-GCM)", () => {
  it("round-trips bigint state", async () => {
    const f = await encryptState(state, PW, undefined, FAST);
    expect(f.header.kdf.algorithm).toBe("argon2id");
    expect(f.ciphertext).not.toContain("123456789012345678901234567890");
    expect(await decryptState(f, PW)).toEqual(state);
  });

  it("rejects a wrong password", async () => {
    const f = await encryptState(state, PW, undefined, FAST);
    await expect(decryptState(f, "wrong password here")).rejects.toThrow(/wrong password/);
  });

  it("authenticates the header: tampering with salt or KDF parameters fails", async () => {
    const f = await encryptState(state, PW, undefined, FAST);
    const badSalt = { ...f, header: { ...f.header, kdf: { ...f.header.kdf, salt: "00".repeat(16) } } };
    await expect(decryptState(badSalt, PW)).rejects.toThrow();
    const downgraded = { ...f, header: { ...f.header, kdf: { ...f.header.kdf, m: 8, t: 1 } } };
    await expect(decryptState(downgraded, PW)).rejects.toThrow(/below the accepted minimum/);
    const flipped = { ...f, ciphertext: (f.ciphertext[0] === "0" ? "1" : "0") + f.ciphertext.slice(1) };
    await expect(decryptState(flipped, PW)).rejects.toThrow();
  });

  it("rejects short passwords", async () => {
    await expect(encryptState(state, "short", undefined, FAST)).rejects.toThrow(/at least 12/);
  });

  it("saves atomically with a backup and supports password rotation", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vv-ks-"));
    const path = join(dir, "k.json");
    const ks = new FileKeystore<typeof state>(path, PW, undefined, FAST);
    await ks.save(state);
    await ks.save({ ...state, version: 1 });
    expect(existsSync(`${path}.bak`)).toBe(true);
    const rotated = await ks.changePassword("another long passphrase");
    expect(await rotated.load()).toEqual(state);
    await expect(new FileKeystore(path, PW, undefined, FAST).load()).rejects.toThrow();
    expect(JSON.parse(readFileSync(path, "utf8")).header.format).toBe("verivote-trustee-keystore");
    writeFileSync(path, readFileSync(`${path}.bak`));
    expect(await new FileKeystore(path, PW, undefined, FAST).load()).toEqual(state);
  });

  it("requires the same key wrapper (HSM-protected keystores cannot be opened with the password alone)", async () => {
    const fakeHsm: KeyWrapper = {
      kind: "pkcs11",
      wrap: async (k) => k.map((b) => b ^ 0x5a),
      unwrap: async (k) => k.map((b) => b ^ 0x5a),
    };
    const f = await encryptState(state, PW, fakeHsm, FAST);
    expect(f.header.protection).toBe("pkcs11");
    await expect(decryptState(f, PW)).rejects.toThrow(/requires the "pkcs11" key wrapper/);
    expect(await decryptState(f, PW, fakeHsm)).toEqual(state);
  });
});
