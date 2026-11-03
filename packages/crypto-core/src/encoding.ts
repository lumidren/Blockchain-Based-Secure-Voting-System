/** Byte/hex/bigint helpers shared by every module. All multi-byte integers are big-endian. */

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

export function bigIntToBytesBE(v: bigint, length = 32): Uint8Array {
  if (v < 0n) throw new Error("negative value");
  const out = new Uint8Array(length);
  let x = v;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x !== 0n) throw new Error(`value does not fit in ${length} bytes`);
  return out;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): `0x${string}` {
  let s = "0x";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s as `0x${string}`;
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("odd hex length");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bigIntToHex(v: bigint, length = 32): `0x${string}` {
  return bytesToHex(bigIntToBytesBE(v, length));
}

export function hexToBigInt(hex: string): bigint {
  return bytesToBigIntBE(hexToBytes(hex));
}

/** abi.encodePacked for a list of uint256 words. */
export function packWords(words: readonly bigint[]): Uint8Array {
  return concatBytes(...words.map((w) => bigIntToBytesBE(w, 32)));
}

/** JSON replacer/reviver so that bigint survives serialisation as decimal strings tagged with "n". */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? `${value.toString()}n` : value;
}

export function bigintReviver(_key: string, value: unknown): unknown {
  return typeof value === "string" && /^-?\d+n$/.test(value) ? BigInt(value.slice(0, -1)) : value;
}

export function stringifyBig(value: unknown, space?: number): string {
  return JSON.stringify(value, bigintReplacer, space);
}

export function parseBig<T = unknown>(text: string): T {
  return JSON.parse(text, bigintReviver) as T;
}
