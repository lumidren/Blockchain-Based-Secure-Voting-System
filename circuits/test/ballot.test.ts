import { beforeAll, describe, expect, it } from "vitest";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import {
  PoseidonMerkleTree,
  babyjub,
  ballotHash224,
  elgamal,
  encryptBallot,
  generateIdentity,
  initCrypto,
  nullifierFor,
  parsePublicSignals,
  proveBallot,
  publicSignalCount,
  verifyBallotProof,
  witnessInput,
  type BallotWitnessInput,
} from "@verivote/crypto-core";

const here = dirname(fileURLToPath(import.meta.url));
const build = resolve(here, "../build");
const electionId = 987654321n;

function artifacts(name: string) {
  return {
    wasm: resolve(build, name, `${name}_js`, `${name}.wasm`),
    zkey: resolve(build, name, `${name}_final.zkey`),
    vkey: resolve(build, name, `${name}_vkey.json`),
    r1cs: resolve(build, name, `${name}.r1cs`),
  };
}

async function witnessThrows(input: Record<string, unknown>, wasm: string): Promise<boolean> {
  try {
    await snarkjs.wtns.calculate(input, wasm, { type: "mem" });
    return false;
  } catch {
    return true;
  }
}

for (const k of [4, 8]) {
  const name = `ballot_k${k}`;
  describe(`${name} (K=${k}, depth 20)`, () => {
    const art = artifacts(name);
    let tree: PoseidonMerkleTree;
    let voter: { secret: bigint; commitment: bigint; index: number };
    let pk: babyjub.Point;
    let vkey: object;
    const timings: { witnessMs: number; proveMs: number }[] = [];

    beforeAll(async () => {
      await initCrypto();
      if (!existsSync(art.zkey)) throw new Error(`missing ${art.zkey}: run pnpm --filter @verivote/circuits dev-keys`);
      vkey = JSON.parse(readFileSync(art.vkey, "utf8"));
      tree = new PoseidonMerkleTree(20);
      const ids = Array.from({ length: 9 }, () => generateIdentity());
      ids.forEach((id) => tree.insert(id.commitment));
      const chosen = ids[5]!;
      voter = { secret: chosen.secret, commitment: chosen.commitment, index: 5 };
      pk = elgamal.generateKeyPair().publicKey;
    });

    function baseInput(choice: number, numCandidates: number, voteIndex = 0): BallotWitnessInput {
      return {
        secret: voter.secret,
        merkleProof: tree.proof(voter.index),
        ballot: encryptBallot(pk, choice, k, numCandidates),
        electionId,
        publicKey: pk,
        numCandidates,
        voteIndex,
      };
    }

    it("produces a valid proof whose public signals match the independent TypeScript computation", async () => {
      const input = baseInput(1, 3);
      const res = await proveBallot(input, art.wasm, art.zkey);
      timings.push(res.timings);
      expect(res.publicSignals.length).toBe(publicSignalCount(k));
      const ps = parsePublicSignals(res.publicSignals);
      expect(ps.nullifier).toBe(nullifierFor(voter.secret, electionId));
      expect(ps.root).toBe(tree.root);
      expect(ps.electionId).toBe(electionId);
      expect(ps.publicKey.x).toBe(pk.x);
      expect(ps.numCandidates).toBe(3n);
      expect(ps.voteIndex).toBe(0n);
      for (let i = 0; i < k; i++) {
        const expected = input.ballot.ciphertexts[i]!;
        expect(ps.ciphertexts[i]!.c1.x).toBe(expected.c1.x);
        expect(ps.ciphertexts[i]!.c1.y).toBe(expected.c1.y);
        expect(ps.ciphertexts[i]!.c2.x).toBe(expected.c2.x);
        expect(ps.ciphertexts[i]!.c2.y).toBe(expected.c2.y);
      }
      expect(ballotHash224(ps.ciphertexts)).toBe(ballotHash224(input.ballot.ciphertexts));
      expect(await verifyBallotProof(vkey, res.publicSignals, res.proof)).toBe(true);
      // tampering with any public signal (e.g. the nullifier) invalidates the proof
      const tampered = [...res.publicSignals];
      tampered[4 * k] = (BigInt(tampered[4 * k]!) + 1n).toString();
      expect(await verifyBallotProof(vkey, tampered, res.proof)).toBe(false);
      // binding of voteIndex: changing it invalidates the proof
      const tamperedVi = [...res.publicSignals];
      tamperedVi[4 * k + 6] = "1";
      expect(await verifyBallotProof(vkey, tamperedVi, res.proof)).toBe(false);
    });

    it("witness generation satisfies every constraint (snarkjs wtns check)", async () => {
      const input = witnessInput(baseInput(0, 2, 1));
      const wtns = { type: "mem" } as { type: "mem"; data: Uint8Array };
      await snarkjs.wtns.calculate(input, art.wasm, wtns);
      expect(await snarkjs.wtns.check(art.r1cs, wtns)).toBe(true);
    });

    it("rejects a ballot with two choices", async () => {
      const input = witnessInput(baseInput(0, 3));
      (input.m as string[])[1] = "1";
      expect(await witnessThrows(input, art.wasm)).toBe(true);
    });

    it("rejects an empty ballot", async () => {
      const input = witnessInput(baseInput(0, 3));
      (input.m as string[])[0] = "0";
      expect(await witnessThrows(input, art.wasm)).toBe(true);
    });

    it("rejects a non-boolean choice", async () => {
      const input = witnessInput(baseInput(0, 3));
      (input.m as string[])[0] = "2";
      expect(await witnessThrows(input, art.wasm)).toBe(true);
    });

    it("rejects a vote in an inactive slot", async () => {
      const input = witnessInput(baseInput(0, 2));
      (input.m as string[])[0] = "0";
      (input.m as string[])[k - 1] = "1"; // slot K-1 ≥ numCandidates = 2
      expect(await witnessThrows(input, art.wasm)).toBe(true);
    });

    it("rejects a wrong Merkle root and a wrong path", async () => {
      const good = baseInput(0, 2);
      const wrongRoot = witnessInput(good);
      wrongRoot.root = (tree.root + 1n).toString();
      expect(await witnessThrows(wrongRoot, art.wasm)).toBe(true);
      const wrongPath = witnessInput(good);
      (wrongPath.pathIndices as string[])[0] = (wrongPath.pathIndices as string[])[0] === "0" ? "1" : "0";
      expect(await witnessThrows(wrongPath, art.wasm)).toBe(true);
    });

    it("rejects a secret that is not in the tree", async () => {
      const input = witnessInput(baseInput(0, 2));
      input.sk = (voter.secret + 1n).toString();
      expect(await witnessThrows(input, art.wasm)).toBe(true);
    });

    it("rejects a public key that is not on the curve", async () => {
      const input = witnessInput(baseInput(0, 2));
      input.pk = [pk.x.toString(), (pk.y + 1n).toString()];
      expect(await witnessThrows(input, art.wasm)).toBe(true);
    });

    it("records proving time", async () => {
      for (let i = 0; i < 2; i++) {
        const res = await proveBallot(baseInput(i % 2, 2), art.wasm, art.zkey);
        timings.push(res.timings);
      }
      const prove = timings.map((t) => t.proveMs);
      const witness = timings.map((t) => t.witnessMs);
      const stats = {
        circuit: name,
        samples: timings.length,
        witnessMsMedian: median(witness),
        proveMsMedian: median(prove),
        totalMsMedian: median(timings.map((t) => t.witnessMs + t.proveMs)),
        node: process.version,
        cpus: (await import("node:os")).cpus().length,
      };
      writeFileSync(resolve(build, `${name}_timings.json`), JSON.stringify(stats, null, 2));
      expect(stats.proveMsMedian).toBeGreaterThan(0);
    });
  });
}

function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}
