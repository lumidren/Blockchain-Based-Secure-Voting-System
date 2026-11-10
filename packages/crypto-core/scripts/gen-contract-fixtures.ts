/**
 * Generates contracts/test/fixtures/Fixtures.sol: a complete, cryptographically real election fixture
 * (5-trustee / threshold-3 DKG transcript, an 8-voter roll, and Groth16 ballot proofs including re-votes)
 * bound to the election IDs that contracts/test/utils/Base.t.sol will produce.
 *
 * The factory proxy address is the third contract created by the Foundry test contract
 * (0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496); Base.t.sol asserts the match.
 *
 * Usage: pnpm --filter @verivote/crypto-core fixtures
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keccak_256 } from "@noble/hashes/sha3";
import { G, mul, randomScalar, type Point } from "../src/babyjub.js";
import { bigIntToBytesBE, bytesToBigIntBE, bytesToHex, concatBytes, hexToBytes, packWords } from "../src/encoding.js";
import { initCrypto } from "../src/poseidon.js";
import { PoseidonMerkleTree } from "../src/merkle.js";
import { generateIdentity, type Identity } from "../src/identity.js";
import { encryptBallot } from "../src/ballot.js";
import { proveBallot, toSolidityProof, verifyBallotProof } from "../src/prover.js";
import { deal, combineFeldman, combineShares, type Deal } from "../src/dkg.js";
import { readFileSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../..");
const out = resolve(root, "contracts/test/fixtures/Fixtures.sol");

const TEST_CONTRACT = "0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496";
const CHAIN_ID = 31337n;
const N = 5;
const T = 3;
const VOTERS = 8;

function contractAddress(sender: string, nonce: number): string {
  if (nonce < 1 || nonce > 0x7f) throw new Error("nonce encoding only implemented for 1..127");
  const rlp = concatBytes(new Uint8Array([0xd6, 0x94]), hexToBytes(sender), new Uint8Array([nonce]));
  return bytesToHex(keccak_256(rlp).subarray(12));
}

function electionIdFor(factory: string, index: number): bigint {
  const enc = concatBytes(bigIntToBytesBE(CHAIN_ID, 32), new Uint8Array(12), hexToBytes(factory), bigIntToBytesBE(BigInt(index), 32));
  return bytesToBigIntBE(keccak_256(enc)) >> 8n;
}

const pt = (p: Point) => `BabyJubJub.Point(${p.x}, ${p.y})`;

interface ProofOut {
  voter: number;
  choice: number;
  voteIndex: number;
  a: [bigint, bigint];
  b: [[bigint, bigint], [bigint, bigint]];
  c: [bigint, bigint];
  signals: bigint[];
}

async function main() {
  await initCrypto();
  const factory = contractAddress(TEST_CONTRACT, 3);
  const electionId = electionIdFor(factory, 1);
  console.log(`factory ${factory}  electionId(1) ${electionId}`);

  // ---- DKG transcript (honest trustees) ----
  const ekSecrets = Array.from({ length: N }, () => randomScalar());
  const eks = ekSecrets.map((s) => mul(G, s));
  const deals: Deal[] = Array.from({ length: N }, (_, i) => deal({ n: N, t: T, electionId }, i + 1, eks));
  const { publicKey } = combineFeldman(deals.map((d) => d.feldman));
  const shares = Array.from({ length: N }, (_, j) => combineShares(deals.map((d) => d.shares[j]!.s)));

  // ---- voter roll ----
  const voters: Identity[] = Array.from({ length: VOTERS }, () => generateIdentity());
  const tree = new PoseidonMerkleTree(20);
  voters.forEach((v) => tree.insert(v.commitment));
  const rootAfter4 = new PoseidonMerkleTree(20, voters.slice(0, 4).map((v) => v.commitment)).root;

  // ---- ballots ----
  const artifacts = (k: number) => {
    const name = `ballot_k${k}`;
    const dir = resolve(root, "circuits/build", name);
    return {
      wasm: resolve(dir, `${name}_js`, `${name}.wasm`),
      zkey: resolve(dir, `${name}_final.zkey`),
      vkey: JSON.parse(readFileSync(resolve(dir, `${name}_vkey.json`), "utf8")) as object,
    };
  };

  async function prove(k: number, numCandidates: number, voter: number, choice: number, voteIndex: number): Promise<ProofOut> {
    const art = artifacts(k);
    const ballot = encryptBallot(publicKey, choice, k, numCandidates);
    const res = await proveBallot(
      { secret: voters[voter]!.secret, merkleProof: tree.proof(voter), ballot, electionId, publicKey, numCandidates, voteIndex },
      art.wasm,
      art.zkey,
    );
    if (!(await verifyBallotProof(art.vkey, res.publicSignals, res.proof))) throw new Error("proof failed to verify");
    const sp = toSolidityProof(res.proof);
    process.stdout.write(".");
    return { voter, choice, voteIndex, a: sp.a, b: sp.b, c: sp.c, signals: res.publicSignals.map(BigInt) };
  }

  const k4Plan: [number, number, number][] = [
    [0, 0, 0], [1, 1, 0], [2, 2, 0], [3, 1, 0], [4, 1, 0], [5, 0, 0], [6, 2, 0], [7, 1, 0],
    [0, 2, 1], [3, 0, 1], [3, 2, 2],
  ];
  const k4: ProofOut[] = [];
  for (const [v, ch, vi] of k4Plan) k4.push(await prove(4, 3, v, ch, vi));
  const k8: ProofOut[] = [await prove(8, 5, 0, 4, 0), await prove(8, 5, 1, 3, 0)];
  process.stdout.write("\n");

  // final ballot per voter = highest voteIndex
  const finalIdx = new Map<number, number>();
  k4.forEach((b, i) => {
    const prev = finalIdx.get(b.voter);
    if (prev === undefined || k4[prev]!.voteIndex < b.voteIndex) finalIdx.set(b.voter, i);
  });
  const finals = [...finalIdx.values()].sort((x, y) => x - y);
  const countsK4 = [0, 0, 0];
  finals.forEach((i) => countsK4[k4[i]!.choice]!++);

  const proofLit = (p: ProofOut) =>
    `BallotProof(${p.voter}, ${p.choice}, ${p.voteIndex}, [uint256(${p.a[0]}), ${p.a[1]}], [[uint256(${p.b[0][0]}), ${p.b[0][1]}], [uint256(${p.b[1][0]}), ${p.b[1][1]}]], [uint256(${p.c[0]}), ${p.c[1]}], _arr(${p.signals.length}, [${p.signals
      .map((s, i) => (i === 0 ? `uint256(${s})` : s.toString()))
      .join(", ")}]))`;

  // Solidity cannot take a dynamic array literal, so signals go through fixed-size helpers.
  const sizes = [...new Set([...k4, ...k8].map((p) => p.signals.length))];
  const arrHelpers = sizes
    .map(
      (n) => `    function _arr(uint256, uint256[${n}] memory x) private pure returns (uint256[] memory r) {
        r = new uint256[](${n});
        for (uint256 i = 0; i < ${n}; i++) r[i] = x[i];
    }`,
    )
    .join("\n\n");

  const sol = `// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// GENERATED by packages/crypto-core/scripts/gen-contract-fixtures.ts — do not edit by hand.
// Real DKG transcript (n=${N}, t=${T}), ${VOTERS}-voter roll and Groth16 proofs (dev proving keys) bound to
// electionId(1) of factory ${factory} on chain ${CHAIN_ID}.
import {BabyJubJub} from "../../src/libraries/BabyJubJub.sol";
import {ITally} from "../../src/interfaces/IVeriVote.sol";

library Fixtures {
    struct BallotProof {
        uint8 voter;
        uint8 choice;
        uint32 voteIndex;
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256[] signals;
    }

    uint8 internal constant N = ${N};
    uint8 internal constant T = ${T};
    uint256 internal constant VOTERS = ${VOTERS};
    address internal constant FACTORY = ${checksum(factory)};
    uint256 internal constant ELECTION_ID = ${electionId};

    function publicKey() internal pure returns (BabyJubJub.Point memory) {
        return ${pt(publicKey)};
    }

    function encryptionKey(uint8 j) internal pure returns (BabyJubJub.Point memory) {
${eks.map((e, i) => `        if (j == ${i + 1}) return ${pt(e)};`).join("\n")}
        revert("bad trustee");
    }

    function share(uint8 j) internal pure returns (uint256) {
${shares.map((s, i) => `        if (j == ${i + 1}) return ${s};`).join("\n")}
        revert("bad trustee");
    }

    /// @dev (s_{i,j}, s'_{i,j}) dealt by dealer i to trustee j
    function sharePair(uint8 i, uint8 j) internal pure returns (uint256 s, uint256 sPrime) {
${deals
  .flatMap((d, i) => d.shares.map((sp, j) => `        if (i == ${i + 1} && j == ${j + 1}) return (${sp.s}, ${sp.sPrime});`))
  .join("\n")}
        revert("bad pair");
    }

    function pedersen(uint8 i) internal pure returns (BabyJubJub.Point[] memory c) {
        c = new BabyJubJub.Point[](T);
${deals.map((d, i) => `        if (i == ${i + 1}) {\n${d.pedersen.map((p, k) => `            c[${k}] = ${pt(p)};`).join("\n")}\n            return c;\n        }`).join("\n")}
        revert("bad dealer");
    }

    function feldman(uint8 i) internal pure returns (BabyJubJub.Point[] memory c) {
        c = new BabyJubJub.Point[](T);
${deals.map((d, i) => `        if (i == ${i + 1}) {\n${d.feldman.map((p, k) => `            c[${k}] = ${pt(p)};`).join("\n")}\n            return c;\n        }`).join("\n")}
        revert("bad dealer");
    }

    function shareBlobs(uint8 i) internal pure returns (bytes[] memory b) {
        b = new bytes[](N);
${deals.map((d, i) => `        if (i == ${i + 1}) {\n${d.encryptedShares.map((blob, j) => `            b[${j}] = hex"${bytesToHex(blob).slice(2)}";`).join("\n")}\n            return b;\n        }`).join("\n")}
        revert("bad dealer");
    }

    function leaves() internal pure returns (uint256[] memory l) {
        l = new uint256[](VOTERS);
${voters.map((v, i) => `        l[${i}] = ${v.commitment};`).join("\n")}
    }

    function leavesRange(uint256 from, uint256 to) internal pure returns (uint256[] memory l) {
        uint256[] memory all = leaves();
        l = new uint256[](to - from);
        for (uint256 i = from; i < to; i++) l[i - from] = all[i];
    }

    function root() internal pure returns (uint256) {
        return ${tree.root};
    }

    function rootAfter(uint256 count) internal pure returns (uint256) {
        if (count == 4) return ${rootAfter4};
        revert("unknown root");
    }

    /// @dev K=4, 3 candidates. Order: first votes of voters 0..7, then re-votes (0→idx1, 3→idx1, 3→idx2).
    function ballotsK4() internal pure returns (BallotProof[] memory b) {
        b = new BallotProof[](${k4.length});
${k4.map((p, i) => `        b[${i}] = ${proofLit(p)};`).join("\n")}
    }

    /// @dev indices into ballotsK4() of each voter's final ballot
    function finalsK4() internal pure returns (uint256[] memory f) {
        f = new uint256[](${finals.length});
${finals.map((v, i) => `        f[${i}] = ${v};`).join("\n")}
    }

    function countsK4() internal pure returns (uint32[] memory c) {
        c = new uint32[](3);
${countsK4.map((v, i) => `        c[${i}] = ${v};`).join("\n")}
    }

    /// @dev K=8, 5 candidates: voter 0 → candidate 4, voter 1 → candidate 3.
    function ballotsK8() internal pure returns (BallotProof[] memory b) {
        b = new BallotProof[](${k8.length});
${k8.map((p, i) => `        b[${i}] = ${proofLit(p)};`).join("\n")}
    }

    function nullifier(BallotProof memory p) internal pure returns (uint256) {
        return p.signals[p.signals.length - 7];
    }

    function ciphertext(BallotProof memory p) internal pure returns (uint256[] memory ct) {
        uint256 words = p.signals.length - 7;
        ct = new uint256[](words);
        for (uint256 i = 0; i < words; i++) ct[i] = p.signals[i];
    }

    function toTallyBallot(BallotProof memory p) internal pure returns (ITally.Ballot memory) {
        return ITally.Ballot({nullifier: nullifier(p), ciphertext: ciphertext(p)});
    }

    function sortByNullifier(BallotProof[] memory arr) internal pure {
        for (uint256 i = 1; i < arr.length; i++) {
            BallotProof memory key = arr[i];
            uint256 k = nullifier(key);
            uint256 j = i;
            while (j > 0 && nullifier(arr[j - 1]) > k) {
                arr[j] = arr[j - 1];
                j--;
            }
            arr[j] = key;
        }
    }

    function select(BallotProof[] memory all, uint256[] memory idx) internal pure returns (BallotProof[] memory out) {
        out = new BallotProof[](idx.length);
        for (uint256 i = 0; i < idx.length; i++) out[i] = all[idx[i]];
    }

${arrHelpers}
}
`;
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, sol);
  console.log(`wrote ${out}`);
  // keep the ballot-hash convention honest: keccak of the packed ciphertext words
  const h = bytesToBigIntBE(keccak_256(packWords(k4[0]!.signals.slice(0, 16)))) >> 32n;
  console.log(`ballotHash(k4[0]) = ${h}`);
}

function checksum(addr: string): string {
  const lower = addr.toLowerCase().replace(/^0x/, "");
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(lower))).slice(2);
  let r = "0x";
  for (let i = 0; i < lower.length; i++) r += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i];
  return r;
}

main().then(() => process.exit(0)).catch((e) => {
  console.error(e);
  process.exit(1);
});
