/**
 * Append-only binary Poseidon Merkle tree (depth 20 by default) matching circuits/src/lib/merkle.circom
 * and the registrar's publication format. Zero leaf is 0; zero hashes Z_{i+1} = Poseidon(Z_i, Z_i).
 */
import { poseidon2 } from "./poseidon.js";

export const DEFAULT_DEPTH = 20;

export interface MerkleProof {
  readonly leaf: bigint;
  readonly index: number;
  readonly pathElements: bigint[];
  /** 0 when the node is a left child, 1 when it is a right child. */
  readonly pathIndices: number[];
  readonly root: bigint;
}

const zeroCache = new Map<number, bigint[]>();

/** Z_0..Z_depth. */
export function zeroHashes(depth: number): bigint[] {
  const cached = zeroCache.get(depth);
  if (cached) return cached;
  const zeros: bigint[] = [0n];
  for (let i = 0; i < depth; i++) {
    const prev = zeros[i] as bigint;
    zeros.push(poseidon2(prev, prev));
  }
  zeroCache.set(depth, zeros);
  return zeros;
}

export class PoseidonMerkleTree {
  readonly depth: number;
  private readonly levels: bigint[][]; // levels[0] = leaves
  private readonly zeros: bigint[];

  constructor(depth: number = DEFAULT_DEPTH, leaves: readonly bigint[] = []) {
    if (depth < 1 || depth > 32) throw new Error("depth must be in 1..32");
    this.depth = depth;
    this.zeros = zeroHashes(depth);
    this.levels = Array.from({ length: depth + 1 }, () => []);
    for (const leaf of leaves) this.insert(leaf);
  }

  get leafCount(): number {
    return (this.levels[0] as bigint[]).length;
  }

  get capacity(): number {
    return 2 ** this.depth;
  }

  get leaves(): readonly bigint[] {
    return this.levels[0] as bigint[];
  }

  insert(leaf: bigint): number {
    if (this.leafCount >= this.capacity) throw new Error("tree is full");
    const index = this.leafCount;
    (this.levels[0] as bigint[]).push(leaf);
    this.recomputePath(index);
    return index;
  }

  insertMany(leaves: readonly bigint[]): number {
    const start = this.leafCount;
    for (const l of leaves) this.insert(l);
    return start;
  }

  private node(level: number, index: number): bigint {
    const arr = this.levels[level] as bigint[];
    return index < arr.length ? (arr[index] as bigint) : (this.zeros[level] as bigint);
  }

  private recomputePath(leafIndex: number): void {
    let idx = leafIndex;
    for (let level = 0; level < this.depth; level++) {
      const parentIdx = idx >> 1;
      const left = this.node(level, parentIdx * 2);
      const right = this.node(level, parentIdx * 2 + 1);
      const parent = poseidon2(left, right);
      const arr = this.levels[level + 1] as bigint[];
      arr[parentIdx] = parent;
      idx = parentIdx;
    }
  }

  get root(): bigint {
    return this.node(this.depth, 0);
  }

  proof(index: number): MerkleProof {
    if (index < 0 || index >= this.leafCount) throw new Error("leaf index out of range");
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    let idx = index;
    for (let level = 0; level < this.depth; level++) {
      const isRight = idx & 1;
      pathIndices.push(isRight);
      pathElements.push(this.node(level, isRight ? idx - 1 : idx + 1));
      idx >>= 1;
    }
    return { leaf: this.node(0, index), index, pathElements, pathIndices, root: this.root };
  }

  indexOf(leaf: bigint): number {
    return (this.levels[0] as bigint[]).indexOf(leaf);
  }
}

export function verifyMerkleProof(proof: MerkleProof): boolean {
  let hash = proof.leaf;
  for (let i = 0; i < proof.pathElements.length; i++) {
    const sibling = proof.pathElements[i] as bigint;
    hash = proof.pathIndices[i] === 0 ? poseidon2(hash, sibling) : poseidon2(sibling, hash);
  }
  return hash === proof.root;
}

/** Root of a leaf list without keeping the tree (used by the audit CLI on published leaves). */
export function computeRoot(leaves: readonly bigint[], depth: number = DEFAULT_DEPTH): bigint {
  return new PoseidonMerkleTree(depth, leaves).root;
}
