/** Voter identity: secret, commitment (Merkle leaf) and per-election nullifier. */
import { randomFieldElement, P } from "./babyjub.js";
import { poseidon1, poseidon2 } from "./poseidon.js";

export interface Identity {
  readonly secret: bigint;
  readonly commitment: bigint;
}

export function generateIdentity(): Identity {
  const secret = randomFieldElement();
  return { secret, commitment: identityCommitment(secret) };
}

export function identityFromSecret(secret: bigint): Identity {
  if (secret <= 0n || secret >= P) throw new Error("secret out of field range");
  return { secret, commitment: identityCommitment(secret) };
}

export function identityCommitment(secret: bigint): bigint {
  return poseidon1(secret);
}

export function nullifierFor(secret: bigint, electionId: bigint): bigint {
  if (electionId < 0n || electionId >= P) throw new Error("electionId out of field range");
  return poseidon2(secret, electionId);
}
