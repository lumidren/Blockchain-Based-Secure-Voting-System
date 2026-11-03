pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/babyjub.circom";
include "lib/merkle.circom";
include "lib/elgamal.circom";

/**
 * VeriVote ballot circuit.
 *
 * Proves, for an election identified by `electionId` with public key `pk`:
 *   1. knowledge of `sk` whose commitment Poseidon(sk) is in the Merkle tree with root `root`;
 *   2. nullifier = Poseidon(sk, electionId);
 *   3. m[0..K) is one-hot with the 1 in an active slot (i < numCandidates);
 *   4. (c1[i], c2[i]) = ElGamal_pk(m[i]; r[i]) for every slot.
 *
 * Public signal order (outputs first, then public inputs in declaration order):
 *   c1[0..K)[x,y], c2[0..K)[x,y], nullifier, root, electionId, pk[0], pk[1], numCandidates, voteIndex
 */
template Ballot(K, D) {
    // private
    signal input sk;
    signal input pathElements[D];
    signal input pathIndices[D];
    signal input m[K];
    signal input r[K];
    // public
    signal input root;
    signal input electionId;
    signal input pk[2];
    signal input numCandidates;
    signal input voteIndex;
    // outputs
    signal output c1[K][2];
    signal output c2[K][2];
    signal output nullifier;

    // 1. membership
    component idc = Poseidon(1);
    idc.inputs[0] <== sk;

    component inclusion = MerkleInclusion(D);
    inclusion.leaf <== idc.out;
    for (var i = 0; i < D; i++) {
        inclusion.pathElements[i] <== pathElements[i];
        inclusion.pathIndices[i] <== pathIndices[i];
    }
    root === inclusion.root;

    // 2. nullifier
    component nul = Poseidon(2);
    nul.inputs[0] <== sk;
    nul.inputs[1] <== electionId;
    nullifier <== nul.out;

    // public key must be a curve point
    component pkCheck = BabyCheck();
    pkCheck.x <== pk[0];
    pkCheck.y <== pk[1];

    // 3. one-hot ballot in an active slot
    component active[K];
    component enc[K];
    var sum = 0;
    for (var i = 0; i < K; i++) {
        m[i] * (m[i] - 1) === 0;
        sum += m[i];

        active[i] = LessThan(8);
        active[i].in[0] <== i;
        active[i].in[1] <== numCandidates;
        m[i] * (1 - active[i].out) === 0;

        // 4. encryption
        enc[i] = ElGamalEncryptBit();
        enc[i].m <== m[i];
        enc[i].r <== r[i];
        enc[i].pk[0] <== pk[0];
        enc[i].pk[1] <== pk[1];
        c1[i][0] <== enc[i].c1[0];
        c1[i][1] <== enc[i].c1[1];
        c2[i][0] <== enc[i].c2[0];
        c2[i][1] <== enc[i].c2[1];
    }
    sum === 1;

    // bind voteIndex into the proof (the optimizer would otherwise drop an unused public input)
    signal voteIndexSq;
    voteIndexSq <== voteIndex * voteIndex;
}
