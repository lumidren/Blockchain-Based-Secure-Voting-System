pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

/**
 * Proves that `leaf` is at the position described by `pathIndices` in a binary Poseidon Merkle tree
 * of depth D and outputs the root. pathIndices[i] = 0 when the running node is a left child.
 */
template MerkleInclusion(D) {
    signal input leaf;
    signal input pathElements[D];
    signal input pathIndices[D];
    signal output root;

    component hashers[D];
    component switchers[D];
    signal levelHash[D + 1];
    levelHash[0] <== leaf;

    for (var i = 0; i < D; i++) {
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== levelHash[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;
        levelHash[i + 1] <== hashers[i].out;
    }

    root <== levelHash[D];
}
