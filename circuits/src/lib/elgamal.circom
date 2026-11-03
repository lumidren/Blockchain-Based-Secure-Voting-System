pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/escalarmulany.circom";

/**
 * Exponential ElGamal encryption of a bit on Baby Jubjub:
 *   c1 = r·G,  c2 = m·G + r·pk
 * `m` must be boolean-constrained by the caller. `r` is a 253-bit scalar.
 */
template ElGamalEncryptBit() {
    signal input m;
    signal input r;
    signal input pk[2];
    signal output c1[2];
    signal output c2[2];

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    component rBits = Num2Bits(253);
    rBits.in <== r;

    component mulG = EscalarMulFix(253, BASE8);
    component mulPk = EscalarMulAny(253);
    mulPk.p[0] <== pk[0];
    mulPk.p[1] <== pk[1];
    for (var i = 0; i < 253; i++) {
        mulG.e[i] <== rBits.out[i];
        mulPk.e[i] <== rBits.out[i];
    }
    c1[0] <== mulG.out[0];
    c1[1] <== mulG.out[1];

    // m·G as a boolean selection between the identity (0, 1) and G
    signal mGx;
    signal mGy;
    mGx <== m * BASE8[0];
    mGy <== 1 + m * (BASE8[1] - 1);

    component sum = BabyAdd();
    sum.x1 <== mGx;
    sum.y1 <== mGy;
    sum.x2 <== mulPk.out[0];
    sum.y2 <== mulPk.out[1];
    c2[0] <== sum.xout;
    c2[1] <== sum.yout;
}
