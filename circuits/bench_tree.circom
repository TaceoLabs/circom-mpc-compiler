pragma circom 2.1.8;

// A balanced product tree over 8 inputs: 4 independent products at depth 1, 2 at depth 2, 1 at
// depth 3. Used by tests/mpc_lowering.rs to assert 3 rounds with widths 4, 2, 1 - the width
// halving at each level is exactly what round_schedule batching is for.
template Tree8() {
    signal input in[8];
    signal output out;

    signal level1[4];
    level1[0] <== in[0] * in[1];
    level1[1] <== in[2] * in[3];
    level1[2] <== in[4] * in[5];
    level1[3] <== in[6] * in[7];

    signal level2[2];
    level2[0] <== level1[0] * level1[1];
    level2[1] <== level1[2] * level1[3];

    out <== level2[0] * level2[1];
}

component main = Tree8();
