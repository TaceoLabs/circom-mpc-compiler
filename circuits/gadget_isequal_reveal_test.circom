pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";
include "@taceo/circom-lib/circuits/mpc.circom";

template Main() {
    signal input secret[2];
    signal input clear;
    signal output out[3];

    signal eqSS <== IsEqual()([secret[0], secret[1]]);
    signal eqSP <== IsEqual()([secret[0], clear]);
    signal eqPS <== IsEqual()([clear, secret[1]]);

    signal revealedSS[1] <== TACEO_REVEAL(1)([eqSS]);
    signal revealedSP[1] <== TACEO_REVEAL(1)([eqSP]);
    signal revealedPS[1] <== TACEO_REVEAL(1)([eqPS]);

    out[0] <== revealedSS[0];
    out[1] <== revealedSP[0];
    out[2] <== revealedPS[0];
}

component main {public [clear]} = Main();
