pragma circom 2.1.8;

// A sum of 4 independent secret products, all at depth 1. Used by tests/mpc_lowering.rs to assert
// they all batch into a single round of width 4 - the headline transform this compiler was built
// for: N independent secret multiplications cost one network round, not N.
template WideSum4() {
    signal input a[4];
    signal input b[4];
    signal output out;

    signal prod[4];
    prod[0] <== a[0] * b[0];
    prod[1] <== a[1] * b[1];
    prod[2] <== a[2] * b[2];
    prod[3] <== a[3] * b[3];

    signal partial[4];
    partial[0] <== prod[0];
    partial[1] <== partial[0] + prod[1];
    partial[2] <== partial[1] + prod[2];
    partial[3] <== partial[2] + prod[3];

    out <== partial[3];
}

component main = WideSum4();
