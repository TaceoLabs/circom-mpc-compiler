pragma circom 2.1.8;

// A chain of 3 sequential secret multiplications: multiplicative depth 3, each product depending
// on the previous one, so round_schedule cannot batch any two of them together. Used by
// tests/mpc_lowering.rs to assert exactly 3 rounds of width 1.
template Chain4() {
    signal input in[4];
    signal output out;

    signal inter[3];
    inter[0] <== in[0] * in[1];
    inter[1] <== inter[0] * in[2];
    inter[2] <== inter[1] * in[3];

    out <== inter[2];
}

component main = Chain4();
