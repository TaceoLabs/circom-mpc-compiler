pragma circom 2.2.2;

include "taceo/poseidon2.circom";

template WrapPoseidon2(T) {
    signal input in[T];
    signal output out[T];

    out <== Poseidon2(T)(in);
}

component main = WrapPoseidon2(3);
