pragma circom 2.2.2;

include "comparators.circom";

template WrapIsZero() {
    signal input in;
    signal output out;

    out <== IsZero()(in);
}

component main = WrapIsZero();
