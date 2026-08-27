pragma circom 2.2.2;

include "bitify.circom";

template WrapNum2Bits(n) {
    signal input in;
    signal output out[n];

    out <== Num2Bits(n)(in);
}

component main = WrapNum2Bits(8);
