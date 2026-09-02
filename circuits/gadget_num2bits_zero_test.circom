pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";

template Num2BitsZeroWrapper() {
    signal input in;
    component bits = Num2Bits(0);
    bits.in <== in;
}

component main = Num2BitsZeroWrapper();
