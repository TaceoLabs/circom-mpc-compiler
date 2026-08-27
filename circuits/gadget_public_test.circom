pragma circom 2.2.2;

include "comparators.circom";

template PublicGadget() {
    signal input a;
    signal input b;
    signal output out;

    component za = IsZero();
    component zb = IsZero();
    za.in <== a;
    zb.in <== b;
    out <== za.out * zb.out;
}

component main {public [a, b]} = PublicGadget();
