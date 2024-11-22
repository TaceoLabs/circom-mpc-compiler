
pragma circom 2.1.8;

template Multiplier2() {
    signal input a;
    signal input b;
    signal output c;
    c <== a*b;
 }

 component main {public [a]}= Multiplier2();
