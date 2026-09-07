pragma circom 2.2.2;

template RepeatedOperandsO2() {
    signal input a;
    signal input b;
    signal input c;
    signal input d;
    signal output out;

    signal ab;
    signal cd;
    signal ab2;
    signal cd2;
    ab <== a * b;
    cd <== c * d;
    ab2 <== ab * ab;
    cd2 <== cd * cd;
    out <== ab2 + cd2;
}

component main = RepeatedOperandsO2();
