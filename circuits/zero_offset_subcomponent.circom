pragma circom 2.0.0;

template Leaf() {
    signal input in;
    signal output out;

    out <== in + 1;
}

template SignalLessWrapper() {
    component leaf = Leaf();
    leaf.in <== 41;
}

component main = SignalLessWrapper();
