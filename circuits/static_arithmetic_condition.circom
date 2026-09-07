pragma circom 2.0.0;

template StaticArithmeticCondition() {
    signal output out[3];

    for (var i = 0; i < 3; i++) {
        if (i + 1) {
            out[i] <== i + 7;
        } else {
            out[i] <== 99;
        }
    }
}

component main = StaticArithmeticCondition();
