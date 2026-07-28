pragma circom 2.0.0;

template StaticSignedCondition() {
    signal output out[3];

    for (var i = 0; i < 3; i++) {
        if ((i - 2) < 0) {
            out[i] <== 7;
        } else {
            out[i] <== 9;
        }
    }
}

component main = StaticSignedCondition();
