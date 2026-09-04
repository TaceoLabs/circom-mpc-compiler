pragma circom 2.2.2;

include "circomlib/circuits/bitify.circom";

template Num2BitsMany(n, k) {
    signal input in[k];
    signal output out[k][n];
    component n2b[k];
    for (var i = 0; i < k; i++) {
        n2b[i] = Num2Bits(n);
        n2b[i].in <== in[i];
        for (var j = 0; j < n; j++) {
            out[i][j] <== n2b[i].out[j];
        }
    }
}

component main = Num2BitsMany(254, 64);
