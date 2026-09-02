pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/mpc.circom";


// Returns the shared domain separator for the commit templates. It is the ASCII byte sequence "TACEO-Merces-Commit" interpreted as a field element.
function commitDs() {
    return 0x544143454f2d4d65726365732d436f6d6d6974;
}

// commit(amount, 0, r, DS). Uses state size 4 for Poseidon so that we can run all commitments in parallel to minimize depth.
template Commit1() {
    signal input value;
    signal input r;
    signal output out;

    var hash[4] = TACEO_PRECOMPUTATION_Poseidon2(4)([value, 0, r, commitDs()]);
    signal revealed[1] <== TACEO_REVEAL(1)([hash[0]]);
    out <== revealed[0];
}

// commit(balance, index; r, DS) — includes user index in the leaf commitment
template Commit2() {
    signal input balance;
    signal input index;
    signal input r;
    signal output out;

    var hash[4] = TACEO_PRECOMPUTATION_Poseidon2(4)([balance, index, r, commitDs()]);
    signal revealed[1] <== TACEO_REVEAL(1)([hash[0]]);
    out <== revealed[0];
}

template AccumulateIndexWithRangeCheck(N) {
    signal input indexBits[N];
    signal output out;

    signal muls[N + 1];
    muls[0] <== 0;

    for (var i = 0; i < N; i++) {
        muls[i + 1] <== muls[i] * 2 + indexBits[N - 1 - i];
        indexBits[N - 1 - i] * (indexBits[N - 1 - i] - 1) === 0;

    }
    out <== muls[N];
}

// Also checks whether index bits are either 0 or 1
template CommitIndexAndB2A(N) {
    signal input indexBits[N];
    signal input r;
    signal output commit;
    signal output index;

    index <== AccumulateIndexWithRangeCheck(N)(indexBits);
    commit <== Commit1()(index, r);
}

// Checks the size of amount and computes a commitment
template CheckAmount(AMOUNT_BITSIZE) {
    signal input amount;
    signal input amountR;
    signal output out;

    var bits[AMOUNT_BITSIZE] = Num2Bits(AMOUNT_BITSIZE)(amount);
    out <== Commit1()(amount, amountR);
}
