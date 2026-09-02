pragma circom 2.2.2;

// This file is copied from https://github.com/zk-kit/zk-kit.circom/blob/main/packages/binary-merkle-root/src/binary-merkle-root.circom and adapted to use Poseidon2 instead of Poseidon and use it in compression mode and not in sponge mode.

include "@taceo/circom-lib/circuits/poseidon2.circom";
include "circomlib/circuits/comparators.circom";

// This circuit is designed to calculate the root of a arity-4 Merkle
// tree given a leaf, its depth, and the necessary sibling
// information (aka proof of membership) which includes the index
// (in binary representation which defines the path indices)
// and the sibling nodes. If the number of siblings equals the depth,
// the index corresponds to the position of the leaf in the tree.
//
// A circuit is designed without the capability to iterate through
// a dynamic array. To address this, a parameter with the static maximum
// tree depth is defined (i.e. 'MAX_DEPTH'). And additionally, the circuit
// receives a dynamic depth as an input, which is utilized in calculating the
// true root of the Merkle tree. The actual depth of the Merkle tree
// may be equal to or less than the static maximum depth.
//
// NOTE: This circuit will successfully verify `out = 0` for `depth > MAX_DEPTH`.
// Furthermore, it is *not* enforced that indexBits are 0 or 1. This needs to
// be done elsewhere in the circuit.
// Make sure to enforce `depth <= MAX_DEPTH` outside the circuit.
template MerkleRootArity4(MAX_DEPTH) {
    signal input leaf;
    signal input indexBits[2 * MAX_DEPTH];
    signal input hashPath[3 * MAX_DEPTH];
    signal input depth;
    signal output out;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leaf;

    signal roots[MAX_DEPTH];
    signal hashInputs[MAX_DEPTH][4];
    var root = 0;

    signal isDepthBits[MAX_DEPTH + 1];
    signal shouldBeZeros[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        var isDepth = IsEqual()([depth, i]);
        isDepthBits[i] <== isDepth;
        roots[i] <== isDepth * nodes[i];
        root += roots[i];

        var pathBits[2] = [indexBits[2*i], indexBits[2*i + 1]];
        var pathHashes[3] = [hashPath[3*i], hashPath[3*i + 1], hashPath[3*i + 2]];
        hashInputs[i] <== CMuxMerkle()(nodes[i], pathHashes, pathBits);

        // Compression mode
        var poseidonResult[4] = Poseidon2(4)([hashInputs[i][0], hashInputs[i][1], hashInputs[i][2], hashInputs[i][3]]);
        nodes[i + 1] <== poseidonResult[0] + hashInputs[i][0];
    }

    var isDepth = IsEqual()([depth, MAX_DEPTH]);
    isDepthBits[MAX_DEPTH] <== isDepth;

    out <== root + isDepth * nodes[MAX_DEPTH];

    // For our use case we need to enforce that the index is in range. We do this by checking that for all bits greater than the depth, the index bit is zero.
    // We can reuse the isDepth signal from above to do this.
    // The following construction translates the one-hot vector isDepth to a vector where each element i is 1 starting with the 1 in isDepth and 0 before.
    // E.g., [0,0,1,0,0] is translated to [0,0,1,1,1].
    // Thus the constraints indexBits[2 * i] * shouldBeZeros[i] === 0
    // and indexBits[2 * i + 1] * shouldBeZeros[i] === 0
    // enforce that all pair of bits in indexBits corresponding to bits after the depth are zero.
    for (var i = 0; i < MAX_DEPTH; i++) {
        if (i == 0) {
            shouldBeZeros[i] <== isDepthBits[i];
        } else {
            shouldBeZeros[i] <== isDepthBits[i] + shouldBeZeros[i-1];
        }
        shouldBeZeros[i] * indexBits[i * 2] === 0;
        shouldBeZeros[i] * indexBits[i * 2 + 1] === 0;
    }
}

template CMuxMerkle() {
    signal input value;
    signal input witness[3];
    signal input selector[2]; // [LSB, MSB]
    signal output hashInput[4];

    hashInput <== Arity4CMux()(value, witness, selector);
}

// Different arrangements of node for values of p
// selector=0=00 => [v, w1, w2, w3]
// selector=1=10 => [w1, v, w2, w3]
// selector=2=01 => [w1, w2, v, w3]
// selector=3=11 => [w1, w2, w3, v]
// It is *not* enforced that selector bits are 0 or 1. This needs to
// be done elsewhere in the circuit.
template Arity4CMux() {
    signal input value;
    signal input witness[3];
    signal input selector[2]; // [LSB, MSB]
    signal output hashInput[4];

    signal p0p1 <== selector[0] * selector[1];
    signal p0n1 <== selector[0] - p0p1; // selector[0] * (1 - selector[1])
    signal n0p1 <== selector[1] - p0p1; // (1 - selector[0]) * selector[1]
    signal n0n1 <== 1 - selector[0] - selector[1] + p0p1; // (1 - selector[0]) * (1 - selector[1])

    // hashInput 0
    // h0 = (1 - p0) * (1 - p1) * v + p0 * w1 + (1 - p0) * p1 * w1
    //    = n0n1 * v + p0 * w1 + n0p1 * w1
    signal s0n0n1 <== value * n0n1;
    signal s1Tmp <==  witness[0] * (n0p1 + selector[0]);
    hashInput[0] <== s0n0n1 + s1Tmp;

    // hashInput 1
    // h1 = (1 - p0) * (1 - p1) * w1 + (1 - p1) * p0 * v + (1 - p0) * p1 * w2 + p0 * p1 * w2
    //    = n0n1 * w1 + p0n1 * v + n0p1 * w2 + p0p1 * w2
    signal s1n0n1 <== witness[0] * n0n1;
    signal s0p0n1 <== value * p0n1;
    signal s2Tmp <== witness[1] * (n0p1 + p0p1);
    hashInput[1] <== s1n0n1 + s0p0n1 + s2Tmp;

    // hashInput 2
    // h2 = (1 - p1) * w2 + (1 - p0) * p1 * v + p0 * p1 * w3
    //    = n1 * w2 + n0p1 * v + p0p1 * w3
    signal s2n1 <== witness[1] * (1 - selector[1]);
    signal s0n0p1 <== value * n0p1;
    signal s3p0p1 <== witness[2] * p0p1;
    hashInput[2] <== s2n1 + s0n0p1 + s3p0p1;

    // hashInput 3
    // h3 = (1 - p1) * w3 + (1 - p0) * p1 * w3 + p1 * p0 * v
    //    = n1 * w3 + n0p1 * w3 + p0p1 * v
    signal s3Tmp <== witness[2] * (1 - selector[1] + n0p1);
    signal s0p0p1 <== value * p0p1;
    hashInput[3] <== s3Tmp + s0p0p1;
}
