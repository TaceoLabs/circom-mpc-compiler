pragma circom 2.2.2;

// This file is copied from https://github.com/zk-kit/zk-kit.circom/blob/main/packages/binary-merkle-root/src/binary-merkle-root.circom and adapted to use Poseidon2 instead of Poseidon and use it in compression mode and not in sponge mode.

include "precomputations.circom";
include "comparators.circom";

// This circuit is designed to calculate the root of a binary Merkle
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
// Furthermore, it is *not* enforced that index_bits are 0 or 1. This needs to
// be done elsewhere in the circuit.
// Make sure to enforce `depth <= MAX_DEPTH` outside the circuit.
//
// There is no dedicated domain separation for compressing the different
// Merkle tree layers. If domain separation is required, leaf values must
// be domain separated before being passed to this circuit. Ideally, leaf
// values should not use the same hash construction as internal nodes
// (e.g. by using a sponge construction with a distinct domain separator
// in the capacity element) to prevent leaf values from being interpreted
// as internal node values.
template BinaryMerkleRoot(MAX_DEPTH) {
    signal input leaf;
    signal input index_bits[MAX_DEPTH];
    signal input hash_path[MAX_DEPTH];
    signal input depth;
    signal output out;

    signal nodes[MAX_DEPTH + 1];
    nodes[0] <== leaf;

    signal roots[MAX_DEPTH];
    signal mul[MAX_DEPTH];
    signal hash_left[MAX_DEPTH];
    signal hash_right[MAX_DEPTH];
    var root = 0;

    signal is_depth[MAX_DEPTH + 1];
    signal should_be_zeros[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        var isDepth = IsEqual()([depth, i]);
        is_depth[i] <== isDepth;
        roots[i] <== isDepth * nodes[i];
        root += roots[i];

        var path_bit = index_bits[i];
        var path_hash = hash_path[i];

        mul[i] <== path_bit * (path_hash - nodes[i]);
        hash_left[i] <== mul[i] + nodes[i];
        hash_right[i] <== path_hash - mul[i];

       // Compression mode
        var poseidon_result[2] = TACEO_PRECOMPUTATION_Poseidon2(2)([hash_left[i], hash_right[i]]);
        nodes[i + 1] <== poseidon_result[0] + hash_left[i];
    }

    var isDepth = IsEqual()([depth, MAX_DEPTH]);
    is_depth[MAX_DEPTH] <== isDepth;

    out <== root + isDepth * nodes[MAX_DEPTH];

    // For our use case we need to enforce that the index is in range. We do this by checking that for all bits greater than the depth, the index bit is zero.
    // We can reuse the isDepth signal from above to do this.
    // The following construction translates the one-hot vector isDepth to a vector where each element i is 1 starting with the 1 in isDepth and 0 before.
    // E.g., [0,0,1,0,0] is translated to [0,0,1,1,1].
    // Thus a constraint index_bits[i] * should_be_zeros[i] === 0 enforces that all bits in index_bits after the depth are zero.
    for (var i = 0; i < MAX_DEPTH; i++) {
        if (i == 0) {
            should_be_zeros[i] <== is_depth[i];
        } else {
            should_be_zeros[i] <== is_depth[i] + should_be_zeros[i-1];
        }
        should_be_zeros[i] * index_bits[i] === 0;
    }
}

