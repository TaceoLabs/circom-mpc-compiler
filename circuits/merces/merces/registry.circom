pragma circom 2.2.2;

include "taceo/babyjubjub.circom";
include "taceo/binary_merkle_root.circom";
include "taceo/poseidon2.circom";

// Derives the public key for `sk` and commits to the value by hashing it down to a single field element together with `domainSep`.
//
// The output is `Poseidon2(3)([pk.x, pk.y, domainSep])[0]`. The circuit additionally constraints `sk` to be a valid element in Fr.
template Query() {
    signal input sk;
    signal input domainSep;
    signal output query;

    component skRangeCheck = BabyJubJubIsInFr();
    skRangeCheck.in <== sk;
    component pkCalc = BabyJubJubScalarGeneratorBits();
    pkCalc.e <== skRangeCheck.out_bits;

    signal hashPk[3] <== Poseidon2(3)([pkCalc.out.x, pkCalc.out.y, domainSep]);
    query <== hashPk[0];
}

// Thin alias naming `Query`'s output as the registry Merkle leaf.
template RegistryPKHash() {
    signal input sk;
    signal input domainSep;
    signal output pkHash;

    component hash = Query();
    hash.sk <== sk;
    hash.domainSep <== domainSep;
    pkHash <== hash.query;
}

// Proves membership of the key derived from `sk` in the registration
// Merkle tree.
//
// Signals:
// - `sk`: private BabyJubJub secret key.
// - `mtIndex`: path bits, LSB first, selecting the leaf position.
// - `hashPath`: sibling hashes along the path to the root.
// - `depth`: the tree's actual depth (`<= MAX_DEPTH`); levels beyond it are
//   zero-padded.
// - `domainSep`: a per-deployment domain separator , matching the
//   registry contract's configured value.
//
// Domain separation only happens at the leaf, via `RegistryPKHash` above.
// `BinaryMerkleRoot` compresses internal nodes as
// `Poseidon2(2)([l, r])[0] + l`, with no domain separator of its own. This is
// safe because the leaf and internal-node hashes use different widths and
// different modes (width-3 truncated permutation vs. width-2 compression
// with feed-forward), so a leaf value can never be reinterpreted as an
// internal node — the precondition `BinaryMerkleRoot` documents in
// `@taceo/circom-lib/circuits/binary_merkle_root.circom`.
//
// Two preconditions are the caller's responsibility, not enforced here:
// - Booleanity of `mtIndex`: `BinaryMerkleRoot` only forces index bits past
//   `depth` to zero, it does not constrain the in-range bits to {0, 1}. In
//   `client.circom`, `Transfer` gets this from `CommitIndexAndB2A` /
//   `AccumulateIndexWithRangeCheck` (`oblivious_vector/hash.circom`) applied
//   to the same `sender` index.
// - `depth <= MAX_DEPTH` must be enforced outside the circuit; if violated,
//   `merkleRoot` is silently computed as 0 rather than raising an error.
template RegistryNoOprf(MAX_DEPTH) {
    signal input sk;
    signal input depth;
    signal input mtIndex[MAX_DEPTH];
    signal input hashPath[MAX_DEPTH];
    signal input domainSep;
    signal output merkleRoot;

    component hash = RegistryPKHash();
    hash.sk <== sk;
    hash.domainSep <== domainSep;

    component merkleProof = BinaryMerkleRoot(MAX_DEPTH);
    merkleProof.leaf <== hash.pkHash;
    merkleProof.index_bits <== mtIndex;
    merkleProof.hash_path <== hashPath;
    merkleProof.depth <== depth;
    merkleRoot <== merkleProof.out;
}
