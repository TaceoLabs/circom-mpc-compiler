pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/binary_merkle_root.circom";
include "@taceo/circom-lib/circuits/poseidon2.circom";
include "oblivious_vector/hash.circom";

// Commits to `authSecret` under `domainSep`: `Poseidon2(2)([authSecret,
// domainSep])[0]`. This is the value the ID-Registry stores per account at
// registration; `RegistryLeafHash` below and `main/user_auth.circom`'s
// `UserAuth` both call this so they derive the identical commitment.
template AuthSecretCommitment() {
    signal input authSecret;
    signal input domainSep;
    signal output authCommitment;

    signal commitmentHash[2] <== Poseidon2(2)([authSecret, domainSep]);
    authCommitment <== commitmentHash[0];
}

// Commits to `authSecret`, then binds that commitment to the user's group and
// `domainSep` to derive the registry Merkle leaf.
//
// `authCommitment = Poseidon2(2)([authSecret, domainSep])[0]`
// `leaf = Poseidon2(3)([userGroupIdx, authCommitment, domainSep])[0]`
// 
// We reuse the same domain separator as Poseidon2 with state size 2 and state size 3 are effectively different hash functions. Therefore reuse of the domain separator is legit.
template RegistryLeafHash(MAX_USER_GROUP_DEPTH) {
    signal input authSecret;
    signal input userGroupIdx[MAX_USER_GROUP_DEPTH];
    signal input domainSep;
    signal output leaf;

    // Also constrains userGroupIdx to be boolean; UserGroupMembership (in
    // user_group.circom) relies on this for the same userGroupIdx array, see
    // its precondition note.
    signal userGroupIdxArith <== AccumulateIndexWithRangeCheck(MAX_USER_GROUP_DEPTH)(userGroupIdx);

    // Compute the commitment to the authSecret. This will be part of the leaf for the user.
    signal authCommitment <== AuthSecretCommitment()(authSecret, domainSep);

    signal leafHash[3] <== Poseidon2(3)([userGroupIdxArith, authCommitment, domainSep]);
    leaf <== leafHash[0];
}

// Proves membership of an authentication commitment in the registration Merkle tree.
//
// Signals:
// - `authSecret`: private authentication secret, a preimage of a poseidon2 hash over BN254 scalar field
// - `userGroupIdx`: path bits, LSB first, of the user's index in the user
//   group tree. Bound into the leaf via `RegistryLeafHash` - a user's group
//   membership is fixed at registration and immutable thereafter.
// - `mtIndex`: path bits, LSB first, selecting the leaf position.
// - `hashPath`: sibling hashes along the path to the root.
// - `depth`: the tree's actual depth (`<= MAX_DEPTH`); levels beyond it are
//   zero-padded.
// - `domainSep`: a per-deployment domain separator , matching the
//   registry contract's configured value.
//
// Domain separation happens in both authentication hashes via `RegistryLeafHash` above.
// `BinaryMerkleRoot` compresses internal nodes as
// `Poseidon2(2)([l, r])[0] + l`, with no domain separator of its own. This is
// safe because the leaf and internal-node hashes use different widths and
// different modes (width-4 truncated permutation vs. width-2 compression
// with feed-forward), so a leaf value can never be reinterpreted as an
// internal node — the precondition `BinaryMerkleRoot` documents in
// `@taceo/circom-lib/circuits/binary_merkle_root.circom`.
//
// Two preconditions are the caller's responsibility, not enforced here:
// - Booleanity of `mtIndex`: `BinaryMerkleRoot` only forces index bits past
//   `depth` to zero, it does not constrain the in-range bits to {0, 1}. In
//   `client.circom`, `Transfer` applies `CommitIndexAndB2A` /
//   `AccumulateIndexWithRangeCheck` (`oblivious_vector/hash.circom`) to both
//   the `sender` and `receiver` indices unconditionally, so booleanity holds
//   for whichever of the two `mtIndex` is muxed to (receiver for deposits,
//   sender otherwise).
// - `depth <= MAX_DEPTH` must be enforced outside the circuit; if violated,
//   `merkleRoot` is silently computed as 0 rather than raising an error.
template RegistryNoOprf(MAX_ID_DEPTH, MAX_USER_GROUP_DEPTH) {
    signal input authSecret;
    signal input userGroupIdx[MAX_USER_GROUP_DEPTH];
    signal input depth;
    signal input mtIndex[MAX_ID_DEPTH];
    signal input hashPath[MAX_ID_DEPTH];
    signal input domainSep;
    signal output merkleRoot;

    component hash = RegistryLeafHash(MAX_USER_GROUP_DEPTH);
    hash.authSecret <== authSecret;
    hash.userGroupIdx <== userGroupIdx;
    hash.domainSep <== domainSep;

    component merkleProof = BinaryMerkleRoot(MAX_ID_DEPTH);
    merkleProof.leaf <== hash.leaf;
    merkleProof.indexBits <== mtIndex;
    merkleProof.hashPath <== hashPath;
    merkleProof.depth <== depth;
    merkleRoot <== merkleProof.out;
}
