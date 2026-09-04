pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/binary_merkle_root.circom";
include "@taceo/circom-lib/circuits/poseidon2.circom";
include "circomlib/circuits/comparators.circom";

// Proves membership of a user group's policy (`maxAmountPerTx`,
// `maxTxsPerEpoch`) at `userGroupIdx` in the user group Merkle tree.
//
// The leaf is `Poseidon2(3)([maxAmountPerTx, maxTxsPerEpoch, domainSep])[0]`.
//
// `userGroupIdx` is not constrained here: the caller must enforce booleanity
// via `AccumulateIndexWithRangeCheck` over the same `userGroupIdx` array,
// which `RegistryLeafHash` (registry.circom) does as part of binding the same
// index into the ID registry leaf. Bits beyond `depth` are forced to zero by
// `BinaryMerkleRoot` itself, so the index cannot alias another group's leaf
// at idx mod 2^depth and no separate range check is needed.
template UserGroupMembership(MAX_DEPTH) {
    signal input userGroupIdx[MAX_DEPTH];
    signal input maxAmountPerTx;
    signal input maxTxsPerEpoch;

    signal input domainSep;

    signal input depth;
    signal input hashPath[MAX_DEPTH];

    signal output merkleRoot;

    signal leafHash[3] <== Poseidon2(3)([maxAmountPerTx, maxTxsPerEpoch, domainSep]);
    signal leaf <== leafHash[0];

    component merkleProof = BinaryMerkleRoot(MAX_DEPTH);
    merkleProof.leaf <== leaf;
    merkleProof.indexBits <== userGroupIdx;
    merkleProof.hashPath <== hashPath;
    merkleProof.depth <== depth;

    merkleRoot <== merkleProof.out;

}

// Enforces a user group's per-tx and per-epoch limits.
//
// Precondition on the caller, not enforced here:
// - `amount < 2^AMOUNT_BITSIZE`, e.g. via `CheckAmount` in `oblivious_vector/hash.circom`.
template UserGroupConstraints(AMOUNT_BITSIZE) {
    signal input maxAmountPerTx;
    signal input maxTxsPerEpoch;

    signal input amount;
    signal input authSecret;
    signal input counter;
    signal input epoch;

    signal output epochNullifier;

    // §1 - enforce amount is within user group limit
    //
    // Both operands of a circomlib comparator must be known to fit n bits, the
    // bound included. The limits are decomposed to the widths of the on-chain
    // `UserGroup` fields (`uint80`, `uint32`).
    signal maxAmountBits[AMOUNT_BITSIZE] <== Num2Bits(AMOUNT_BITSIZE)(maxAmountPerTx);
    signal amountCheck <== LessEqThan(AMOUNT_BITSIZE)([amount, maxAmountPerTx]);
    amountCheck === 1;

    // §2 - a user has a limit for txs/epoch. For that the user needs to compute a nullifier within this epoch as:
    //
    // nullifier = h(authSecret, counter, week_timestamp)
    //
    // where authSecret is the user's authentication secret and counter is smaller than maxTxsPerEpoch.

    // §2.1 - enforce counter is < maxTxsPerEpoch
    signal maxTxsBits[32] <== Num2Bits(32)(maxTxsPerEpoch);
    signal counterBits[32] <== Num2Bits(32)(counter);
    signal counterCheck <== LessThan(32)([counter, maxTxsPerEpoch]);
    counterCheck === 1;

    // §2.2 - build the nullifier
    // This is the ASCII byte sequence "TACEO-UserGroupConstraint-2.1" interpreted as a field element.
    // We don't need a dedicated domain separator per deployment for the nullifier as the nullifier is bound to the user's authentication secret. A user is able to bridge domains anyways and reusing the secret only hurts themselves.
    var DS = 0x544143454F2D5573657247726F7570436F6E73747261696E742D322E31;
    signal epochNullifierHash[4] <== Poseidon2(4)([authSecret, counter, epoch, DS]);
    epochNullifier <== epochNullifierHash[0];
}
