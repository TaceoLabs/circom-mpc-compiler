pragma circom 2.2.2;

include "merces/registry.circom";
include "oblivious_vector/hash.circom";
include "merces/encryption.circom";
include "taceo/compression.circom";

template AdditiveThirdShare() {
    signal input secret;
    signal input r[2];
    signal output share;

    share <== secret - r[0] - r[1];
}

template RangeCheckIndex(MAX_DEPTH) {
    signal input indexBits[MAX_DEPTH];
    signal input depth;

    signal shouldBeZeros[MAX_DEPTH];
    for (var i = 0; i < MAX_DEPTH; i++) {
        var isDepth = IsEqual()([depth, i]);
        if (i == 0) {
            shouldBeZeros[i] <== isDepth;
        } else {
            shouldBeZeros[i] <== isDepth + shouldBeZeros[i-1];
        }
        shouldBeZeros[i] * indexBits[i] === 0;
    }
}

template Transfer(MAX_DEPTH, AMOUNT_BITSIZE) {
    signal input sender[MAX_DEPTH];
    signal input receiver[MAX_DEPTH];
    signal input amount;
    signal input senderR;
    signal input receiverR;
    signal input amountR;
    signal input nullifier; // Public
    signal input message; // Public
    // Registry proof
    signal input sk;
    signal input depth; // Public
    signal input hashPath[MAX_DEPTH];
    // Encryptions
    signal input encryptSk;
    signal input pks[3][2]; // Public
    // secret shares (sender and receiver indices are encrypted plaintext, not shared)
    signal input shareAmount[2];
    signal input shareRSender[2];
    signal input shareRReceiver[2];
    signal input shareRAmount[2];
    // domain separator
    signal input domainSep; // Public
    // Outputs
    signal output merkleRoot;
    signal output senderCommitment;
    signal output receiverCommitment;
    signal output amountCommitment;
    signal output encryptPk[2];
    signal output ciphertexts[3][6];

    // The nullifier is a random value which is intended to prevent replaying the same proof. In other words, the receiver maintains a list of nullifiers that have been used in proofs before.
    // Dummy square to prevent tampering nullifier, same as done in Semaphore
    signal nullifierSquared <== nullifier * nullifier;
    // The message can be used to encode additional data which will be part of the proof
    signal messageSquared <== message * message;

    // 1. Proof ID registry of sender
    component registry = RegistryNoOprf(MAX_DEPTH);
    registry.domainSep <== domainSep;
    registry.sk <== sk;
    registry.depth <== depth;
    registry.mtIndex <== sender;
    registry.hashPath <== hashPath;
    merkleRoot <== registry.merkleRoot;

    // 2. Range check of receiver index bits. Note sender range check is included in Registry above
    component rangeCheck = RangeCheckIndex(MAX_DEPTH);
    rangeCheck.indexBits <== receiver;
    rangeCheck.depth <== depth;

    // 3. Commitments and bit compose
    signal senderArith;
    signal receiverArith;
    (senderCommitment, senderArith) <== CommitIndexAndB2A(MAX_DEPTH)(sender, senderR);
    (receiverCommitment, receiverArith) <== CommitIndexAndB2A(MAX_DEPTH)(receiver, receiverR);
    amountCommitment <== CheckAmount(AMOUNT_BITSIZE)(amount, amountR);

    // 3.1 Check that sender != receiver
    signal senderReceiverEqual <== IsEqual()([senderArith, receiverArith]);
    senderReceiverEqual === 0;

    ////////////////////////////////////////////////////////////////////////////
    // Encryption for MPC nodes:

    // 4. Additive shares for amount and randomness; sender/receiver are encrypted as plaintext
    signal shareAmountAll[3];
    signal shareRSenderAll[3];
    signal shareRReceiverAll[3];
    signal shareRAmountAll[3];
    for (var i = 0; i < 2; i++) {
        shareAmountAll[i] <== shareAmount[i];
        shareRSenderAll[i] <== shareRSender[i];
        shareRReceiverAll[i] <== shareRReceiver[i];
        shareRAmountAll[i] <== shareRAmount[i];
    }
    shareAmountAll[2] <== AdditiveThirdShare()(amount, [shareAmountAll[0], shareAmountAll[1]]);
    shareRSenderAll[2] <== AdditiveThirdShare()(senderR, [shareRSenderAll[0], shareRSenderAll[1]]);
    shareRReceiverAll[2] <== AdditiveThirdShare()(receiverR, [shareRReceiverAll[0], shareRReceiverAll[1]]);
    shareRAmountAll[2] <== AdditiveThirdShare()(amountR, [shareRAmountAll[0], shareRAmountAll[1]]);
    // 5. ciphertexts: [senderIdx, receiverIdx, amountShare, senderRShare, receiverRShare, amountRShare] encrypted under pk derived from encryptSk for each MPC node
    component skRangeCheck = BabyJubJubIsInFr();
    skRangeCheck.in <== encryptSk;
    for (var i = 0; i < 3; i++) {
        var symkey = DeriveSymKeyBits()(skRangeCheck.out_bits, pks[i]);
        // nonce = 0 is fine: `symkey` is derived from a freshly
        // sampled `encryptSk`, so each key is used for exactly one
        // encryption.
        ciphertexts[i] <== Encrypt6()(symkey, 0,
        [senderArith, receiverArith, shareAmountAll[i], shareRSenderAll[i], shareRReceiverAll[i], shareRAmountAll[i]]);
    }

    // 6. Prove the correct public key was used for encryption
    component pkCalc = BabyJubJubScalarGeneratorBits();
    pkCalc.e <== skRangeCheck.out_bits;
    encryptPk[0] <== pkCalc.out.x;
    encryptPk[1] <== pkCalc.out.y;
}

template TransferCompressed(MAX_DEPTH, AMOUNT_BITSIZE) {
    signal input sender[MAX_DEPTH];
    signal input receiver[MAX_DEPTH];
    signal input amount;
    signal input senderR;
    signal input receiverR;
    signal input amountR;
    signal input nullifier; // Public
    signal input message; // Public
    // Registry proof
    signal input sk;
    signal input depth; // Public
    signal input hashPath[MAX_DEPTH];
    // Encryptions
    signal input encryptSk;
    signal input pks[3][2]; // Public
    // secret shares (sender and receiver indices are encrypted plaintext, not shared)
    signal input shareAmount[2];
    signal input shareRSender[2];
    signal input shareRReceiver[2];
    signal input shareRAmount[2];
    // domain separator
    signal input domainSep; // Public
    // Original Outputs
    signal merkleRoot;
    signal senderCommitment;
    signal receiverCommitment;
    signal amountCommitment;
    signal encryptPk[2];
    signal ciphertexts[3][6];
    // Public input for compression
    signal input alpha; // Public
    // Outputs
    signal output betaCompression;
    signal output gamma;

    component transfer = Transfer(MAX_DEPTH, AMOUNT_BITSIZE);
    transfer.domainSep <== domainSep;
    transfer.sender <== sender;
    transfer.receiver <== receiver;
    transfer.amount <== amount;
    transfer.senderR <== senderR;
    transfer.receiverR <== receiverR;
    transfer.amountR <== amountR;
    transfer.nullifier <== nullifier;
    transfer.message <== message;
    transfer.sk <== sk;
    transfer.depth <== depth;
    transfer.hashPath <== hashPath;
    transfer.encryptSk <== encryptSk;
    transfer.pks <== pks;
    transfer.shareAmount <== shareAmount;
    transfer.shareRSender <== shareRSender;
    transfer.shareRReceiver <== shareRReceiver;
    transfer.shareRAmount <== shareRAmount;

    merkleRoot <== transfer.merkleRoot;
    senderCommitment <== transfer.senderCommitment;
    receiverCommitment <== transfer.receiverCommitment;
    amountCommitment <== transfer.amountCommitment;
    encryptPk <== transfer.encryptPk;
    ciphertexts <== transfer.ciphertexts;

    // The original public inputs/outputs
    var q[34];
    q[0] = nullifier;
    q[1] = message;
    q[2] = depth;
    q[3] = pks[0][0];
    q[4] = pks[0][1];
    q[5] = pks[1][0];
    q[6] = pks[1][1];
    q[7] = pks[2][0];
    q[8] = pks[2][1];
    q[9] = merkleRoot;
    q[10] = senderCommitment;
    q[11] = receiverCommitment;
    q[12] = amountCommitment;
    q[13] = encryptPk[0];
    q[14] = encryptPk[1];
    for (var i = 0; i < 6; i++) {
        q[15 + i] = ciphertexts[0][i];
        q[21 + i] = ciphertexts[1][i];
        q[27 + i] = ciphertexts[2][i];
    }
    q[33] = domainSep;

    component compression = Compression(34, 16);
    compression.q <== q;
    compression.alpha <== alpha;
    betaCompression <== compression.beta;
    gamma <== compression.gamma;
}
