pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/compression.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/mux1.circom";
include "merces/encryption.circom";
include "merces/registry.circom";
include "merces/user_group.circom";
include "oblivious_vector/hash.circom";

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

// Selects the account whose registry membership is proven: the receiver for
// deposits, or the sender for transfers and withdrawals. The caller must
// constrain isDeposit to be boolean.
template SelectClientRegistryIndex(MAX_ID_DEPTH) {
    signal input sender[MAX_ID_DEPTH];
    signal input receiver[MAX_ID_DEPTH];
    signal input isDeposit;
    signal output registryIndex[MAX_ID_DEPTH];

    signal registryCandidates[MAX_ID_DEPTH][2];
    for (var i = 0; i < MAX_ID_DEPTH; i++) {
        registryCandidates[i] <== [sender[i], receiver[i]];
    }
    registryIndex <== MultiMux1(MAX_ID_DEPTH)(registryCandidates, isDeposit);
}

// Validates and composes the action fields, creates their commitments, and
// returns the arithmetic indices used for encryption. Require
// distinct sender and receiver indices. Deposits/Withdraws are expected to supply zero
// sender inputs; the verifier enforces this by binding the sender commitment
// to Commit1(0, 0).
template ClientActionCommitments(MAX_ID_DEPTH, AMOUNT_BITSIZE) {
    signal input sender[MAX_ID_DEPTH];
    signal input receiver[MAX_ID_DEPTH];
    signal input amount;
    signal input senderR;
    signal input receiverR;
    signal input amountR;
    signal output senderCommitment;
    signal output receiverCommitment;
    signal output amountCommitment;
    signal output senderArith;
    signal output receiverArith;

    (senderCommitment, senderArith) <== CommitIndexAndB2A(MAX_ID_DEPTH)(sender, senderR);
    (receiverCommitment, receiverArith) <== CommitIndexAndB2A(MAX_ID_DEPTH)(receiver, receiverR);
    amountCommitment <== CheckAmount(AMOUNT_BITSIZE)(amount, amountR);

    signal senderReceiverEqual <== IsEqual()([senderArith, receiverArith]);
    senderReceiverEqual === 0;
}

template Transfer(MAX_ID_DEPTH, MAX_USER_GROUP_DEPTH, AMOUNT_BITSIZE) {
    signal input sender[MAX_ID_DEPTH];
    signal input receiver[MAX_ID_DEPTH];
    signal input amount;
    signal input senderR;
    signal input receiverR;
    signal input amountR;
    signal input message; // Public
    // ID registry proof
    signal input authSecret;
    signal input idDepth; // Public
    signal input idHashPath[MAX_ID_DEPTH];
    signal input idRegistryLength; // Public
    // Encryption
    signal input encryptSk;
    signal input mpcPk[2]; // Public
    // domain separators
    signal input idDomainSep; // Public
    signal input userGroupDomainSep; // Public
    // user group proof
    signal input userGroupIdx[MAX_USER_GROUP_DEPTH];
    signal input maxAmountPerTx;
    signal input maxTxsPerEpoch;
    signal input userGroupDepth; // Public
    signal input userGroupHashPath[MAX_USER_GROUP_DEPTH];
    // user group per-epoch tx limit
    signal input counter;
    signal input epoch; // Public
    signal input isDeposit; // Public
    // Outputs
    signal output idRoot;
    signal output userGroupRoot;
    signal output senderCommitment;
    signal output receiverCommitment;
    signal output amountCommitment;
    signal output encryptPk[2];
    signal output ciphertext[6];
    signal output epochNullifier;

    // The message can be used to encode additional data which will be part of the proof
    signal messageSquared <== message * message;

    // §1 - Multiplex whether this is a deposit or transfer/withdraw.
    //
    // The input to the Registry templates depends whether this is a deposit or transfer/withdraw.
    //
    // §1.1 - Enforce that isDeposit is boolean
    //
    // isDeposit is a public input therefore this is not strictly necessary. Nevertheless, this might be a footgun and is only one constraint therefore we add constraint it in circuit.
    isDeposit * (1 - isDeposit) === 0;

    // We need to enforce the user-group constraints on all transactions. As the receiver is the one executing the deposit, we need to enforce their user group. For transfer/withdraw it is the sender.
    component registryIndex = SelectClientRegistryIndex(MAX_ID_DEPTH);
    registryIndex.sender <== sender;
    registryIndex.receiver <== receiver;
    registryIndex.isDeposit <== isDeposit;

    // §2 - Perform the registry merkle-proof check
    //
    // This check verifies an account against a public merkle-root of the registry. The leaf of a user is computed as:
    //
    // authCommitment = Poseidon2([authSecret, DS])[0]
    // leaf = Poseidon2([userGroupIdx, authCommitment, DS])[0].
    //
    // Only the entity knowing the authentication secret can execute this circuit (including deposits).
    component registry = RegistryNoOprf(MAX_ID_DEPTH, MAX_USER_GROUP_DEPTH);
    registry.domainSep <== idDomainSep;
    registry.authSecret <== authSecret;
    registry.userGroupIdx <== userGroupIdx;
    registry.depth <== idDepth;
    registry.mtIndex <== registryIndex.registryIndex;
    registry.hashPath <== idHashPath;
    idRoot <== registry.merkleRoot;

    // §2.1 - Range-check the receiver index.
    //
    // The registry proof checks the selected account: the sender for transfer/withdraw, or the receiver for deposits. The receiver therefore needs a separate active-depth check for transfers and withdrawals.
    //
    // No separate sender check is needed: the registry proof checks it when active, and deposits bind the sender commitment to Commit1(0, 0) on the contract side, forcing zero sender inputs.
    //
    // No separate userGroupIdx check is needed: RegistryLeafHash enforces booleanity,
    // and UserGroupMembership enforces zero padding above userGroupDepth.
    component rangeCheck = RangeCheckIndex(MAX_ID_DEPTH);
    rangeCheck.indexBits <== receiver;
    rangeCheck.depth <== idDepth;

    // §3 - Validate and commit the action fields.
    //
    // This composes the bit-decomposed indices into arithmetic values while
    // enforcing bit booleanity, range-checks the amount, and creates the
    // sender, receiver, and amount commitments. For deposits, the sender is
    // inactive: the contract binds the sender commitment to Commit1(0, 0),
    // which forces zero sender inputs. A contract can bind a public deposit
    // or withdrawal amount by supplying Commit1(amount, 0) as the expected
    // amount commitment. For transfers and withdrawals, the sender and
    // receiver must be distinct. The arithmetic indices are reused when
    // building the encrypted payloads.
    component commitments = ClientActionCommitments(MAX_ID_DEPTH, AMOUNT_BITSIZE);
    commitments.sender <== sender;
    commitments.receiver <== receiver;
    commitments.amount <== amount;
    commitments.senderR <== senderR;
    commitments.receiverR <== receiverR;
    commitments.amountR <== amountR;
    senderCommitment <== commitments.senderCommitment;
    receiverCommitment <== commitments.receiverCommitment;
    amountCommitment <== commitments.amountCommitment;

    // §3.1 - Check that sender/receiver index fit in the IMT.
    //
    // The client proves that both indices existed within its requested
    // registry length. The contract separately caps that public value at the
    // registry's current length.
    signal idRegistryLengthBits[MAX_ID_DEPTH + 1] <== Num2Bits(MAX_ID_DEPTH + 1)(idRegistryLength);
    signal senderInRegistry <== LessThan(MAX_ID_DEPTH + 1)([commitments.senderArith, idRegistryLength]);
    signal receiverInRegistry <== LessThan(MAX_ID_DEPTH + 1)([commitments.receiverArith, idRegistryLength]);
    senderInRegistry === 1;
    receiverInRegistry === 1;

    // §4 - Prove membership of the selected account's user group.
    //
    // The user group is bound to the user by §2. We now need to verify that this user group exists against a public merkle root. The user group leaf is computed as
    //
    // Poseidon2([maxAmountPerTx, maxTxsPerEpoch, domainSep])[0].
    component userGroupMember = UserGroupMembership(MAX_USER_GROUP_DEPTH);
    userGroupMember.userGroupIdx <== userGroupIdx;
    userGroupMember.maxAmountPerTx <== maxAmountPerTx;
    userGroupMember.maxTxsPerEpoch <== maxTxsPerEpoch;
    userGroupMember.domainSep <== userGroupDomainSep;
    userGroupMember.depth <== userGroupDepth;
    userGroupMember.hashPath <== userGroupHashPath;
    userGroupRoot <== userGroupMember.merkleRoot;

    // §5 - Enforce user group constraints
    //
    // This includes two constraints and one computation at the moment:
    //
    // §5.1 - Amount must be <= maxAmountPerTx
    // §5.2 - Counter must be < maxTxsPerEpoch
    // §5.3 - Computes an epochNullifier as
    //        Poseidon2([authSecret, counter, weekTimestamp, DS])
    component userGroupConstraints = UserGroupConstraints(AMOUNT_BITSIZE);
    userGroupConstraints.maxAmountPerTx <== maxAmountPerTx;
    userGroupConstraints.maxTxsPerEpoch <== maxTxsPerEpoch;
    userGroupConstraints.amount <== amount;
    userGroupConstraints.authSecret <== authSecret;
    userGroupConstraints.counter <== counter;
    userGroupConstraints.epoch <== epoch;
    epochNullifier <== userGroupConstraints.epochNullifier;


    // §6 - Encrypt the plaintext for the MPC network.
    //
    // First, encryptSk is constrained to be a valid BabyJubJub scalar.
    // Diffie-Hellman with the MPC network's public key derives a symmetric key
    // and Encrypt6 encrypts [senderIdx, receiverIdx, amount, senderR,
    // receiverR, amountR]. The MPC nodes hold a secret-shared decryption key
    // and decrypt inside MPC, obtaining shares of these values. The MPC public
    // key must be a valid subgroup point; this is an external precondition.
    component skRangeCheck = BabyJubJubIsInFr();
    skRangeCheck.in <== encryptSk;
    signal symkey <== DeriveSymKeyBits()(skRangeCheck.outBits, mpcPk);
    // nonce = 0 is fine: `symkey` is derived from a freshly sampled
    // `encryptSk`, so each key is used for exactly one encryption.
    ciphertext <== Encrypt6()(symkey, 0, [
        commitments.senderArith,
        commitments.receiverArith,
        amount,
        senderR,
        receiverR,
        amountR
    ]);

    // §7 - Bind the ephemeral public key used for encryption.
    //
    // Compute encryptPk = encryptSk * G from the same scalar used in §6. This
    // binds the ciphertext key derivation to the exposed ephemeral public key
    // and lets the MPC network derive the matching shared key with its secret.
    component pkCalc = BabyJubJubScalarGeneratorBits();
    pkCalc.e <== skRangeCheck.outBits;
    encryptPk[0] <== pkCalc.out.x;
    encryptPk[1] <== pkCalc.out.y;
}

template TransferCompressed(MAX_ID_DEPTH, MAX_USER_GROUP_DEPTH, AMOUNT_BITSIZE) {
    signal input sender[MAX_ID_DEPTH];
    signal input receiver[MAX_ID_DEPTH];
    signal input amount;
    signal input senderR;
    signal input receiverR;
    signal input amountR;
    signal input message; // Public
    // ID registry proof
    signal input authSecret;
    signal input idDepth; // Public
    signal input idHashPath[MAX_ID_DEPTH];
    signal input idRegistryLength; // Public
    // Encryption
    signal input encryptSk;
    signal input mpcPk[2]; // Public
    // domain separators
    signal input idDomainSep; // Public
    signal input userGroupDomainSep; // Public
    // user group proof
    signal input userGroupIdx[MAX_USER_GROUP_DEPTH];
    signal input maxAmountPerTx;
    signal input maxTxsPerEpoch;
    signal input userGroupDepth; // Public
    signal input userGroupHashPath[MAX_USER_GROUP_DEPTH];
    // user group per-epoch tx limit
    signal input counter;
    signal input epoch; // Public
    signal input isDeposit; // Public
    // Original Outputs
    signal idRoot;
    signal userGroupRoot;
    signal senderCommitment;
    signal receiverCommitment;
    signal amountCommitment;
    signal encryptPk[2];
    signal ciphertext[6];
    signal epochNullifier;
    // Public input for compression
    signal input alpha; // Public
    // Outputs
    signal output betaCompression;
    signal output gamma;

    component transfer = Transfer(MAX_ID_DEPTH, MAX_USER_GROUP_DEPTH, AMOUNT_BITSIZE);
    transfer.sender <== sender;
    transfer.receiver <== receiver;
    transfer.amount <== amount;
    transfer.senderR <== senderR;
    transfer.receiverR <== receiverR;
    transfer.amountR <== amountR;
    transfer.message <== message;
    transfer.authSecret <== authSecret;
    transfer.idDepth <== idDepth;
    transfer.idHashPath <== idHashPath;
    transfer.idRegistryLength <== idRegistryLength;
    transfer.encryptSk <== encryptSk;
    transfer.mpcPk <== mpcPk;
    transfer.idDomainSep <== idDomainSep;
    transfer.userGroupDomainSep <== userGroupDomainSep;
    transfer.userGroupIdx <== userGroupIdx;
    transfer.maxAmountPerTx <== maxAmountPerTx;
    transfer.maxTxsPerEpoch <== maxTxsPerEpoch;
    transfer.userGroupDepth <== userGroupDepth;
    transfer.userGroupHashPath <== userGroupHashPath;
    transfer.counter <== counter;
    transfer.epoch <== epoch;
    transfer.isDeposit <== isDeposit;

    idRoot <== transfer.idRoot;
    userGroupRoot <== transfer.userGroupRoot;
    senderCommitment <== transfer.senderCommitment;
    receiverCommitment <== transfer.receiverCommitment;
    amountCommitment <== transfer.amountCommitment;
    encryptPk <== transfer.encryptPk;
    ciphertext <== transfer.ciphertext;
    epochNullifier <== transfer.epochNullifier;

    // The original public inputs/outputs
    var q[24];
    q[0] = epochNullifier;
    q[1] = message;
    q[2] = idDepth;
    q[3] = mpcPk[0];
    q[4] = mpcPk[1];
    q[5] = idRoot;
    q[6] = senderCommitment;
    q[7] = receiverCommitment;
    q[8] = amountCommitment;
    q[9] = encryptPk[0];
    q[10] = encryptPk[1];
    for (var i = 0; i < 6; i++) {
        q[11 + i] = ciphertext[i];
    }
    q[17] = idDomainSep;
    q[18] = userGroupRoot;
    q[19] = userGroupDepth;
    q[20] = userGroupDomainSep;
    q[21] = epoch;
    q[22] = isDeposit;
    q[23] = idRegistryLength;

    component compression = Compression(24, 16);
    compression.q <== q;
    compression.alpha <== alpha;
    betaCompression <== compression.beta;
    gamma <== compression.gamma;
}
