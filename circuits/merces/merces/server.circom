pragma circom 2.2.2;

include "bitify.circom";
include "oblivious_vector/hash.circom";
include "dependencies/merkle_root_4.circom";
include "taceo/compression.circom";

template RangeCheckWithOutputFlag(BITSIZE) {
    assert(BITSIZE <= 254);
    assert(BITSIZE > 0);
    signal input in;
    signal output valid;

    // Num2Bits_strict with taceo_precomputation
    component n2b = TACEO_PRECOMPUTATION_Num2Bits(254);
    in ==> n2b.in;

    TACEO_PRECOMPUTATION_AliasCheck()(n2b.out);

    // Sum up all bits above BITSIZE
    // Works since bits are enforced to be 0 or 1 already.
    // Thus this sum cannot overflow and if at least one bit is 1, sum > 0
    var sum = 0;
    for (var i=BITSIZE; i<254; i++) {
        sum += n2b.out[i];
    }

    // Declassified: `valid` is one of the ten fields of the batch statement `q` compressed at the
    // end of `TransferBatchedCompressedArity4` (see `compression.circom`), so it is revealed there
    // regardless - doing it here lets it feed the rest of that compression as public, deterministic
    // work instead of round-tripping through MPC.
    signal isZeroOut <== TACEO_PRECOMPUTATION_IsZero()(sum);
    signal revealed[1] <== TACEO_REVEAL(1)([isZeroOut]);
    valid <== revealed[0];
}

// ─── Arity-4 variants ────────────────────────────────────────────────────────
template WithdrawInnerArity4(MAX_DEPTH, BALANCE_BITSIZE) {
    signal input index[2 * MAX_DEPTH];
     // Note: it is not enforced here that index and indexInt are the same.
    signal input indexInt;
    signal input hashPath[3 * MAX_DEPTH];
    signal input oldBalance;
    signal input oldBalanceR;
    signal input newBalanceR;
    signal input amount;
    signal input depth;
    // Outputs
    signal output oldRoot;
    signal output newRoot;
    signal output valid;
    signal output newBalanceCommitment;

    signal newBalance <== oldBalance - amount;
    valid <== RangeCheckWithOutputFlag(BALANCE_BITSIZE)(newBalance);
    signal oldBalanceCommitment <== Commit2()(oldBalance, indexInt, oldBalanceR);
    newBalanceCommitment <== Commit2()(newBalance, indexInt, newBalanceR);
    oldRoot <== MerkleRootArity4(MAX_DEPTH)(oldBalanceCommitment, index, hashPath, depth);
    newRoot <== MerkleRootArity4(MAX_DEPTH)(newBalanceCommitment, index, hashPath, depth);
}

template DepositInnerArity4(MAX_DEPTH) {
    signal input index[2 * MAX_DEPTH];
     // Note: it is not enforced here that index and indexInt are the same.
    signal input indexInt;
    signal input hashPath[3 * MAX_DEPTH];
    signal input oldBalance;
    signal input oldBalanceR;
    signal input newBalanceR;
    signal input amount; // Public
    signal input depth; // Public
    // Outputs
    signal output oldRoot;
    signal output newRoot;
    signal output newBalanceCommitment;

    signal newBalance <== oldBalance + amount;
    signal oldBalanceCommitment <== Commit2()(oldBalance, indexInt, oldBalanceR);
    newBalanceCommitment <== Commit2()(newBalance, indexInt, newBalanceR);
    oldRoot <== MerkleRootArity4(MAX_DEPTH)(oldBalanceCommitment, index, hashPath, depth);
    newRoot <== MerkleRootArity4(MAX_DEPTH)(newBalanceCommitment, index, hashPath, depth);
}

// Allows to batch a deposit/withdraw into a transfer
template DepositWithdrawTransferArity4(MAX_DEPTH, BALANCE_BITSIZE) {
    signal input sender[2 * MAX_DEPTH];
    signal input senderOldBalance;
    signal input senderOldBalanceR;
    signal input senderNewBalanceR;
    signal input senderIndexR;
    signal input senderPath[3 * MAX_DEPTH];
    signal input receiver[2 * MAX_DEPTH];
    signal input receiverOldBalance;
    signal input receiverOldBalanceR;
    signal input receiverNewBalanceR;
    signal input receiverIndexR;
    signal input receiverPath[3 * MAX_DEPTH];
    signal input amount;
    signal input amountR;
    signal input isDeposit; // Public
    signal input isWithdraw; // Public
    signal input depth; // Public
    // Outputs
    signal output oldRoot;
    signal output newRoot;
    signal output senderCommitment;
    signal output receiverCommitment;
    signal output amountCommitment;
    signal output valid;
    signal output senderNewCommitment;
    signal output receiverNewCommitment;

    // Enforce flags are correct
    // Both flags can be 0 (transfer), but cannot both be 1
    // Need to enforce outside the ZK proof that they are 0 or 1
    isDeposit * isWithdraw === 0; // Cannot be both deposit and withdraw

    component senderIdx = CommitIndexAndB2A(2 * MAX_DEPTH); // Includes range check of bits
    senderIdx.indexBits <== sender;
    senderIdx.r <== senderIndexR;
    senderCommitment <== senderIdx.commit;

    component receiverIdx = CommitIndexAndB2A(2 * MAX_DEPTH); // Includes range check of bits
    receiverIdx.indexBits <== receiver;
    receiverIdx.r <== receiverIndexR;
    receiverCommitment <== receiverIdx.commit;

    amountCommitment <== Commit1()(amount, amountR);

    component senderWithdraw = WithdrawInnerArity4(MAX_DEPTH, BALANCE_BITSIZE);
    senderWithdraw.index <== sender;
    senderWithdraw.indexInt <== senderIdx.index;
    senderWithdraw.hashPath <== senderPath;
    senderWithdraw.oldBalance <== senderOldBalance;
    senderWithdraw.oldBalanceR <== senderOldBalanceR;
    senderWithdraw.newBalanceR <== senderNewBalanceR;
    senderWithdraw.amount <== amount;
    senderWithdraw.depth <== depth;
    valid <== senderWithdraw.valid;
    senderNewCommitment <== senderWithdraw.newBalanceCommitment;

    component receiverDeposit = DepositInnerArity4(MAX_DEPTH);
    receiverDeposit.index <== receiver;
    receiverDeposit.indexInt <== receiverIdx.index;
    receiverDeposit.hashPath <== receiverPath;
    receiverDeposit.oldBalance <== receiverOldBalance;
    receiverDeposit.oldBalanceR <== receiverOldBalanceR;
    receiverDeposit.newBalanceR <== receiverNewBalanceR;
    receiverDeposit.amount <== amount;
    receiverDeposit.depth <== depth;
    receiverNewCommitment <== receiverDeposit.newBalanceCommitment;

    signal firstTerm <== isDeposit * receiverDeposit.oldRoot;
    signal secondTerm <== (1 - isDeposit) * senderWithdraw.oldRoot;
    signal thirdTerm <== isWithdraw * senderWithdraw.newRoot;
    signal fourthTerm <== (1 - isWithdraw) * receiverDeposit.newRoot;

    // If it is a deposit, we ignore the withdraw part of the proof and enforce that the deposit was done on the old root
    oldRoot <== firstTerm + secondTerm;
    // If it is a withdraw, we ignore the deposit part of the proof and enforce that the withdraw produced the new root
    newRoot <== thirdTerm + fourthTerm;

    // If it is a transfer, we need to link the withdraw and deposit together by enforcing the old deposit root is the new withdraw root
    signal isTransfer <== 1 - isDeposit - isWithdraw; // If both flags are 0, it's a transfer
    isTransfer * (senderWithdraw.newRoot - receiverDeposit.oldRoot) === 0; // If it's a transfer, enforce the roots are the same
}

template TransferBatchedArity4(N, MAX_DEPTH, BALANCE_BITSIZE, T) {
    signal input sender[N][2 * MAX_DEPTH];
    signal input senderOldBalance[N];
    signal input senderOldBalanceR[N];
    signal input senderNewBalanceR[N];
    signal input senderIndexR[N];
    signal input senderPath[N][3 * MAX_DEPTH];
    signal input receiver[N][2 * MAX_DEPTH];
    signal input receiverOldBalance[N];
    signal input receiverOldBalanceR[N];
    signal input receiverNewBalanceR[N];
    signal input receiverIndexR[N];
    signal input receiverPath[N][3 * MAX_DEPTH];
    signal input amount[N];
    signal input amountR[N];
    signal input depth; // Public input
    signal input isDeposit[N]; // Public input
    signal input isWithdraw[N]; // Public input
    // Outputs
    signal output oldRoot[N];
    signal output newRoot[N];
    signal output senderCommitment[N];
    signal output receiverCommitment[N];
    signal output amountCommitment[N];
    signal output valid[N];
    signal output senderNewCommitment[N];
    signal output receiverNewCommitment[N];

    component transactions[N];
    for (var i=0; i<N; i++) {
        transactions[i] = DepositWithdrawTransferArity4(MAX_DEPTH, BALANCE_BITSIZE);
        transactions[i].sender <== sender[i];
        transactions[i].senderOldBalance <== senderOldBalance[i];
        transactions[i].senderOldBalanceR <== senderOldBalanceR[i];
        transactions[i].senderNewBalanceR <== senderNewBalanceR[i];
        transactions[i].senderIndexR <== senderIndexR[i];
        transactions[i].senderPath <== senderPath[i];
        transactions[i].receiver <== receiver[i];
        transactions[i].receiverOldBalance <== receiverOldBalance[i];
        transactions[i].receiverOldBalanceR <== receiverOldBalanceR[i];
        transactions[i].receiverNewBalanceR <== receiverNewBalanceR[i];
        transactions[i].receiverIndexR <== receiverIndexR[i];
        transactions[i].receiverPath <== receiverPath[i];
        transactions[i].amount <== amount[i];
        transactions[i].amountR <== amountR[i];
        transactions[i].depth <== depth;
        transactions[i].isDeposit <== isDeposit[i];
        transactions[i].isWithdraw <== isWithdraw[i];

        oldRoot[i] <== transactions[i].oldRoot;
        newRoot[i] <== transactions[i].newRoot;
        // if (i != 0) { oldRoot[i] === newRoot[i - 1]; } Will be enforced on smart contract level

        senderCommitment[i] <== transactions[i].senderCommitment;
        receiverCommitment[i] <== transactions[i].receiverCommitment;
        amountCommitment[i] <== transactions[i].amountCommitment;
        valid[i] <== transactions[i].valid;
        senderNewCommitment[i] <== transactions[i].senderNewCommitment;
        receiverNewCommitment[i] <== transactions[i].receiverNewCommitment;
    }
}

template TransferBatchedCompressedArity4(N, MAX_DEPTH, BALANCE_BITSIZE, T) {
    signal input sender[N][2 * MAX_DEPTH];
    signal input senderOldBalance[N];
    signal input senderOldBalanceR[N];
    signal input senderNewBalanceR[N];
    signal input senderIndexR[N];
    signal input senderPath[N][3 * MAX_DEPTH];
    signal input receiver[N][2 * MAX_DEPTH];
    signal input receiverOldBalance[N];
    signal input receiverOldBalanceR[N];
    signal input receiverNewBalanceR[N];
    signal input receiverIndexR[N];
    signal input receiverPath[N][3 * MAX_DEPTH];
    signal input amount[N];
    signal input amountR[N];
    signal input depth; // Public input
    signal input isDeposit[N]; // Public input
    signal input isWithdraw[N]; // Public input
    // Original Outputs
    signal oldRoot[N];
    signal newRoot[N];
    signal senderCommitment[N];
    signal receiverCommitment[N];
    signal amountCommitment[N];
    signal valid[N];
    signal senderNewCommitment[N];
    signal receiverNewCommitment[N];

    signal input alpha; // Public input for compression
    signal output beta;
    signal output gamma;

    component transferBatched = TransferBatchedArity4(N, MAX_DEPTH, BALANCE_BITSIZE, T);
    transferBatched.sender <== sender;
    transferBatched.senderOldBalance <== senderOldBalance;
    transferBatched.senderOldBalanceR <== senderOldBalanceR;
    transferBatched.senderNewBalanceR <== senderNewBalanceR;
    transferBatched.senderIndexR <== senderIndexR;
    transferBatched.senderPath <== senderPath;
    transferBatched.receiver <== receiver;
    transferBatched.receiverOldBalance <== receiverOldBalance;
    transferBatched.receiverOldBalanceR <== receiverOldBalanceR;
    transferBatched.receiverNewBalanceR <== receiverNewBalanceR;
    transferBatched.receiverIndexR <== receiverIndexR;
    transferBatched.receiverPath <== receiverPath;
    transferBatched.amount <== amount;
    transferBatched.amountR <== amountR;
    transferBatched.depth <== depth;
    transferBatched.isDeposit <== isDeposit;
    transferBatched.isWithdraw <== isWithdraw;

    senderCommitment <== transferBatched.senderCommitment;
    receiverCommitment <== transferBatched.receiverCommitment;
    amountCommitment <== transferBatched.amountCommitment;
    valid <== transferBatched.valid;
    oldRoot <== transferBatched.oldRoot;
    newRoot <== transferBatched.newRoot;
    senderNewCommitment <== transferBatched.senderNewCommitment;
    receiverNewCommitment <== transferBatched.receiverNewCommitment;

    // Compressing the outputs
    var q[10 * N + 1];
    for (var i = 0; i < N; i++) {
        q[10 * i]      = senderCommitment[i];
        q[10 * i + 1]  = receiverCommitment[i];
        q[10 * i + 2]  = amountCommitment[i];
        q[10 * i + 3]  = valid[i];
        q[10 * i + 4]  = isDeposit[i];
        q[10 * i + 5]  = isWithdraw[i];
        q[10 * i + 6]  = oldRoot[i];
        q[10 * i + 7]  = newRoot[i];
        q[10 * i + 8]  = senderNewCommitment[i];
        q[10 * i + 9]  = receiverNewCommitment[i];
    }
    q[10 * N] = depth;

    component compression = Compression(10 * N + 1, T);
    compression.q <== q;
    compression.alpha <== alpha;
    beta <== compression.beta;
    gamma <== compression.gamma;
}
