pragma circom 2.2.2;

include "merces/server.circom";

// Params:
// N = 16 transactions per batch,
// MAX_DEPTH = 13 (arity-4),
// BALANCE_BITSIZE = 124,
// T = 16 (Poseidon2 sponge width used for compressing the public inputs).
component main {public [alpha]} = TransferBatchedCompressedArity4(16, 13, 124, 16);
