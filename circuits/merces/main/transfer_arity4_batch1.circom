pragma circom 2.2.2;

include "merces/server.circom";

// Params:
// N = 1 transaction per batch,
// MAX_DEPTH = 13 (arity-4),
// BALANCE_BITSIZE = 124,
// T = 16 (Poseidon2 sponge width used for compressing the public inputs).
component main {public [alpha]} = TransferBatchedCompressedArity4(1, 13, 124, 16);
