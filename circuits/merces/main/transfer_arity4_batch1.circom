pragma circom 2.2.2;

include "merces/server.circom";

// Params:
// N = 1 transactions per batch,
// MAX_DEPTH = 13 (arity-4),
// BALANCE_BITSIZE = 100,
// T = 16 (Poseidon2 sponge width used for compressing the public inputs).
component main {public [alpha]} = TransferBatchedCompressedArity4(1, 13, 100, 16);
