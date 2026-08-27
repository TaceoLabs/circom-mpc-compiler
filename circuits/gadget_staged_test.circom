pragma circom 2.2.2;

include "comparators.circom";

// Two gadget sites of the *same kind* that cannot be serviced together: the second one's
// input depends on the first one's output, through a secret multiplication each way. This is the
// minimal version of the shape the merces circuits have at scale
// (`circuits/merces/merces/dependencies/merkle_root_4.circom` chains MAX_DEPTH Poseidon2 sites the
// same way), and it is what "staged batching" exists for: an implementation that ran every batch
// up front, or that keyed batches on multiplicative depth alone, gets this wrong.
//
// `IsZero` rather than `Poseidon2` deliberately: it is this compiler's own gadget on both the plain
// and rep3 paths, so this fixture tests *staging* rather than a gadget's trace layout.
//
// Expected: 2 sites, 2 batches (one site each) - see `Graph::mpc_summary`.
template StagedGadget() {
    signal input a;
    signal input b;
    signal output out;

    signal p <== a * b;
    signal z <== IsZero()(p);
    signal q <== z * a;
    out <== IsZero()(q);
}

component main = StagedGadget();
