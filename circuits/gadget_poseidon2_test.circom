pragma circom 2.2.2;

include "taceo/poseidon2.circom";

// Wrapped so the gadget is a subcomponent: the compiler only cuts gadget sites at
// component-instantiation sites, never for `main` itself.
template Poseidon2Site(T) {
    signal input in[T];
    signal output out[T];

    out <== Poseidon2(T)(in);
}

component main = Poseidon2Site(3);
