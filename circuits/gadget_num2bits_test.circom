pragma circom 2.2.2;

include "bitify.circom";

// Wrapped so the gadget is a subcomponent: the compiler only cuts gadget sites at
// component-instantiation sites, never for `main` itself.
template Num2BitsSite(n) {
    signal input in;
    signal output out[n];

    out <== Num2Bits(n)(in);
}

component main = Num2BitsSite(8);
