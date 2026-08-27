pragma circom 2.2.2;

include "comparators.circom";

// Wrapped so the gadget is a subcomponent: the compiler only cuts gadget sites at
// component-instantiation sites, never for `main` itself.
template IsZeroSite() {
    signal input in;
    signal output out;

    out <== IsZero()(in);
}

component main = IsZeroSite();
