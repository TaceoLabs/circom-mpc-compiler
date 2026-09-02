pragma circom 2.2.2;

include "circomlib/circuits/aliascheck.circom";

// Wrapped so the gadget is a subcomponent: the compiler only cuts gadget sites at
// component-instantiation sites, never for `main` itself.
template AliasCheckSite() {
    signal input in[254];

    AliasCheck()(in);
}

component main = AliasCheckSite();
