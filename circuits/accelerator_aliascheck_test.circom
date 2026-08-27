pragma circom 2.2.2;

include "aliascheck.circom";

template WrapAliasCheck() {
    signal input in[254];

    AliasCheck()(in);
}

component main = WrapAliasCheck();
