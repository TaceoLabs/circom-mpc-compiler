pragma circom 2.2.2;

include "@taceo/circom-lib/circuits/babyjubjub.circom";
include "@taceo/circom-lib/circuits/poseidon2.circom";

template DeriveSymKeyBits() {
    signal input mySkBits[251];
    signal input pk[2];
    signal output key;

    // NOTE: `pk` is assigned into a `twisted_edwards_in_subgroup` point without a
    // BabyJubJubCheckAndSubgroupCheck, so subgroup membership is NOT checked.
    // BabyJubJubScalarMulBits (EscalarMulAny) assumes a well-formed
    // subgroup point; an unchecked `pk` can break the Montgomery arithmetic or
    // leak small-subgroup information about the derived key. The CALLER must
    // guarantee `pk` is a valid BabyJubJub subgroup point before calling this template.
    BabyJubJubPoint() { twistedEdwardsInSubgroup } pkP;
    pkP.x <== pk[0];
    pkP.y <== pk[1];
    component symKey = BabyJubJubScalarMulBits();
    symKey.p <== pkP;
    symKey.e <== mySkBits;

    key <== symKey.out.x;
}

template Encrypt6() {
    signal input key;
    signal input nonce;
    signal input message[6];
    signal output cipher[6];

    // This is the ASCII byte sequence "TACEO-Merces-Encrypt" interpreted as a field element.
    var DS = 0x544143454F2D4D65726365732D456E6372797074;
    var poseidon2CipherState[8] = Poseidon2(8)([key, nonce, 0, 0, 0, 0, 0, DS]);
    for (var i = 0; i < 6; i++) {
        cipher[i] <== poseidon2CipherState[i] + message[i];
    }
}
