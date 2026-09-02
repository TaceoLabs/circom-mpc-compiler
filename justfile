# Generates inputs/zkey/<main>.arks.zkey for the merces mains (batch sizes 1 8 16 32 by default).
# CIRCOM must be the fork rev pinned in Cargo.toml; PTAU defaults to
# ~/powers_of_tau/powersOfTau28_hez_final_21.ptau.
merces-zkeys *BATCHES:
    scripts/gen-merces-zkeys.sh {{BATCHES}}
