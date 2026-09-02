# Generates inputs/zkey/<main>.arks.zkey for the merces mains (batch sizes 1 8 16 32 by default).
# CIRCOM must be the fork rev pinned in Cargo.toml; PTAU defaults to
# ~/powers_of_tau/powersOfTau28_hez_final_21.ptau.
merces-zkeys *BATCHES:
    scripts/gen-merces-zkeys.sh {{BATCHES}}

# Downloads the powers-of-tau file used by merces-zkeys. Set PTAU to override the destination.
download-ptau:
    #!/usr/bin/env bash
    set -euo pipefail

    url="https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau"
    target="${PTAU:-$HOME/powers_of_tau/powersOfTau28_hez_final_21.ptau}"
    partial="$target.part"

    if [[ -f "$target" ]]; then
        echo "powers of tau already exists at $target"
        exit 0
    fi

    mkdir -p "$(dirname "$target")"
    curl --fail --location --retry 3 --continue-at - --output "$partial" "$url"
    mv "$partial" "$target"
    echo "downloaded powers of tau to $target"
