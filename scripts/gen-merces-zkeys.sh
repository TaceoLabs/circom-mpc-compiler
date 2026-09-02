#!/usr/bin/env bash
# Generates `inputs/zkey/<main>.arks.zkey` for the merces mains: the ark-serialized, uncompressed
# groth16 proving keys `crates/circom-mpc-compiler-tests/tests/merces.rs` proves against. Plain
# `snarkjs groth16 setup` over a real powers-of-tau, no phase-2 contribution - fine for tests, not a
# ceremony.
#
# Prerequisites:
#   - circom built from the fork revision pinned in Cargo.toml (see gen-proving-artifacts.sh for
#     why a stock circom yields a different witness length), passed as CIRCOM
#   - snarkjs and convert-zkey-to-ark (co-snarks) on PATH
#   - a powers-of-tau, PTAU (default ~/powers_of_tau/powersOfTau28_hez_final_21.ptau)
#
# Usage:
#   CIRCOM=/path/to/pinned/circom scripts/gen-merces-zkeys.sh [batch-size ...]
# Defaults to batch sizes 1 8 16 32.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCOM="${CIRCOM:-circom}"
PTAU="${PTAU:-$HOME/powers_of_tau/powersOfTau28_hez_final_21.ptau}"
OUT="$ROOT/inputs/zkey"
BATCHES=("$@")
[[ $# -eq 0 ]] && BATCHES=(1 8 16 32)

for tool in "$CIRCOM" snarkjs convert-zkey-to-ark; do
    command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool not found" >&2; exit 1; }
done
[[ -f "$PTAU" ]] || { echo "error: powers of tau not found at $PTAU" >&2; exit 1; }

echo "circom: $CIRCOM ($("$CIRCOM" --version 2>&1 | head -1)) - must be the fork rev pinned in Cargo.toml"
mkdir -p "$OUT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gen-merces-zkeys.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

for n in "${BATCHES[@]}"; do
    main="transfer_arity4_batch$n"
    echo
    echo "=== $main ==="
    "$CIRCOM" "$ROOT/circuits/merces/main/$main.circom" \
        -l "$ROOT/circuits/node_modules" -l "$ROOT/circuits/merces" --r1cs --O2 -o "$WORK"
    snarkjs groth16 setup "$WORK/$main.r1cs" "$PTAU" "$WORK/$main.zkey"
    convert-zkey-to-ark --zkey-path "$WORK/$main.zkey" --arks-zkey-path "$OUT/$main.arks.zkey" --uncompressed
    rm -f "$WORK/$main.r1cs" "$WORK/$main.zkey"
    echo "$OUT/$main.arks.zkey  $(wc -c < "$OUT/$main.arks.zkey") bytes"
done
