#!/usr/bin/env bash
# Generates the local zkeys `crates/circom-mpc-compiler-tests/tests/proving.rs` proves and
# verifies against:
#
#   kats/proving/<name>.zkey            a groth16 proving key
#   kats/proving/<name>-r1cs-info.txt   snarkjs r1cs info, for eyeballing variable counts
#
# The shared phase-2-ready power-14 transcript is downloaded into a unique temporary directory,
# verified, used, and deleted on every exit. It is deliberately never cached or committed.
#
# Prerequisites:
#
#   A `circom` built from THIS CRATE'S PINNED FORK REVISION (`rev = "53c1ccd0c74f12665c5aeb89592360f42c3d1226"` in Cargo.toml), not
#   whatever is on PATH. Different forks disagree on constraint-simplification-driven witness
#   compaction, so a circuit's variable count can differ for the same source and the same flags.
#   That revision already self-reports as circom 2.2.2, so no VERSION patch is needed:
#
#     cd ~/.cargo/git/checkouts/circom-*/53c1ccd0c74f12665c5aeb89592360f42c3d1226
#     cargo build --release --bin circom
#
#   then point CIRCOM at the result. `snarkjs` on PATH.
#
# Usage:
#   CIRCOM=/path/to/pinned/circom scripts/gen-proving-artifacts.sh [circuit ...]
#
# Defaults to every circuit the proving integration test wires up.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCOM="${CIRCOM:-circom}"
OUT="$ROOT/kats/proving"
if [[ $# -gt 0 ]]; then
    CIRCUITS=("$@")
else
    CIRCUITS=(
        multiplier3 multiplier16 loop_unrolling dead_code
        multiplier2_public constants_test babycheck_test control_flow
        gadget_poseidon2_test gadget_num2bits_test
        gadget_iszero_test gadget_aliascheck_test
    )
fi

if ! command -v "$CIRCOM" >/dev/null 2>&1; then
    echo "error: circom not found (CIRCOM=$CIRCOM). See the prerequisites in this script." >&2
    exit 1
fi
SNARKJS="${SNARKJS:-$ROOT/circuits/node_modules/.bin/snarkjs}"
if ! command -v "$SNARKJS" >/dev/null 2>&1; then
    echo "error: snarkjs not found (SNARKJS=$SNARKJS)." >&2
    exit 1
fi

echo "circom: $CIRCOM ($("$CIRCOM" --version 2>&1 | head -1))"
echo "note: this MUST be the pinned fork rev 53c1ccd0c74f12665c5aeb89592360f42c3d1226 - a stock circom produces different variable"
echo "      counts for the same circuit, and the prove+verify test will fail confusingly."

mkdir -p "$OUT"

POT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gen-proving-artifacts.XXXXXX")"
trap 'rm -rf "$POT_DIR"' EXIT
echo
echo "=== powers of tau (perpetual powers of tau contribution 0080, 2^14) ==="
PTAU="$POT_DIR/ppot_0080_14.ptau"
curl --fail --location --retry 3 --output "$PTAU" \
    https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_14.ptau
"$SNARKJS" powersoftau verify "$PTAU"

for name in "${CIRCUITS[@]}"; do
    echo
    echo "=== $name ==="
    "$CIRCOM" "$ROOT/circuits/$name.circom" -l "$ROOT/circuits/node_modules" --r1cs --O2 -o "$OUT"
    "$SNARKJS" r1cs info "$OUT/$name.r1cs" | tee "$OUT/$name-r1cs-info.txt" >/dev/null

    "$SNARKJS" groth16 setup "$OUT/$name.r1cs" "$PTAU" "$OUT/$name.zkey"

    size=$(wc -c < "$OUT/$name.zkey")
    echo "$name.zkey   $size bytes"
    if [[ "$size" -gt 5000000 ]]; then
        echo "note: $name.zkey is $((size / 1000000)) MB - too large to commit, removing it."
        echo "      (none of the default circuits should hit this; only relevant for custom -- args)"
        rm -f "$OUT/$name.zkey"
    fi
done

echo
echo "done. run: cargo test -p circom-mpc-compiler-tests --test proving"
