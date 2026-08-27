#!/usr/bin/env bash
# Generates the checked-in zkeys `crates/circom-mpc-compiler-tests/tests/proving.rs` proves and
# verifies against:
#
#   kats/proving/<name>.zkey            a groth16 proving key, over a local toy powers-of-tau
#   kats/proving/<name>-r1cs-info.txt   snarkjs r1cs info, for eyeballing variable counts
#
# Every zkey here comes from a locally-generated toy powers-of-tau (one contribution, never
# reused across runs) - fine for exercising plumbing, never for anything real. The proving test
# skips a circuit's test with a printed note when its zkey is absent, so `cargo test` stays green
# on a fresh clone before this script has run.
#
# Prerequisites:
#
#   A `circom` built from THIS CRATE'S PINNED FORK REVISION (`rev = "1cc17fb"` in Cargo.toml), not
#   whatever is on PATH. Different forks disagree on constraint-simplification-driven witness
#   compaction, so a circuit's variable count can differ for the same source and the same flags.
#   That revision also self-reports as circom 2.2.0 and rejects `pragma circom 2.2.2`, so patch
#   the VERSION const before building it:
#
#     cd ~/.cargo/git/checkouts/circom-*/1cc17fb
#     sed -i '' 's/^pub const VERSION.*/pub const VERSION: \&str = "2.2.2";/' circom/src/main.rs
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
        accelerator_poseidon2_test accelerator_num2bits_test
        accelerator_iszero_test accelerator_aliascheck_test
    )
fi

if ! command -v "$CIRCOM" >/dev/null 2>&1; then
    echo "error: circom not found (CIRCOM=$CIRCOM). See the prerequisites in this script." >&2
    exit 1
fi
if ! command -v snarkjs >/dev/null 2>&1; then
    echo "error: snarkjs not found on PATH." >&2
    exit 1
fi

echo "circom: $CIRCOM ($("$CIRCOM" --version 2>&1 | head -1))"
echo "note: this MUST be the pinned fork rev 1cc17fb - a stock circom produces different variable"
echo "      counts for the same circuit, and the prove+verify test will fail confusingly."

mkdir -p "$OUT"

# One shared toy powers-of-tau, big enough for every circuit here (`loop_unrolling`'s ~1800 linear
# constraints is the largest by far, needing 2^13; 2^14 leaves headroom). Regenerated every run,
# never committed - it is not a trusted setup.
POT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gen-proving-artifacts.XXXXXX")"
trap 'rm -rf "$POT_DIR"' EXIT
echo
echo "=== powers of tau (toy, local, 2^14) ==="
snarkjs powersoftau new bn128 14 "$POT_DIR/pot0.ptau"
snarkjs powersoftau contribute "$POT_DIR/pot0.ptau" "$POT_DIR/pot1.ptau" --name=probe -e="$RANDOM$RANDOM"
snarkjs powersoftau prepare phase2 "$POT_DIR/pot1.ptau" "$POT_DIR/pot.ptau"

for name in "${CIRCUITS[@]}"; do
    echo
    echo "=== $name ==="
    "$CIRCOM" "$ROOT/circuits/$name.circom" -l "$ROOT/circuits/libs" --r1cs --O2 -o "$OUT"
    snarkjs r1cs info "$OUT/$name.r1cs" | tee "$OUT/$name-r1cs-info.txt" >/dev/null

    if ! snarkjs groth16 setup "$OUT/$name.r1cs" "$POT_DIR/pot.ptau" "$OUT/$name.zkey"; then
        echo "note: $name: groth16 setup failed (likely a degenerate R1CS) - skipping this circuit's zkey."
        rm -f "$OUT/$name.zkey"
        continue
    fi

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
