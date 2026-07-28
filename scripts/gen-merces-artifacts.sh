#!/usr/bin/env bash
# Generates the reference artifact tests/merces.rs needs to check this compiler's output against
# circom's:
#
#   artifacts/<main>/<main>.r1cs           the constraint system
#
# `artifacts/` is gitignored. tests/merces.rs degrades gracefully on whatever is present and skips
# with a clear message when nothing is, so `cargo test` stays green on a fresh clone.
#
# The proving key comes from a separate source entirely: `inputs/zkey/<main>.arks.zkey`, the merces
# ceremony proving key (ark-serialized, uncompressed - see `tests/merces.rs`'s `ceremony_zkey`). It is
# too large to commit or regenerate here; this script does not touch it.
#
# Prerequisites:
#
#   A `circom` built from THIS CRATE'S PINNED FORK REVISION (`rev = "1cc17fb"` in Cargo.toml), not
#   whatever is on PATH. Different forks disagree on constraint-simplification-driven witness
#   compaction, so an R1CS from the wrong binary disagrees with this compiler's own witness layout
#   for the same circuit and flags. See docs/ARCHITECTURE.md, "Generating the zkeys and R1CS
#   fixtures". That revision also self-reports as circom 2.2.0 and rejects `pragma circom 2.2.2`, so
#   patch the VERSION const before building it:
#
#     cd ~/.cargo/git/checkouts/circom-*/1cc17fb
#     sed -i '' 's/^pub const VERSION.*/pub const VERSION: \&str = "2.2.2";/' circom/src/main.rs
#     cargo build --release --bin circom
#
#   then point CIRCOM at the result.
#
# Usage:
#   CIRCOM=/path/to/pinned/circom scripts/gen-merces-artifacts.sh [main ...]
#
# Defaults to both server mains; batch8's R1CS runs to hundreds of MB.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCOM="${CIRCOM:-circom}"
if [[ $# -gt 0 ]]; then
    MAINS=("$@")
else
    MAINS=(transfer_arity4_batch1 transfer_arity4_batch8)
fi

if ! command -v "$CIRCOM" >/dev/null 2>&1; then
    echo "error: circom not found (CIRCOM=$CIRCOM). See the prerequisites in this script." >&2
    exit 1
fi

echo "circom: $CIRCOM ($("$CIRCOM" --version 2>&1 | head -1))"
echo "note: this MUST be the pinned fork rev 1cc17fb - a stock circom produces a different"
echo "      witness length for the same circuit, and proving will fail confusingly."

for main in "${MAINS[@]}"; do
    out="$ROOT/artifacts/$main"
    mkdir -p "$out"
    echo
    echo "=== $main ==="

    # --O2 is the only level this compiler supports.
    "$CIRCOM" "$ROOT/circuits/merces/main/$main.circom" \
        -l "$ROOT/circuits/libs" -l "$ROOT/circuits/merces" \
        --r1cs --O2 -o "$out"
    echo "r1cs            $(wc -c < "$out/$main.r1cs") bytes"
    snarkjs r1cs info "$out/$main.r1cs" | tee "$out/r1cs-info.txt" >/dev/null
done

echo
echo "done. run: cargo test --test merces"
echo "        or: cargo test --test merces -- --ignored   (batch8, slow)"
