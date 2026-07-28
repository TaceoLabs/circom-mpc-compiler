#!/usr/bin/env bash
# Generates the reference artifacts tests/merces.rs needs to check this compiler's output against
# circom's, and to produce a co-groth16 proof:
#
#   artifacts/<main>/input.json     the placeholder inputs (src/fixtures.rs), also fed to circom
#   artifacts/<main>/witness.wtns   circom's own witness  -> golden-KAT comparison
#   artifacts/<main>/<main>.r1cs    the constraint system -> R1CS satisfaction check
#   artifacts/<main>/<main>.zkey    a groth16 proving key -> prove + verify
#
# `artifacts/` is gitignored. tests/merces.rs degrades gracefully on whatever is present and skips
# with a clear message when nothing is, so `cargo test` stays green on a fresh clone.
#
# Prerequisites, neither of which this script can install for you:
#
#   1. A `circom` built from THIS CRATE'S PINNED FORK REVISION (`rev = "1cc17fb"` in Cargo.toml), not
#      whatever is on PATH. Different forks disagree on constraint-simplification-driven witness
#      compaction, so a witness from the wrong binary has a different length for the same circuit and
#      the same flags. See docs/ARCHITECTURE.md, "Generating and cross-checking the golden KATs".
#      That revision also self-reports as circom 2.2.0 and rejects `pragma circom 2.2.2`, so patch
#      the VERSION const before building it:
#
#        cd ~/.cargo/git/checkouts/circom-*/1cc17fb
#        sed -i '' 's/^pub const VERSION.*/pub const VERSION: \&str = "2.2.2";/' circom/src/main.rs
#        cargo build --release --bin circom
#
#      then point CIRCOM at the result.
#
#   2. snarkjs, and a powers-of-tau file big enough for the circuit (batch8 is large).
#
# Usage:
#   CIRCOM=/path/to/pinned/circom PTAU=/path/to/powersOfTau28_hez_final_21.ptau \
#     scripts/gen-merces-artifacts.sh [main ...]
#
# Defaults to transfer_arity4_batch1 only, since batch8's R1CS runs to hundreds of MB.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCOM="${CIRCOM:-circom}"
MAINS=("${@:-transfer_arity4_batch1}")

if ! command -v "$CIRCOM" >/dev/null 2>&1; then
    echo "error: circom not found (CIRCOM=$CIRCOM). See the prerequisites in this script." >&2
    exit 1
fi

echo "circom: $CIRCOM ($("$CIRCOM" --version 2>&1 | head -1))"
echo "note: this MUST be the pinned fork rev 1cc17fb - a stock circom produces a different"
echo "      witness length for the same circuit, and the KAT comparison will fail confusingly."

for main in "${MAINS[@]}"; do
    out="$ROOT/artifacts/$main"
    mkdir -p "$out"
    echo
    echo "=== $main ==="

    # 1. Inputs. Emitted by the same code path tests/merces.rs uses, so the two cannot disagree.
    cargo run --quiet --release --example gen-merces-input -- "$main" > "$out/input.json"
    echo "input.json      $(wc -c < "$out/input.json") bytes"

    # 2. R1CS + the witness calculator. --O2 matches tests/merces.rs's SimplificationLevel.
    "$CIRCOM" "$ROOT/circuits/merces/main/$main.circom" \
        -l "$ROOT/circuits/libs" -l "$ROOT/circuits/merces" \
        --r1cs --wasm --O2 -o "$out"
    echo "r1cs            $(wc -c < "$out/$main.r1cs") bytes"

    # 3. circom's own witness - the golden oracle.
    node "$out/${main}_js/generate_witness.js" \
        "$out/${main}_js/$main.wasm" "$out/input.json" "$out/witness.wtns"
    echo "witness.wtns    $(wc -c < "$out/witness.wtns") bytes"

    # 4. A proving key. Skipped without a PTAU, since everything except prove+verify still works.
    if [[ -n "${PTAU:-}" ]]; then
        snarkjs groth16 setup "$out/$main.r1cs" "$PTAU" "$out/$main.zkey"
        snarkjs zkey export verificationkey "$out/$main.zkey" "$out/$main.vkey.json"
        echo "zkey            $(wc -c < "$out/$main.zkey") bytes"
    else
        echo "zkey            skipped (set PTAU=... to generate one; prove+verify will be skipped)"
    fi
done

echo
echo "done. run: cargo test --features proving --test merces"
