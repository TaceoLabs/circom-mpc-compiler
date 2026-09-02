#!/usr/bin/env bash
# Prepares a fresh benchmark host to build and run merces-net with proving enabled.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${MERCES_BENCH_TOOLS_DIR:-$HOME/.local/share/merces-benchmark-tools}"
TOOLS_BIN="$TOOLS_DIR/node_modules/.bin"

CIRCOM_REV="53c1ccd0c74f12665c5aeb89592360f42c3d1226"
CIRCOM_HELPERS_REV="8aacd73ed6ab0a2b9b2158e613acfa920860865a"

# pnpm's standalone package avoids depending on the benchmark AMI's Node version.
npm install --prefix "$TOOLS_DIR" --no-save \
    @pnpm/exe@11.22.0 \
    snarkjs@0.7.5
"$TOOLS_BIN/pnpm" -C "$ROOT/circuits" install --frozen-lockfile

cargo install just --version 1.42.4 --locked
cargo install \
    --git https://github.com/TaceoLabs/circom \
    --rev "$CIRCOM_REV" \
    --locked \
    --bin circom \
    circom
cargo install \
    --git https://github.com/TaceoLabs/circom-helpers \
    --rev "$CIRCOM_HELPERS_REV" \
    --features bin \
    --bin convert-zkey-to-ark \
    taceo-circom-types

export PATH="$TOOLS_BIN:$HOME/.cargo/bin:$PATH"

just --justfile "$ROOT/justfile" download-ptau
just --justfile "$ROOT/justfile" merces-zkeys 1 8 16 32
