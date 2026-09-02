#!/usr/bin/env bash
# Prepares a fresh benchmark host to build and run merces-net with proving enabled.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_BIN="$ROOT/circuits/node_modules/.bin"

CIRCOM_REV="53c1ccd0c74f12665c5aeb89592360f42c3d1226"
CIRCOM_HELPERS_REV="8aacd73ed6ab0a2b9b2158e613acfa920860865a"

# Keep this compatible with the benchmark AMI's Node 18. The package versions match
# circuits/package.json and its pnpm lockfile; --no-save leaves both manifests untouched.
npm install --prefix "$ROOT/circuits" --no-save --no-package-lock \
    @taceo/circom-lib@0.9.0 \
    circomlib@2.0.5 \
    snarkjs@0.7.5

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

export PATH="$CIRCUIT_BIN:$HOME/.cargo/bin:$PATH"

just --justfile "$ROOT/justfile" download-ptau
just --justfile "$ROOT/justfile" merces-zkeys 1 8 16 32
