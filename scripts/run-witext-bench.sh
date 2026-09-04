#!/usr/bin/env bash
# Smoke-runs `witext-bench` as three real processes on loopback, over a genuine TLS network -
# builds the binary, then launches all three parties against party configs (TOML + TLS key/cert
# material) produced outside this repo. Run this from wherever those configs' relative cert paths
# resolve.
#
# Usage:
#   scripts/run-witext-bench.sh [witext-bench args, e.g. --all-cases --batches 8,32 --opt 2 --runs 5]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
configs="${WITEXT_BENCH_CONFIGS:-$root/configs}"

cargo build --release -p circom-mpc-compiler-tests --no-default-features --features tls \
  --bin witext-bench --manifest-path "$root/Cargo.toml"
bin="$root/target/release/witext-bench"

for i in 1 2 3; do
  if [ ! -f "$configs/party$i.toml" ]; then
    echo "missing $configs/party$i.toml - supply party1.toml/party2.toml/party3.toml" \
         "(my_id 0/1/2) plus their TLS key/cert material, or set WITEXT_BENCH_CONFIGS" >&2
    exit 1
  fi
done

RUST_LOG="${RUST_LOG:-warn}" "$bin" --config "$configs/party2.toml" "$@" &
RUST_LOG="${RUST_LOG:-warn}" "$bin" --config "$configs/party3.toml" "$@" &
"$bin" --config "$configs/party1.toml" "$@"
wait
