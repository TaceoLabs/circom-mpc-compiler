#!/usr/bin/env bash
# Smoke-runs `merces-net` as three real processes on loopback, over a genuine TLS network - builds
# the binary, then launches all three parties against party configs (TOML + TLS key/cert material)
# produced outside this repo. Run this from wherever those configs' relative cert paths resolve.
#
# Usage:
#   scripts/run-merces-net.sh [merces-net args, e.g. --runs 5 --opt 2 --batches 1,8,16,32]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
configs="${MERCES_NET_CONFIGS:-$root/configs}"

cargo build --release -p circom-mpc-compiler-tests --no-default-features --features tls \
  --bin merces-net --manifest-path "$root/Cargo.toml"
bin="$root/target/release/merces-net"

for i in 1 2 3; do
  if [ ! -f "$configs/party$i.toml" ]; then
    echo "missing $configs/party$i.toml - supply party1.toml/party2.toml/party3.toml" \
         "(my_id 0/1/2) plus their TLS key/cert material, or set MERCES_NET_CONFIGS" >&2
    exit 1
  fi
done

RUST_LOG="${RUST_LOG:-warn}" "$bin" --config "$configs/party2.toml" "$@" &
RUST_LOG="${RUST_LOG:-warn}" "$bin" --config "$configs/party3.toml" "$@" &
"$bin" --config "$configs/party1.toml" "$@"
wait
