#!/usr/bin/env bash
# Smoke-runs `merces-net` as three real processes on loopback, over a genuine TCP network - builds
# the binary, then launches all three parties against the checked-in `netcfg/` (loopback
# addresses, regenerate with `gen-config --hosts <real hostnames>` for an actual deployment).
#
# Usage:
#   scripts/run-merces-net.sh [merces-net run args, e.g. --runs 5 --opt 2 --check]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
netcfg="${MERCES_NET_NETCFG:-$root/netcfg}"

cargo build --release --features net --bin merces-net --manifest-path "$root/Cargo.toml"
bin="$root/target/release/merces-net"

if [ ! -f "$netcfg/party0.toml" ]; then
  "$bin" gen-config --out-dir "$netcfg" --hosts 127.0.0.1:10000 127.0.0.1:10001 127.0.0.1:10002
fi

RUST_LOG="${RUST_LOG:-warn}" "$bin" run --config "$netcfg/party1.toml" "$@" &
RUST_LOG="${RUST_LOG:-warn}" "$bin" run --config "$netcfg/party2.toml" "$@" &
"$bin" run --config "$netcfg/party0.toml" "$@"
wait
