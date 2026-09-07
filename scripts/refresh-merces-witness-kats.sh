#!/usr/bin/env bash
# Developer-only: refresh the independent Circom full-witness digests checked by tests/merces.rs.
# CIRCOM must be the workspace-pinned Taceo fork at rev 53c1ccd0c74f12665c5aeb89592360f42c3d1226.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCOM="${CIRCOM:-circom}"
SNARKJS="${SNARKJS:-$ROOT/circuits/node_modules/.bin/snarkjs}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/refresh-merces-kats.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

for batch in 1 4; do
    name="transfer_arity4_batch${batch}"
    kat="$ROOT/kats/merces/$name"
    out="$WORK/$name"
    mkdir -p "$out"
    "$CIRCOM" "$ROOT/circuits/merces/main/$name.circom" \
        -l "$ROOT/circuits/node_modules" -l "$ROOT/circuits/merces" --wasm --O2 -o "$out"
    "$SNARKJS" wtns calculate "$out/${name}_js/${name}.wasm" "$kat/valid.json" "$out/witness.wtns"
    "$SNARKJS" wtns export json "$out/witness.wtns" "$out/witness.json"
    node - "$out/witness.json" "$kat/expected.sha256" <<'NODE'
const crypto = require("crypto");
const fs = require("fs");
const witness = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const hash = crypto.createHash("sha256");
for (const decimal of witness) {
  let value = BigInt(decimal);
  const canonical = Buffer.alloc(32);
  for (let i = 0; i < canonical.length; i++) {
    canonical[i] = Number(value & 255n);
    value >>= 8n;
  }
  if (value !== 0n) throw new Error("field element exceeds 32 bytes");
  hash.update(canonical);
}
fs.writeFileSync(process.argv[3], hash.digest("hex") + "\n");
NODE
    echo "$name: $(cat "$kat/expected.sha256")"
done
