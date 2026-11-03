#!/usr/bin/env bash
# Fast, NON-CEREMONY proving keys for local tests (single deterministic phase-2 contribution).
# Never deploy a verifier produced by this script; use scripts/ceremony.sh for real artifacts.
set -euo pipefail
cd "$(dirname "$0")/.."
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=8192}"
SNARKJS="pnpm exec snarkjs"
POWER="${POWER:-16}"
NAMES=("$@")
if [ ${#NAMES[@]} -eq 0 ]; then NAMES=(ballot_k4 ballot_k8); fi
bash scripts/ptau.sh "$POWER"
for name in "${NAMES[@]}"; do
  out="build/${name:?}"
  if [ ! -f "$out/$name.r1cs" ]; then bash scripts/build.sh "$name"; fi
  echo "==> dev zkey for $name"
  $SNARKJS groth16 setup "$out/$name.r1cs" "ptau/pot${POWER}_final.ptau" "$out/${name}_0000.zkey" >/dev/null
  $SNARKJS zkey contribute "$out/${name}_0000.zkey" "$out/${name}_final.zkey" --name="dev" -e="dev-entropy-not-for-production" >/dev/null
  $SNARKJS zkey export verificationkey "$out/${name}_final.zkey" "$out/${name}_vkey.json" >/dev/null
  $SNARKJS zkey export solidityverifier "$out/${name}_final.zkey" "$out/${name}_verifier.sol" >/dev/null
  rm -f "${out:?}/${name:?}_0000.zkey"
  echo "    $out/${name}_final.zkey, ${name}_vkey.json, ${name}_verifier.sol"
done
