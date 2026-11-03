#!/usr/bin/env bash
# Circuit-specific phase-2 ceremony with contribution verification.
#
#   scripts/ceremony.sh init       <circuit>              groth16 setup from the phase-1 ptau -> <circuit>_0000.zkey
#   scripts/ceremony.sh contribute <circuit> <name>       add a contribution (entropy from $ENTROPY or prompt)
#   scripts/ceremony.sh verify     <circuit>              verify the whole chain against r1cs + ptau
#   scripts/ceremony.sh finalize   <circuit> <beaconHex>  apply the beacon, export vkey + Solidity verifier
#
# Each contributor runs `contribute` on their own machine and publishes the contribution hash that snarkjs
# prints; the coordinator runs `verify` after every contribution. The final zkey is reproducible from the
# chain of contributions and is re-verified in CI. See docs/RUNBOOK.md §4 for the production procedure.
set -euo pipefail
cd "$(dirname "$0")/.."
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=8192}"
SNARKJS="pnpm exec snarkjs"
POWER="${POWER:-16}"
PTAU="${PTAU:-ptau/pot${POWER}_final.ptau}"
cmd="${1:-}"
circuit="${2:-}"
if [ -z "$cmd" ] || [ -z "$circuit" ]; then sed -n '2,12p' "$0"; exit 1; fi
dir="ceremony/${circuit:?}"
mkdir -p "$dir"
latest() { ls "$dir"/"${circuit}"_[0-9][0-9][0-9][0-9].zkey 2>/dev/null | sort | tail -1; }
case "$cmd" in
  init)
    if [ ! -f "$PTAU" ]; then bash scripts/ptau.sh "$POWER"; fi
    if [ ! -f "build/$circuit/$circuit.r1cs" ]; then bash scripts/build.sh "$circuit"; fi
    $SNARKJS groth16 setup "build/$circuit/$circuit.r1cs" "$PTAU" "$dir/${circuit}_0000.zkey"
    sha256sum "$dir/${circuit}_0000.zkey" | tee "$dir/${circuit}_0000.sha256"
    ;;
  contribute)
    name="${3:?contributor name}"
    prev="$(latest)"
    if [ -z "$prev" ]; then echo "run init first"; exit 1; fi
    idx=$(( 10#$(basename "$prev" .zkey | sed "s/${circuit}_//") + 1 ))
    next="$dir/$(printf '%s_%04d.zkey' "$circuit" "$idx")"
    log="$dir/$(printf 'contribution_%04d.log' "$idx")"
    if [ -n "${ENTROPY:-}" ]; then
      $SNARKJS zkey contribute "$prev" "$next" --name="$name" -e="$ENTROPY" -v | tee "$log"
    else
      $SNARKJS zkey contribute "$prev" "$next" --name="$name" -v | tee "$log"
    fi
    sha256sum "$next" | tee "$dir/$(printf '%s_%04d.sha256' "$circuit" "$idx")"
    $SNARKJS zkey verify "build/$circuit/$circuit.r1cs" "$PTAU" "$next" | tail -2
    ;;
  verify)
    last="$(latest)"
    if [ -z "$last" ]; then echo "no zkeys"; exit 1; fi
    $SNARKJS zkey verify "build/$circuit/$circuit.r1cs" "$PTAU" "$last"
    if [ -f "$dir/${circuit}_final.zkey" ]; then
      $SNARKJS zkey verify "build/$circuit/$circuit.r1cs" "$PTAU" "$dir/${circuit}_final.zkey"
    fi
    ;;
  finalize)
    beacon="${3:?beacon hex (e.g. drand round randomness)}"
    last="$(latest)"
    $SNARKJS zkey beacon "$last" "$dir/${circuit}_final.zkey" "$beacon" 10 -n="final beacon"
    $SNARKJS zkey verify "build/$circuit/$circuit.r1cs" "$PTAU" "$dir/${circuit}_final.zkey" | tail -2
    $SNARKJS zkey export verificationkey "$dir/${circuit}_final.zkey" "$dir/${circuit}_vkey.json"
    $SNARKJS zkey export solidityverifier "$dir/${circuit}_final.zkey" "$dir/${circuit}_verifier.sol"
    sha256sum "$dir/${circuit}_final.zkey" "$dir/${circuit}_vkey.json" "$dir/${circuit}_verifier.sol" | tee "$dir/${circuit}_final.sha256"
    mkdir -p "build/$circuit"
    cp "$dir/${circuit}_final.zkey" "$dir/${circuit}_vkey.json" "$dir/${circuit}_verifier.sol" "build/$circuit/"
    ;;
  *) sed -n '2,12p' "$0"; exit 1 ;;
esac
