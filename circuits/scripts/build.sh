#!/usr/bin/env bash
# Compile every main circuit in src/ to build/<name>/ (r1cs, wasm witness generator, sym).
# Usage: scripts/build.sh [circuit-name ...]   (default: ballot_k4 ballot_k8)
set -euo pipefail
cd "$(dirname "$0")/.."
CIRCOM="${CIRCOM:-circom}"
if ! command -v "$CIRCOM" >/dev/null 2>&1; then
  for cand in "$HOME/.circom/bin/circom.exe" "$HOME/.circom/bin/circom" "$HOME/.cargo/bin/circom"; do
    if [ -x "$cand" ]; then CIRCOM="$cand"; break; fi
  done
fi
command -v "$CIRCOM" >/dev/null 2>&1 || { echo "circom not found (set CIRCOM=/path/to/circom)"; exit 1; }
NAMES=("$@")
if [ ${#NAMES[@]} -eq 0 ]; then NAMES=(ballot_k4 ballot_k8); fi
mkdir -p build
for name in "${NAMES[@]}"; do
  out="build/${name:?}"
  mkdir -p "$out"
  echo "==> compiling $name"
  "$CIRCOM" "src/$name.circom" --r1cs --wasm --sym --O2 -o "$out" -l node_modules -l ../node_modules
  echo "    r1cs: $out/$name.r1cs  wasm: $out/${name}_js/$name.wasm"
done
