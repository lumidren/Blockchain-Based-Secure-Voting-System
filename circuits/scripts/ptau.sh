#!/usr/bin/env bash
# Phase-1 Powers of Tau for local development and CI.
# Production deployments MUST use the Perpetual Powers of Tau (Hermez) file instead, e.g.
#   PTAU_URL=https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau scripts/ptau.sh 17
# (expected sha256 recorded in docs/RUNBOOK.md §4).
# Usage: scripts/ptau.sh [power]   (default 17 — enough for ballot_k8)
set -euo pipefail
cd "$(dirname "$0")/.."
POWER="${1:-17}"
export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=8192}"
SNARKJS="pnpm exec snarkjs"
mkdir -p ptau
FINAL="ptau/pot${POWER}_final.ptau"
if [ -f "$FINAL" ]; then echo "ptau exists: $FINAL"; exit 0; fi
if [ -n "${PTAU_URL:-}" ]; then
  echo "==> downloading $PTAU_URL"
  curl -sSL -o "$FINAL" "$PTAU_URL"
  $SNARKJS powersoftau verify "$FINAL" | tail -2
  exit 0
fi
echo "==> generating local powers of tau 2^$POWER (development only)"
entropy() { head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
$SNARKJS powersoftau new bn128 "$POWER" ptau/pot_0000.ptau >/dev/null
$SNARKJS powersoftau contribute ptau/pot_0000.ptau ptau/pot_0001.ptau --name="dev contribution 1" -e="$(entropy)" >/dev/null
$SNARKJS powersoftau contribute ptau/pot_0001.ptau ptau/pot_0002.ptau --name="dev contribution 2" -e="$(entropy)" >/dev/null
# Beacon: for development a fixed documented value; production uses a drand round (see RUNBOOK §4).
$SNARKJS powersoftau beacon ptau/pot_0002.ptau ptau/pot_beacon.ptau 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20 10 -n="dev beacon" >/dev/null
$SNARKJS powersoftau prepare phase2 ptau/pot_beacon.ptau "$FINAL" >/dev/null
$SNARKJS powersoftau verify "$FINAL" | tail -2
rm -f ptau/pot_0000.ptau ptau/pot_0001.ptau ptau/pot_0002.ptau ptau/pot_beacon.ptau
echo "ptau ready: $FINAL"
