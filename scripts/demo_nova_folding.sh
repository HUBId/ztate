#!/usr/bin/env bash
set -euo pipefail

# Reproducible Nova folding demo that bootstraps I_boot/π_boot and folds three blocks
# using the mock backend. The example prints the instance commitments, proof handle,
# and verification status for every step so operators can trace the chain end-to-end.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export RUST_LOG="${RUST_LOG:-info,folding=info,folding.pipeline=debug}"

cd "$ROOT_DIR"

cargo run \
  -p prover-backend-interface \
  --example nova_folding_demo \
  --features "prover-mock" \
  "$@"
