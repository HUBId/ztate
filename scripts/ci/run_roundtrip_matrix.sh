#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export FIXTURE_ROOT="${ROOT}/tests/fixtures"

if [[ ! -d "${FIXTURE_ROOT}" ]]; then
  echo "::error ::Fixture root not found at ${FIXTURE_ROOT}" >&2
  exit 1
fi

python3 - <<'PY'
from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

root = Path(os.environ["FIXTURE_ROOT"])
versions = sorted(root.glob("v*"))

if not versions:
    print("::error ::No fixtures available for roundtrip matrix", file=sys.stderr)
    sys.exit(1)

failures = 0
for version_dir in versions:
    version = version_dir.name
    proof = json.loads((version_dir / "proof.json").read_text())
    vk = json.loads((version_dir / "vk.json").read_text())

    if proof.get("version") != version or vk.get("version") != version:
        print(f"::error file={version_dir}::Version mismatch inside fixture", file=sys.stderr)
        failures += 1
        continue

    if proof.get("vk_commitment") != vk.get("commitment"):
        print(
            f"::error file={version_dir}::VK commitment mismatch between proof and vk",
            file=sys.stderr,
        )
        failures += 1

    rotation = vk.get("rotation")
    if not isinstance(rotation, list) or len(rotation) != 3:
        print(f"::error file={version_dir/'vk.json'}::Rotation matrix is not 3x3", file=sys.stderr)
        failures += 1
    else:
        valid_rows = [row for row in rotation if isinstance(row, list) and len(row) == 3]
        if len(valid_rows) != 3:
            print(f"::error file={version_dir/'vk.json'}::Rotation rows malformed", file=sys.stderr)
            failures += 1
        else:
            det = (
                rotation[0][0] * (rotation[1][1] * rotation[2][2] - rotation[1][2] * rotation[2][1])
                - rotation[0][1] * (rotation[1][0] * rotation[2][2] - rotation[1][2] * rotation[2][0])
                + rotation[0][2] * (rotation[1][0] * rotation[2][1] - rotation[1][1] * rotation[2][0])
            )
            if not math.isfinite(det) or abs(det - 1) > 0.1:
                print(
                    f"::error file={version_dir/'vk.json'}::Rotation determinant not within tolerance (det={det:.4f})",
                    file=sys.stderr,
                )
                failures += 1

if failures:
    sys.exit(1)

print(f"Validated roundtrip + rotation matrix for {len(versions)} fixture versions.")
PY
