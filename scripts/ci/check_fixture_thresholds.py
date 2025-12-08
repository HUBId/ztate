#!/usr/bin/env python3
"""Guard proof and VK size/latency metrics against regressions."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures"

DEFAULT_THRESHOLDS = {
    "proof_bytes": int(os.environ.get("PROOF_SIZE_THRESHOLD", 26000)),
    "vk_bytes": int(os.environ.get("VK_SIZE_THRESHOLD", 20000)),
    "roundtrip_latency_ms": int(os.environ.get("ROUNDTRIP_LATENCY_THRESHOLD", 150)),
    "rotation_latency_ms": int(os.environ.get("ROTATION_LATENCY_THRESHOLD", 120)),
}


def load_meta(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> int:
    failures = 0
    for meta_path in sorted(FIXTURE_ROOT.glob("v*/metadata.json")):
        meta = load_meta(meta_path)
        version = meta.get("version", meta_path.parent.name)
        for field, threshold in DEFAULT_THRESHOLDS.items():
            if field not in meta:
                print(f"::error file={meta_path}::{field} missing for {version}", file=sys.stderr)
                failures += 1
                continue
            value = meta[field]
            if value > threshold:
                print(
                    f"::error file={meta_path}::{field}={value} exceeds threshold {threshold} for {version}",
                    file=sys.stderr,
                )
                failures += 1
    if failures:
        return 1
    print(f"All fixture metrics are within thresholds: {DEFAULT_THRESHOLDS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
