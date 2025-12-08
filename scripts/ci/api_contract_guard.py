#!/usr/bin/env python3
"""
Validate that historical proof payloads continue to satisfy the public API contract.

The check is intentionally lightweight and file-system only so it can run in CI
without external dependencies. It enforces a stable set of required fields per
fixture version and guards that the fixture version matches its directory name.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures"


class ContractViolation(RuntimeError):
    pass


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001 - failing fast in CI is acceptable here
        raise ContractViolation(f"{path} is not valid JSON: {exc}") from exc


def validate_proof_contract(version_dir: Path) -> None:
    metadata = load_json(version_dir / "metadata.json")
    proof = load_json(version_dir / "proof.json")
    version = version_dir.name

    if metadata.get("version") != version:
        raise ContractViolation(
            f"metadata version mismatch: expected {version}, found {metadata.get('version')}"
        )

    required = metadata.get("api_contract", {}).get("required_fields", [])
    missing = [field for field in required if field not in proof]
    if missing:
        raise ContractViolation(
            f"{version}/proof.json is missing contract fields: {', '.join(missing)}"
        )

    if proof.get("version") != version:
        raise ContractViolation(
            f"proof version mismatch for {version}: {proof.get('version')}"
        )

    commitment = proof.get("vk_commitment")
    if not commitment:
        raise ContractViolation(f"{version}/proof.json must define vk_commitment")



def main() -> int:
    if not FIXTURE_ROOT.exists():
        print("::error ::Fixture root missing; run from repository root", file=sys.stderr)
        return 1

    violations: list[str] = []
    for version_dir in sorted(FIXTURE_ROOT.glob("v*")):
        try:
            validate_proof_contract(version_dir)
        except ContractViolation as exc:
            violations.append(str(exc))

    if violations:
        for violation in violations:
            print(f"::error ::{violation}", file=sys.stderr)
        return 1

    print(f"Validated API contract for {len(list(FIXTURE_ROOT.glob('v*')))} fixture versions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
