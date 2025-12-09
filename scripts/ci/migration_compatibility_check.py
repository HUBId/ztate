#!/usr/bin/env python3
"""Ensure migration metadata remains monotonic and consistent."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = ROOT / "tests" / "fixtures"
MIGRATION_FILE = ROOT / "MIGRATION.md"


def load_meta(path: Path) -> dict:
    return json.loads(path.read_text())


def main() -> int:
    if not MIGRATION_FILE.exists():
        print(f"::error file={MIGRATION_FILE}::MIGRATION.md fehlt", file=sys.stderr)
        return 1

    versions = sorted(FIXTURE_ROOT.glob("v*/metadata.json"))
    if not versions:
        print("::error ::Keine Fixture-Metadaten gefunden", file=sys.stderr)
        return 1

    migration_tags: list[tuple[str, str]] = []
    for meta_path in versions:
        meta = load_meta(meta_path)
        version = meta.get("version", meta_path.parent.name)
        tag = meta.get("migration_tag")
        if not tag:
            print(f"::error file={meta_path}::migration_tag fehlt für {version}", file=sys.stderr)
            return 1
        migration_tags.append((version, tag))

    # Verify monotonic order: v1 < v2 < v3 ...
    sorted_versions = sorted(migration_tags, key=lambda pair: pair[0])
    if migration_tags != sorted_versions:
        print("::error ::Fixture versions are not ordered lexicographically", file=sys.stderr)
        return 1

    content = MIGRATION_FILE.read_text()
    missing = [tag for _, tag in migration_tags if tag not in content]
    if missing:
        for tag in missing:
            print(
                f"::error file={MIGRATION_FILE}::Migration tag {tag} fehlt im Handbuch",
                file=sys.stderr,
            )
        return 1

    print(
        f"Checked migration compatibility for {len(migration_tags)} fixture versions: "
        + ", ".join(f"{v}→{t}" for v, t in migration_tags)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
