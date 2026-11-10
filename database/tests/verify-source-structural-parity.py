#!/usr/bin/env python3
"""Check portable schema section hashes against the reviewed Neon source snapshot.

Deliberately excludes provider ACLs, roles, memberships and extensions. No SQL
connection, credentials or application data are accessed by this checker.
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

REQUIRED = frozenset(("aggregates", "format", "iam_routines", "policies",
 "relations", "schemas", "sequences", "server_version_num", "triggers", "types"))
SHA256 = re.compile(r"[0-9a-f]{64}\Z")

def validate(snapshot_path: Path, tsv_path: Path) -> None:
    doc = json.loads(snapshot_path.read_text(encoding="utf-8"))
    src = doc.get("source")
    expected = doc.get("section_digests")
    if doc.get("format") != "iam-neon-source-structural-fingerprint/v1" or not isinstance(src, dict):
        raise ValueError("invalid source snapshot format")
    if src.get("project_id") != "twilight-fire-88497009" or src.get("branch_id") != "br-little-fire-b6adup9f" or src.get("database") != "iam_database":
        raise ValueError("unexpected source project/branch/database")
    if not isinstance(expected, dict) or set(expected) != REQUIRED:
        raise ValueError("required portable sections are missing or unexpected")
    actual = {}
    for line_no, line in enumerate(tsv_path.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split("\t")
        if len(parts) != 3:
            raise ValueError(f"invalid TSV columns at line {line_no}")
        name, count_text, digest = parts
        if not name or name in actual or SHA256.fullmatch(digest) is None:
            raise ValueError(f"duplicate/invalid section or SHA-256 at line {line_no}")
        if count_text == "-":
            count = None
        elif count_text.isdecimal():
            count = int(count_text)
        else:
            raise ValueError(f"invalid count at line {line_no}")
        actual[name] = (count, digest)
    failures = []
    for name in sorted(REQUIRED):
        row = expected[name]
        if not isinstance(row, dict):
            raise ValueError(f"invalid reviewed snapshot entry {name}")
        count, digest = row.get("count"), row.get("sha256")
        if (count is not None and (type(count) is not int or count < 0)) or not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise ValueError(f"invalid pinned digest/count for {name}")
        if name not in actual:
            failures.append(f"{name}: missing in restore")
        elif actual[name] != (count, digest):
            failures.append(f"{name}: expected {count!r}/{digest}; got {actual[name]}")
    if failures:
        raise ValueError("portable Neon source parity failed:\n" + "\n".join(failures))
    print(f"PASS: {len(REQUIRED)} portable schema sections match pinned Neon main. "
          "Provider ACLs/memberships/extensions and valid-context RLS remain separate gates.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify-source-structural-parity.py PINNED_SOURCE.json RESTORE.tsv")
    try:
        validate(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
