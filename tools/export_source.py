"""Produce a clean, source-only copy of this repository — for sharing or submission —
that can never contain a live secret, a runtime audit trail, or a local registry
override, regardless of what is or isn't currently gitignored.

Excluded entirely (never copied, by name/path, no exceptions):
  .git/, .venv/, venv/, any __pycache__/, .pytest_cache/, any *.egg-info/, dist/
  .env, .env.app, .env.policy, any *.env.local
  audit/ledger.jsonl                   (a real runtime audit trail, not source)
  data/merchant_registry.local.json    (a local registry override, may hold real data)
  *.pyc

Everything else is copied verbatim, including *.example files (meant to be shared) and
data/merchant_registry.json (the shipped seed registry — sample data, not a secret).

Usage:
  python -m tools.export_source [DEST_DIR]             # default: ./dist/procureguard-source
  python -m tools.export_source --dry-run [DEST_DIR]   # list what would be copied, copy nothing

Exit codes:
  0 - export completed (or dry-run listed) cleanly
  1 - DEST_DIR already exists and is non-empty (refuses to silently overwrite)
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DEST = ROOT / "dist" / "procureguard-source"

# Directory names never descended into, anywhere in the tree.
EXCLUDED_DIR_NAMES = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "dist"}
EXCLUDED_DIR_SUFFIXES = (".egg-info",)

# Exact repo-relative file paths never copied, regardless of any other rule.
EXCLUDED_EXACT_PATHS = {
    ".env", ".env.app", ".env.policy",
    "audit/ledger.jsonl",
    "data/merchant_registry.local.json",
}


def _dir_excluded(name: str) -> bool:
    return name in EXCLUDED_DIR_NAMES or any(name.endswith(suffix) for suffix in EXCLUDED_DIR_SUFFIXES)


def _file_excluded(rel_posix: str, name: str) -> bool:
    if rel_posix in EXCLUDED_EXACT_PATHS:
        return True
    if name.endswith(".pyc") or name.endswith(".env.local"):
        return True
    return False


def iter_source_files(root: Path = ROOT) -> list[Path]:
    """Every repo-relative `Path` (files only) that belongs in a source-only export, in a
    stable sorted order. Pruning excluded directories via `os.walk`'s `dirnames[:]` means
    this never even descends into `.git/` or a virtualenv — not just filters them out
    afterwards."""
    root = Path(root)
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not _dir_excluded(d))
        rel_dir = Path(dirpath).relative_to(root)
        for name in sorted(filenames):
            rel = (rel_dir / name) if str(rel_dir) != "." else Path(name)
            if _file_excluded(rel.as_posix(), name):
                continue
            found.append(rel)
    return sorted(found)


def export(dest: Path, *, root: Path = ROOT, dry_run: bool = False) -> int:
    root = Path(root)
    dest = Path(dest)
    files = iter_source_files(root)

    if dry_run:
        for rel in files:
            print(rel.as_posix())
        print(f"\n{len(files)} files would be copied to {dest}", file=sys.stderr)
        return 0

    if dest.exists() and any(dest.iterdir()):
        print(f"refusing to export into a non-empty existing directory: {dest}", file=sys.stderr)
        return 1

    for rel in files:
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / rel, target)

    print(f"exported {len(files)} files to {dest}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    dry_run = "--dry-run" in argv
    positional = [a for a in argv if a != "--dry-run"]
    dest = Path(positional[0]).resolve() if positional else DEFAULT_DEST
    return export(dest, dry_run=dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
