"""Safe-packaging guarantee for `tools/export_source.py`, as an executable table.

Proves two things, deterministically and without ever touching the real .env*/audit/
data files on disk for real:
  1. Against a synthetic fixture repo (a temp directory standing in for a repo root),
     every excluded secret/artifact path is absent from the exported tree, every ordinary
     source/.example file is present with byte-identical content, and re-exporting into a
     non-empty destination is refused rather than silently overwritten.
  2. Against the REAL repository root, `iter_source_files()` (dry-run only — nothing is
     ever copied or read from the real secret files) never includes any of the known
     excluded paths, proving the exclusion list actually matches this repo's real layout.

Run:  python -m tests.export_source_matrix
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.export_source import EXCLUDED_EXACT_PATHS, ROOT, export, iter_source_files

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}


def _write(root: Path, rel: str, content: str = "content") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _build_fixture_repo(root: Path) -> None:
    """A synthetic repo standing in for the real one: real-looking secrets and build
    artifacts that must NEVER be exported, alongside ordinary source/.example files that
    must always survive the export unchanged."""
    # Secrets and runtime artifacts — must never appear in an export.
    _write(root, ".env", "POLICY_SECRET=super-secret-real-value-do-not-leak")
    _write(root, ".env.app", "OPENAI_API_KEY=sk-real-fake-for-fixture-only")
    _write(root, ".env.policy", "AGENT_PRIVATE_KEY=0x" + "ab" * 32)
    _write(root, "staging.env.local", "RELAYER_PRIVATE_KEY=0x" + "cd" * 32)
    _write(root, "audit/ledger.jsonl", '{"seq": 0, "hash": "real-runtime-audit-data"}\n')
    _write(root, "data/merchant_registry.local.json", '{"techstore": {"payment_recipient": "0xREALADDR"}}')
    _write(root, ".git/HEAD", "ref: refs/heads/main")
    _write(root, ".venv/pyvenv.cfg", "home = /usr/bin")
    _write(root, "pg/__pycache__/policy_engine.cpython-314.pyc", "binary-garbage")
    _write(root, "some_module.pyc", "binary-garbage")

    # Ordinary source/example files — must survive, byte-identical.
    _write(root, "pg/policy_engine.py", "# real policy engine source\n")
    _write(root, "README.md", "# ProcureGuard\n")
    _write(root, ".env.app.example", "OPENAI_API_KEY=sk-your-key-here\n")
    _write(root, "data/merchant_registry.local.json.example", '{"techstore": {"payment_recipient": null}}')


def fixture_cases() -> list[tuple]:
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        fake_root = Path(tmp) / "fake_repo"
        dest = Path(tmp) / "export_dest"
        _build_fixture_repo(fake_root)

        code = export(dest, root=fake_root)
        out.append(("P1", "export() against the fixture repo returns 0 (success)", code, 0))

        excluded = [
            ".env", ".env.app", ".env.policy", "staging.env.local",
            "audit/ledger.jsonl", "data/merchant_registry.local.json",
            ".git/HEAD", ".venv/pyvenv.cfg",
            "pg/__pycache__/policy_engine.cpython-314.pyc", "some_module.pyc",
        ]
        leaked = [rel for rel in excluded if (dest / rel).exists()]
        out.append(("P2", "none of the 10 excluded secret/artifact/build paths appear in the export",
                   leaked, []))

        survivors = {
            "pg/policy_engine.py": "# real policy engine source\n",
            "README.md": "# ProcureGuard\n",
            ".env.app.example": "OPENAI_API_KEY=sk-your-key-here\n",
            "data/merchant_registry.local.json.example": '{"techstore": {"payment_recipient": null}}',
        }
        mismatched = [rel for rel, expected in survivors.items()
                      if not (dest / rel).exists() or (dest / rel).read_text() != expected]
        out.append(("P3", "every ordinary source/.example file survives with byte-identical content",
                   mismatched, []))

        never_walked = ".git" not in {p.parts[0] for p in iter_source_files(fake_root) if len(p.parts) > 1}
        out.append(("P4", "the exported file list never includes anything under .git/ at all",
                   never_walked, True))

        code_again = export(dest, root=fake_root)
        out.append(("P5", "re-exporting into the same (now non-empty) destination is refused, not overwritten",
                   code_again, 1))

    return out


def real_repo_cases() -> list[tuple]:
    """Dry-run only against the REAL repo root: iter_source_files() never opens, reads, or
    copies any file — this only proves the exclusion list matches this repo's actual
    layout, without ever touching real secret content."""
    out = []
    real_files = {p.as_posix() for p in iter_source_files(ROOT)}

    leaked = sorted(EXCLUDED_EXACT_PATHS & real_files)
    out.append(("R1", "none of the real repo's known excluded exact paths would be exported",
               leaked, []))

    pyc_or_local_env = [f for f in real_files if f.endswith(".pyc") or f.endswith(".env.local")]
    out.append(("R2", "no *.pyc or *.env.local file anywhere in the real repo would be exported",
               pyc_or_local_env, []))

    under_git_or_venv = [f for f in real_files if f.split("/")[0] in {".git", ".venv", "venv", "__pycache__"}]
    out.append(("R3", "nothing under .git/.venv/venv/__pycache__ in the real repo would be exported",
               under_git_or_venv, []))

    # The shipped, non-secret seed registry and .example files ARE expected to survive.
    expected_present = {"README.md", "pg/policy_engine.py", ".env.app.example", ".env.policy.example"}
    out.append(("R4", "ordinary shipped source/.example files are still included for the real repo",
               expected_present <= real_files, True))

    return out


def run() -> int:
    failures = 0
    sections = [
        ("fixture repo — excluded paths never leak, survivors are byte-identical", fixture_cases()),
        ("real repo root (dry-run only, nothing copied/read) — exclusion list matches reality", real_repo_cases()),
    ]

    total = 0
    for title, cases in sections:
        print(f"\n{C['b']}EXPORT SOURCE MATRIX — {title}{C['off']}")
        print(f"{C['dim']}{'id':<5}{'expect':<10}{'got':<10}case{C['off']}")
        for cid, desc, got, expect in cases:
            ok = got == expect
            failures += not ok
            total += 1
            mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
            print(f"{cid:<5}{str(expect):<10}{str(got):<10}{desc}  [{mark}]")

    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
