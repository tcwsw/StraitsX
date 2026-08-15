"""Process-level secret isolation — proof, as an executable table.

Proves config/process_env.py's contract: the execution-agent / dashboard process REFUSES
TO START rather than loading, inheriting, or retaining AGENT_PRIVATE_KEY / POLICY_SECRET /
RELAYER_PRIVATE_KEY, even when a single shared .env file (this repo's local-dev
convenience) defines all of them together, or when one leaks in only via the parent shell.
Uses a real subprocess (not just in-process os.environ patching) so the check is against
what a genuinely separate execution-agent process would actually end up holding.

Run:  python -m tests.env_isolation
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.process_env import (
    ALLOWED_KEYS, FORBIDDEN_KEYS, assert_no_financial_secrets, isolate_execution_agent_env,
)

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}

REPO_ROOT = Path(__file__).resolve().parent.parent

SHARED_DOTENV = """
OPENAI_API_KEY=sk-test-not-a-real-key
OPENAI_MODEL=gpt-4.1-mini
AGENT_MODE=scripted
AUDIT_MODE=heuristic
POLICY_URL=http://127.0.0.1:8001
MERCHANTS_URL=http://127.0.0.1:8002
AGENT_PRIVATE_KEY=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
POLICY_SECRET=this-is-a-32-plus-character-fake-secret-value
RELAYER_PRIVATE_KEY=0xfeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface
"""

CLEAN_DOTENV = """
OPENAI_API_KEY=sk-test-not-a-real-key
OPENAI_MODEL=gpt-4.1-mini
AGENT_MODE=scripted
AUDIT_MODE=heuristic
POLICY_URL=http://127.0.0.1:8001
MERCHANTS_URL=http://127.0.0.1:8002
"""


def _run_child(dotenv_path: Path, extra_env: dict | None = None) -> str:
    env = dict(os.environ)
    env.pop("POLICY_SECRET", None)
    env.pop("AGENT_PRIVATE_KEY", None)
    env.pop("RELAYER_PRIVATE_KEY", None)
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, "-m", "tests._env_isolation_child", str(dotenv_path)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=30,
    )
    return result.stdout.strip()


def cases() -> list[tuple]:
    out = []
    tmp_dir = Path(tempfile.mkdtemp(prefix="pg-env-isolation-"))
    shared_dotenv = tmp_dir / ".env.app"
    shared_dotenv.write_text(SHARED_DOTENV, encoding="utf-8")
    clean_dotenv = tmp_dir / ".env.app.clean"
    clean_dotenv.write_text(CLEAN_DOTENV, encoding="utf-8")

    out.append(("E1", "dotenv file itself defines all 3 secrets: child REFUSES to start",
        lambda: _run_child(shared_dotenv),
        "REFUSED:AGENT_PRIVATE_KEY,POLICY_SECRET,RELAYER_PRIVATE_KEY"))

    # E2: a CLEAN dotenv (no forbidden keys at all) but a secret pre-exported by the
    # parent shell (not just present in .env.app) must still cause a refusal — isolation
    # is not merely "don't load .env.app's own copy".
    out.append(("E2", "clean dotenv + secret pre-exported in the shell: child still REFUSES",
        lambda: _run_child(clean_dotenv, {"POLICY_SECRET": "leaked-from-shell-env"}),
        "REFUSED:POLICY_SECRET"))

    return out


def run() -> int:
    failures = 0
    print(f"\n{C['b']}PROCESS ENV ISOLATION — subprocess proof{C['off']}")
    for cid, desc, fn, expect in cases():
        got = fn()
        ok = got == expect
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{str(expect):<10}{str(got):<10}{desc}  [{mark}]")

    print(f"\n{C['b']}PROCESS ENV ISOLATION — in-process assertion{C['off']}")

    # A1: a clean environment (no forbidden keys) must not raise.
    saved = {k: os.environ.pop(k, None) for k in FORBIDDEN_KEYS}
    try:
        assert_no_financial_secrets()
        a1_ok = True
    except RuntimeError:
        a1_ok = False
    failures += not a1_ok
    mark = f"{C['ok']}PASS{C['off']}" if a1_ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{'A1':<5}{'no raise':<10}{str(a1_ok):<10}clean environment passes the assertion  [{mark}]")

    # A2: a leaked financial secret must raise, by name.
    os.environ["POLICY_SECRET"] = "a-leaked-secret-value"
    try:
        assert_no_financial_secrets()
        a2_ok = False
    except RuntimeError as exc:
        a2_ok = "POLICY_SECRET" in str(exc)
    finally:
        os.environ.pop("POLICY_SECRET", None)
    failures += not a2_ok
    mark = f"{C['ok']}PASS{C['off']}" if a2_ok else f"{C['bad']}FAIL{C['off']}"
    print(f"{'A2':<5}{'raise':<10}{str(a2_ok):<10}leaked POLICY_SECRET raises, naming it  [{mark}]")

    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v

    total = len(cases()) + 2
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
