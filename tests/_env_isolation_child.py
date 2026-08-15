"""Subprocess entrypoint used only by tests/env_isolation.py.

Run as `python -m tests._env_isolation_child <dotenv_path>` in a subprocess with a
fully-loaded environment (as if a single shared .env had been sourced, financial secrets
included). Calls the same `isolate_execution_agent_env()` every execution-agent entrypoint
calls, then prints exactly one line the parent test can check:
- "REFUSED:<comma-separated-keys>" if isolation refused to start this process at all
  (a forbidden financial secret was present, in the dotenv file or the shell);
- "LEAKED:<comma-separated-keys>" if isolation somehow returned without raising yet a
  secret still ended up in this process's environment (should never happen; kept only as
  a canary);
- "CLEAN:OPENAI_MODEL=<value>" if isolation succeeded and no financial secret is present.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.process_env import FORBIDDEN_KEYS, isolate_execution_agent_env

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _forbidden_present(dotenv_path: str) -> list[str]:
    try:
        from dotenv import dotenv_values
    except ImportError:
        values = {}
    else:
        values = dotenv_values(dotenv_path) or {}
    return sorted(key for key in FORBIDDEN_KEYS if os.environ.get(key) or values.get(key))


def main() -> None:
    dotenv_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO_ROOT, ".env")
    try:
        isolate_execution_agent_env(dotenv_path)
    except RuntimeError:
        print(f"REFUSED:{','.join(_forbidden_present(dotenv_path))}")
        return

    leaked = sorted(key for key in FORBIDDEN_KEYS if os.environ.get(key))
    if leaked:
        print(f"LEAKED:{','.join(leaked)}")
    else:
        print(f"CLEAN:OPENAI_MODEL={os.environ.get('OPENAI_MODEL', '')}")


if __name__ == "__main__":
    main()
