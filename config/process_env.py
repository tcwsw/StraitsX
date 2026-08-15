"""Process-level secret isolation for the execution-agent / dashboard process.

pg/policy_server.py owns POLICY_SECRET, AGENT_PRIVATE_KEY, and RELAYER_PRIVATE_KEY — loaded
from its own `.env.policy` — the only process allowed to hold them and sign or submit
anything. The execution agent's entrypoints (agent/run.py, dashboard/app.py,
agent/execution_agent.py) load their own, separate `.env.app` and must never load, inherit,
or forward those secrets.

This module is the single choke point every execution-agent entrypoint uses to populate
os.environ from `.env.app`: it allow-lists exactly the keys the execution agent needs
(OPENAI_API_KEY, OPENAI_MODEL, AGENT_MODE, AUDIT_MODE, and the service URLs). If any
financial secret (AGENT_PRIVATE_KEY / POLICY_SECRET / RELAYER_PRIVATE_KEY) is found — in
`.env.app` itself, or already exported into this process by the parent shell — the process
REFUSES TO START rather than silently continuing without it. Isolation is a hard boundary,
not a best-effort scrub.
"""
from __future__ import annotations

import os
from pathlib import Path

# Everything the execution-agent / dashboard process is allowed to hold. Nothing here can
# move money, sign a payment, or reach card material.
ALLOWED_KEYS = {
    "OPENAI_API_KEY",
    "OPENAI_MODEL",
    "AGENT_MODE",
    "AUDIT_MODE",
    "POLICY_URL",
    "MERCHANTS_URL",
    "CARD_FEATURE_ENABLED",
    # ^ A dashboard-only UI toggle (show/hide the StraitsX card controls). Never moves
    # money and never gates a policy/payment decision by itself — CARD_MODE (policy tier)
    # still decides whether an issued card is simulated or real. Safe to allow here.
}

# Everything that moves money, authorizes a signature, or belongs to card issuance. If any
# of these ever shows up in the execution-agent process's environment, something is
# misconfigured (e.g. a single shared .env) and the process must scrub it, not silently
# hold a secret it should never see. Owned exclusively by pg/policy_server.py.
FORBIDDEN_KEYS = {
    "AGENT_PRIVATE_KEY",
    "POLICY_SECRET",
    "RELAYER_PRIVATE_KEY",
}


def isolate_execution_agent_env(dotenv_path: Path | str) -> None:
    """Load ONLY the allow-listed keys from `dotenv_path` (normally `.env.app`) into
    os.environ (a value already set in the shell always wins, mirroring the previous
    override=False behaviour). Safe to call even if `dotenv_path` does not exist or
    python-dotenv is not installed (both are treated as "nothing to load from .env.app").

    Before loading anything, this REFUSES TO START (raises RuntimeError) if any forbidden
    financial secret is present — either already exported into this process's shell
    environment, or defined in `dotenv_path` itself. Earlier revisions of this function
    silently scrubbed such a secret and continued; that let a misconfigured process start
    up "successfully" while briefly holding a key it must never see. Refusing to start is
    the only way to guarantee that never happens, even for the instant before a scrub
    would have run.
    """
    values: dict[str, str | None] = {}
    try:
        from dotenv import dotenv_values
    except ImportError:
        pass
    else:
        values = dotenv_values(dotenv_path) or {}

    present = sorted(
        key for key in FORBIDDEN_KEYS
        if os.environ.get(key) or values.get(key)
    )
    if present:
        raise RuntimeError(
            "execution-agent process refuses to start: forbidden financial secret(s) "
            f"present: {', '.join(present)}. These belong only to pg/policy_server.py "
            "(loaded from .env.policy) and must never reach this process. Remove them "
            f"from {dotenv_path!s} and from the shell environment before starting."
        )

    for key in ALLOWED_KEYS:
        value = values.get(key)
        if value is not None and key not in os.environ:
            os.environ[key] = value


def assert_no_financial_secrets() -> None:
    """Startup assertion: proves this process's environment holds none of the secrets
    pg/policy_server.py owns. Call immediately after `isolate_execution_agent_env()` in
    every execution-agent entrypoint. Also exercised directly by tests/env_isolation.py,
    including the case where a secret leaks in AFTER isolation ran."""
    present = sorted(key for key in FORBIDDEN_KEYS if os.environ.get(key))
    if present:
        raise RuntimeError(
            "execution-agent process must not hold financial secrets, but found: "
            f"{', '.join(present)}. These belong only to pg/policy_server.py."
        )
