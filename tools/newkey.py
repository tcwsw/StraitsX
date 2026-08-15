"""Generate a throwaway event wallet. Prints the ADDRESS only; the key goes to .env.

Run once, then send the printed address to the StraitsX team for funding and whitelisting.
Never reuse a personal key for a hackathon.

    python -m tools.newkey
"""
from __future__ import annotations

import os
from pathlib import Path

from eth_account import Account

ENV = Path(__file__).resolve().parent.parent / ".env"


def main() -> None:
    Account.enable_unaudited_hdwallet_features()
    acct = Account.create()
    key = acct.key.hex()
    key = key if key.startswith("0x") else "0x" + key

    existing = ENV.read_text() if ENV.exists() else ""
    if "AGENT_PRIVATE_KEY=0x" in existing:
        print("\n  .env already has an AGENT_PRIVATE_KEY. Refusing to overwrite it.")
        print("  Delete that line first if you really want a new wallet.\n")
        return

    if existing and not existing.endswith("\n"):
        existing += "\n"
    lines = [ln for ln in existing.splitlines() if not ln.startswith("AGENT_PRIVATE_KEY=")]
    lines.append(f"AGENT_PRIVATE_KEY={key}")
    ENV.write_text("\n".join(lines) + "\n")
    os.chmod(ENV, 0o600)

    print(f"""
  Agent wallet created. The private key is in .env (chmod 600) and is not printed here.

    ADDRESS   {acct.address}

  Send exactly this to the StraitsX team:

    "Team ProcureGuard, agent wallet {acct.address} — please fund with Fuji XSGD,
     and whitelist for production if possible."

  Then verify with:

    python -m tools.probe_straitsx --env sandbox --address {acct.address}
""")


if __name__ == "__main__":
    main()
