"""Spec for config/loader.py: the developer-owned loader that reads PM- and FINTECH-owned
config files and refuses to hand back a placeholder as if it were a real value.

Run:  python -m tests.config_loader
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import loader

C = {"ok": "\033[92m", "bad": "\033[91m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}


def case_repo_config_currently_incomplete() -> tuple[bool, str]:
    """As shipped, several PM/FINTECH values are still placeholders. load_all() must say so,
    never silently invent a number or a wallet."""
    report = loader.load_all()
    owners = {issue.owner for issue in report.issues}
    ok = report.status == "CONFIG_INCOMPLETE" and owners == {"PM", "FINTECH"}
    return ok, f"status={report.status} owners_found={sorted(owners)} issues={len(report.issues)}"


def case_require_config_raises_with_owner_detail() -> tuple[bool, str]:
    """require_config() must raise, and the message must name at least one owner per
    outstanding field so a human knows who to chase."""
    try:
        loader.require_config()
    except loader.ConfigIncompleteError as exc:
        msg = str(exc)
        ok = "PM must supply" in msg and "FINTECH must supply" in msg
        return ok, "raised ConfigIncompleteError with owner-attributed detail"
    return False, "did not raise ConfigIncompleteError"


def case_production_wallet_placeholders_detected() -> tuple[bool, str]:
    """Every merchant's production_wallet is still FINTECH_TODO_REQUIRED in the shipped
    fintech/policy_config.json — confirm each one is individually reported."""
    report = loader.load_all()
    wallet_issues = [
        i for i in report.issues
        if i.file == "fintech/policy_config.json" and "production_wallet" in i.path
    ]
    ok = len(wallet_issues) == 4 and all(i.owner == "FINTECH" for i in wallet_issues)
    return ok, f"found {len(wallet_issues)} production_wallet placeholders"


def case_catalog_migrated_without_changes() -> tuple[bool, str]:
    """product/catalog.json must be exactly what used to live at data/catalog.json — same
    merchants, same items, same injection payload. Nothing invented, nothing dropped."""
    report = loader.load_all()
    catalog = report.product["catalog.json"]
    merchants = catalog.get("merchants", {})
    ok = (
        set(merchants) == {"techstore", "gadgethub", "quickelectronics", "bargainbin"}
        and merchants["techstore"]["items"][0]["sku"] == "TS-USBC-65"
        and merchants["bargainbin"]["hostile"] is True
        and "0xATTACKER" in catalog.get("injection", "")
    )
    return ok, f"merchants={sorted(merchants)}"


def case_fully_resolved_config_loads_clean() -> tuple[bool, str]:
    """Once every PM_TODO_REQUIRED / FINTECH_TODO_REQUIRED placeholder is replaced with a
    real value, require_config() must return the merged config without raising."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_root = Path(tmp)
        product_dir = tmp_root / "product"
        fintech_dir = tmp_root / "fintech"
        product_dir.mkdir()
        fintech_dir.mkdir()

        def resolve(text: str) -> str:
            return (text.replace("PM_TODO_REQUIRED", "resolved")
                        .replace("FINTECH_TODO_REQUIRED", "0x0000000000000000000000000000000000000000"))

        def resolve_text(text: str) -> str:
            return (text.replace("PM_TODO_REQUIRED", "resolved")
                        .replace("FINTECH_TODO_REQUIRED", "resolved"))

        for filename, kind in loader.PRODUCT_FILES.items():
            src = (loader.PRODUCT_DIR / filename).read_text(encoding="utf-8")
            fixed = resolve(src) if kind == "json" else resolve_text(src)
            (product_dir / filename).write_text(fixed, encoding="utf-8")
        for filename, kind in loader.FINTECH_FILES.items():
            src = (loader.FINTECH_DIR / filename).read_text(encoding="utf-8")
            fixed = resolve(src) if kind == "json" else resolve_text(src)
            (fintech_dir / filename).write_text(fixed, encoding="utf-8")

        old_product_dir, old_fintech_dir = loader.PRODUCT_DIR, loader.FINTECH_DIR
        loader.PRODUCT_DIR, loader.FINTECH_DIR = product_dir, fintech_dir
        try:
            # sanity: every resolved file must still be valid JSON/text
            for filename, kind in loader.PRODUCT_FILES.items():
                if kind == "json":
                    json.loads((product_dir / filename).read_text(encoding="utf-8"))
            cfg = loader.require_config()
            ok = "product" in cfg and "fintech" in cfg
            detail = "require_config() returned merged config without raising"
        except loader.ConfigIncompleteError as exc:
            ok = False
            detail = f"unexpectedly still incomplete: {exc}"
        finally:
            loader.PRODUCT_DIR, loader.FINTECH_DIR = old_product_dir, old_fintech_dir
        return ok, detail


CASES = [
    ("C1", "shipped repo config is CONFIG_INCOMPLETE, both owners represented", case_repo_config_currently_incomplete),
    ("C2", "require_config() raises with owner-attributed detail", case_require_config_raises_with_owner_detail),
    ("C3", "all 4 merchant production_wallet placeholders detected", case_production_wallet_placeholders_detected),
    ("C4", "product/catalog.json migrated without changing contents", case_catalog_migrated_without_changes),
    ("C5", "fully-resolved config loads clean via require_config()", case_fully_resolved_config_loads_clean),
]


def run() -> int:
    failures = 0
    print(f"\n{C['b']}CONFIG LOADER — ownership boundary{C['off']}")
    for cid, desc, fn in CASES:
        ok, detail = fn()
        failures += not ok
        mark = f"{C['ok']}PASS{C['off']}" if ok else f"{C['bad']}FAIL{C['off']}"
        print(f"{cid:<5}{desc:<62}[{mark}]{C['dim']}  {detail}{C['off']}")

    total = len(CASES)
    colour = C["ok"] if failures == 0 else C["bad"]
    print(f"\n{colour}{total - failures}/{total} cases as specified{C['off']}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())
