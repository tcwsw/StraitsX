"""config: developer-owned loader/validator for PM- and FINTECH-owned config files.

Nobody on the dev track edits the *contents* of product/ or fintech/ files. This module is
the only code that reads them, and its job is narrow: load, validate, and refuse to hand back
anything that still contains a placeholder.

Ownership sentinels
--------------------
A value of "PM_TODO_REQUIRED" or "FINTECH_TODO_REQUIRED" (anywhere in a JSON file, or as
literal text in a markdown file) means the responsible team has not supplied that value yet.
This module never invents a replacement — financial numbers (budgets, wallets, thresholds)
and product copy are not something a developer gets to guess. It reports CONFIG_INCOMPLETE
and says exactly which owner and which file/field is missing.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
PRODUCT_DIR = ROOT / "product"
FINTECH_DIR = ROOT / "fintech"

# token -> the team that must supply a real value in its place
SENTINELS = {
    "PM_TODO_REQUIRED": "PM",
    "FINTECH_TODO_REQUIRED": "FINTECH",
}

# file name -> ("json" | "text", owning team) — the manifest of files this module loads.
PRODUCT_FILES: dict[str, str] = {
    "catalog.json": "json",
    "demo_scenarios.json": "json",
    "ui_copy.json": "json",
    "agent_behaviour.json": "json",
    "demo_script.md": "text",
}
FINTECH_FILES: dict[str, str] = {
    "policy_config.json": "json",
    "payment_config.example.json": "json",
    "payment_contract.md": "text",
    "x402_402_fixture.json": "json",
    "x402_success_fixture.json": "json",
    "straitsx_fixture.json": "json",
}


class ConfigIncompleteError(RuntimeError):
    """Raised by require_config() when any owned file still has a TODO placeholder."""


@dataclass
class ConfigIssue:
    file: str
    path: str          # dotted/bracketed location inside the file, or "<file>" for text files
    owner: str          # "PM" or "FINTECH" — who must supply the real value
    token: str

    def __str__(self) -> str:
        return f"{self.owner} must supply {self.file}:{self.path} (found {self.token})"


@dataclass
class ConfigReport:
    status: str                              # "OK" or "CONFIG_INCOMPLETE"
    product: dict[str, Any] = field(default_factory=dict)
    fintech: dict[str, Any] = field(default_factory=dict)
    issues: list[ConfigIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "OK"


def _load_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"required config file missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_text(path: Path) -> str:
    if not path.exists():
        raise FileNotFoundError(f"required config file missing: {path}")
    return path.read_text(encoding="utf-8")


def _scan_text(file_label: str, path_label: str, text: str) -> list[ConfigIssue]:
    issues = []
    for token, owner in SENTINELS.items():
        if token in text:
            issues.append(ConfigIssue(file=file_label, path=path_label, owner=owner, token=token))
    return issues


def _scan_json(file_label: str, node: Any, location: str) -> list[ConfigIssue]:
    issues: list[ConfigIssue] = []
    if isinstance(node, dict):
        for key, value in node.items():
            issues.extend(_scan_json(file_label, value, f"{location}.{key}" if location else key))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            issues.extend(_scan_json(file_label, value, f"{location}[{i}]"))
    elif isinstance(node, str):
        issues.extend(_scan_text(file_label, location or "<root>", node))
    return issues


def _load_group(directory: Path, manifest: dict[str, str]) -> tuple[dict[str, Any], list[ConfigIssue]]:
    loaded: dict[str, Any] = {}
    issues: list[ConfigIssue] = []
    for filename, kind in manifest.items():
        path = directory / filename
        file_label = f"{directory.name}/{filename}"
        if kind == "json":
            data = _load_json(path)
            loaded[filename] = data
            issues.extend(_scan_json(file_label, data, ""))
        else:
            text = _load_text(path)
            loaded[filename] = text
            issues.extend(_scan_text(file_label, "<document>", text))
    return loaded, issues


def load_all() -> ConfigReport:
    """Load every PM- and FINTECH-owned file and scan for outstanding placeholders. Never
    raises for an incomplete config — that is what the `status` field is for. Raises
    FileNotFoundError if a required file itself is missing (that is a developer/deploy bug,
    not an ownership gap)."""
    product, product_issues = _load_group(PRODUCT_DIR, PRODUCT_FILES)
    fintech, fintech_issues = _load_group(FINTECH_DIR, FINTECH_FILES)
    issues = product_issues + fintech_issues
    return ConfigReport(
        status="CONFIG_INCOMPLETE" if issues else "OK",
        product=product,
        fintech=fintech,
        issues=issues,
    )


def require_config() -> dict[str, dict[str, Any]]:
    """The entrypoint real code should call. Returns {"product": {...}, "fintech": {...}} on
    success. Raises ConfigIncompleteError, listing every missing field and its owner, if any
    PM_TODO_REQUIRED / FINTECH_TODO_REQUIRED placeholder remains."""
    report = load_all()
    if not report.ok:
        detail = "\n".join(f"  - {issue}" for issue in report.issues)
        raise ConfigIncompleteError(
            "CONFIG_INCOMPLETE: the following values must be supplied before this config can "
            f"be used:\n{detail}"
        )
    return {"product": report.product, "fintech": report.fintech}


def _print_report(report: ConfigReport) -> None:
    ok = "\033[92mOK\033[0m"
    bad = "\033[91mCONFIG_INCOMPLETE\033[0m"
    print(f"config status: {ok if report.ok else bad}")
    for issue in report.issues:
        print(f"  [{issue.owner:<8}] {issue.file}:{issue.path} \u2014 {issue.token}")
    if report.ok:
        print(f"  all {len(PRODUCT_FILES) + len(FINTECH_FILES)} files loaded clean, no placeholders")


if __name__ == "__main__":
    import sys

    _report = load_all()
    _print_report(_report)
    sys.exit(0 if _report.ok else 1)
