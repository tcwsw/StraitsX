"""The StraitsX MCP-over-SSE integration, as an executable table.

Everything here runs against MockMcpServer, a fully local MCP-over-SSE stand-in bound to
127.0.0.1 on an OS-assigned port. No case in this file ever contacts
https://card.straitsx.ai (sandbox or production) — the point is to prove the fail-closed
handshake, the tool schema check, and the policy boundary (no MCP call before policy
approval, no commit before StraitsX reports success) without depending on, or risking side
effects on, the real StraitsX rails.

Run:  python -m tests.straitsx_mcp_matrix
"""
from __future__ import annotations

import http.server
import json
import os
import queue
import sys
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# A real secret is required to import pg.policy_engine at all (it refuses to start
# without one). Only set a placeholder if the environment did not already provide a real
# one, so a real deployment's POLICY_SECRET always wins.
os.environ.setdefault("POLICY_SECRET", "test-only-straitsx-mcp-matrix-secret-do-not-use")

from eth_account import Account
from fastapi.testclient import TestClient

from pg import card_adapter
from pg import policy_engine as pe
from pg import policy_server as ps
from pg import straitsx_mcp_client as mcp_client
from tests.policy_matrix import C, decision, mandate, quote

# A throwaway signing key: /authorize-card now derives the public wallet address from this
# (never sent anywhere) so it must be set for the endpoint to proceed past the dry-run gate.
os.environ.setdefault("AGENT_PRIVATE_KEY", Account.create().key.hex())

ROOT = Path(__file__).resolve().parent.parent
client = TestClient(ps.app)

VALID_TOOL_SCHEMA = {
    "type": "object",
    "properties": {
        "wallet_address": {"type": "string"},
        "cardholder_name": {"type": "string"},
        "amount_sgd": {"type": "number"},
    },
    "required": ["wallet_address", "cardholder_name", "amount_sgd"],
}


def _valid_tools(tool_name: str) -> list[dict]:
    return [{"name": tool_name, "inputSchema": VALID_TOOL_SCHEMA}]


def _card_payload(**over) -> dict:
    base = {
        "card_opaque_id": "card_mock_" + uuid.uuid4().hex[:8],
        "settlement_tx": "0x" + uuid.uuid4().hex + uuid.uuid4().hex,
        "iframe_url": "https://card.straitsx.ai/mock/view/" + uuid.uuid4().hex[:8],
        "pan": "4111111111111111",
        "cvv": "999",
        "expiry": "12/29",
        "card_html": "<div>FULL CARD MATERIAL</div>",
    }
    base.update(over)
    return base


# ---------------------------------------------------------------- mock MCP/SSE server


class _Config:
    def __init__(self) -> None:
        self.tools: list[dict] = []
        self.on_call = None
        self.response_queue: "queue.Queue" = queue.Queue()
        self.stop = threading.Event()
        self.send_endpoint = True
        self.answer_calls = True


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a) -> None:                # silence request logging
        pass

    def do_GET(self) -> None:                            # noqa: N802
        cfg: _Config = self.server.cfg                    # type: ignore[attr-defined]
        if self.path != "/sse":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if not cfg.send_endpoint:
            while not cfg.stop.is_set():
                time.sleep(0.02)
            return
        self._write("endpoint", "/rpc")
        while not cfg.stop.is_set():
            try:
                item = cfg.response_queue.get(timeout=0.05)
            except queue.Empty:
                continue
            if item is None:
                return
            # Real MCP/SSE servers label ordinary JSON-RPC responses "message" (only the
            # one-time bootstrap event is "endpoint") — mirrored here so the client's
            # `event == "endpoint"` routing check behaves the same as it does for real
            # traffic, matching tools/probe_straitsx.py's proven assumption.
            self._write("message", json.dumps(item))

    def _write(self, event: str | None, data: str) -> None:
        try:
            if event:
                self.wfile.write(f"event: {event}\n".encode())
            self.wfile.write(f"data: {data}\n\n".encode())
            self.wfile.flush()
        except Exception:                                # noqa: BLE001
            pass

    def do_POST(self) -> None:                           # noqa: N802
        cfg: _Config = self.server.cfg                    # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        self.send_response(200)
        self.end_headers()

        method = body.get("method")
        rid = body.get("id")
        if rid is None:
            return   # a notification (e.g. notifications/initialized); no response expected

        if method == "initialize":
            result = {"jsonrpc": "2.0", "id": rid,
                      "result": {"serverInfo": {"name": "mock-straitsx", "version": "0.1"}}}
        elif method == "tools/list":
            result = {"jsonrpc": "2.0", "id": rid, "result": {"tools": cfg.tools}}
        elif method == "tools/call":
            if not cfg.answer_calls:
                return   # simulate a hang: the caller must time out and fail closed
            params = body.get("params", {})
            name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                payload = cfg.on_call(name, arguments) if cfg.on_call else {}
                result = {"jsonrpc": "2.0", "id": rid, "result": {"structuredContent": payload}}
            except Exception as exc:                     # noqa: BLE001
                result = {"jsonrpc": "2.0", "id": rid, "result": {"isError": True, "detail": str(exc)}}
        else:
            result = {"jsonrpc": "2.0", "id": rid, "result": {}}
        cfg.response_queue.put(result)


class MockMcpServer:
    """A fully local, in-process MCP-over-SSE stand-in. Never touches any network beyond
    127.0.0.1. One instance per case: construct, configure `.cfg`, then `.stop()`."""

    def __init__(self) -> None:
        self.cfg = _Config()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.httpd.cfg = self.cfg                        # type: ignore[attr-defined]
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/sse"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.cfg.stop.set()
        self.cfg.response_queue.put(None)
        self.httpd.shutdown()
        self.httpd.server_close()


def _patch_card_adapter(server: "MockMcpServer", tool_name: str):
    """Point pg.card_adapter at the mock server as if CARD_MODE=live, and return the
    (mode, url, tool) tuple to restore afterwards."""
    saved = (card_adapter.CARD_MODE, card_adapter.STRAITSX_MCP_URL, card_adapter.STRAITSX_CARD_TOOL)
    card_adapter.CARD_MODE = "live"
    card_adapter.STRAITSX_MCP_URL = server.url
    card_adapter.STRAITSX_CARD_TOOL = tool_name
    return saved


def _restore_card_adapter(saved) -> None:
    card_adapter.CARD_MODE, card_adapter.STRAITSX_MCP_URL, card_adapter.STRAITSX_CARD_TOOL = saved


# ---------------------------------------------------------------- cases


def case_initialize_sequence() -> tuple[bool, str]:
    """initialize -> notifications/initialized -> tools/list -> tools/call all complete
    against the mock server, using the exact sequence from tools/probe_straitsx.py."""
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_sandbox")
    server.cfg.on_call = lambda name, args: _card_payload()
    try:
        result = mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_sandbox",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
        )
        ok = isinstance(result, dict) and not result.get("isError")
        return ok, "full MCP handshake + tools/call completed"
    finally:
        server.stop()


def case_tools_list_schema_validation() -> tuple[bool, str]:
    """A tool whose inputSchema declares all three required fields is accepted."""
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_sandbox")
    server.cfg.on_call = lambda name, args: _card_payload()
    try:
        mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_sandbox",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
        )
        return True, "tool schema with wallet_address/cardholder_name/amount_sgd accepted"
    except mcp_client.McpCallFailed as exc:
        return False, f"unexpectedly refused a valid schema: {exc}"
    finally:
        server.stop()


def case_sandbox_tool_selection() -> tuple[bool, str]:
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_sandbox")
    seen: dict = {}
    server.cfg.on_call = lambda name, args: (seen.setdefault("name", name), _card_payload())[1]
    try:
        mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_sandbox",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
        )
        ok = seen.get("name") == "get_card_sandbox"
        return ok, f"tool actually called = {seen.get('name')!r}"
    finally:
        server.stop()


def case_production_tool_selection() -> tuple[bool, str]:
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_prod")
    seen: dict = {}
    server.cfg.on_call = lambda name, args: (seen.setdefault("name", name), _card_payload())[1]
    try:
        mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_prod",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
        )
        ok = seen.get("name") == "get_card_prod"
        return ok, f"tool actually called = {seen.get('name')!r}"
    finally:
        server.stop()


def case_missing_tool_fails_closed() -> tuple[bool, str]:
    """The configured tool name is not in tools/list. Must refuse, not fall back."""
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_sandbox")   # configured tool ("get_card_prod") absent
    try:
        mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_prod",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
        )
        return False, "expected McpCallFailed for a missing tool"
    except mcp_client.McpCallFailed as exc:
        return True, str(exc)
    finally:
        server.stop()


def case_incorrect_schema_fails_closed() -> tuple[bool, str]:
    """The tool exists but its input schema is missing required fields. Must refuse."""
    server = MockMcpServer()
    server.cfg.tools = [{"name": "get_card_sandbox", "inputSchema": {
        "type": "object",
        "properties": {"wallet_address": {"type": "string"}},
        "required": ["wallet_address"],
    }}]
    try:
        mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_sandbox",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
        )
        return False, "expected McpCallFailed for a tool missing required schema fields"
    except mcp_client.McpCallFailed as exc:
        return True, str(exc)
    finally:
        server.stop()


def case_mcp_timeout_fails_closed() -> tuple[bool, str]:
    """No `endpoint` SSE event ever arrives. Must time out and fail closed, quickly."""
    server = MockMcpServer()
    server.cfg.send_endpoint = False
    try:
        mcp_client.issue_card(
            mcp_url=server.url, tool_name="get_card_sandbox",
            wallet_address="0xAgentWallet", cardholder_name="Test Person", amount_sgd=10,
            sse_timeout=0.3,
        )
        return False, "expected McpCallFailed on SSE handshake timeout"
    except mcp_client.McpCallFailed as exc:
        return True, str(exc)
    finally:
        server.stop()


def case_policy_rejection_makes_no_mcp_call() -> tuple[bool, str]:
    """An unknown merchant is refused before card_adapter.issue() (and therefore the MCP
    client) is ever touched."""
    calls: list = []
    real_issue = ps.card_adapter.issue

    def spy(*a, **kw):
        calls.append((a, kw))
        return real_issue(*a, **kw)

    ps.card_adapter.issue = spy
    try:
        resp = client.post("/authorize-card", json={
            "spend_intent": "not-a-real-token", "merchant_id": "not-a-real-merchant",
            "amount": 8.50, "cardholder_name": "Test Person",
        }).json()
        ok = (not resp["ok"]) and len(calls) == 0
        return ok, f"ok={resp['ok']} mcp_calls={len(calls)} detail={resp.get('detail')!r}"
    finally:
        ps.card_adapter.issue = real_issue


def case_failed_mcp_call_releases_reservation() -> tuple[bool, str]:
    """StraitsX (the MCP client, mocked here as a failure) refuses. The reservation must be
    released: no spend recorded."""
    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)

    real_issue = ps.card_adapter.issue

    def boom(_amount, _name, _wallet):
        raise ps.card_adapter.CardRefused("StraitsX card issuance failed: mock MCP failure")

    ps.card_adapter.issue = boom
    try:
        resp = client.post("/authorize-card", json={
            "spend_intent": v.spend_intent, "merchant_id": "techstore",
            "amount": 8.50, "cardholder_name": "Test Person",
        }).json()
    finally:
        ps.card_adapter.issue = real_issue

    after = pe.spent(m.mandate_id)
    ok = (not resp["ok"]) and after == before
    return ok, f"ok={resp['ok']} spent {before}->{after} detail={resp.get('detail')!r}"


def case_successful_call_commits_once() -> tuple[bool, str]:
    """A successful StraitsX issuance commits the budget exactly once; replaying the same
    SpendIntent afterwards is refused."""
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_sandbox")
    server.cfg.on_call = lambda name, args: _card_payload(
        card_opaque_id="card_mock_commit", settlement_tx="0xcommitcommitcommit",
    )

    m, d = mandate(), decision(quote(price=8.50))
    v = pe.evaluate(m, d)
    before = pe.spent(m.mandate_id)

    saved = _patch_card_adapter(server, "get_card_sandbox")
    try:
        first = client.post("/authorize-card", json={
            "spend_intent": v.spend_intent, "merchant_id": "techstore",
            "amount": 8.50, "cardholder_name": "Test Person",
        }).json()
        after_first = pe.spent(m.mandate_id)
        second = client.post("/authorize-card", json={
            "spend_intent": v.spend_intent, "merchant_id": "techstore",
            "amount": 8.50, "cardholder_name": "Test Person",
        }).json()
        after_second = pe.spent(m.mandate_id)
    finally:
        _restore_card_adapter(saved)
        server.stop()

    ok = (
        first["ok"] and first.get("card_opaque_id") == "card_mock_commit"
        and abs(after_first - round(before + 8.50, 2)) < 1e-9
        and not second["ok"] and after_second == after_first
    )
    return ok, (f"first_ok={first['ok']} spent {before}->{after_first}->{after_second} "
                f"second_ok={second['ok']}")


def case_agent_safe_excludes_sensitive_fields() -> tuple[bool, str]:
    """agent_safe is exactly {card_opaque_id, settlement_tx, amount, mode} — the PAN, CVV,
    expiry, iframe_url and card_html the mock server returns must never appear in it."""
    server = MockMcpServer()
    server.cfg.tools = _valid_tools("get_card_sandbox")
    server.cfg.on_call = lambda name, args: _card_payload()

    saved = _patch_card_adapter(server, "get_card_sandbox")
    try:
        result = card_adapter.issue(9.0, "Test Person", "0xAgentWalletAddress")
    finally:
        _restore_card_adapter(saved)
        server.stop()

    safe = result["agent_safe"]
    safe_text = json.dumps(safe)
    forbidden_substrings = ("pan", "cvv", "card_html", "4111111111111111", "FULL CARD MATERIAL")
    ok = (
        set(safe) == {"card_opaque_id", "settlement_tx", "amount", "mode"}
        and all(tok not in safe_text for tok in forbidden_substrings)
    )
    return ok, f"agent_safe keys={sorted(safe)}"


def case_execution_agent_isolated_from_mcp() -> tuple[bool, str]:
    """agent/execution_agent.py must not import or call pg.straitsx_mcp_client or
    pg.card_adapter directly — only the policy engine process may."""
    src = (ROOT / "agent" / "execution_agent.py").read_text(encoding="utf-8")
    ok = "straitsx_mcp_client" not in src and "card_adapter" not in src
    return ok, "no reference to straitsx_mcp_client or card_adapter in agent/execution_agent.py"


CASES = [
    ("M1", "correct initialize -> initialized -> tools/list -> tools/call sequence", case_initialize_sequence),
    ("M2", "tools/list schema validation accepts a compliant tool", case_tools_list_schema_validation),
    ("M3", "sandbox env calls get_card_sandbox", case_sandbox_tool_selection),
    ("M4", "production env calls get_card_prod", case_production_tool_selection),
    ("M5", "missing configured tool fails closed", case_missing_tool_fails_closed),
    ("M6", "incorrect tool input schema fails closed", case_incorrect_schema_fails_closed),
    ("M7", "MCP handshake timeout fails closed", case_mcp_timeout_fails_closed),
    ("M8", "policy rejection makes no MCP call", case_policy_rejection_makes_no_mcp_call),
    ("M9", "failed MCP call releases the reservation", case_failed_mcp_call_releases_reservation),
    ("M10", "successful MCP call commits budget exactly once", case_successful_call_commits_once),
    ("M11", "agent_safe excludes PAN, CVV and complete card material", case_agent_safe_excludes_sensitive_fields),
    ("M12", "execution_agent.py cannot import or call the MCP client", case_execution_agent_isolated_from_mcp),
]


def run() -> int:
    failures = 0
    print(f"\n{C['b']}STRAITSX MCP-OVER-SSE — mocked handshake, schema and policy boundary{C['off']}")
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
