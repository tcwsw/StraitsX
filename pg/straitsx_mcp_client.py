"""MCP-over-SSE client for the StraitsX card tool.

Reuses the exact protocol sequence already proven read-only by tools/probe_straitsx.py's
probe_mcp(): open an SSE stream, wait for the `endpoint` event, then drive JSON-RPC 2.0 over
POST to that endpoint — initialize -> notifications/initialized -> tools/list -> tools/call.

This runs inside the policy engine process only. pg/card_adapter.py is the sole caller;
nothing in agent/ imports this module, so a compromised or merely buggy execution agent
cannot reach StraitsX directly.

Fails closed: a missing endpoint event, a failed initialize, a failed tools/list, a missing
target tool, a target tool whose input schema doesn't match what we're about to send, or a
failed tools/call all raise McpCallFailed rather than guessing or falling back to anything
else. The SSE connection is always closed before returning, success or failure.

Never logs a raw tool result — it may contain PAN, CVV, expiry, iframe HTML, or other
complete card material. Only method names and generic failure reasons are ever raised/logged.
"""
from __future__ import annotations

import json
import queue
import threading
from typing import Any

import httpx

# The three arguments StraitsX's get_card_sandbox / get_card_prod tools require.
REQUIRED_TOOL_FIELDS = {"wallet_address", "cardholder_name", "amount_sgd"}

# The single argument StraitsX's view_card_sandbox / view_card_prod tools require.
VIEW_TOOL_REQUIRED_FIELDS = {"card_opaque_id"}

DEFAULT_SSE_TIMEOUT = 20.0    # seconds to wait for the `endpoint` SSE event
DEFAULT_RPC_TIMEOUT = 20.0    # seconds to wait for initialize / tools/list responses
DEFAULT_CALL_TIMEOUT = 60.0   # seconds to wait for the tools/call response (card issuance)


class McpCallFailed(Exception):
    """The MCP handshake, schema validation, or tools/call did not succeed. Fail closed."""


def _run_sse_reader(
    url: str,
    endpoint_q: "queue.Queue[Any]",
    response_q: "queue.Queue[dict]",
    stop: threading.Event,
    holder: dict,
) -> None:
    try:
        with httpx.Client(timeout=DEFAULT_SSE_TIMEOUT) as client:
            with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as resp:
                holder["response"] = resp
                if resp.status_code != 200:
                    endpoint_q.put(McpCallFailed(f"MCP SSE returned HTTP {resp.status_code}"))
                    return
                event = None
                for raw in resp.iter_lines():
                    if stop.is_set():
                        return
                    if raw.startswith("event:"):
                        event = raw.split(":", 1)[1].strip()
                    elif raw.startswith("data:"):
                        data = raw.split(":", 1)[1].strip()
                        if event == "endpoint":
                            endpoint_q.put(data)
                        else:
                            try:
                                response_q.put(json.loads(data))
                            except json.JSONDecodeError:
                                pass
    except Exception as exc:                                        # noqa: BLE001
        endpoint_q.put(exc)


def call_tool(
    *,
    mcp_url: str,
    tool_name: str,
    arguments: dict[str, Any],
    required_fields: set[str] | None = None,
    sse_timeout: float = DEFAULT_SSE_TIMEOUT,
    rpc_timeout: float = DEFAULT_RPC_TIMEOUT,
    call_timeout: float = DEFAULT_CALL_TIMEOUT,
) -> dict[str, Any]:
    """Run the full MCP-over-SSE sequence once against ANY single tool (card issuance,
    card view, ...) and return the raw `tools/call` result.

    Raises McpCallFailed (fail closed) on any handshake, schema, or call failure. Always
    closes the SSE connection before returning.
    """
    if not mcp_url or not tool_name:
        raise McpCallFailed("MCP URL / tool name are not configured")

    required = required_fields or set()
    endpoint_q: "queue.Queue[Any]" = queue.Queue()
    response_q: "queue.Queue[dict]" = queue.Queue()
    stop = threading.Event()
    holder: dict[str, Any] = {"response": None}

    thread = threading.Thread(
        target=_run_sse_reader, args=(mcp_url, endpoint_q, response_q, stop, holder), daemon=True,
    )
    thread.start()

    try:
        try:
            ep = endpoint_q.get(timeout=sse_timeout)
        except queue.Empty:
            raise McpCallFailed(f"no MCP endpoint event within {sse_timeout}s")
        if isinstance(ep, Exception):
            raise McpCallFailed(f"MCP SSE connect failed: {ep.__class__.__name__}") from ep

        post_url = ep if ep.startswith("http") else str(httpx.URL(mcp_url).join(ep))

        def call(method: str, params: dict | None = None, rid: int | None = None,
                  wait: float = rpc_timeout) -> dict | None:
            body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                body["params"] = params
            if rid is not None:
                body["id"] = rid
            try:
                httpx.post(post_url, json=body, timeout=rpc_timeout)
            except httpx.HTTPError as exc:
                raise McpCallFailed(f"MCP POST {method} failed: {exc.__class__.__name__}") from exc
            if rid is None:
                return None
            try:
                while True:
                    msg = response_q.get(timeout=wait)
                    if msg.get("id") == rid:
                        return msg
            except queue.Empty:
                raise McpCallFailed(f"no MCP response to {method} within {wait}s")

        init = call("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "procureguard-policy-engine", "version": "0.1"},
        }, rid=1)
        if not init or "result" not in init:
            raise McpCallFailed("MCP initialize did not return a result")

        call("notifications/initialized")

        tools_resp = call("tools/list", {}, rid=2)
        if not tools_resp or "result" not in tools_resp:
            raise McpCallFailed("MCP tools/list did not return a result")

        tools = tools_resp["result"].get("tools", [])
        target = next((t for t in tools if t.get("name") == tool_name), None)
        if target is None:
            raise McpCallFailed(f"MCP tool {tool_name!r} not found in tools/list")

        schema_props = set(target.get("inputSchema", {}).get("properties", {}))
        missing = required - schema_props
        if missing:
            raise McpCallFailed(
                f"MCP tool {tool_name!r} input schema is missing required field(s): {sorted(missing)}"
            )

        call_resp = call("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        }, rid=3, wait=call_timeout)
        if not call_resp or "result" not in call_resp:
            raise McpCallFailed(f"MCP tools/call did not return a result for {tool_name!r}")
        if call_resp["result"].get("isError"):
            raise McpCallFailed(f"MCP tool {tool_name!r} reported an error result")

        return call_resp["result"]
    finally:
        stop.set()
        response = holder.get("response")
        if response is not None:
            try:
                response.close()
            except Exception:                                       # noqa: BLE001
                pass
        thread.join(timeout=5)


def issue_card(
    *,
    mcp_url: str,
    tool_name: str,
    wallet_address: str,
    cardholder_name: str,
    amount_sgd: float,
    sse_timeout: float = DEFAULT_SSE_TIMEOUT,
    rpc_timeout: float = DEFAULT_RPC_TIMEOUT,
    call_timeout: float = DEFAULT_CALL_TIMEOUT,
) -> dict[str, Any]:
    """Issue a card via `get_card_sandbox` / `get_card_prod`. Thin wrapper over
    `call_tool()` that pins the exact argument shape and required-field schema StraitsX's
    issuance tools expect."""
    return call_tool(
        mcp_url=mcp_url, tool_name=tool_name,
        arguments={
            "wallet_address": wallet_address,
            "cardholder_name": cardholder_name,
            # StraitsX's wire-level JSON-RPC tool call requires a native JSON number;
            # amount_sgd may arrive as a Decimal from the policy layer, so it is cast to
            # float only here, at the external MCP boundary.
            "amount_sgd": float(amount_sgd),
        },
        required_fields=REQUIRED_TOOL_FIELDS,
        sse_timeout=sse_timeout, rpc_timeout=rpc_timeout, call_timeout=call_timeout,
    )


def view_card(
    *,
    mcp_url: str,
    tool_name: str,
    card_opaque_id: str,
    sse_timeout: float = DEFAULT_SSE_TIMEOUT,
    rpc_timeout: float = DEFAULT_RPC_TIMEOUT,
    call_timeout: float = DEFAULT_CALL_TIMEOUT,
) -> dict[str, Any]:
    """Fetch a live view of a previously issued card via `view_card_sandbox` /
    `view_card_prod`. Thin wrapper over `call_tool()` — always a fresh call, never cached,
    so the human always sees the card's current state."""
    return call_tool(
        mcp_url=mcp_url, tool_name=tool_name,
        arguments={"card_opaque_id": card_opaque_id},
        required_fields=VIEW_TOOL_REQUIRED_FIELDS,
        sse_timeout=sse_timeout, rpc_timeout=rpc_timeout, call_timeout=call_timeout,
    )
