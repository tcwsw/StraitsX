"""Read-only probe of the live StraitsX rails. Run this, paste the output to the developer.

Checks, in order:
  1. MCP over SSE      — handshake, list tools, confirm names and input schemas
  2. cardapi 402        — UNPAID POST, decode the challenge, print payTo/asset/amount/domain
  3. Avalanche RPC      — chain id, XSGD name/version/decimals, your balance
  4. Domain agreement   — does the 402's EIP-712 domain match what the token contract reports

SAFETY: this never sends a paid POST. An unfunded paid POST still burns sponsor relayer gas
at settlement, which is the one thing the StraitsX repo asks you not to do.

Usage:
  python -m tools.probe_straitsx --env sandbox --address 0xYourAgentAddress
  python -m tools.probe_straitsx --env production --address 0xYourAgentAddress
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import queue

import httpx

ENVS = {
    "sandbox": {
        "mcp": "https://card.straitsx.ai/sandbox/sse",
        "cardapi": "https://card.straitsx.ai/sandbox/cardapi/issue_card",
        "rpc": "https://api.avax-test.network/ext/bc/C/rpc",
        "chain_id": 43113,
        "xsgd": "0xd769410dC8772695A7F55a304d2125320A65c2A5",
        "tool": "get_card_sandbox",
    },
    "production": {
        "mcp": "https://card.straitsx.ai/production/sse",
        "cardapi": "https://card.straitsx.ai/production/cardapi/issue_card",
        "rpc": "https://api.avax.network/ext/bc/C/rpc",
        "chain_id": 43114,
        "xsgd": "0xb2F85b7AB3c2b6f62DF06dE6aE7D09c010a5096E",
        "tool": "get_card_prod",
    },
}

C = {"ok": "\033[92m", "bad": "\033[91m", "warn": "\033[93m", "dim": "\033[2m", "b": "\033[1m", "off": "\033[0m"}


def line(status: str, label: str, detail: str = "") -> None:
    colour = {"OK": C["ok"], "FAIL": C["bad"], "WARN": C["warn"], "INFO": C["dim"]}[status]
    print(f"  {colour}{status:<5}{C['off']} {label:<26} {C['dim']}{detail}{C['off']}")


# ------------------------------------------------------------------ 1. MCP over SSE

def probe_mcp(url: str) -> dict | None:
    """Minimal MCP/SSE client: open the stream, read the endpoint event, JSON-RPC over POST."""
    responses: queue.Queue = queue.Queue()
    endpoint: queue.Queue = queue.Queue()
    stop = threading.Event()

    def reader() -> None:
        try:
            with httpx.Client(timeout=30) as c:
                with c.stream("GET", url, headers={"Accept": "text/event-stream"}) as r:
                    if r.status_code != 200:
                        endpoint.put(RuntimeError(f"SSE returned HTTP {r.status_code}"))
                        return
                    event = None
                    for raw in r.iter_lines():
                        if stop.is_set():
                            return
                        if raw.startswith("event:"):
                            event = raw.split(":", 1)[1].strip()
                        elif raw.startswith("data:"):
                            data = raw.split(":", 1)[1].strip()
                            if event == "endpoint":
                                endpoint.put(data)
                            else:
                                try:
                                    responses.put(json.loads(data))
                                except json.JSONDecodeError:
                                    pass
        except Exception as exc:                                  # noqa: BLE001
            endpoint.put(exc)

    threading.Thread(target=reader, daemon=True).start()
    try:
        ep = endpoint.get(timeout=20)
    except queue.Empty:
        line("FAIL", "MCP SSE", "no endpoint event within 20s")
        return None
    if isinstance(ep, Exception):
        line("FAIL", "MCP SSE", str(ep))
        return None

    base = url.rsplit("/", 1)[0].rsplit("/", 1)[0]
    post_url = ep if ep.startswith("http") else httpx.URL(url).join(ep).__str__()
    line("OK", "MCP SSE handshake", post_url)

    def call(method: str, params: dict | None = None, rid: int | None = None) -> dict | None:
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if rid is not None:
            body["id"] = rid
        httpx.post(post_url, json=body, timeout=20)
        if rid is None:
            return None
        try:
            while True:
                msg = responses.get(timeout=20)
                if msg.get("id") == rid:
                    return msg
        except queue.Empty:
            return None

    init = call("initialize", {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "procureguard-probe", "version": "0.1"},
    }, rid=1)
    if not init:
        line("FAIL", "MCP initialize", "no response")
        stop.set()
        return None
    server = init.get("result", {}).get("serverInfo", {})
    line("OK", "MCP initialize", f"{server.get('name')} {server.get('version', '')}")

    call("notifications/initialized")
    tools = call("tools/list", {}, rid=2)
    stop.set()
    if not tools:
        line("FAIL", "MCP tools/list", "no response")
        return None
    listed = tools.get("result", {}).get("tools", [])
    line("OK", "MCP tools/list", ", ".join(t["name"] for t in listed))
    for t in listed:
        props = t.get("inputSchema", {}).get("properties", {})
        required = t.get("inputSchema", {}).get("required", [])
        line("INFO", f"  {t['name']}", f"{', '.join(props)}  required={required}")
    return {"tools": listed}


# ------------------------------------------------------------------ 2. unpaid 402

def probe_402(cardapi: str, address: str) -> dict | None:
    body = {"wallet_address": address, "cardholder_name": "Probe Only", "amount_sgd": 5}
    try:
        r = httpx.post(cardapi, json=body, timeout=30)
    except Exception as exc:                                       # noqa: BLE001
        line("FAIL", "cardapi reachable", str(exc))
        return None
    if r.status_code != 402:
        line("WARN", "cardapi unpaid probe", f"expected 402, got {r.status_code}: {r.text[:120]}")
        return None
    line("OK", "cardapi returns 402", f"PAYMENT-REQUIRED header: {'PAYMENT-REQUIRED' in r.headers}")
    try:
        challenge = r.json()
    except json.JSONDecodeError:
        line("WARN", "402 body", "not JSON, challenge may be header-only")
        return None
    accept = challenge.get("accepts", [{}])[0]
    line("INFO", "  scheme / network", f"{accept.get('scheme')} / {accept.get('network')}")
    line("INFO", "  amount (atomic)", str(accept.get("amount")))
    line("INFO", "  asset", str(accept.get("asset")))
    line("INFO", "  payTo", str(accept.get("payTo")))
    line("INFO", "  transfer method", str(accept.get("extra", {}).get("assetTransferMethod")))
    line("INFO", "  EIP-712 domain", json.dumps(accept.get("extra", {})))
    return accept


# ------------------------------------------------------------------ 3. chain facts

def eth_call(rpc: str, to: str, selector: str, args: str = "") -> str | None:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_call",
               "params": [{"to": to, "data": selector + args}, "latest"]}
    try:
        r = httpx.post(rpc, json=payload, timeout=20).json()
    except Exception:                                              # noqa: BLE001
        return None
    return r.get("result")


def decode_string(hex_result: str) -> str:
    raw = bytes.fromhex(hex_result[2:])
    if len(raw) < 64:
        return ""
    length = int.from_bytes(raw[32:64], "big")
    return raw[64:64 + length].decode(errors="replace")


def probe_chain(rpc: str, xsgd: str, address: str, expect_chain: int) -> dict:
    facts: dict = {}
    try:
        cid = httpx.post(rpc, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId",
                                    "params": []}, timeout=20).json()["result"]
        got = int(cid, 16)
        line("OK" if got == expect_chain else "FAIL", "RPC chain id",
             f"{got} (expected {expect_chain})")
    except Exception as exc:                                       # noqa: BLE001
        line("FAIL", "RPC reachable", str(exc))
        return facts

    # Native AVAX. This is GAS, not money. The build.avax.network faucet gives you this.
    # It does not give you XSGD, and XSGD is what the card API's 402 demands.
    try:
        raw = httpx.post(rpc, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                                    "params": [address, "latest"]}, timeout=20).json()["result"]
        avax = int(raw, 16) / 1e18
        line("OK" if avax > 0 else "INFO", "native AVAX (gas only)",
             f"{avax:.6f}" + ("" if avax > 0 else "  <- faucet: build.avax.network/console/primary-network/faucet"))
        facts["avax"] = avax
    except Exception:                                              # noqa: BLE001
        pass

    name = eth_call(rpc, xsgd, "0x06fdde03")          # name()
    version = eth_call(rpc, xsgd, "0x54fd4d50")       # version()
    decimals = eth_call(rpc, xsgd, "0x313ce567")      # decimals()
    bal = eth_call(rpc, xsgd, "0x70a08231", address[2:].lower().rjust(64, "0"))  # balanceOf

    if name:
        facts["name"] = decode_string(name)
        line("OK", "token name()", facts["name"])
    if version:
        facts["version"] = decode_string(version)
        line("OK", "token version()", facts["version"])
    if decimals:
        facts["decimals"] = int(decimals, 16)
        line("OK", "token decimals()", str(facts["decimals"]))
    if bal:
        human = int(bal, 16) / 10 ** facts.get("decimals", 6)
        status = "OK" if human > 0 else "WARN"
        line(status, "your XSGD balance", f"{human:.6f}"
             + ("" if human > 0 else "  <- NO FAUCET FOR THIS. StraitsX must send it to you."))
        facts["balance"] = human

    # EIP-3009 support: authorizationState(address,bytes32) must not revert
    probe = eth_call(rpc, xsgd, "0xe94a0102",
                     address[2:].lower().rjust(64, "0") + "00" * 32)
    line("OK" if probe else "FAIL", "EIP-3009 support",
         "authorizationState() responds" if probe else "no response, token may not support 3009")
    return facts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", choices=list(ENVS), default="sandbox")
    ap.add_argument("--address", required=True, help="your agent wallet address")
    ap.add_argument("--skip-mcp", action="store_true")
    args = ap.parse_args()
    cfg = ENVS[args.env]

    print(f"\n{C['b']}ProcureGuard rails probe — {args.env}{C['off']}")
    print(f"{C['dim']}  agent address {args.address}{C['off']}\n")

    print(f"{C['b']}1. Card MCP (SSE){C['off']}")
    if not args.skip_mcp:
        probe_mcp(cfg["mcp"])
    else:
        line("INFO", "skipped", "--skip-mcp")

    print(f"\n{C['b']}2. Card API x402 challenge (unpaid){C['off']}")
    accept = probe_402(cfg["cardapi"], args.address)

    print(f"\n{C['b']}3. Avalanche + XSGD{C['off']}")
    facts = probe_chain(cfg["rpc"], cfg["xsgd"], args.address, cfg["chain_id"])

    print(f"\n{C['b']}4. Domain agreement{C['off']}")
    if accept and facts:
        want = accept.get("extra", {})
        for field, onchain in (("name", facts.get("name")), ("version", facts.get("version"))):
            quoted = want.get(field)
            match = quoted == onchain
            line("OK" if match else "FAIL", f"domain {field}",
                 f"402 says {quoted!r}, contract says {onchain!r}")
        asset_match = (accept.get("asset", "").lower() == cfg["xsgd"].lower())
        line("OK" if asset_match else "FAIL", "asset address",
             f"402 quotes {accept.get('asset')}")
    else:
        line("WARN", "skipped", "need both a 402 challenge and chain facts")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
