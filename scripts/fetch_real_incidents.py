"""Fetches the real WazirX and Bybit exploit transactions from Ethereum mainnet and decodes them.

Each was a Safe execTransaction. The inner call (to, value, data, operation) is exactly what the
signers approved, so it is what Vero checks before signing. Writes frontend/data/real_incidents.json
(requests and provenance only, no verdicts).

Usage: python scripts/fetch_real_incidents.py [--rpc URL]   (default: a public mainnet RPC)
"""

import argparse
import json
import ssl
import urllib.request
from pathlib import Path

from eth_abi import decode

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "frontend" / "data" / "real_incidents.json"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
EXEC_TRANSACTION = "0x6a761202"
EXEC_TYPES = ["address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"]

INCIDENTS = [
    {
        "id": "wazirx-mainnet",
        "tag": "WazirX · real mainnet tx",
        "title": "WazirX multisig, 18 July 2024 (about $230M)",
        "hash": "0x48164d3adbab78c2cb9876f6e17f88e321097fcd14cadd57556866e4ef3e185d",
        "claim": "Signers were shown a routine transfer",
    },
    {
        "id": "bybit-mainnet",
        "tag": "Bybit · real mainnet tx",
        "title": "Bybit cold wallet, 21 February 2025 (about $1.5B)",
        "hash": "0x46deef0f52e3a983b67abf4714448a41dd7ffd6d32d32da69d62081c68ad7882",
        "claim": "Signers were shown a normal move from cold storage",
    },
]


def _tls_context() -> ssl.SSLContext:
    """Verify TLS against certifi's CA bundle when available (python.org macOS builds ship none)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "vero-evidence"})
    with urllib.request.urlopen(req, timeout=20, context=_tls_context()) as resp:
        payload = json.load(resp)
    if payload.get("error") or payload.get("result") is None:
        raise RuntimeError(f"{method} failed: {payload.get('error')}")
    return payload["result"]


def decode_exec(tx: dict) -> dict:
    data = tx["input"]
    if not data.startswith(EXEC_TRANSACTION):
        raise ValueError(f"{tx['hash']} is not a Safe execTransaction")
    to, value, inner, operation, *_ = decode(EXEC_TYPES, bytes.fromhex(data[10:]))
    return {"to": to, "value": str(value), "data": "0x" + inner.hex(), "operation": int(operation)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default=DEFAULT_RPC)
    args = parser.parse_args()

    entries = []
    for incident in INCIDENTS:
        tx = rpc(args.rpc, "eth_getTransactionByHash", [incident["hash"]])
        inner = decode_exec(tx)
        block = int(tx["blockNumber"], 16)
        entries.append({
            "id": incident["id"], "tag": incident["tag"], "title": incident["title"], "expected": "BLOCK",
            "claim": incident["claim"], "foundry": None,
            "source": {"txHash": incident["hash"], "block": block, "safe": tx["to"],
                       "etherscan": f"https://etherscan.io/tx/{incident['hash']}"},
            "request": {"chain_id": 1, "safe_address": tx["to"], **inner,
                        "label": incident["claim"]},
        })
        print(f"{incident['id']}: block {block}, safe {tx['to']}, inner to {inner['to']}, "
              f"op {inner['operation']}, selector {inner['data'][:10]}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"Wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
