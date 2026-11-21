"""Live Polygon Amoy status for the batch builder.

Reads the Amoy fork named by VERO_AMOY_RPC (an Anvil fork of the live chain): chain id, fork block, and a
funded account taken from that block's real transactions, so the builder can simulate as a vault whose
balance is actual Amoy state. Nothing here is stored or invented.
"""

import json
import os
import time
import urllib.request
from typing import Any, Optional

from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool

from api_agents.adapters.vero_engine_adapter import AMOY_CHAIN_ID, CHAIN_FORK_ENV

router = APIRouter(prefix="/v1/chain", tags=["chain"])
RPC_TIMEOUT_S = 8
MIN_VAULT_BALANCE_WEI = 2 * 10**18   # enough POL for the builder's presets
MAX_CANDIDATES = 20
MAX_ACCOUNTS = 6
CANONICAL_MULTISEND = "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526"
AMOY_UPSTREAM = "https://polygon-amoy-bor-rpc.publicnode.com"
# Public RPCs keep only recent state, so a fork older than this is moved to the newest Amoy block first.
STALE_AFTER_S = 60


def _rpc(url: str, method: str, params: list) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=RPC_TIMEOUT_S) as resp:
        payload = json.load(resp)
    if payload.get("error"):
        raise RuntimeError(payload["error"].get("message", "rpc error"))
    return payload["result"]


def _unique(values) -> list:
    return list(dict.fromkeys(v.lower() for v in values if v))


def _funded_vault(url: str, block: dict) -> Optional[dict]:
    seen = _unique(tx.get("from") for tx in block.get("transactions", []))
    for sender in seen[:MAX_CANDIDATES]:
        balance = int(_rpc(url, "eth_getBalance", [sender, "latest"]), 16)
        if balance >= MIN_VAULT_BALANCE_WEI:
            return {"address": sender, "balance_wei": str(balance)}
    return None


def _live_accounts(url: str, block: dict, vault: Optional[dict]) -> list:
    """Real externally owned accounts active in the block (no code), other than the vault."""
    skip = (vault or {}).get("address")
    found = []
    for addr in _unique([tx.get("from") for tx in block.get("transactions", [])] +
                        [tx.get("to") for tx in block.get("transactions", [])])[:MAX_CANDIDATES]:
        try:
            code = _rpc(url, "eth_getCode", [addr, "latest"])
        except (OSError, RuntimeError, ValueError):
            continue   # state the public RPC no longer serves; use the next account
        if addr != skip and code in ("0x", "0x0", ""):
            found.append(addr)
        if len(found) >= MAX_ACCOUNTS:
            break
    return found


def _refresh_if_stale(url: str) -> None:
    """Re-fork at the newest Amoy block when the fork's head is old (anvil_reset with no block number)."""
    head = _rpc(url, "eth_getBlockByNumber", ["latest", False])
    if time.time() - int(head["timestamp"], 16) > STALE_AFTER_S:
        upstream = os.getenv("VERO_AMOY_UPSTREAM", AMOY_UPSTREAM)
        _rpc(url, "anvil_reset", [{"forking": {"jsonRpcUrl": upstream}}])


def _status() -> dict:
    url = os.getenv(CHAIN_FORK_ENV[AMOY_CHAIN_ID])
    if not url:
        return {"available": False, "reason": "VERO_AMOY_RPC is not set; start an Anvil fork of Polygon Amoy"}
    try:
        _refresh_if_stale(url)
        chain_id = int(_rpc(url, "eth_chainId", []), 16)
        block = _rpc(url, "eth_getBlockByNumber", ["latest", True])
        multisend_code = _rpc(url, "eth_getCode", [CANONICAL_MULTISEND, "latest"])
        vault = _funded_vault(url, block)
        accounts = _live_accounts(url, block, vault)
    except (OSError, RuntimeError, ValueError) as exc:
        return {"available": False, "reason": f"Amoy fork unreachable: {type(exc).__name__}"}
    return {
        "available": chain_id == AMOY_CHAIN_ID and vault is not None and len(multisend_code) > 2,
        "chain_id": chain_id, "block": int(block["number"], 16), "block_hash": block["hash"],
        "multisend": CANONICAL_MULTISEND, "multisend_deployed": len(multisend_code) > 2,
        "vault": vault, "accounts": accounts,
    }


def amoy_status_sync() -> dict:
    return _status()


@router.get("/amoy")
async def amoy_status() -> dict:
    return await run_in_threadpool(_status)
