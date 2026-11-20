"""Fill gaps in EngineContext from the fork: block time, token metadata, balances,
and whether touched contracts are younger than 24 hours. Failures are logged and
skipped; enrichment never blocks a verdict."""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import TYPE_CHECKING, Optional

from eth_abi import decode
from eth_abi.exceptions import DecodingError

from shared.api_schemas import SimulationRequest
from simulator.constants import (
    DEFAULT_BLOCK_TIME_SECONDS,
    EIP7702_DESIGNATOR_PREFIX,
    NEW_CONTRACT_WINDOW_SECONDS,
)
from simulator.context import EngineContext
from simulator.diff import asset_root, safe_outflows
from simulator.hexutil import hex_to_bytes, parse_int

if TYPE_CHECKING:
    from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator, TraceResult

logger = logging.getLogger(__name__)
SYMBOL_SELECTOR = "0x95d89b41"
DECIMALS_SELECTOR = "0x313ce567"
BALANCE_OF_SELECTOR = "0x70a08231"
MAX_AGE_CHECKS = 8
MAX_TOKEN_LOOKUPS = 16
MAX_SYMBOL_CHARS = 32


async def _call(sim: "AnvilForkSimulator", to: str, data: str) -> Optional[bytes]:
    try:
        return hex_to_bytes(await sim.rpc("eth_call", [{"to": to, "data": data}, "latest"]) or "0x")
    except Exception as exc:  # noqa: BLE001 - enrichment is best effort, logged
        logger.warning("eth_call %s on %s failed: %s", data[:10], to, exc)
        return None


def _decode_symbol(raw: Optional[bytes]) -> Optional[str]:
    if not raw:
        return None
    try:
        (text,) = decode(["string"], raw)
    except (DecodingError, ValueError, OverflowError):
        text = raw[:32].rstrip(b"\x00").decode("utf-8", "ignore")
    # Token-controlled text reaches the summary: drop control characters and cap length.
    clean = "".join(ch for ch in text if ch.isprintable()).strip()[:MAX_SYMBOL_CHARS]
    return clean or None


async def _token_meta(sim, token: str) -> Optional[tuple[str, int]]:
    symbol_raw, decimals_raw = await asyncio.gather(_call(sim, token, SYMBOL_SELECTOR),
                                                    _call(sim, token, DECIMALS_SELECTOR))
    symbol = _decode_symbol(symbol_raw)
    if symbol is None or not decimals_raw:
        return None
    return symbol, int.from_bytes(decimals_raw[:32], "big")


async def _balance(sim, token: str, holder: str) -> Optional[int]:
    raw = await _call(sim, token, BALANCE_OF_SELECTOR + "00" * 12 + holder[2:])
    return int.from_bytes(raw[:32], "big") if raw else None


def _has_code(code: str) -> bool:
    return code not in ("0x", "0x0", "")


async def _is_young(sim, address: str, latest_block: int) -> bool:
    """True when the address has code now but had none ~24 hours of blocks ago.
    EOAs, and chains shorter than the window, cannot be judged and return False."""
    blocks_back = NEW_CONTRACT_WINDOW_SECONDS // DEFAULT_BLOCK_TIME_SECONDS
    if latest_block < blocks_back:
        return False
    try:
        current, old = await asyncio.gather(sim.get_code(address),
                                            sim.get_code(address, hex(latest_block - blocks_back)))
    except Exception as exc:  # noqa: BLE001 - best effort, logged
        logger.warning("contract age check for %s failed: %s", address, exc)
        return False
    return _has_code(current) and not _has_code(old)


async def enrich_context(sim: "AnvilForkSimulator", ctx: EngineContext, request: SimulationRequest,
                         trace: "TraceResult") -> EngineContext:
    from simulator.tracer.trace_diff import build_state_diff

    safe = request.safeAddress
    latest_hex, block = await asyncio.gather(sim.rpc("eth_blockNumber", []),
                                             sim.rpc("eth_getBlockByNumber", ["latest", False]))
    latest = parse_int(latest_hex or "0x0")
    now = ctx.now if ctx.now is not None else parse_int((block or {}).get("timestamp", "0x0"))

    observed = build_state_diff(safe, trace)
    tokens = sorted({log.address for log in trace.logs} - set(ctx.token_meta))[:MAX_TOKEN_LOOKUPS]
    metas = await asyncio.gather(*(_token_meta(sim, t) for t in tokens))
    token_meta = {**ctx.token_meta, **{t: m for t, m in zip(tokens, metas) if m}}

    balances = dict(ctx.safe_balances)
    for asset in safe_outflows(observed, safe):
        if asset in balances or "#" in asset:
            continue
        if asset == "ETH":
            balances["ETH"] = parse_int(trace.pre.get(safe, {}).get("balance", "0x0"))
        elif (value := await _balance(sim, asset_root(asset), safe)) is not None:
            balances[asset] = value

    deploy_times = dict(ctx.deploy_times)
    for addr, acct in trace.post.items():
        code = acct.get("code", "")
        if code and code not in ("0x",) and not code.startswith(EIP7702_DESIGNATOR_PREFIX) \
                and trace.pre.get(addr, {}).get("code", "0x") in ("0x", ""):
            deploy_times.setdefault(addr, now)
    # Inner frames matter: a batch's top-level target is only the MultiSend contract.
    frame_targets = {str(f.get("to", "")).lower() for f in trace.frames if f.get("to")}
    candidates = ({t.to for t in request.transactions} | frame_targets) - set(deploy_times) - {safe}
    targets = sorted(candidates)[:MAX_AGE_CHECKS]
    young = await asyncio.gather(*(_is_young(sim, a, latest) for a in targets))
    deploy_times.update({a: now for a, y in zip(targets, young) if y})

    return dataclasses.replace(ctx, now=now, token_meta=token_meta, safe_balances=balances,
                               deploy_times=deploy_times)
