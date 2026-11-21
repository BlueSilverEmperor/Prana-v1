"""Feature #01 / #06: exact-bytes simulation on a local Foundry Anvil fork.

Single transaction: two concurrent ``debug_traceCall`` requests (``prestateTracer`` in
diff mode for state, ``callTracer`` with logs for events and frames). Nothing is mined.

Batch: ``evm_snapshot`` -> impersonate the Safe -> send each tx with zero gas price ->
``debug_traceTransaction`` -> ``evm_revert`` (always, in ``finally``).

DELEGATECALL (operation 1) is reproduced by overriding the Safe's code with the
target's code and calling the Safe: same storage, same ``address(this)``, target logic.
A lock serialises simulations so snapshots never interleave.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping, Optional, Sequence

from eth_utils import keccak
from web3 import AsyncHTTPProvider, AsyncWeb3

from shared.api_schemas import SimulationRequest, TransactionTuple
from simulator.constants import (
    ERC1967_IMPLEMENTATION_SLOT,
    MAX_MULTISEND_DEPTH,
    SAFE_SINGLETON_SLOT,
    TRUSTED_DELEGATECALL_TARGETS,
)
from simulator.context import EngineContext
from simulator.decoders.multisend_unpacker import (
    MULTISEND_SELECTOR,
    MultiSendDecodeError,
    decode_multisend_bytes,
    unpack_multisend,
)
from simulator.hexutil import hex_to_bytes, parse_int, word_to_address

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 10.0
PRESTATE = {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}
CALLTRACE = {"tracer": "callTracer", "tracerConfig": {"withLog": True}}
RECEIPT_POLL_SECONDS = 0.05
RECEIPT_MAX_POLLS = 100   # 5 s: a forked block that needs remote state can take a moment to mine


class SimulationRPCError(RuntimeError):
    """The node rejected or failed an RPC call needed for simulation."""


@dataclass(frozen=True)
class LogEntry:
    address: str
    topics: tuple[str, ...]
    data: str


@dataclass(frozen=True)
class TraceResult:
    success: bool
    error: Optional[str]
    gas_used: int
    pre: Mapping[str, Any]
    post: Mapping[str, Any]
    logs: tuple[LogEntry, ...]
    frames: tuple[Mapping[str, Any], ...]
    latency_ms: float
    per_tx_latency_ms: tuple[float, ...] = ()
    chain_id: Optional[int] = None


@dataclass(frozen=True)
class ProxySnapshot:
    address: str
    erc1967_implementation: str
    slot0_value: str
    codehash: str


@dataclass(frozen=True)
class _TxTrace:
    prestate: Mapping[str, Any]
    calltrace: Mapping[str, Any]
    ok: bool = True
    error: Optional[str] = None
    latency_ms: float = 0.0
    extra: Mapping[str, Any] = field(default_factory=dict)


def _rejected(exc: Exception, started: float) -> _TxTrace:
    """The node refused the transaction itself (funds, gas estimation): report it as a
    failed simulation, not an infrastructure error. Connection failures still raise."""
    logger.info("node rejected simulated tx: %s", exc)
    return _TxTrace({}, {}, ok=False, error=str(exc), latency_ms=(time.perf_counter() - started) * 1000)


def _walk_frames(frame: Mapping[str, Any], frames: list, logs: list) -> None:
    frames.append({k: v for k, v in frame.items() if k not in ("calls", "logs")})
    if frame.get("error"):
        return  # logs of reverted frames never reach chain state
    logs.extend(
        LogEntry(log["address"].lower(), tuple(t.lower() for t in log.get("topics", [])), log.get("data", "0x"))
        for log in frame.get("logs", [])
    )
    for child in frame.get("calls", []):
        _walk_frames(child, frames, logs)


def _merge_states(traces: Sequence[_TxTrace]) -> tuple[dict, dict]:
    """Net change across a batch: each value's pre from before the batch, its post from the last write.

    diffMode leaves out an account that did not exist yet, so a later trace's pre can hold a value an
    earlier trace wrote. Such a value is skipped: its true pre is the absent (zero) one.
    """
    pre: dict[str, dict] = {}
    post: dict[str, dict] = {}
    for t in traces:
        for addr, acct in t.prestate.get("pre", {}).items():
            written = post.get(addr.lower(), {})
            target = pre.setdefault(addr.lower(), {})
            for key, value in acct.items():
                if key == "storage":
                    slots = target.setdefault("storage", {})
                    slots.update({k: v for k, v in value.items()
                                  if k not in slots and k not in written.get("storage", {})})
                elif key not in written:
                    target.setdefault(key, value)
        for addr, acct in t.prestate.get("post", {}).items():
            target = post.setdefault(addr.lower(), {})
            for key, value in acct.items():
                if key == "storage":
                    target.setdefault("storage", {}).update(value)
                else:
                    target[key] = value
    return pre, post


class AnvilForkSimulator:
    def __init__(self, rpc_url: Optional[str] = None, *, w3: Any = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS,
                 trusted_delegatecall: frozenset[str] = TRUSTED_DELEGATECALL_TARGETS) -> None:
        if w3 is None and rpc_url is None:
            raise ValueError("rpc_url or w3 is required")
        self._w3 = w3 or AsyncWeb3(AsyncHTTPProvider(rpc_url, request_kwargs={"timeout": timeout}))
        self._trusted = trusted_delegatecall
        self._lock = asyncio.Lock()  # one per Anvil instance: share the simulator, not the node

    async def close(self) -> None:
        """Release the HTTP session held by the async provider."""
        disconnect = getattr(self._w3.provider, "disconnect", None)
        if disconnect is not None:
            await disconnect()

    async def __aenter__(self) -> "AnvilForkSimulator":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def rpc(self, method: str, params: list) -> Any:
        response = await self._w3.provider.make_request(method, params)
        if not isinstance(response, Mapping):
            raise SimulationRPCError(f"{method}: malformed response")
        if response.get("error"):
            err = response["error"]
            message = err.get("message", err) if isinstance(err, Mapping) else err
            raise SimulationRPCError(f"{method}: {message}")
        return response.get("result")

    async def chain_id(self) -> int:
        return parse_int(await self.rpc("eth_chainId", []))

    async def get_code(self, address: str, block: str = "latest") -> str:
        return await self.rpc("eth_getCode", [address, block]) or "0x"

    async def get_storage_at(self, address: str, slot: str, block: str = "latest") -> str:
        return await self.rpc("eth_getStorageAt", [address, slot, block]) or "0x0"

    async def inspect_proxy(self, address: str) -> ProxySnapshot:
        """Feature #06 fallback: read implementation slots and codehash directly."""
        impl, slot0, code = await asyncio.gather(
            self.get_storage_at(address, ERC1967_IMPLEMENTATION_SLOT),
            self.get_storage_at(address, SAFE_SINGLETON_SLOT),
            self.get_code(address),
        )
        return ProxySnapshot(address, word_to_address(impl.rjust(66, "0")), slot0,
                             "0x" + keccak(hex_to_bytes(code)).hex())

    def _call_object(self, safe: str, tx: TransactionTuple) -> dict:
        call = {"from": safe, "to": safe if tx.operation == 1 else tx.to,
                "value": hex(parse_int(tx.value)), "data": tx.data}
        if tx.gas is not None:
            call["gas"] = hex(parse_int(tx.gas))
        return call

    async def _trace_call(self, safe: str, tx: TransactionTuple) -> _TxTrace:
        started = time.perf_counter()
        overrides = {safe: {"code": await self.get_code(tx.to)}} if tx.operation == 1 else {}
        call = self._call_object(safe, tx)
        try:
            prestate, calltrace = await asyncio.gather(
                self.rpc("debug_traceCall", [call, "latest", {**PRESTATE, "stateOverrides": overrides}]),
                self.rpc("debug_traceCall", [call, "latest", {**CALLTRACE, "stateOverrides": overrides}]),
            )
        except SimulationRPCError as exc:
            return _rejected(exc, started)
        error = calltrace.get("revertReason") or calltrace.get("error")
        return _TxTrace(prestate or {}, calltrace or {}, ok=not calltrace.get("error"), error=error,
                        latency_ms=(time.perf_counter() - started) * 1000)

    async def _mined_receipt(self, tx_hash: str) -> dict:
        """Wait until Anvil has mined the tx; tracing an unknown hash is forwarded to the forked RPC and fails."""
        for _ in range(RECEIPT_MAX_POLLS):
            receipt = await self.rpc("eth_getTransactionReceipt", [tx_hash])
            if receipt:
                return receipt
            await asyncio.sleep(RECEIPT_POLL_SECONDS)
        raise SimulationRPCError(f"transaction {tx_hash} was not mined on the fork")

    async def _send_one(self, safe: str, tx: TransactionTuple) -> _TxTrace:
        started = time.perf_counter()
        original_code = None
        if tx.operation == 1:
            original_code = await self.get_code(safe)
            await self.rpc("anvil_setCode", [safe, await self.get_code(tx.to)])
        try:
            await self.rpc("anvil_setNextBlockBaseFeePerGas", ["0x0"])
            tx_hash = await self.rpc("eth_sendTransaction", [{**self._call_object(safe, tx), "gasPrice": "0x0"}])
        except SimulationRPCError as exc:
            return _rejected(exc, started)
        finally:
            if original_code is not None:
                await self.rpc("anvil_setCode", [safe, original_code])
        receipt = await self._mined_receipt(tx_hash)
        prestate, calltrace = await asyncio.gather(
            self.rpc("debug_traceTransaction", [tx_hash, PRESTATE]),
            self.rpc("debug_traceTransaction", [tx_hash, CALLTRACE]),
        )
        ok = parse_int((receipt or {}).get("status", "0x0")) == 1
        error = None if ok else (calltrace or {}).get("revertReason") or (calltrace or {}).get("error") or "reverted"
        return _TxTrace(prestate or {}, calltrace or {}, ok=ok, error=error,
                        latency_ms=(time.perf_counter() - started) * 1000)

    async def _trace_batch(self, safe: str, txs: Sequence[TransactionTuple]) -> list[_TxTrace]:
        snapshot = await self.rpc("evm_snapshot", [])
        traces: list[_TxTrace] = []
        try:
            await self.rpc("anvil_impersonateAccount", [safe])
            for tx in txs:
                traces.append(await self._send_one(safe, tx))
                if not traces[-1].ok:
                    break
        finally:
            try:
                await self.rpc("anvil_stopImpersonatingAccount", [safe])
            finally:
                if await self.rpc("evm_revert", [snapshot]) is False:
                    logger.error("evm_revert(%s) returned false; fork state is dirty", snapshot)
                    raise SimulationRPCError("evm_revert failed; restart Anvil before the next simulation")
        return traces

    def _expand_trusted(self, txs: Sequence[TransactionTuple], depth: int = 0) -> list[TransactionTuple]:
        """Replace DELEGATECALLs to canonical MultiSend with their sub-calls.

        Running them as separate calls from the Safe keeps the Safe's real code in place,
        so inner calls to the Safe itself (owner/threshold changes) behave as on-chain.
        """
        out: list[TransactionTuple] = []
        for tx in txs:
            data = hex_to_bytes(tx.data)
            if tx.operation == 1 and tx.to in self._trusted and "0x" + data[:4].hex() == MULTISEND_SELECTOR:
                if depth >= MAX_MULTISEND_DEPTH:
                    raise MultiSendDecodeError("MultiSend nesting too deep")
                out.extend(self._expand_trusted(unpack_multisend(decode_multisend_bytes(data)), depth + 1))
            else:
                out.append(tx)
        return out

    async def simulate_transaction_batch(self, safe_address: str, txs: Sequence[TransactionTuple]) -> TraceResult:
        safe = safe_address.lower()
        started = time.perf_counter()
        try:
            expanded = self._expand_trusted(txs) or list(txs)
        except MultiSendDecodeError as exc:
            logger.warning("could not expand MultiSend for %s, simulating raw bytes: %s", safe, exc)
            expanded = list(txs)
        async with self._lock:
            run = self._trace_call(safe, expanded[0]) if len(expanded) == 1 else self._trace_batch(safe, expanded)
            chain_id, traces = await asyncio.gather(self.chain_id(), run)
            traces = traces if isinstance(traces, list) else [traces]
        frames: list = []
        logs: list = []
        for t in traces:
            _walk_frames(t.calltrace, frames, logs)
        pre, post = _merge_states(traces)
        failed = next((t for t in traces if not t.ok), None)
        latency = (time.perf_counter() - started) * 1000
        logger.info("simulated %d tx for %s in %.1f ms", len(txs), safe, latency)
        return TraceResult(
            success=failed is None, error=failed.error if failed else None,
            gas_used=sum(parse_int(t.calltrace.get("gasUsed", "0x0")) for t in traces),
            pre=MappingProxyType(pre), post=MappingProxyType(post), logs=tuple(logs), frames=tuple(frames),
            latency_ms=round(latency, 3), per_tx_latency_ms=tuple(round(t.latency_ms, 3) for t in traces),
            chain_id=chain_id,
        )

    async def enrich_context(self, ctx: EngineContext, request: SimulationRequest,
                             trace: TraceResult) -> EngineContext:
        from simulator.tracer.context_enricher import enrich_context

        async with self._lock:  # never read "latest" while another batch is mid-snapshot
            return await enrich_context(self, ctx, request, trace)
