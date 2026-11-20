"""Engine entry points used by the API, MCP server and benchmark.

``simulate``        fork mode: exact-bytes simulation on Anvil, then rules.
``analyze_offline`` static mode: calldata-only prediction, then the same rules.
Both return the same ``SimulationResult`` shape so every channel agrees.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from shared.api_schemas import Metrics, RiskAlert, SimulationRequest, SimulationResult, StateDiffSummary
from simulator.constants import SEVERITY_WEIGHT
from simulator.context import EngineContext
from simulator.decoders.calldata import DecodedCall, decode_call
from simulator.decoders.erc7730_and_8213 import calldata_digest
from simulator.decoders.multisend_unpacker import MultiSendDecodeError, flatten_transactions
from simulator.decoders.permit_and_bridge_decoders import (
    decode_bridge_call,
    decode_permit_calls,
    is_known_permit_or_bridge_selector,
)
from simulator.diff import merge_diffs, static_diff
from simulator.hexutil import hex_to_bytes, parse_int
from simulator.renderer.plain_english_renderer import render_summary
from simulator.rules.base import AnalysisInput, alert
from simulator.rules.behavioral_and_poisoning import SHIELDS
from simulator.rules.intent_diff import compare_intent
from simulator.rules.twelve_rule_engine import RULES, run_rules

if TYPE_CHECKING:
    from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator

logger = logging.getLogger(__name__)
MAX_RISK_SCORE = 100


@dataclass(frozen=True)
class _Decoded:
    calls: tuple[DecodedCall, ...]
    errors: tuple[RiskAlert, ...]


def _integrity_alerts(calls: tuple[DecodedCall, ...]) -> tuple[RiskAlert, ...]:
    """Fail closed: a known selector whose arguments do not decode strictly (dirty padding,
    truncation) may still execute on-chain, so it must never pass silently."""
    return tuple(
        alert("DECODE", "CRITICAL", f"Call to {c.target} uses a known function selector {c.selector} "
              "with arguments that do not decode strictly", target=c.target, selector=c.selector)
        for c in calls
        if c.malformed or (c.name is None and is_known_permit_or_bridge_selector(c.data)
                           and not decode_permit_calls(c.target, c.data)
                           and decode_bridge_call(c.target, c.value, c.data, 0) is None)
    )


def _decode(request: SimulationRequest) -> _Decoded:
    try:
        calls = flatten_transactions(request.transactions)
        return _Decoded(calls, _integrity_alerts(calls))
    except (MultiSendDecodeError, ValueError) as exc:
        logger.warning("MultiSend decode failed for safe %s: %s", request.safeAddress, exc)
        calls = tuple(
            decode_call(t.to, parse_int(t.value), hex_to_bytes(t.data), t.operation, path=(i,))
            for i, t in enumerate(request.transactions)
        )
        err = alert("DECODE", "CRITICAL", f"Batch payload could not be decoded safely: {exc}")
        return _Decoded(calls, (err, *_integrity_alerts(calls)))


def risk_score(alerts: list[RiskAlert]) -> int:
    return min(MAX_RISK_SCORE, sum(SEVERITY_WEIGHT[a.severity] for a in alerts))


def _evaluate(
    request: SimulationRequest,
    ctx: EngineContext,
    decoded: _Decoded,
    observed: Optional[StateDiffSummary],
    *,
    started: float,
    mode: str,
    success: bool,
    gas_used: int = 0,
    observed_chain_id: Optional[int] = None,
    revert_reason: Optional[str] = None,
) -> SimulationResult:
    calls = decoded.calls
    permits = tuple(p for c in calls for p in decode_permit_calls(c.target, c.data))
    bridges = tuple(b for c in calls if (b := decode_bridge_call(c.target, c.value, c.data, request.chainId)))
    predicted = static_diff(request.safeAddress, calls, bridges)
    diff = merge_diffs(observed, predicted) if observed is not None else predicted
    inp = AnalysisInput(request=request, calls=calls, diff=diff,
                        intent=compare_intent(request.intentPolicy, diff, request.safeAddress),
                        permits=permits, bridges=bridges, ctx=ctx, observed_chain_id=observed_chain_id)
    alerts = run_rules(inp, RULES + SHIELDS)
    alerts = sorted([*decoded.errors, *alerts], key=lambda a: -SEVERITY_WEIGHT[a.severity])
    summary = render_summary(diff, alerts, ctx, safe=request.safeAddress, label=request.label, permits=permits)
    return SimulationResult(
        success=success and not decoded.errors,
        simulationLatencyMs=round((time.perf_counter() - started) * 1000, 3),
        stateDiff=diff,
        alerts=alerts,
        plainEnglishSummary=summary,
        metrics=Metrics(gasUsed=str(gas_used), riskScore=risk_score(alerts)),
        mode=mode,
        calldataDigests=[calldata_digest(hex_to_bytes(t.data)) for t in request.transactions],
        revertReason=revert_reason,
    )


def analyze_offline(request: SimulationRequest, ctx: EngineContext = EngineContext()) -> SimulationResult:
    started = time.perf_counter()
    return _evaluate(request, ctx, _decode(request), None, started=started, mode="static", success=True)


async def simulate(
    request: SimulationRequest,
    ctx: EngineContext = EngineContext(),
    simulator: Optional["AnvilForkSimulator"] = None,
) -> SimulationResult:
    """Fork-simulate the exact bytes when a simulator is given, else fall back to static mode."""
    if simulator is None:
        return analyze_offline(request, ctx)
    from simulator.tracer.trace_diff import build_state_diff

    started = time.perf_counter()
    decoded = _decode(request)
    trace = await simulator.simulate_transaction_batch(request.safeAddress, request.transactions)
    enriched = await simulator.enrich_context(ctx, request, trace)
    observed = build_state_diff(request.safeAddress, trace) if trace.success else None
    if not trace.success:
        # A revert in simulation may be a fidelity gap, not safety: show calldata-predicted
        # effects and block, instead of reporting "nothing happens".
        reverted = alert("SIM-REVERTED", "HIGH", f"Simulation reverted ({trace.error}); effects shown are "
                         "predicted from calldata", reason=trace.error)
        decoded = _Decoded(decoded.calls, (*decoded.errors, reverted))
    return _evaluate(
        request, enriched, decoded, observed, started=started, mode="fork", success=trace.success,
        gas_used=trace.gas_used, observed_chain_id=trace.chain_id, revert_reason=trace.error,
    )
