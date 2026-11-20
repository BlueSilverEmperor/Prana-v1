"""VeroEngineAdapter: the real Vero simulator and rule engine behind the firewall API.

Implements SimulatorProtocol and RuleEngineProtocol by calling ``simulator.engine``
(owned by Person 2). The engine decodes, simulates and judges in one pass, so
``simulate_tx`` runs it and caches the verdict; ``evaluate`` reads that cache and
recomputes statically on a miss. No LLM is on this path.

Fork mode is used when ``rpc_url`` (env VERO_ANVIL_RPC) is set. If the node is
unreachable the adapter falls back to static analysis and adds FORK_UNAVAILABLE,
so a dead node degrades fidelity but never silences a verdict.
"""

from __future__ import annotations

import logging
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Optional

from pydantic import ValidationError

from api_agents.adapters.errors import EngineInputError
from api_agents.adapters.simulator_protocol import RawSimulationResult, RuleEvaluationResult
from api_agents.models.schemas import DecisionEnum, SimulateRequest, StateDiff


def _ensure_engine_importable() -> None:
    """In the monorepo the engine lives at the repo root; make it importable without install."""
    try:
        import simulator.engine  # noqa: F401
    except ImportError:
        root = Path(__file__).resolve().parents[3]
        if (root / "simulator" / "engine.py").exists():
            sys.path.insert(0, str(root))


_ensure_engine_importable()

from shared.api_schemas import SimulationRequest, SimulationResult, StateDiffSummary  # noqa: E402
from simulator.constants import UNLIMITED_THRESHOLD  # noqa: E402
from simulator.context import EngineContext  # noqa: E402
from simulator.engine import analyze_offline, simulate  # noqa: E402
from simulator.renderer.plain_english_renderer import format_amount  # noqa: E402

logger = logging.getLogger(__name__)

DEFAULT_CACHE_SIZE = 256
FORK_UNAVAILABLE = "FORK_UNAVAILABLE"
FLAG_NAMES = {
    "R1": "TOKEN_APPROVAL",
    "R2": "PERMIT_SIGNATURE",
    "R3": "PROXY_UPGRADE_ATTEMPT",
    "R4": "UNVERIFIED_DELEGATECALL",
    "R5": "OWNER_OR_THRESHOLD_CHANGE",
    "R6": "GUARD_CHANGE",
    "R7": "MODULE_ENABLED",
    "R8": "EIP7702_DELEGATION",
    "R9": "UNDECLARED_RECIPIENT",
    "R10": "OUTFLOW_CAP_EXCEEDED",
    "R11": "LOOKALIKE_TOKEN",
    "R12": "THREAT_REGISTRY_HIT",
    "P33-POISON": "ADDRESS_POISONING",
    "C31-CHAIN": "WRONG_CHAIN",
    "G28-GAS-CEILING": "GAS_CEILING_EXCEEDED",
    "G28-GRIEFING": "GAS_GRIEFING",
    "G28-MALFORMED": "MALFORMED_GAS_FIELDS",
    "B26-VAULT-SHARE": "LARGE_VAULT_OUTFLOW",
    "B26-NEW-CONTRACT": "NEW_CONTRACT",
    "B26-FIRST-RECIPIENT": "FIRST_TIME_RECIPIENT",
    "B36-BRIDGE": "UNKNOWN_BRIDGE_DESTINATION",
    "DECODE": "UNDECODABLE_CALLDATA",
    "SIM-REVERTED": "SIMULATION_REVERTED",
}


def to_engine_request(req: SimulateRequest) -> SimulationRequest:
    tx = {"to": req.to, "value": req.value, "data": req.data, "operation": req.operation}
    if req.gas_limit is not None:
        tx["gas"] = str(req.gas_limit)
    payload = {"chainId": req.chain_id, "safeAddress": req.safe_address, "transactions": [tx],
               "label": req.label}
    if req.declared_intent is not None:
        d = req.declared_intent
        payload["intentPolicy"] = {"allowedRecipients": d.allowed_recipients, "allowedTokens": d.allowed_tokens,
                                   "maxOutflowWei": d.max_outflow_wei}
    try:
        return SimulationRequest.model_validate(payload)
    except ValidationError as exc:
        raise EngineInputError(f"invalid simulation request: {exc.errors()[0]['msg']}") from exc


def _asset_type(asset: str) -> str:
    if asset == "ETH":
        return "NATIVE"
    return "ERC721" if "#" in asset else "ERC20"


def to_state_diffs(diff: StateDiffSummary, safe: str, ctx: EngineContext) -> list[StateDiff]:
    rows: list[StateDiff] = []
    for c in diff.balanceChanges:
        delta = int(c.delta)
        if delta > 0 and c.address != safe:
            rows.append(StateDiff(asset_type=_asset_type(c.asset),
                                  contract_address=None if c.asset == "ETH" else c.asset.split("#")[0],
                                  from_address=safe, to_address=c.address, amount_raw=str(delta),
                                  delta_human=f"-{format_amount(c.asset, delta, ctx)}"))
    for a in diff.approvals:
        if a.amount in ("0", "NONE"):
            human = "APPROVAL REVOKED"
        elif a.amount == "ALL" or int(a.amount) >= UNLIMITED_THRESHOLD:
            human = f"APPROVAL GRANTED ({format_amount(a.token, UNLIMITED_THRESHOLD, ctx)})"
        else:
            human = f"APPROVAL GRANTED ({format_amount(a.token, int(a.amount), ctx)})"
        rows.append(StateDiff(asset_type="ERC20_ALLOWANCE", contract_address=a.token, from_address=a.owner,
                              to_address=a.spender, amount_raw=a.amount, delta_human=human))
    rows += [StateDiff(asset_type="STORAGE", contract_address=o.safe, from_address=o.safe, to_address=added,
                       delta_human="OWNER_ADDED") for o in diff.ownerChanges for added in o.added]
    rows += [StateDiff(asset_type="STORAGE", contract_address=o.safe, from_address=o.safe,
                       delta_human=f"THRESHOLD_CHANGED_TO_{o.newThreshold}")
             for o in diff.ownerChanges if o.newThreshold is not None]
    rows += [StateDiff(asset_type="STORAGE", contract_address=m.safe, from_address=m.safe, to_address=mod,
                       delta_human="MODULE_ENABLED") for m in diff.moduleChanges for mod in m.enabledModules]
    rows += [StateDiff(asset_type="STORAGE", contract_address=g.safe, from_address=g.safe, to_address=g.newGuard,
                       delta_human="GUARD_CHANGED") for g in diff.guardChanges]
    rows += [StateDiff(asset_type="STORAGE", contract_address=s.address, from_address=s.address,
                       to_address=s.newImpl if len(s.newImpl) == 42 else None,
                       delta_human="IMPLEMENTATION_CHANGED") for s in diff.implementationSwaps]
    return rows


def _flag_for(rule_id: str, context: Optional[dict]) -> str:
    if rule_id == "R1" and context and (context.get("amount") == "ALL" or
                                         str(context.get("amount", "0")).isdigit() and
                                         int(context["amount"]) >= UNLIMITED_THRESHOLD):
        return "INFINITE_TOKEN_APPROVAL"
    return FLAG_NAMES.get(rule_id, rule_id)


def to_verdict(result: SimulationResult, fork_failed: bool) -> RuleEvaluationResult:
    severities = {a.severity for a in result.alerts}
    if severities & {"CRITICAL", "HIGH"}:
        decision = DecisionEnum.BLOCK
    elif "MEDIUM" in severities or fork_failed:
        decision = DecisionEnum.WARN
    else:
        decision = DecisionEnum.ALLOW
    flags = list(dict.fromkeys(_flag_for(a.ruleId, a.context) for a in result.alerts))
    warnings = [f"[{a.ruleId}] {a.severity}: {a.description}" for a in result.alerts]
    if fork_failed:
        flags.append(FORK_UNAVAILABLE)
        warnings.append("Fork simulation unavailable; verdict is based on calldata analysis only.")
    return RuleEvaluationResult(decision=decision, risk_score=result.metrics.riskScore, flags=flags,
                                human_warnings=warnings)


class VeroEngineAdapter:
    """SimulatorProtocol + RuleEngineProtocol backed by the Vero engine."""

    def __init__(self, ctx: Optional[EngineContext] = None, rpc_url: Optional[str] = None,
                 cache_size: int = DEFAULT_CACHE_SIZE) -> None:
        self._ctx = ctx or EngineContext()
        self._rpc_url = rpc_url
        self._cache: OrderedDict[str, tuple[SimulationResult, bool]] = OrderedDict()
        self._cache_size = cache_size

    async def _run(self, request: SimulationRequest) -> tuple[SimulationResult, bool]:
        if not self._rpc_url:
            return analyze_offline(request, self._ctx), False
        from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator

        try:
            async with AnvilForkSimulator(self._rpc_url) as fork:
                return await simulate(request, self._ctx, fork), False
        except Exception as exc:  # noqa: BLE001 - any node failure degrades to static, flagged
            logger.exception("fork simulation failed (%s); using static analysis", exc)
            return analyze_offline(request, self._ctx), True

    def _remember(self, key: str, value: tuple[SimulationResult, bool]) -> None:
        self._cache[key] = value
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)

    async def simulate_tx(self, req: SimulateRequest) -> RawSimulationResult:
        request = to_engine_request(req)
        result, fork_failed = await self._run(request)
        self._remember(req.model_dump_json(), (result, fork_failed))
        return RawSimulationResult(
            success=result.success, gas_used=int(result.metrics.gasUsed),
            state_diffs=to_state_diffs(result.stateDiff, request.safeAddress, self._ctx),
            raw_logs=[], revert_reason=result.revertReason or "",
        )

    def evaluate(self, sim: RawSimulationResult, req: SimulateRequest) -> RuleEvaluationResult:
        cached = self._cache.get(req.model_dump_json())
        if cached is None:
            cached = (analyze_offline(to_engine_request(req), self._ctx), False)
        return to_verdict(*cached)
