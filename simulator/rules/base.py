"""Shared input type and helpers for every deterministic rule."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from shared.api_schemas import RiskAlert, SimulationRequest, StateDiffSummary
from simulator.context import EngineContext
from simulator.decoders.calldata import DecodedCall
from simulator.decoders.permit_and_bridge_decoders import BridgeInfo, PermitInfo
from simulator.rules.intent_diff import IntentDiff


@dataclass(frozen=True)
class AnalysisInput:
    request: SimulationRequest
    calls: tuple[DecodedCall, ...]
    diff: StateDiffSummary
    intent: Optional[IntentDiff]
    permits: tuple[PermitInfo, ...]
    bridges: tuple[BridgeInfo, ...]
    ctx: EngineContext
    observed_chain_id: Optional[int] = None

    @property
    def safe(self) -> str:
        return self.request.safeAddress

    @property
    def policy(self):
        return self.request.intentPolicy

    def declared(self, address: str) -> bool:
        return self.policy is not None and address in self.policy.allowedRecipients


def alert(rule: str, severity: str, description: str, **context: Any) -> RiskAlert:
    return RiskAlert(ruleId=rule, severity=severity, description=description, context=context or None)
