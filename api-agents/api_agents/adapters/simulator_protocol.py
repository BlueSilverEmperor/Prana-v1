"""
Protocol definitions for downstream Anvil simulator and 12-rule engine.
Per Hackathon Spec: Teammates own the live Anvil node and 12-rule engine;
these protocols decouple Person 3's firewall & API layer.
"""

from typing import List, Protocol, runtime_checkable
from pydantic import BaseModel
from api_agents.models.schemas import DecisionEnum, SimulateRequest, StateDiff


class RawSimulationResult(BaseModel):
    success: bool
    gas_used: int
    state_diffs: List[StateDiff]
    raw_logs: List[str]
    revert_reason: str = ""


class RuleEvaluationResult(BaseModel):
    decision: DecisionEnum
    risk_score: int
    flags: List[str]
    human_warnings: List[str]


@runtime_checkable
class SimulatorProtocol(Protocol):
    """Protocol for EVM State Fork Simulator (Anvil / RPC)."""
    async def simulate_tx(self, req: SimulateRequest) -> RawSimulationResult:
        ...


@runtime_checkable
class RuleEngineProtocol(Protocol):
    """Protocol for 12-Rule Deterministic Evaluation Engine."""
    def evaluate(self, sim: RawSimulationResult, req: SimulateRequest) -> RuleEvaluationResult:
        ...
