"""Red/green MCMC sampler over HTTP, for the attack-vs-defense page.

The sampler throws mutated attacks (red) and harmless lookalikes (green) at the deterministic engine and
reports what got through. Requests are bounded so one call stays a few seconds of CPU at most.
"""

from typing import List, Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from simulator.redteam.mcmc import run

router = APIRouter(prefix="/v1/redteam", tags=["redteam"])
MAX_STEPS = 3000
MAX_TRACE = 400


class McmcRequest(BaseModel):
    steps: int = Field(600, ge=50, le=MAX_STEPS, description="Metropolis steps per chain")
    chains: int = Field(4, ge=1, le=4, description="Chains; with mode=both they alternate red and green")
    seed: int = Field(7, ge=0, lt=2**31)
    mode: Literal["both", "red", "green"] = "both"


class McmcResponse(BaseModel):
    steps: int
    chains: int
    seed: int
    mode: str
    acceptance_rate: float
    unique_variants: int
    harmful_unique: int
    escapes: List[dict]
    escape_rate: float
    false_positives: List[dict]
    block_rate_by_primitive: dict
    attacks_by_primitive: dict
    rule_hits: dict
    latency_p50_ms: float
    latency_p95_ms: float
    trace: List[dict]


@router.post("/mcmc", response_model=McmcResponse)
async def mcmc(req: McmcRequest) -> McmcResponse:
    report = await run_in_threadpool(run, req.steps, req.chains, req.seed, 0.5, req.mode, MAX_TRACE)
    return McmcResponse(steps=report.steps, chains=report.chains, seed=report.seed, mode=req.mode,
                        acceptance_rate=report.acceptance_rate, unique_variants=report.unique_variants,
                        harmful_unique=report.harmful_unique, escapes=report.escapes, escape_rate=report.escape_rate,
                        false_positives=report.false_positives,
                        block_rate_by_primitive=report.block_rate_by_primitive,
                        attacks_by_primitive=report.attacks_by_primitive, rule_hits=dict(report.rule_hits),
                        latency_p50_ms=_percentile(report.latencies_ms, 50),
                        latency_p95_ms=_percentile(report.latencies_ms, 95), trace=report.trace)


def _percentile(values: List[float], pct: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(len(ordered) * pct / 100))], 3)
