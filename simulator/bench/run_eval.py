"""Features #23/#24: run the scenario harness and compare four baselines.

Usage:
    python -m simulator.bench.run_eval                     # static mode, no node needed
    python -m simulator.bench.run_eval --rpc http://127.0.0.1:8545   # fork mode on Anvil

Honesty notes written into every report:
- "block rate" for full-vero models the on-chain guard reverting HIGH/CRITICAL
  verdicts; it becomes a measured number once the guard contracts replay these cases.
- In static mode effects are predicted from calldata, not executed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional, Sequence

from shared.api_schemas import BenchmarkMetrics, ConfidenceIntervals, SimulationResult
from simulator.bench.scenario import Scenario, load_scenarios
from simulator.bench.stats import percentile, wilson_interval
from simulator.constants import BLOCKING_SEVERITIES
from simulator.context import EngineContext
from simulator.engine import simulate

logger = logging.getLogger(__name__)
DEFAULT_SCENARIOS = Path(__file__).parent / "scenarios"
DEFAULT_OUT = Path(__file__).parent / "results"
BASELINES = ("plain-wallet", "static-blocklist", "warnings-only", "full-vero")


@dataclass(frozen=True)
class Rate:
    successes: int
    trials: int
    rate: float
    ci95: tuple[float, float]


@dataclass(frozen=True)
class BaselineRow:
    name: str
    detection: Rate
    block: Rate
    false_positive: Rate


@dataclass(frozen=True)
class ScenarioOutcome:
    id: str
    set: str
    label: str
    flagged: bool
    registry_hit: bool
    fired: tuple[str, ...]
    expected_matched: bool
    latency_ms: float


@dataclass(frozen=True)
class BenchmarkReport:
    metrics: BenchmarkMetrics
    baselines: tuple[BaselineRow, ...]
    outcomes: tuple[ScenarioOutcome, ...]
    rule_attribution: Rate
    mode: str


def _rate(successes: int, trials: int) -> Rate:
    return Rate(successes, trials, round(successes / trials, 4) if trials else 0.0, wilson_interval(successes, trials))


def _outcome(s: Scenario, r: SimulationResult) -> ScenarioOutcome:
    fired = tuple(sorted({a.ruleId for a in r.alerts}))
    flagged = any(a.severity in BLOCKING_SEVERITIES for a in r.alerts)
    return ScenarioOutcome(
        id=s.id, set=s.set, label=s.label, flagged=flagged,
        registry_hit=any(a.ruleId == "R12" for a in r.alerts), fired=fired,
        expected_matched=set(s.expectedRules) <= set(fired), latency_ms=r.simulationLatencyMs,
    )


def _baseline(name: str, outcomes: Sequence[ScenarioOutcome]) -> BaselineRow:
    def flags(o: ScenarioOutcome) -> bool:
        return {"plain-wallet": False, "static-blocklist": o.registry_hit}.get(name, o.flagged)

    def blocks(o: ScenarioOutcome) -> bool:
        return flags(o) if name in ("static-blocklist", "full-vero") else False

    bad = [o for o in outcomes if o.label == "malicious"]
    good = [o for o in outcomes if o.label == "benign"]
    return BaselineRow(name, _rate(sum(map(flags, bad)), len(bad)), _rate(sum(map(blocks, bad)), len(bad)),
                       _rate(sum(map(flags, good)), len(good)))


async def run_benchmark(scenarios: Sequence[Scenario], simulator=None) -> BenchmarkReport:
    outcomes = []
    for s in scenarios:
        ctx = EngineContext.from_mapping(s.context)
        if simulator is not None and "ETH" in ctx.safe_balances:
            # Fork mode on a disposable Anvil: give the Safe its declared ETH so benign
            # payments do not revert for lack of funds. This mutates the node's state.
            await simulator.rpc("anvil_setBalance", [s.request.safeAddress, hex(ctx.safe_balances["ETH"])])
        result = await simulate(s.request, ctx, simulator)
        outcomes.append(_outcome(s, result))
    rows = tuple(_baseline(name, outcomes) for name in BASELINES)
    full = rows[-1]
    latencies = [o.latency_ms for o in outcomes]
    bad = [o for o in outcomes if o.label == "malicious"]
    metrics = BenchmarkMetrics(
        totalScenarios=len(outcomes), detectionRate=full.detection.rate, blockRate=full.block.rate,
        falsePositiveRate=full.false_positive.rate, p95LatencyMs=percentile(latencies, 95),
        p50LatencyMs=percentile(latencies, 50), mode="fork" if simulator else "static",
        confidenceIntervals=ConfidenceIntervals(detectionRate95=full.detection.ci95, blockRate95=full.block.ci95,
                                                falsePositiveRate95=full.false_positive.ci95),
    )
    return BenchmarkReport(metrics, rows, tuple(outcomes), _rate(sum(o.expected_matched for o in bad), len(bad)),
                           metrics.mode or "static")


def _fmt(r: Rate) -> str:
    return f"{r.successes}/{r.trials} ({r.rate:.1%}, CI {r.ci95[0]:.1%}–{r.ci95[1]:.1%})"


def render_markdown(report: BenchmarkReport) -> str:
    m = report.metrics
    lines = [
        f"# Vero benchmark ({report.mode} mode)", "",
        f"Scenarios: {m.totalScenarios}. Latency p50 {m.p50LatencyMs} ms, p95 {m.p95LatencyMs} ms.",
        f"Expected-rule attribution on malicious scenarios: {_fmt(report.rule_attribution)}.", "",
        "| Baseline | Detection | Block | False positives |", "|---|---|---|---|",
    ]
    lines += [f"| {b.name} | {_fmt(b.detection)} | {_fmt(b.block)} | {_fmt(b.false_positive)} |"
              for b in report.baselines]
    misses = [o for o in report.outcomes if (o.label == "malicious") != o.flagged]
    lines += ["", "## Misclassified", ""] + ([f"- {o.id} ({o.label}): fired {', '.join(o.fired) or 'none'}"
                                              for o in misses] or ["- none"])
    lines += ["", "## Caveats", "",
              "- Intervals are Wilson 95%. Counts are small; read the intervals, not the point rates.",
              "- full-vero block rate is modelled (guard reverts HIGH/CRITICAL); measure it on-chain with the "
              "guard contracts before quoting it as enforcement.",
              "- Static mode predicts effects from calldata; run with --rpc for executed traces.",
              "- Held-out scenarios were not written by an outside author yet; replace them before the pitch.",
              "- Public scenarios are calldata-shape reconstructions of cited incidents, not mainnet replays."]
    return "\n".join(lines) + "\n"


def write_reports(report: BenchmarkReport, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"metrics": report.metrics.model_dump(), "mode": report.mode,
               "ruleAttribution": asdict(report.rule_attribution),
               "baselines": [asdict(b) for b in report.baselines],
               "outcomes": [asdict(o) for o in report.outcomes]}
    json_path, md_path = out_dir / "benchmark.json", out_dir / "benchmark.md"
    json_path.write_text(json.dumps(payload, indent=2) + "\n")
    md_path.write_text(render_markdown(report))
    return json_path, md_path


async def _amain(args: argparse.Namespace) -> int:
    scenarios = load_scenarios(Path(args.scenarios))
    if args.rpc:
        from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator

        async with AnvilForkSimulator(args.rpc) as simulator:
            report = await run_benchmark(scenarios, simulator)
    else:
        report = await run_benchmark(scenarios)
    json_path, md_path = write_reports(report, Path(args.out))
    sys.stdout.write(render_markdown(report))
    sys.stdout.write(f"\nWrote {json_path} and {md_path}\n")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Vero 55-scenario benchmark")
    parser.add_argument("--rpc", help="Anvil RPC URL for fork mode (default: static mode)")
    parser.add_argument("--scenarios", default=str(DEFAULT_SCENARIOS))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    logging.basicConfig(level=logging.WARNING)
    return asyncio.run(_amain(parser.parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
