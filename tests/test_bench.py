import json
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from simulator.bench.run_eval import BASELINES, run_benchmark, write_reports
from simulator.bench.scenario import Scenario, load_scenarios
from simulator.bench.stats import percentile, wilson_interval

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "simulator" / "bench" / "scenarios"


class TestStats:
    def test_wilson_matches_reference_values(self):
        low, high = wilson_interval(8, 10)
        assert low == pytest.approx(0.4902, abs=1e-3)
        assert high == pytest.approx(0.9433, abs=1e-3)

    def test_wilson_handles_zero_trials(self):
        assert wilson_interval(0, 0) == (0.0, 0.0)

    def test_wilson_rejects_impossible_counts(self):
        with pytest.raises(ValueError):
            wilson_interval(5, 3)

    def test_percentile_of_empty_is_zero(self):
        assert percentile([], 95) == 0.0
        assert percentile([1.0, 2.0, 3.0], 50) == 2.0


class TestScenarios:
    def test_scenario_counts_match_design(self):
        scenarios = load_scenarios(SCENARIO_DIR)
        by_set = {s: [x for x in scenarios if x.set == s] for s in ("main", "heldout", "public")}
        assert (len(by_set["main"]), len(by_set["heldout"]), len(by_set["public"])) == (40, 10, 5)
        assert sum(x.label == "malicious" for x in scenarios) == 30
        assert len({x.id for x in scenarios}) == 55

    def test_malicious_scenarios_declare_expected_rules(self):
        for s in load_scenarios(SCENARIO_DIR):
            assert (s.label == "malicious") == bool(s.expectedRules), s.id

    def test_invalid_scenario_rejected(self):
        with pytest.raises(ValidationError):
            Scenario.model_validate({"id": "x", "set": "main", "label": "evil", "category": "c", "title": "t",
                                     "request": {}, "context": {}, "expectedRules": []})


class TestBenchmark:
    async def test_runs_all_scenarios_fast_with_four_baselines(self):
        started = time.perf_counter()
        report = await run_benchmark(load_scenarios(SCENARIO_DIR))
        assert time.perf_counter() - started < 15
        assert report.metrics.totalScenarios == 55
        assert [b.name for b in report.baselines] == list(BASELINES)

    async def test_baseline_ordering_is_sane(self):
        report = await run_benchmark(load_scenarios(SCENARIO_DIR))
        rows = {b.name: b for b in report.baselines}
        assert rows["plain-wallet"].detection.successes == 0
        assert rows["warnings-only"].block.successes == 0
        assert rows["static-blocklist"].detection.successes <= rows["full-vero"].detection.successes
        low, high = report.metrics.confidenceIntervals.detectionRate95
        assert 0.0 <= low <= report.metrics.detectionRate <= high <= 1.0

    async def test_write_reports_creates_json_and_markdown(self, tmp_path):
        report = await run_benchmark(load_scenarios(SCENARIO_DIR))
        json_path, md_path = write_reports(report, tmp_path)
        data = json.loads(json_path.read_text())
        assert data["metrics"]["totalScenarios"] == 55
        assert "| full-vero |" in md_path.read_text()
