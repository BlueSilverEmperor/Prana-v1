"""
50-scenario synthetic evaluation of the Vero firewall API path (real engine).

Runs every request through the same adapter /v1/simulate uses (VeroEngineAdapter, static
calldata analysis unless VERO_ANVIL_RPC is set). Every number printed is computed from the
run; nothing is hardcoded.

Scenario set (generated here, team-authored, so treat results as a regression check, not
an independent score; simulator/bench/ holds the 55-scenario benchmark):
- 25 malicious: 10 proxy upgrades (upgradeTo), 10 unlimited ERC-20 approvals,
  5 large ETH sends to an address outside the signer's declared intent
- 25 benign: ETH payments to the declared recipient within the declared cap

Usage: python scripts/run_evidence_eval.py
"""

import asyncio
import os
import statistics
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO_ROOT, os.path.join(REPO_ROOT, "api-agents")):
    if path not in sys.path:
        sys.path.insert(0, path)

from api_agents.adapters.factory import build_adapter, engine_name  # noqa: E402
from api_agents.models.schemas import DecisionEnum, DeclaredIntent, SimulateRequest  # noqa: E402
from simulator.bench.stats import percentile, wilson_interval  # noqa: E402

SAFE = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
DECLARED_RECIPIENT = "0x" + "d" * 40
UNDECLARED_RECIPIENT = "0x" + "c" * 40
ETH = 10**18
DECLARED_CAP_WEI = 5 * ETH
PAY_DECLARED = DeclaredIntent(allowed_recipients=[DECLARED_RECIPIENT], allowed_tokens=["ETH"],
                              max_outflow_wei=str(DECLARED_CAP_WEI))


def build_scenarios() -> list[dict]:
    def req(**kw) -> SimulateRequest:
        return SimulateRequest(chain_id=1, safe_address=SAFE, **kw)

    scenarios = []
    for i in range(10):
        scenarios.append({"name": f"Proxy upgrade #{i + 1}", "malicious": True,
                          "req": req(to="0x" + "a" * 40, data="0x3659cfe6" + "0" * 24 + f"{i + 1:040x}", nonce=i)})
    for i in range(10):
        scenarios.append({"name": f"Unlimited approval #{i + 1}", "malicious": True,
                          "req": req(to="0x" + "b" * 40, nonce=10 + i,
                                     data="0x095ea7b3" + "0" * 24 + f"{i + 1:040x}" + "f" * 64)})
    for i in range(5):
        scenarios.append({"name": f"Drain to undeclared address #{i + 1}", "malicious": True,
                          "req": req(to=UNDECLARED_RECIPIENT, value=str(50 * ETH), nonce=20 + i,
                                     declared_intent=PAY_DECLARED)})
    for i in range(25):
        amount = ETH // 2 + i * (ETH // 10)  # 0.5 ETH .. 2.9 ETH, all within the 5 ETH cap
        scenarios.append({"name": f"Declared payment #{i + 1}", "malicious": False,
                          "req": req(to=DECLARED_RECIPIENT, value=str(amount), nonce=30 + i,
                                     declared_intent=PAY_DECLARED)})
    return scenarios


def fmt_rate(hits: int, total: int) -> str:
    low, high = wilson_interval(hits, total)
    return f"{hits} / {total} ({hits / total:.1%}, 95% CI {low:.1%}-{high:.1%})"


def run_evaluation_benchmark() -> dict:
    adapter = build_adapter()
    scenarios = build_scenarios()
    latencies, counts, misses = [], {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "warn": 0}, []
    for s in scenarios:
        t0 = time.perf_counter()
        sim = asyncio.run(adapter.simulate_tx(s["req"]))
        verdict = adapter.evaluate(sim, s["req"])
        latencies.append((time.perf_counter() - t0) * 1000.0)
        blocked = verdict.decision == DecisionEnum.BLOCK
        counts["warn"] += verdict.decision == DecisionEnum.WARN
        key = ("tp" if blocked else "fn") if s["malicious"] else ("fp" if blocked else "tn")
        counts[key] += 1
        if key in ("fn", "fp"):
            misses.append(f"{s['name']}: {verdict.decision.value} {verdict.flags}")

    n_mal = sum(s["malicious"] for s in scenarios)
    n_ben = len(scenarios) - n_mal
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    print("\n" + "=" * 70)
    print("   PROJECT VERO // 50-SCENARIO SYNTHETIC EVALUATION (team-authored)")
    print("=" * 70)
    print(f"Engine                     : {engine_name(adapter)}")
    print(f"Scenarios                  : {len(scenarios)} ({n_mal} malicious, {n_ben} benign)")
    print("-" * 70)
    print(f"Blocked (malicious)        : {fmt_rate(tp, n_mal)}")
    print(f"False positives (benign)   : {fmt_rate(fp, n_ben)}")
    print(f"WARN verdicts (any)        : {counts['warn']}")
    print(f"Accuracy                   : {(tp + tn) / len(scenarios):.2%}")
    print(f"Precision / Recall / F1    : {precision:.4f} / {recall:.4f} / {f1:.4f}")
    print("-" * 70)
    print(f"Latency mean / p50 / p95   : {statistics.mean(latencies):.3f} / {percentile(latencies, 50):.3f} / "
          f"{percentile(latencies, 95):.3f} ms (in-process, static analysis)")
    print("=" * 70)
    print("Misclassified              : " + ("none" if not misses else ""))
    for line in misses:
        print(f"  - {line}")
    print("\nNote: synthetic scenarios written by the team; see simulator/bench for the 55-scenario benchmark.\n")
    return {**counts, "n_mal": n_mal, "n_ben": n_ben}


if __name__ == "__main__":
    run_evaluation_benchmark()
