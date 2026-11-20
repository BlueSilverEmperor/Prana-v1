"""
Latency Benchmark Script for Project Vero Firewall API (/v1/simulate).
Measures end-to-end request/response round-trip latency against the < 150 ms SLA target.
"""

import statistics
import time
from fastapi.testclient import TestClient
from api_agents.main import app

NUM_ITERATIONS = 100
TARGET_SLA_MS = 150.0


def run_benchmark():
    client = TestClient(app)
    latencies_ms = []

    payload = {
        "chain_id": 1,
        "safe_address": "0x1111111111111111111111111111111111111111",
        "to": "0x2222222222222222222222222222222222222222",
        "value": "1000000000000000000",
        "data": "0x095ea7b3" + "0" * 24 + "8" * 40 + "f" * 64,
        "nonce": 42,
    }

    # Warm-up request
    client.post("/v1/simulate", json=payload)

    print(f"\n[BENCHMARK] Executing {NUM_ITERATIONS} iterations on /v1/simulate...")
    for i in range(NUM_ITERATIONS):
        t0 = time.perf_counter()
        res = client.post("/v1/simulate", json=payload)
        t1 = time.perf_counter()

        if res.status_code != 200:
            raise RuntimeError(f"Request {i} failed with status {res.status_code}: {res.text}")

        elapsed_ms = (t1 - t0) * 1000.0
        latencies_ms.append(elapsed_ms)

    latencies_sorted = sorted(latencies_ms)
    avg_latency = statistics.mean(latencies_ms)
    median_latency = statistics.median(latencies_ms)
    p95 = latencies_sorted[int(NUM_ITERATIONS * 0.95)]
    p99 = latencies_sorted[int(NUM_ITERATIONS * 0.99)]
    min_latency = min(latencies_ms)
    max_latency = max(latencies_ms)

    print("\n" + "=" * 55)
    print("      PROJECT VERO: /v1/simulate LATENCY REPORT     ")
    print("=" * 55)
    print(f" Total Requests    : {NUM_ITERATIONS}")
    print(f" Target Max SLA    : < {TARGET_SLA_MS:.1f} ms")
    print(f" Average Latency   : {avg_latency:.3f} ms")
    print(f" Median (p50)      : {median_latency:.3f} ms")
    print(f" 95th Percentile   : {p95:.3f} ms")
    print(f" 99th Percentile   : {p99:.3f} ms")
    print(f" Min Latency       : {min_latency:.3f} ms")
    print(f" Max Latency       : {max_latency:.3f} ms")
    print("=" * 55)

    if p99 < TARGET_SLA_MS:
        print(f" [PASS] 99th percentile ({p99:.2f} ms) is well within target (< {TARGET_SLA_MS} ms).\n")
    else:
        print(f" [FAIL] 99th percentile ({p99:.2f} ms) exceeded target ({TARGET_SLA_MS} ms).\n")
        exit(1)


if __name__ == "__main__":
    run_benchmark()
