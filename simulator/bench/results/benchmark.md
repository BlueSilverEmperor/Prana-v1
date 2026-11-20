# Vero benchmark (static mode)

Scenarios: 55. Latency p50 0.094 ms, p95 0.195 ms.
Expected-rule attribution on malicious scenarios: 30/30 (100.0%, CI 88.6%–100.0%).

| Baseline | Detection | Block | False positives |
|---|---|---|---|
| plain-wallet | 0/30 (0.0%, CI 0.0%–11.3%) | 0/30 (0.0%, CI 0.0%–11.3%) | 0/25 (0.0%, CI 0.0%–13.3%) |
| static-blocklist | 3/30 (10.0%, CI 3.5%–25.6%) | 3/30 (10.0%, CI 3.5%–25.6%) | 0/25 (0.0%, CI 0.0%–13.3%) |
| warnings-only | 30/30 (100.0%, CI 88.6%–100.0%) | 0/30 (0.0%, CI 0.0%–11.3%) | 0/25 (0.0%, CI 0.0%–13.3%) |
| full-vero | 30/30 (100.0%, CI 88.6%–100.0%) | 30/30 (100.0%, CI 88.6%–100.0%) | 0/25 (0.0%, CI 0.0%–13.3%) |

## Misclassified

- none

## Caveats

- Intervals are Wilson 95%. Counts are small; read the intervals, not the point rates.
- full-vero block rate is modelled (guard reverts HIGH/CRITICAL); measure it on-chain with the guard contracts before quoting it as enforcement.
- Static mode predicts effects from calldata; run with --rpc for executed traces.
- Held-out scenarios were not written by an outside author yet; replace them before the pitch.
- Public scenarios are calldata-shape reconstructions of cited incidents, not mainnet replays.
