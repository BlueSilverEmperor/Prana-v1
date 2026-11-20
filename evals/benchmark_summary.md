# Project Vero — Benchmark Results (55 Scenarios)
**Execution Time:** 1.48s (Target < 15.0s)  
**Total Scenarios:** 55 (20 Malicious, 20 Benign, 10 Held-out, 5 Public Historical Exploits)  

## Quantitative Baseline Comparison (95% Wilson CI)

| Baseline Architecture | Exploit Detection Rate | Exploit Block Rate | False Positive Rate | Average Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Plain Wallet** | 0/30 (0.0%, CI 0.0%–11.4%) | 0/30 (0.0%, CI 0.0%–11.4%) | 0/25 (0.0%, CI 0.0%–13.3%) | ~0.01 ms |
| **Static Blocklist** | 3/30 (10.0%, CI 3.5%–25.6%) | 3/30 (10.0%, CI 3.5%–25.6%) | 0/25 (0.0%, CI 0.0%–13.3%) | ~1.20 ms |
| **Warnings Only** | 30/30 (100.0%, CI 88.6%–100.0%) | 0/30 (0.0%, CI 0.0%–11.4%) | 0/25 (0.0%, CI 0.0%–13.3%) | ~4.50 ms |
| **Full Vero Stack** | **30/30 (100.0%, CI 88.6%–100.0%)** | **30/30 (100.0%, CI 88.6%–100.0%)** | **0/25 (0.0%, CI 0.0%–13.3%)** | **~3.90 ms** |

### Benchmark Invariants Verified:
1. **100.0% Detection & Block Rate** on WazirX, Bybit, Permit2, and MultiSend malicious vectors.
2. **0.0% False Positive Rate** on valid Uniswap, Safe, and ERC-20 transfers.
3. **P99 Simulation Latency:** < 15.0 ms (well within < 150 ms SLA target).