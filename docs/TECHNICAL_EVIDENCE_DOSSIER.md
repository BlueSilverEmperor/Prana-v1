# Project Vero (Prana-v1) — Technical Evidence & Verification Dossier
**The Big Hack 2.0 | Track 02: Cybersecurity & Blockchain | Problem B1: "Know What You're Signing"**  
**Repository:** [https://github.com/BlueSilverEmperor/Prana-v1](https://github.com/BlueSilverEmperor/Prana-v1)

---

## 1. Executive Summary & Problem Recap

In July 2024, Indian crypto exchange **WazirX lost about $230 million** from its multisig wallet. In February 2025, **Bybit lost about $1.5 billion** in a similar attack.
* **The Vulnerability:** In both cases signers approved transactions whose displayed meaning differed from their real effect; the signing interface, not the private keys, was the weak point.
* **The Mechanism:** The screen showed a routine transfer, while the signed bytes replaced the wallet's logic. Our replay models this as an `upgradeTo` on the wallet.
* **Why Existing Solutions Fail:** Browser extensions, RPC-level alerts, and dApp simulations are **client-side only**. If the frontend or signer workstation is compromised, these warnings are suppressed or bypassed.
* **Vero’s Resolution:** **On-Chain Invariant Enforcement.** Vero binds user signatures to an on-chain **EIP-712 IntentPolicy**. Even if all multisig signers are tricked into signing, **the smart contract (`VeroGuard.sol`) reverts the transaction at the EVM execution level**.

---

## 2. Evidence Layer 1: The WazirX Exploit Anatomy & On-Chain Revert

### A. The Attack Bytecode Breakdown
In `contracts/test/ExploitReplays.t.sol` (`test_WazirX_Slot0Swap_Blocked`), we reproduce the exact attack payload:
```solidity
// Method Selector: 0x3659cfe6 = bytes4(keccak256("upgradeTo(address)"))
// Followed by 32-byte padded attacker address:
bytes memory maliciousPayload = abi.encodeWithSelector(
    bytes4(0x3659cfe6), 
    address(0xDeadDeAddeAddEAddeadbeefdeadbeefdeadbeef)
);
```

### B. The Target Storage Slot
The attack aims to overwrite the ERC-1967 logic proxy implementation slot:
$$\text{Slot } \texttt{0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc} = \text{bytes32}(\text{uint256}(\text{keccak256}('eip1967.proxy.implementation')) - 1)$$

### C. The Vero On-Chain Defense (`VeroGuard.sol`)
`GuardedMultisig.execTransaction` asks `VeroGuard.takeSnapshot` for a pre-execution snapshot (ETH and registered token balances, wallet codehash, `masterCopy`, owners hash, threshold, guard), held in memory, then calls `VeroGuard.checkAfterExecution` with it after the inner call. Any changed control value reverts with `ControlSlotMutated(...)`. Simplified from `contracts/src/VeroGuard.sol` (the contracts do not use transient storage):
```solidity
// GuardedMultisig.execTransaction (simplified)
preSnap = VeroGuard(guard).takeSnapshot(address(this), policy.tokenAddresses);
(success, ) = operation == 1 ? to.delegatecall(data) : to.call{value: value}(data);
VeroGuard(guard).checkAfterExecution(address(this), success, policy, preSnap);

// VeroGuard.checkAfterExecution (simplified)
if (ms.masterCopy() != preSnap.masterCopy) revert ControlSlotMutated("masterCopy");
```

### D. Empirical Foundry Test Evidence
```bash
cd contracts && forge test --match-test test_WazirX_Slot0Swap_Blocked
```
**Output (Foundry 1.10.0):**
```text
[PASS] test_WazirX_Slot0Swap_Blocked() (gas: 419003)
```

---

## 3. Evidence Layer 2: Invariant Fuzz Testing (12,800 Calls)

Foundry invariant fuzzing (`contracts/test/VeroInvariants.t.sol`) searches random call sequences for a violation. It found none; this is strong testing evidence, not a formal proof.
* **Measured:** `VeroInvariantsTest invariants (runs: 256, calls: 12800, reverts: 0)`.

| Invariant | Property checked under fuzzing | Result |
| :--- | :--- | :---: |
| `invariant_ZeroUndeclaredOutflows` | Total outgoing token balance delta $\le \sum \text{policy.maxPayments}$ under all random calldata permutations. | **PASS** |
| `invariant_ControlSlotImmutability` | Slots `masterCopy`, `ownersHash`, `threshold`, and `guard` remain identical before and after execution. | **PASS** |
| `invariant_GasPriceCompliance` | No transaction executes if `tx.gasprice > policy.maxGasFeeWei` (anti-MEV frontrunning). | **PASS** |
| `invariant_DirectEnableModuleAlwaysReverts` | Direct calls to `enableModule(0x610b5925)` without 24h timelock revert unconditionally. | **PASS** |

---

## 4. Evidence Layer 3: Scenario Benchmarks (real engine)

**A. 55-scenario benchmark** (`python -m simulator.bench.run_eval`, summarised by `node evals/run_benchmark.js`):
40 main (20 malicious, 20 benign), 10 held-out, 5 public-incident reconstructions; four baselines with 95% Wilson intervals.

| Baseline | Detection | Block | False positives |
| :--- | :--- | :--- | :--- |
| Plain wallet | 0/30 (0.0%, CI 0.0–11.4%) | 0/30 | 0/25 |
| Static blocklist | 3/30 (10.0%, CI 3.5–25.6%) | 3/30 | 0/25 |
| Warnings only | 30/30 (100.0%, CI 88.6–100%) | 0/30 | 0/25 |
| Full Vero | 30/30 (100.0%, CI 88.6–100%) | 30/30 (modelled) | 0/25 (CI 0.0–13.3%) |

**B. 50-scenario synthetic check** (`python scripts/run_evidence_eval.py`, same adapter as `/v1/simulate`):
25 malicious (10 `upgradeTo`, 10 unlimited approvals, 5 large ETH sends outside the declared intent) and 25 benign declared payments.
Result: blocked 25/25 (95% CI 86.7–100%), false positives 0/25 (95% CI 0.0–13.3%).

**Caveats judges should hear from us:** all scenarios are team-authored and the engine was developed against them, so read
the confidence intervals, not the point rates; the held-out set still needs an outside author; the Full Vero block rate is
modelled from HIGH/CRITICAL verdicts, while on-chain blocking is demonstrated by the Foundry replays in Layer 1.

---

## 5. Evidence Layer 4: Latency & Performance SLA Benchmark

The hackathon specification mandated measured execution latency **$< 150\text{ ms}$**.  
`api-agents/scripts/benchmark_latency.py` sends 100 sequential requests through the full `/v1/simulate` route in-process (FastAPI TestClient, static calldata analysis, no fork). Measured on a MacBook:

```text
=======================================================
      PROJECT VERO: /v1/simulate LATENCY REPORT     
=======================================================
 Total Requests    : 100
 Target Max SLA    : < 150.0 ms
 Average Latency   : 3.111 ms
 Median (p50)      : 3.063 ms
 95th Percentile   : 3.509 ms
 99th Percentile   : 3.662 ms
 Min Latency       : 2.824 ms
 Max Latency       : 3.662 ms
=======================================================
 [PASS] 99th percentile (3.66 ms) is well within target (< 150.0 ms).
```

Fork mode (real `debug_traceCall` on a local Anvil) measured about 2–4 ms per simple transfer in the live Anvil
integration tests (`tests/integration/test_anvil_live.py`); a mainnet fork will be slower and has not been measured yet.

---

## 6. Evidence Layer 5: Dual-Device Checksum Cryptographic Proof

In `api-agents/api_agents/utils/four_word_checksum.py`:
$$\text{Preimage} = \text{chainId}_{32} \,||\, \text{safeAddress}_{20} \,||\, \text{nonce}_{32} \,||\, \text{rawTxHash}_{32} \,||\, \text{intentHash}_{32} \quad (148\text{ bytes})$$
$$\text{Digest} = \text{keccak256}(\text{Preimage})$$

### Entropy Calculation:
* BIP-39 contains $2048 = 2^{11}$ words (11 bits per word).
* 4 words $\implies 4 \times 11 = \mathbf{44\text{ bits of entropy}}$.
* Total combinations: $2^{44} = \mathbf{17,592,186,044,416}$ ($> 17.5\text{ trillion}$).

### Sensitivity Vector (computed with `compute_four_word_checksum`):
* Input A: `chain_id=1, safe=0x5a5a…5a5a, nonce=10, raw_tx_hash=0x1111…1111, intent_hash=0x0` $\implies$ **`menu-avocado-silver-smart`**
* Input B (first byte of the tx hash changed to `0x12`): $\implies$ **`zebra-host-minor-slight`**
* **Result:** a one-byte change gives an unrelated word set. With 44 bits, an attacker needs about $2^{43}$ tries on average to find a different transaction with the same words.

---

## 7. Evidence Layer 6: CERT-In Forensic Receipt & Ed25519 Verification

Indian regulatory rules (CERT-In Directions, April 2022) mandate reporting specified cyber incidents within 6 hours.  
When an exploit is blocked, Vero auto-generates:
1. Machine-readable JSON log (`receipt.json`).
2. A 1-page PDF document (`receipt.pdf`).
3. Cryptographically sealed with pure-Python **Ed25519 (RFC 8032)**.

### Standalone Auditor Verification:
An auditor can verify a receipt offline against the public key it carries. Set `VERO_RECEIPT_SIGNING_SEED` (32 bytes hex) on the server and publish its public key; without it, each server start uses a fresh key:
```bash
python scripts/verify_receipt.py receipt.json
```
**Output:**
```text
============================================================
      PROJECT VERO // ED25519 RECEIPT VERIFIER      
============================================================
 Receipt ID        : VERO-CERTIN-A9B20B73
 Timestamp         : 2026-11-20T18:57:55.454667+00:00
 Decision          : BLOCK (Risk: 95)
 Public Key        : 9782fb8959c53b80568ad36c02e533d9...
 Ed25519 Signature : 2c942f00bbdcf1fa84a3caf6b54947eb...
------------------------------------------------------------
 [VERIFICATION SUCCESS] Signature matches public key and payload.
============================================================
```

---

## 8. Summary of Evidence Files in the Repository

| Evidence Tool | Description | File Location in Repo |
| :--- | :--- | :--- |
| **WazirX Replay CLI** | Runs the payload through the real engine, the Foundry revert test and a signed receipt | [`scripts/demo_wazirx_live.py`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/scripts/demo_wazirx_live.py) |
| **Illustrative Web Cockpit** | Scripted walkthrough (static values); live verdicts are in the Web HUD at `/` | [`demo_cockpit.html`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/demo_cockpit.html) |
| **50-Scenario Synthetic Check** | Real-engine run, computed counts and 95% Wilson intervals | [`scripts/run_evidence_eval.py`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/scripts/run_evidence_eval.py) |
| **Latency Benchmark Harness** | 100-request in-process profiler (measured average 3.1 ms, static mode) | [`api-agents/scripts/benchmark_latency.py`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/api-agents/scripts/benchmark_latency.py) |
| **Exploit Replay Test Suite** | 13 live exploit tests passing on Foundry | [`contracts/test/ExploitReplays.t.sol`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/contracts/test/ExploitReplays.t.sol) |
| **Invariant Fuzzing Suite** | 12,800 random state calls with zero invariant violations | [`contracts/test/VeroInvariants.t.sol`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/contracts/test/VeroInvariants.t.sol) |
| **Ed25519 Receipt Verifier** | Independent auditor verification script | [`api-agents/scripts/verify_receipt.py`](https://github.com/BlueSilverEmperor/Prana-v1/blob/main/api-agents/scripts/verify_receipt.py) |
