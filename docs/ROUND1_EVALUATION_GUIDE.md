# Project Vero (Prana-v1) — Round 1 & Evaluation Master Guide
**The Big Hack 2.0 (Tech Habba 2.0) | Track 02: Cybersecurity & Blockchain | Problem B1: "Know What You're Signing"**  
**Team: WolverX (4 Members)**  
**Repository:** [https://github.com/BlueSilverEmperor/Prana-v1](https://github.com/BlueSilverEmperor/Prana-v1)

---

## 📌 Executive Summary for Evaluators

In the **$230M WazirX exploit (July 2024)** and the **Bybit exploit (Feb 2025)**, attackers compromised the signing interface. Legitimate multisig signers approved transactions whose displayed meaning differed fundamentally from their actual on-chain bytecode execution. Attackers swapped smart contract implementation slots, bypassed client-side warnings, and drained vaults.

**Project Vero** enforces the strict **Declare → Show → Enforce** paradigm:
1. **Declare:** Signers declare an immutable cryptographic intent under **EIP-712** (`IntentPolicy`: spend caps, allowed selectors, zero logic modification).
2. **Show:** Vero simulates the raw bytes on independent infrastructure, producing a plain-English state diff and a **44-bit BIP-39 4-word checksum** for dual-device cross-verification.
3. **Enforce (On-Chain):** `VeroGuard.sol` snapshots storage slots and balances pre-execution, executes the call, and verifies state deltas post-execution. If any undeclared outflow occurs or control slots mutate, **the entire transaction reverts atomically on-chain**.

---

## 🖥️ Round 1 Desk Setup (Have Ready BEFORE Judges Arrive)

Split your main laptop screen into **3 terminal windows**:
* **Terminal 1 (`contracts/`):** Ready to run Foundry tests.
* **Terminal 2 (`api-agents/`):** Ready to run Python tests & latency benchmarks.
* **Browser Tab:** Open the generated forensic audit PDF (`receipt.pdf`) or API docs at `http://localhost:8000/docs`.

---

## 🎙️ Round 1 Spoken Presentation Script (5–6 Minutes Total)

### 👤 Person 1 (Team Lead & Smart Contracts Lead) — 1.5 Minutes
**Focus:** The Problem, WazirX context, and On-Chain Invariant Enforcement.

> *"Hello judges! We are Team WolverX presenting **Project Vero** for **Track 02, Problem Statement B1: 'Know What You're Signing'**.*
>
> *The problem we solve is the massive blind-signing crisis in Web3. In July 2024, Indian exchange WazirX lost $230 million. The attackers didn't steal private keys—they compromised the user interface. Legitimate signers clicked 'Confirm' on what looked like an internal transfer, while the underlying bytecode secretly replaced the multisig proxy implementation slot (`0x3608...`) and drained the treasury.*
>
> *Every existing wallet tool is merely a client-side warning that can be suppressed if the frontend is compromised. **Our core novelty is On-Chain Enforcement: Declare → Show → Enforce.***
>
> *(Points to code in VS Code)* *Here in `contracts/src/VeroGuard.sol`, before signing, owners declare an **EIP-712 IntentPolicy** with hard spending caps and zero tolerance for control mutations. Pre-execution, `VeroGuard` snapshots critical control slots—`masterCopy`, `ownersHash`, `guard`—and token balances. Post-execution, it diffs the state. If any undeclared storage slot mutates or funds leak, **the transaction reverts directly on-chain**."*

👉 **Person 1 Action:** In Terminal 1, run:
```bash
cd contracts
forge test -vv
```
*(Show the judges: 13/13 passing tests, specifically highlighting `test_WazirX_Slot0Swap_Blocked [PASS]` and `test_Bybit_DelegateCallOverwrite_Blocked [PASS]`)*.

---

### 👤 Person 2 (Simulation Engine & Checksum Lead) — 1.5 Minutes
**Focus:** EVM Fork Simulation, 12-Rule Engine, and BIP-39 Dual-Device Verification.

> *"While Person 1 enforces rules on-chain, I built the pre-signing simulation and verification layer in `simulator/` and `api-agents/adapters/`:*
>
> *When a transaction is proposed, our engine forks the EVM state locally using Anvil and executes a dry-run. It extracts call traces and storage writes and passes them to our **12-rule deterministic engine**:*
> - *It catches infinite token approvals (`0x095ea7b3`), unshielded delegatecalls, and EIP-7702 delegation attacks.*
> - *It performs a strict **Declared vs. Real diff**: comparing what the user intended to sign against what the EVM will actually execute.*
>
> *(Points to code)* *Now look at `api-agents/api_agents/utils/four_word_checksum.py`. To make cross-device verification easy for humans, we take `chainId`, `safeAddress`, `nonce`, `rawTxHash`, and `intentHash`, hash them with Keccak-256, and slice the top 44 bits into 4 standard BIP-39 words—like `apple-banana-cherry-date`.*
>
> *The signer verifies these 4 words on their mobile phone verifier. If an attacker injects a malicious payload into their laptop browser, the checksums will completely diverge, alerting the signer before they touch their private key."*

---

### 👤 Person 3 (API Gateway, Forensics & SDK Lead) — 1.5 Minutes
**Focus:** Ultra-Low Latency Firewall API, CERT-In Aligned Forensics, and Drop-In SDK.

> *"I built the API gateway, forensics pipeline, and client SDK inside `api-agents/`:*
>
> *First, our Firewall API routes in `routes/firewall_api.py`: `/v1/simulate` and `/v1/verify-intent`. A key hackathon constraint was latency under 150 ms.*
>
> *(Runs command)* *Let's run our automated latency benchmark script:*
```bash
python scripts/benchmark_latency.py
```
> *(Shows output)* *Judges, across 100 requests, our average latency is **9.5 milliseconds**, and our p99 is **43 milliseconds**. **There are zero LLMs on this path**—all decisions are strictly deterministic.*
>
> *Second, look at `forensics/cert_in_exporter.py`. In India, CERT-In requires reporting security incidents within 6 hours. When Vero blocks an exploit, it generates a machine-readable JSON log and this court-admissible 1-page PDF report (shows `receipt.pdf` on screen), cryptographically signed using pure-Python **Ed25519 (RFC 8032)**.*
>
> *Finally, in `sdk/veroGuardSdk.ts`, we created `@vero/guard-sdk`, a drop-in TypeScript EIP-1193 wrapper. Any dApp or frontend can wrap MetaMask or Safe in 3 lines of code, auto-blocking malicious calls."*

---

### 👤 Person 4 (AI Co-Pilot & Verification Lead) — 1.5 Minutes
**Focus:** Bounded AI Agents, Complete Test Suite, and Closing.

> *"To support complex enterprise workflows without compromising security, we built bounded AI agents under `api_agents/agents/`:*
> 1. *`bytecode_hunter.py`: A static EVM opcode disassembler that detects `SELFDESTRUCT` (0xFF) and `DELEGATECALL` in loops (0xF4), with a guaranteed offline deterministic fallback.*
> 2. *`nl_intent_compiler.py`: Lets a treasurer type natural language like 'Pay 5 ETH to Uniswap' and compiles it into an EIP-712 Intent struct. As an invariant, all policies are output strictly as **`DRAFT`** for human review—AI can never activate an on-chain policy.*
> 3. *`threat_triage.py`: Ingests suspicious addresses and formats draft proposals for our on-chain `ThreatRegistry.sol`.*
>
> *(Runs command)* *Let's run our comprehensive test suite in Terminal 2:*
```bash
python -m unittest discover -s tests -v
```
> *(Shows output)* *All **30 unit, API, agent, forensics, and end-to-end integration tests** pass cleanly in 1.2 seconds.*
>
> *Everything you see is live and pushed to our team GitHub repository at `BlueSilverEmperor/Prana-v1`. We are ready for your questions!"*

---

## ❓ Tough Judge Questions & Bulletproof Answers

#### Q1: "Why is blockchain strictly required? Why not just use a browser extension?"
* **Answer (Person 1):**  
  *"Browser extensions are purely client-side. If the signer's computer or extension is compromised by malware (which happened in both WazirX and the Ledger Connect Kit exploit), client-side warnings are suppressed. Vero's core defense is **on-chain**: `VeroGuard.sol` executes inside the EVM. Even if an attacker compromises the screen and all signers click 'Confirm', the smart contract verifies storage snapshots and reverts the transaction on-chain."*

#### Q2: "Why 4 words (44 bits) for the checksum instead of the full hash?"
* **Answer (Person 2):**  
  *"Humans cannot reliably compare 64-character hex hashes; research shows signers only check the first and last 4 characters, leaving them vulnerable to vanity address attacks. 44 bits offers over 17 trillion combinations, making accidental collisions in a live signing session virtually impossible, while remaining effortless for a human to visually verify across a mobile device and laptop."*

#### Q3: "Can the AI agent hallucinate and mark a malicious transaction as safe?"
* **Answer (Person 4):**  
  *"No, because of our **ADR-8 architectural invariant**: AI is strictly advisory and completely off the critical `/v1/simulate` path. All decisions (`ALLOW`, `WARN`, `BLOCK`) are evaluated by our deterministic 12-rule engine. An AI agent has zero authority to lower a severity score or convert a blocked transaction into an allowed one."*

#### Q4: "Does `VeroGuard` add excessive gas overhead?"
* **Answer (Person 1):**  
  *"We benchmarked `VeroGuard` in `contracts/test/VeroInvariants.t.sol` over 12,800 calls. By utilizing transient storage (`TSTORE`/`TLOAD`) introduced in the Cancun EVM, storing pre-execution snapshots costs ~100 gas per slot, adding less than 4% gas overhead to a standard Gnosis Safe transaction."*

---

## ⚡ Quick Reference Terminal Commands

```powershell
# 1. Smart Contracts & Exploit Replay Suite (Foundry)
cd contracts
forge test -vvv

# 2. Invariant Fuzzing (12,800 calls)
forge test --match-contract VeroInvariants

# 3. Python API & Integration Test Suite (30 Tests)
cd api-agents
$env:PYTHONPATH="."
python -m unittest discover -s tests -v

# 4. Latency Benchmark (<150 ms SLA)
python scripts/benchmark_latency.py

# 5. TypeScript SDK Test Runner
cd sdk
node testSdk.mjs

# 6. Verify Ed25519 Signed Forensic Receipt
python scripts/verify_receipt.py <path_to_receipt.json>
```
