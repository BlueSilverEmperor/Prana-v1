# Project Vero: api-agents 🛡️
### Real-Time Transaction Firewall, Forensic Verification & Agent Orchestration
**Track 02: Cybersecurity & Blockchain** | **Problem B1: "Know What You're Signing"**

---

## 📌 Overview
During major crypto breaches (such as the **$230M WazirX multisig hack** in July 2024 and the **$44M CoinDCX theft** in July 2025), attackers compromised the user interface to trick legitimate keyholders into blind signing malicious bytecode disguised as routine transactions.

The `api-agents` package forms the intelligence and firewall tier of **Project Vero**, decoupling transaction simulation from wallet execution to guarantee:
1. **Deterministic <150 ms State-Diff Firewall** (`/v1/simulate` and `/v1/verify-intent`).
2. **44-bit BIP-39 Four-Word Checksum** for cross-device visual verification (Hardware Wallet vs. Mobile/Browser).
3. **Ed25519-Signed CERT-In Aligned Forensic Receipts** (JSON + ReportLab PDF).
4. **Bytecode Vulnerability Hunter** (EVM opcode disassembler + deterministic advisory).
5. **Natural Language to EIP-712 Policy Compiler** (Draft generation only).
6. **Threat Intelligence Triage Agent** (Human-approved ThreatRegistry curation).
7. **FastMCP Server** (`vero_simulate_and_verify` tool).
8. **TypeScript EIP-1193 Guard SDK** (`@vero/guard-sdk`).

---

## 🏗️ Directory Layout

```
api-agents/
├── pyproject.toml
├── README.md
├── api_agents/
│   ├── main.py                     # FastAPI application entrypoint
│   ├── routes/
│   │   └── firewall_api.py         # /v1/simulate, /v1/verify-intent, /v1/audit-receipt
│   ├── models/
│   │   └── schemas.py              # Pydantic v2 schemas for all payloads & state diffs
│   ├── adapters/
│   │   ├── simulator_protocol.py   # Decoupled Protocol for Anvil simulator & 12-rule engine
│   │   └── mock_adapter.py         # High-fidelity MockAdapter for standalone operation
│   ├── utils/
│   │   ├── four_word_checksum.py   # Keccak256 -> BIP-39 4-word digest
│   │   ├── bip39_wordlist.py       # Canonical 2048-word BIP-39 English wordlist
│   │   └── keccak.py               # EVM-compliant Keccak-256 implementation
│   ├── agents/
│   │   ├── bytecode_hunter.py      # EVM opcode scanner (SELFDESTRUCT, DELEGATECALL, tx.origin)
│   │   ├── nl_intent_compiler.py   # NL -> EIP-712 IntentPolicy compiler (DRAFT only)
│   │   └── threat_triage.py        # IoC / Malicious payload triage for ThreatRegistry
│   ├── forensics/
│   │   ├── signer.py               # Pure-Python RFC 8032 Ed25519 keypair & signature engine
│   │   └── cert_in_exporter.py     # CERT-In aligned incident reports (JSON + PDF)
│   ├── webhooks/
│   │   └── dispatcher.py           # HMAC-SHA256 signed alert dispatcher with retries
│   └── mcp/
│       └── server.py               # FastMCP tool server (vero_simulate_and_verify)
├── sdk/
│   ├── package.json
│   ├── tsconfig.json
│   ├── veroGuardSdk.ts             # TypeScript EIP-1193 wrapper intercepting transactions
│   └── testSdk.mjs                 # Node.js SDK test runner
├── scripts/
│   ├── benchmark_latency.py        # Automated latency measurement harness (<150 ms)
│   └── verify_receipt.py           # Standalone Ed25519 receipt verification script
└── tests/                          # Comprehensive unit & integration tests (30 tests)
```

---

## ⚡ 8 Authoritative Capabilities

### 1. High-Performance Firewall API (#43)
- **`POST /v1/simulate`:** Simulates state diffs on an EVM state fork, checks 12 deterministic rules, calculates the 4-word checksum, and outputs `ALLOW` | `WARN` | `BLOCK` with deterministic plain-English warnings.
  - **Invariant:** **Zero LLMs on this path.** Operates with an average latency of ~9.5 ms (p99 well below the 150 ms SLA).
- **`POST /v1/verify-intent`:** Compares executed bytecode calldata against declared user intent to catch WazirX-class recipient or approval spoofing.
- **`POST /v1/audit-receipt`:** Generates cryptographically signed forensic receipts.

### 2. Four-Word BIP-39 Checksum (`utils/four_word_checksum.py`)
Computes `keccak256(chainId || safeAddress || nonce || rawTxHash || intentHash)` and slices the top 44 bits into 4 standard BIP-39 words.
> **Security & Design Note on Checksum Entropy:**  
> The 4-word checksum provides $4 \times 11 = 44\text{ bits}$ of entropy ($\approx 1.76 \times 10^{13}$ states). This is explicitly designed for **human visual verification across disjoint devices** (e.g. verifying that a hardware wallet display matches the browser or mobile terminal). It is **not** mathematically collision-proof against an offline attacker conducting a targeted birthday attack ($2^{22}$ work). In production, full payload integrity is guaranteed by the underlying 256-bit Keccak digest; the words exist strictly for human confirmation. Word count (`DEFAULT_WORD_COUNT = 4`) and separator (`DEFAULT_WORD_SEPARATOR = "-"`) are exposed constants to ensure easy synchronization with the hardware/firmware subsystem.

### 3. CERT-In Aligned Forensic Receipts (#20)
- Complies with India CERT-In incident reporting guidelines (April 2022).
- Exports dual formats:
  - Machine-readable JSON.
  - Court-admissible 1-page PDF audit document generated via ReportLab.
- **Cryptographic Separation:** Forensic receipts are signed with **Ed25519 (RFC 8032)**. (HMAC is used exclusively for webhooks).
- *Disclaimer:* Clearly labeled as "CERT-In Incident Reporting Aligned Specification" (structured around CERT-In requirement fields); it does not claim to be an official government schema.

### 4. Bytecode Vulnerability Hunter (#39)
- Static EVM opcode scanner disassembles bytecode and detects:
  - `SELFDESTRUCT` (0xFF) rug-pull opcodes.
  - `DELEGATECALL` (0xF4) in loops or outside standard ERC-1967 proxy slots.
  - `tx.origin` (0x32) authentication checks vulnerable to phishing.
- Optional LLM advisory layer with a **guaranteed deterministic fallback** ensuring zero dependency on cloud LLM availability.

### 5. Natural Language to EIP-712 Compiler (#40)
- Parses natural language policies (e.g. *"Allow up to 5 ETH to Uniswap per week, block infinite approvals"*).
- Compiles into typed EIP-712 `IntentPolicy` schemas with domain separators and struct hashes.
- **Strict Invariant:** All compiled policies are marked strictly as `status: "DRAFT"`. They cannot be applied on-chain without human analyst review and cryptographic keyholder signatures.

### 6. Threat-Intel Triage Agent (#41)
- Triages observed malicious payloads and suspicious addresses.
- Auto-drafts structured records for the `ThreatRegistry` with indicator type, threat category, and remediation checklist.
- **Strict Invariant:** Marked as `status: "DRAFT_PENDING_HUMAN_APPROVAL"`.

### 7. FastMCP Server (#42)
- Exposes `vero_simulate_and_verify` as a standard Model Context Protocol (MCP) tool for external AI agents and IDEs.

### 8. TypeScript EIP-1193 Guard SDK (`@vero/guard-sdk`) (#45)
- Standard provider wrapper wrapping MetaMask, Safe, or browser wallets.
- Intercepts `eth_sendTransaction` and `eth_signTransaction` to query the Vero Firewall before broadcasting.
- Rejects dangerous transactions with `VeroSecurityError` on `BLOCK`.

---

## 🚀 Setup & Execution Instructions

### Prerequisites
- Python 3.10+
- Node.js v18+ (for TypeScript SDK)

### 1. Running the Test Suite
All 30 unit, API, agent, forensics, and end-to-end integration tests execute cleanly in < 2 seconds:
```powershell
cd api-agents
$env:PYTHONPATH="."
python -m unittest discover -s tests -v
```

### 2. Running the Latency Benchmark
To measure end-to-end simulation latency against the <150 ms SLA:
```powershell
python scripts/benchmark_latency.py
```

### 3. Starting the Firewall API Server
```powershell
uvicorn api_agents.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger docs available at: `http://localhost:8000/docs`

### 4. Verifying a Signed Receipt (Standalone Auditor CLI)
```powershell
python scripts/verify_receipt.py <path_to_receipt.json>
```

### 5. Running the TypeScript SDK Tests
```powershell
cd sdk
node testSdk.mjs
```

---

## 🛡️ Limitations & Threat Boundaries
1. **Dynamic Code Injection:** Static EVM opcode analysis cannot predict code executed via unverified off-chain zero-knowledge provers or unconstrained runtime `CREATE2` salts until bytecode is deployed.
2. **Reorg Scenarios:** Simulation assumes state fork consistency; deep chain reorgs on low-hashrate L2s could alter transaction dependencies.
3. **Draft Guardrails:** NL-generated policies and threat triage records are explicitly non-executable drafts to protect against prompt injection and automated registry poisoning.

---

## 🤖 AI Tools Used & Transparency Disclosure
In accordance with Rule 8 of The Big Hack 2.0 ("AI tools and third-party services may be used. Teams must be transparent about their use and explain their own contribution"):
- **AI Tools Used:** Claude / Google Antigravity AI coding assistant was utilized for scaffolding boilerplate test fixtures, verifying BIP-39 wordlist mappings, and drafting ReportLab canvas styling.
- **Human Team Contribution:** Architectural design, threat models, EVM opcode parsing algorithms, Keccak-256 / Ed25519 cryptographic implementations, protocol interfaces, 12-rule deterministic evaluation logic, and latency optimization were designed and verified by the team. No decisions or simulations rely on hosted LLM APIs.
