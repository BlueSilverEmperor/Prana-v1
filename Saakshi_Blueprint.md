# Saakshi Blueprint: See Before You Sign

**Event:** The Big Hack 2.0, Cybersecurity and blockchain track, problem B1 "Know what you're signing"
**Team:** WolverX (4 people), 24 hours
**Mode:** direct mode (no git remote assumed; branches optional)
**Version:** 3.1. Merges the 45-feature specification (`Saakshi_45Feature_Agentic_API_Architecture_v6`) into the v2 architecture, with architect review notes (section 13)
**Objective:** a working prototype that makes it very hard for a person, an organisation or an AI agent to sign a transaction whose real effect they do not understand, with on-chain enforcement, open developer APIs and measured evidence.

---

## 1. Problem framing

Signers approve raw bytes or a summary produced by an interface the attacker may control. In the WazirX (July 2024) and Bybit (February 2025) incidents, multisig signers approved transactions whose displayed meaning differed from their effect: the wallet's logic was replaced and funds were drained. AI agents that trade or pay on a user's behalf now face the same risk through prompt injection.

**Root cause:** the signature is bound to bytes, and the meaning of those bytes is supplied by an untrusted screen or an untrusted agent.

**Our answer, Declare → Show → Enforce:**

1. **Declare:** the signer (person, treasury or AI agent) states what they intend: send at most X of token T to address A, approve at most Y to spender S, change nothing else.
2. **Show:** Saakshi simulates the exact bytes on independent infrastructure and shows any difference between the declaration and the real effect, deterministically, in plain language.
3. **Enforce:** the wallet's guard enforces the declaration on-chain. If the executed effect goes beyond what was declared and signed, the whole transaction reverts.

The declaration always comes from the signer, never from the simulation. AI agents may *draft* a declaration, but a human reviews and signs it, and AI never decides a verdict.

## 2. Threat model

| Actor | Assumed capability | In scope |
|---|---|---|
| Attacker controlling the signing interface or dapp | Shows any label, builds any calldata, swaps the transaction before signing | Yes |
| Attacker injecting scripts into the signer's web page | Tampers with form fields or displayed values | Yes (DOM canary, phone verifier) |
| Attacker deploying malicious contracts | Phishing spenders, fake tokens, malicious implementations, drainers, lookalike addresses | Yes |
| Attacker compromising one signer's laptop | Fakes that signer's screen and the data it shows | Yes (phone verifier) |
| Prompt-injected AI agent controlling a wallet | Proposes any transaction | Yes (Agent Guard Mode: the agent's wallet is bound to on-chain intent caps) |
| Attacker holding a threshold of private keys | Can sign anything | No: stated limitation |
| Compromised chain or RPC for every device | Lies about state everywhere | No: phone verifier uses an independent node, stated assumption |
| Off-chain order signatures (EIP-1271 on the multisig, Seaport orders) | Authorise transfers without a transaction | No for the multisig, which does not implement EIP-1271. Retail permit prompts are decoded and explained (feature 18) but cannot be enforced on-chain |
| Off-chain phishing (seed phrase theft) | No transaction involved | No: listed in failure analysis |

**Security goals:**

- G1: before signing, every signer sees the real effect of the exact bytes.
- G2: a signature only authorises the effect the signer declared.
- G3: if the executed effect exceeds the declared effect, the transaction reverts on-chain.
- G4: wallet control (logic, owners, threshold, guard, modules, asset list, emergency vault) cannot change without a public 24-hour delay that any one signer can veto.
- G5: a signer can confirm on a second device that the bytes they sign are the bytes that were explained.
- G6: no AI output can turn a blocked transaction into an allowed one.

## 3. Architecture (five tiers)

```
Tier 1  Clients:   Next.js signer HUD + @saakshi/guard-sdk (EIP-1193 wrapper) | Phone verifier | Judge sandbox
                         | REST / JSON-RPC / MCP                                   | independent check
Tier 2  Gateway:   /v1 API, webhooks (HMAC), MCP server, rate limits, API keys
Tier 3  Engine:    Simulator (Anvil A) -> Decoder -> 12-rule + behavioural engine -> Declared-vs-real diff
                   -> Deterministic plain-language renderer -> Fingerprint / calldata digest -> Forensic receipt
                   Engine B (Anvil B, forked from A at a pinned block) serves the phone verifier only
        Agents:    Bounded, advisory, read-only: NL-to-intent compiler, bytecode hunter, threat-intel triage
Tier 4  Chain:     GuardedMultisig (ERC-1967 proxy) -> MultisigLogic -> SaakshiGuard, GovernanceTimelock,
                   ThreatRegistry, MultiSend, EmergencyVault, AgentPolicy
Tier 5  Evidence:  Exploit replays, 55-scenario harness, baselines, gas profile, comprehension study
```

### Architecture decision records

**ADR-1: Custom minimal multisig behind an ERC-1967 proxy.**
`GuardedMultisig` is an ERC-1967 proxy; `MultisigLogic` (about 300 lines) holds owners, threshold, nonce, guard, registered asset list, module list, `CALL`/`DELEGATECALL`, EIP-712 signatures and guard hooks. Solidity `^0.8.24` with `evm_version = "cancun"` (transient storage). The guard design follows Safe's transaction-guard pattern and can be ported later; say so in the pitch.

**ADR-2: Control state is read by the executing frame, not by calls back into the wallet.**
Inside `execTransaction`, the running logic frame reads with `sload` the implementation slot, codehash, owners hash, threshold, guard, modules hash, asset-list hash, emergency-vault address and nonce, before and after the inner call. It caches the guard address in memory and passes both snapshots to that guard's post-check. The pre-check bans `DELEGATECALL` except to the allowlisted `MultiSend`, and rejects `to == address(this)`.

**ADR-3: Effect-bound signatures with a declared `Intent`.**
Signers sign `SafeTx(to, value, data, operation, nonce, intentHash)` under EIP-712, with `chainId` and the wallet address in the domain separator (feature 31).

```
struct Payment   { address token; address to; uint256 max; }      // token = address(0) for ETH
struct Allowance { address token; address spender; uint256 max; }
struct Intent {
  Payment[]   payments;        // max 4: per-recipient caps
  Allowance[] allowances;      // max 4: approvals the signer agrees to
  bool        controlChange;   // only true for timelocked governance actions
  uint256     maxGasFeeWei;    // gas-fee ceiling (feature 28)
  uint64      deadline;        // TOCTOU defence (feature 14)
}
```

Post-check rules, for every registered asset plus ETH:

1. Each listed recipient's increase is at most its `max`.
2. The wallet's total outflow is at most the sum of `max` over that asset's payments.
3. Outflow to unlisted addresses is 0, except for assets flagged fee-on-transfer through the timelock.
4. Every declared or decoded approval ends at or below its `max`; undeclared approvals end at 0.
5. Control-state snapshot unchanged unless `controlChange` is true and the caller is the timelock.

**ADR-4: Approvals and modules are checked call by call, including inside batches.**
The pre-check decodes the top-level call and every `MultiSend` sub-call: `approve`, `increaseAllowance`, `setApprovalForAll`, `permit` (checked against `Intent.allowances`), `enableModule` (only through the timelock, feature 13), and registry hits.

**ADR-5: Simulation by snapshot and code swap.**
`evm_snapshot` on the engine's own Anvil; swap in `SimHarness` with `anvil_setCode` (same storage layout, no signatures, no guard); impersonate a funded EOA; send; trace with `debug_traceTransaction` (`callTracer`, `withLog: true`); read post-state and `eth_getCode`; `evm_revert`; take a fresh snapshot. A mutex serialises simulations per Anvil. Target latency under 150 ms for simple transfers (p50), reported honestly for complex ones.

**ADR-6: Independent second device bound to the signed bytes.**
The QR carries the `SafeTx` fields and the declared `Intent`. The phone calls engine B on Anvil B (a separate process forked from A at a pinned block), recomputes the hash, re-simulates the exact bytes and shows the real effect plus 4 BIP-39 words from `keccak(chainId, wallet, nonce, safeTxHash, intentHash)`. The laptop signing step shows words computed from the same inputs.

**ADR-7: Threat registry, timelock and emergency controls.**
- `ThreatRegistry` entries are added by a curator multisig through a timelock (feature 16); community attestations (feature 38) are submitted as *proposals* that a curator must approve, so attackers cannot poison the registry.
- `GovernanceTimelock`: owners, threshold, guard, modules, asset list, emergency vault, fee tolerances; 24-hour delay; any single owner can veto (feature 15).
- `emergencyPause()` (feature 27): any single owner can freeze outgoing transfers; unfreezing needs the full threshold.
- Three-strike lock (feature 37): after 3 guard reverts within 10 minutes, normal execution locks automatically. The only action then allowed is a sweep to the **pre-registered** emergency vault, which itself requires the full threshold. The vault address can only change through the timelock. This prevents an attacker from forcing reverts and then redirecting the sweep.

**ADR-8: Deterministic core; AI is advisory only.**
Decoding, the 12 rules, the declared-vs-real diff, warning templates and the guard are 100% deterministic. AI agents (Module H) may draft, investigate and summarise, but:
- their output is shown in a separate, labelled "Advisory" panel;
- they cannot lower a severity or change a verdict;
- the NL-to-intent compiler produces JSON validated against the `Intent` zod schema, rendered back as plain text, and must be reviewed and signed by a human;
- agents run read-only, with no keys and no transaction-sending tools.

**ADR-9: TypeScript monorepo with shared types and frozen EIP-712 vectors.**
npm workspaces: `contracts`, `engine`, `agents`, `api`, `sdk`, `mcp`, `web`, `eval`, `shared`. Typehashes and one hashed example are frozen at hour 2 and tested in Foundry and vitest.

**ADR-10: Open APIs, webhooks, SDK and MCP share one code path.**
`/v1/simulate`, `/v1/verify-intent`, the MCP tool `saakshi_simulate_and_verify` and the SDK all call the same engine function, so every channel returns the same verdict. Webhooks are signed with HMAC-SHA256 and include a timestamp to prevent replay. The API requires an API key and is rate-limited.

**ADR-11: Session sub-intents and Agent Guard Mode are bounded, pre-approved policies.**
A `SessionPolicy` (feature 10) or `AgentPolicy` (feature 35) is itself created through the full threshold plus timelock, and stores: allowed recipients, per-transaction cap, rolling 24-hour cap, allowed tokens, expiry. Within it, a designated operator key or AI-agent key can execute without collecting all signatures, but the guard's post-check still applies every rule. The rolling cap is tracked on-chain.

**ADR-12: Standards claims must be verified before the pitch.**
EIP-712, EIP-1193, EIP-2612, Permit2, EIP-7702 and ERC-7730 are established. **ERC-8213 and ERC-8176, as named in the 45-feature spec, must be checked against the official EIPs repository before they appear on slides.** If they cannot be confirmed, present the features generically ("calldata digest", "signed threat attestations").

## 4. Feature catalogue (45 features)

Priority: **P0** = demo-critical, must work by hour 14. **P1** = build by hour 18. **P2** = only if ahead of schedule. Changes from the v6 spec are marked ▲ (priority raised) or ▼ (lowered or reduced), with the reason in section 13.

### Module A: Pre-signing truth and deterministic simulation

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 01 | Exact-bytes fork simulation (call frames, events, code changes, storage writes) | P0 | 1.5 | P2 | 7 |
| 02 | Deterministic 12-rule risk engine (R1 approvals, R2 permits, R3 code/slot swap, R4 unknown delegatecall, R5 owner/threshold, R6 guard removal, R7 `enableModule`, R8 EIP-7702 delegation, R9 undeclared recipient, R10 outflow cap, R11 lookalike token, R12 registry hit) | P0 | 2.0 | P2 | 8 |
| 03 | Declared-vs-real diff comparator | P0 | 0.5 | P2 | 8 |
| 04 | Hallucination-free plain-language explanations | P0 | 1.0 | P2 | 9 |
| 05 | Interactive fund-flow diagram (source → intermediaries → recipients, red for undeclared) | P1 | 1.0 | P3 | 11 |
| 06 | Bytecode and proxy-slot diff inspector (`eth_getCode`, implementation slot, risky opcodes) | P0 | 0.5 | P2 | 7 |

### Module B: Collaborative multisig and out-of-band verification

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 07 | EIP-712 typed intent signing | P0 | 1.0 | P1 | 2 |
| 08 | Side-by-side multisig signer HUD (3 of 5) | P0 | 2.0 | P3 | 11 |
| 09 | Independent QR phone verifier with 4-word checksum | P1 | 1.5 | P2 + P3 | 9, 12 |
| 10 | Session sub-intents (daily-ops fast lane) | P1 | 1.0 | P1 | 5 |

### Module C: On-chain guard and enforcement

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 11 | Guard pre-check (signatures, deadline, nonce, registry, self-call, delegatecall, MultiSend) | P0 | 1.5 | P1 | 3 |
| 12 | Multi-asset vault snapshot post-check | P0 | 1.5 | P1 | 4 |
| 13 | Module firewall on-chain; EIP-7702 delegation flagged by the engine for retail EOAs | P0 | 0.5 | P1 + P2 | 3, 8 |
| 14 | Intent expiry and state-drift lock (TOCTOU) | P0 | 0.25 | P1 | 2 |
| 15 | 24-hour governance timelock with single-signer veto | P1 | 1.0 | P1 | 4 |
| 16 | Timelocked on-chain threat registry | P0 | 0.25 | P1 | 3 |

### Module D: Retail wallet protection

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 17 | Automatic unlimited-approval capping | P1 | 0.75 | P2 + P3 | 9, 12 |
| 18 | Gasless permit decoder (EIP-2612, Permit2) | P1 | 0.75 | P2 | 8 |
| 19 | Open-approval scanner and one-click revoke | P2 | 0.75 | P3 | 12 |

### Module E: Forensics and demo tooling

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 20 | Signed forensic audit receipt (JSON and PDF) for CERT-In reporting | P1 | 0.5 | P4 | 15 |
| 21 | Spoofed-UI vs reality split-screen demo toggle | P0 | 0.75 | P3 | 12 |

### Module F: Validation and benchmarking

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 22 | Exploit replay tests (WazirX code swap, Bybit delegatecall, hidden batch drain, Permit2 phishing) | P0 | 1.0 | P1 | 6 |
| 23 | 55-scenario evaluation harness (40 main, 10 held-out, 5 public) | ▲ P0 | 1.5 | P4 | 15 |
| 24 | Metrics and four baselines with 95% confidence intervals | ▲ P0 | 0.5 | P4 | 15 |
| 25 | Comprehension micro-study (in-app quiz, raw vs Saakshi) | ▲ P1 | 0.5 | P3 + P4 | 12, 15 |

### Module G: Active defence, standards and accessibility

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 26 | Behavioural anomaly scoring (large share of vault, new contract, first-time recipient) | P1 | 0.5 | P2 | 8 |
| 27 | Emergency pause (one signer freezes, threshold unfreezes) | P1 | 0.5 | P1 | 5 |
| 28 | Gas-fee ceiling in the intent ▼ (renamed from "EIP-4337 paymaster protection"; the multisig is not a 4337 account) | P1 | 0.5 | P1 | 3 |
| 29 | Browser DOM integrity canary (forces phone verification) | P1 | 0.5 | P3 | 11 |
| 30 | Voice readout of warnings | P2 | 0.25 | P3 | 11 |
| 31 | Cross-chain replay and wrong-network shield (`chainId` in domain and checksum) | P0 | 0.25 | P1 + P2 | 2, 9 |
| 32 | Judge "what-if" sandbox (paste calldata or pick 6 presets) | ▲ P1 | 0.5 | P3 | 12 |
| 33 | Address-poisoning shield (lookalike first-4/last-4 characters) | P1 | 0.35 | P2 | 8 |
| 34 | ERC-7730 clear-signing descriptors and calldata digest on both devices (see ADR-12) | P1 | 0.5 | P2 | 9 |
| 35 | Agent Guard Mode (AI-agent wallet bound to on-chain policy) | P1 | 0.5 | P1 | 5 |
| 36 | Bridge message validator ▼ (one protocol: OP Stack standard bridge; others are roadmap) | ▼ P2 | 0.5 | P2 | 8 |
| 37 | Three-strike lock and sweep to pre-registered vault (see ADR-7) | ▼ P2 | 0.5 | P1 | 5 |
| 38 | Community threat attestations, curator-approved | P2 | 0.4 | P1 | 5 |

### Module H: Bounded agentic AI co-pilot (advisory only, ADR-8)

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 39 | Bytecode decompiler and vulnerability-hunter agent (local model or API; advisory dossier) | P1 | 1.0 | P4 | 14 |
| 40 | Natural-language-to-intent co-pilot (plain English → validated `Intent` JSON for human review) | P1 | 0.75 | P4 | 14 |
| 41 | Threat-intelligence triage agent (proposes registry entries and draft rules for curators) | P2 | 0.75 | P4 | 14 |
| 42 | MCP security server (`saakshi_simulate_and_verify`) for external AI agents | P1 | 0.75 | P2 | 10 |

### Module I: Open developer APIs and SDK

| # | Feature | Pri | Hrs | Owner | Step |
|---|---|---|---|---|---|
| 43 | REST and JSON-RPC firewall API (`/v1/simulate`, `/v1/verify-intent`) | P1 | 0.75 | P2 | 9 |
| 44 | Signed alert webhooks (Slack, Telegram, SIEM) | P2 | 0.5 | P2 | 10 |
| 45 | Drop-in TypeScript SDK (`@saakshi/guard-sdk`, EIP-1193 wrapper) | P1 | 0.75 | P3 | 13 |

**Effort:** the spec's estimates total 35 hours (P0 14.5, P1 14.85, P2 5.65). Realistic effort is roughly 1.5 to 2 times that, about 55 to 70 person-hours, against about 72 productive person-hours for 4 people. The plan therefore fits only with the P2 cut line enforced at hour 14.

## 5. Repository layout

```
saakshi/
  package.json                npm workspaces
  shared/                     types.ts, intent.schema.ts (zod), eip712.ts, vectors.json, abis/
  contracts/
    foundry.toml              solc 0.8.24+, evm_version = "cancun"
    src/  GuardedMultisig.sol (proxy)  MultisigLogic.sol  SaakshiGuard.sol  IntentLib.sol
          GovernanceTimelock.sol  ThreatRegistry.sol  MultiSend.sol  SessionPolicy.sol
          AgentPolicy.sol  EmergencyVault.sol  SimHarness.sol
    src/fixtures/  MockUSDT.sol MockWBTC.sol FakeToken.sol MaliciousLogic.sol StorageRewriter.sol
                   Drainer.sol PhishingSpender.sol Router.sol Permit2Mock.sol
    test/  Wallet Guard Intent Approvals Modules Timelock Emergency Session Agent
           Replays Invariants Vectors (.t.sol)
    script/ Deploy.s.sol      writes deployments.json
  engine/   simulate decode rules/ behaviour diff explain/ fingerprint digest
            permit bridge cap receipt (.ts)
  agents/   nl-intent.ts  bytecode-hunter.ts  threat-triage.ts  (read-only tools, schema-validated output)
  api/      server.ts (/v1), webhooks.ts, auth.ts
  mcp/      server.ts (saakshi_simulate_and_verify)
  sdk/      @saakshi/guard-sdk (EIP-1193 wrapper)
  web/      app/ signer/ dashboard/ demo/ verify/ retail/ sandbox/ quiz/
  eval/     scenarios/{main,heldout,public}/  run.ts  stats.ts  results/
  scripts/  dev.sh  reset-demo.sh  spike.sh
  docs/     architecture.md  demo-script.md
```

## 6. Interfaces (frozen at hour 2)

**Types (shared/types.ts):**

```ts
type Effect =
  | { kind: 'transfer'; token: Address; from: Address; to: Address; amount: bigint }
  | { kind: 'ethTransfer'; to: Address; amount: bigint }
  | { kind: 'approval'; token: Address; spender: Address; amount: bigint; unlimited: boolean }
  | { kind: 'approvalForAll'; token: Address; operator: Address; approved: boolean }
  | { kind: 'permit'; token: Address; spender: Address; amount: bigint; deadline: bigint }
  | { kind: 'logicChange'; from: Address; to: Address; codehashChanged: boolean }
  | { kind: 'ownerChange'; added: Address[]; removed: Address[]; threshold?: number }
  | { kind: 'guardChange'; from: Address; to: Address }
  | { kind: 'moduleEnabled'; module: Address }
  | { kind: 'delegatecall'; target: Address; allowlisted: boolean }
  | { kind: 'eip7702Delegation'; to: Address; chainId: number }
  | { kind: 'bridge'; protocol: 'op-stack'; fromChain: number; toChain: number; token: Address; amount: bigint }
  | { kind: 'unknownControlWrite'; slot: Hex };

type Finding  = { rule: string; severity: 0|1|2|3; effectIndex?: number; evidence: string };
type Advisory = { agent: string; summary: string; confidence: 'low'|'medium'|'high' };  // never changes verdict
type Verdict  = { effects: Effect[]; findings: Finding[]; exceedsIntent: boolean;
                  explanation: string[]; words: string[]; digest: Hex;
                  flow: FlowEdge[]; advisories: Advisory[]; latencyMs: number };
```

**API (v1, API key required):**

| Method | Path | Body → result |
|---|---|---|
| POST | `/v1/declare` | `{text, lang}` → draft `Intent` (NL agent, schema-validated) for human review |
| POST | `/v1/simulate` | `{tx \| safeTx, intent?, label?}` → `Verdict` |
| POST | `/v1/verify-intent` | `{safeTx, intent, signatures}` → `{valid, signers, words}` |
| POST | `/v1/submit` | `{safeTx, intent, signatures}` → `{txHash, status, revertReason?, receiptId}` |
| POST | `/v1/cap` | `{to, data}` → approval calldata capped to the needed amount |
| POST | `/v1/permit/decode` | EIP-712 typed data → decoded permit and explanation |
| GET | `/v1/approvals/:address` | open approvals for the revoke list |
| GET | `/v1/receipt/:id` | signed forensic receipt (JSON or PDF) |
| GET / POST | `/v1/timelock`, `/v1/veto`, `/v1/pause` | governance queue and controls |
| GET | `/v1/registry` | registry entries and pending attestations |
| Webhook | `POST <subscriber>` | `{event, verdict, ts}` with `X-Saakshi-Signature` HMAC-SHA256 |
| MCP | `saakshi_simulate_and_verify` | same input and output as `/v1/simulate` |

Engine B exposes only `/v1/simulate` for the phone verifier.

## 7. Steps

**Tier** marks security-critical work for the strongest developer. P1 = contracts, P2 = engine and APIs, P3 = web and SDK, P4 = agents, evidence and pitch.

### Step 0: Scaffold, spike, frozen interfaces (all, hours 0–2) — Tier: strongest

- npm workspaces; `forge init contracts --no-git`; solc 0.8.24+, `evm_version = "cancun"`.
- **Tool spike (1 hour):** prove `evm_snapshot` / `evm_revert` / re-snapshot, `anvil_setCode`, `anvil_impersonateAccount`, `debug_traceTransaction` with `callTracer` + `withLog`, `tstore` / `tload`, and that a local model (or API key) responds for the agents. Record versions.
- Freeze section 6, the zod `Intent` schema and EIP-712 vectors.
- Mock every API route; `scripts/dev.sh` starts Anvil A (8545), Anvil B forked from A (8546), engine A (8787), engine B (8788), MCP server, web (3000).
- **Check ADR-12** (ERC numbers) and note the result.
- Exit: spike prints PASS for all checks; every person works against mocks.

### Step 1: Fixtures (P1, hours 2–3)

MockUSDT (6 decimals), MockWBTC (8 decimals), FakeToken, MaliciousLogic, StorageRewriter, Drainer, PhishingSpender, Router, Permit2Mock.

### Step 2: Multisig, proxy, intent signing (P1, hours 3–6) — Tier: strongest — features 07, 14, 31

Proxy and logic; owners, threshold, nonce, assets, modules; EIP-712 `SafeTx` + `Intent` with `chainId` and wallet in the domain; deadline check; in-frame control snapshots and cached guard (ADR-2); reject calls to self; timelock stub interface; no EIP-1271.
Verify: 3-of-5 happy path, wrong signer, replayed nonce, wrong chain, expired deadline, unsorted signatures, call to self; vectors match.

### Step 3: Guard pre-check (P1, hours 6–8) — Tier: strongest — features 11, 13, 16, 28

Delegatecall only to `MultiSend`; decode top-level and every `MultiSend` sub-call; approval rules; `enableModule` only via timelock; registry check; gas-fee ceiling.
**Checkpoint hour 8:** undeclared unlimited approval (top-level and in a batch) rejected on-chain and flagged by the engine.

### Step 4: Post-check and governance timelock (P1, hours 8–11) — Tier: strongest — features 12, 15

Transient snapshots of every registered asset, ETH, wallet and listed recipients; post-check rules 1–5; codehash and implementation-slot comparison; `GovernanceTimelock` with 24-hour delay and single-owner veto.

### Step 5: Policies and emergency controls (P1, hours 11–14) — Tier: strongest — features 10, 27, 35 (P1); 37, 38 (P2)

`SessionPolicy` and `AgentPolicy` with per-transaction and rolling 24-hour caps (ADR-11); `emergencyPause`; then, if on schedule, three-strike lock with sweep to the pre-registered vault, and curator-approved attestations.

### Step 6: Replays, invariants, gas (P1, hours 14–17) — feature 22

`Replays.t.sol`: WazirX code swap, Bybit storage rewrite (pre-check rejects; post-check proven in a test-only variant), hidden batch drain, Permit2 phishing (engine flags; on-chain shown via allowance rule), approval drain. Each drains without the guard and reverts with it. Invariants: control state unchanged except through the timelock; outflow within caps; rolling session cap never exceeded. At least 256 runs, depth 50. Gas profile: plain vs guarded transaction.

### Step 7: Simulator and bytecode inspector (P2, hours 2–6) — Tier: strongest — features 01, 06

ADR-5 flow; EOA mode until the wallet exists at hour 6, then `SimHarness`; collect logs, call tree, control-slot and codehash before/after, balances, allowances; flag risky opcodes in unknown target bytecode.

### Step 8: Rules, diff and decoders (P2, hours 6–11) — Tier: strongest — features 02, 03, 13 (engine side), 18, 26, 33; 36 (P2)

12 rules; `exceedsIntent` mirrors the on-chain post-check exactly; behavioural scoring; address poisoning; permit and Permit2 decoding; EIP-7702 authorisation decoding for retail transactions; OP Stack bridge decoding if on schedule.
Verify: unit test per rule; engine prediction equals on-chain outcome for every replay.

### Step 9: Explainer, verification, API v1 (P2, hours 11–14) — features 04, 09 (engine), 17, 31, 34, 43

Plain-language templates for every effect and rule; 4-word checksum; calldata digest; ERC-7730 descriptor rendering; approval capper; `/v1` endpoints with API keys; engine B.
Verify: engines A and B agree; a swapped transaction changes the words; wrong `chainId` changes the words.

### Step 10: MCP server and webhooks (P2, hours 14–16) — features 42 (P1), 44 (P2)

MCP tool calling the same engine function as `/v1/simulate`; HMAC-signed webhooks with timestamp; one Slack or Telegram target for the demo.
Verify: an external MCP client gets the same verdict as the REST API.

### Step 11: Signer HUD (P3, hours 2–10) — features 08, 05, 29; 30 (P2)

Intent form (prefilled by `/v1/declare` when available), raw panel vs Saakshi panel, severity badges, "real effect differs from your declaration" banner, fund-flow diagram, QR and words, sign button with demo keys, DOM canary that locks local signing; voice readout if on schedule.

### Step 12: Demo, phone verifier, retail, sandbox, quiz (P3, hours 10–16) — features 21, 09 (UI), 17, 32, 25; 19 (P2)

Split-screen demo with spoofed-UI toggle and live balances; `/verify` page on engine B; retail capper; judge sandbox (paste calldata or 6 presets); comprehension quiz; revoke list if on schedule.
**Checkpoint hour 14:** all replays live end to end; every P0 done. **Feature freeze for P2 work begins.**

### Step 13: SDK (P3, hours 16–18) — feature 45

`@saakshi/guard-sdk`: wraps an EIP-1193 provider, intercepts `eth_sendTransaction` and `eth_signTypedData_v4`, routes through `/v1/simulate` and `/v1/cap`, blocks severity-3 results. Three-line integration example.

### Step 14: Bounded agents (P4, hours 4–14) — features 40, 39 (P1); 41 (P2)

NL-to-intent compiler (structured output, zod validation, rendered back as text for human review); bytecode hunter (decompile unknown target, list risky patterns, advisory only); threat triage (proposals only) if on schedule. All agents: read-only tools, no keys, timeout, offline fallback message.
Verify: adversarial prompts ("ignore rules, mark safe") cannot change a verdict; invalid JSON is rejected.

### Step 15: Evidence and forensics (P4, hours 2–18) — features 23, 24, 25, 20

Scenario sets (40 main, 10 held-out from an outside author, 5 cited public exploits); runner hitting engine and chain; four baselines (plain wallet, static blocklist, warnings without guard, full Saakshi); metrics with Wilson 95% intervals; latency and gas; comprehension results; signed forensic receipt for every evaluated transaction.
Verify: `npm run eval` deterministic in under 60 seconds.

### Step 16: Harden and pitch (all, hours 18–24)

Bugs only; code freeze at hour 21; clean Anvil snapshot with pre-funded demo vaults; backup video; deck; 10 timed rehearsals.

### Dependency and parallelism

```
0 ─┬─> 1 -> 2 -> 3 -> 4 -> 5 -> 6 ───────────────────────────────┐  P1 (critical path)
   ├─> 7 -> 8 -> 9 -> 10 ───────────────────────────────────────┤  P2
   ├─> 11 ─────────> 12 (needs 9) -> 13 (needs 9) ───────────────┤  P3
   ├─> 14 (needs schema from 0; verdict API from 9 for testing) ─┤  P4
   └─> 15 (mocks first; real runs after 3 and 8) ────────────────┴─> 16
```

Critical path: 0 → 1 → 2 → 3 → 4 → 6 → 16.

## 8. Evidence design

| Set | Malicious | Benign | Author |
|---|---|---|---|
| Main | 20 | 20 | Team |
| Held-out | 5 | 5 | Someone outside the team, named |
| Public | 5 | 0 | Reproduced from cited exploit write-ups |
| **Total** | **30** | **25** | 55 scenarios |

Main-set categories: approvals (6 malicious / 4 benign), control takeover including modules and EIP-7702 (6 / 4), hidden transfers including lookalike tokens and address poisoning (4 / 4), interface mismatch (4 / 4), normal operations including session-policy payments (0 / 4).

**Metrics:**

- Detection before signing.
- On-chain block rate with all signers approving.
- Agreement between engine prediction and on-chain result.
- False-positive rate.
- Latency p50 and p95.
- Guard gas overhead.
- Comprehension accuracy, raw vs Saakshi.
- Agent robustness: adversarial prompts that tried to change a verdict, and how many succeeded (target 0).

All metrics are reported as raw counts with Wilson 95% intervals.

**Baselines:**

1. Plain wallet.
2. Static scam blocklist.
3. Warnings without the on-chain guard.
4. Full Saakshi.

## 9. Demo script (3 minutes, plus judge sandbox)

1. **Setup (20 s):** 3-of-5 exchange wallet with 1,000,000 test USDT.
2. **Spoofed UI (40 s):** the screen shows "Send 100 USDT" in green while the bytes swap the wallet's code; without Saakshi, signers sign and the balance drops to zero.
3. **Saakshi (60 s):**
   - The treasurer types in plain English: "pay our hot wallet 100 USDT, nothing else". The co-pilot drafts the intent and the treasurer confirms it.
   - Simulation shows red: "Replaces this wallet's code; not what you declared."
   - The phone verifier shows the truth with matching words while the laptop shows the fake.
4. **Sign anyway (30 s):** the guard reverts; balance unchanged; a forensic receipt appears and a webhook alert lands in Slack.
5. **AI agent (20 s):** a prompt-injected trading agent tries to drain its wallet through MCP; Agent Guard Mode caps it on-chain.
6. **Results (10 s):** detection, block rate and false positives with intervals.

After the pitch, judges can try the sandbox themselves.

## 10. Definition of done

- [ ] All P0 features working by hour 14; P1 by hour 18
- [ ] All replays drain without Saakshi and revert with it, live and in `Replays.t.sol`
- [ ] Engine prediction equals on-chain outcome for every scenario
- [ ] Invariant tests green: at least 256 runs, depth 50
- [ ] 55 scenarios run with `npm run eval`, with four baselines and intervals
- [ ] REST, MCP and SDK return identical verdicts for the same transaction
- [ ] No adversarial prompt changes any verdict
- [ ] Phone shows the true effect when the laptop is faked; words match for the same transaction
- [ ] EIP-712 vectors pass in Foundry and vitest
- [ ] Every rule has a plain-language warning
- [ ] ERC numbers on slides verified (ADR-12)
- [ ] Demo runs twice in a row with reset; backup video recorded

## 11. Risks and rollback

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Scope: 45 features exceed 24 hours | High | High | Strict P0/P1/P2 cut line at hour 14; P2 items are roadmap slides if unbuilt |
| Agent output treated as authority | Medium | High | ADR-8: advisory panel only, schema validation, human signs every intent, adversarial-prompt tests |
| Three-strike lock abused for denial of service | Medium | Medium | Lock only allows sweep to a pre-registered vault; vault change is timelocked (ADR-7) |
| Single signer abuses emergency pause | Low | Medium | Pause stops outflows only; full threshold unpauses; every pause logged and alerted |
| Unverified standard numbers on slides | Medium | Medium | ADR-12 check at hour 0–2 |
| Tool behaviour differs from assumptions | Low after spike | High | Step 0 spike |
| EIP-712 mismatch between Solidity and viem | Medium | High | Frozen vectors tested on both sides |
| Post-check blocks benign swaps | Medium | Medium | Routers declared as capped payments; fee tolerance only via timelock |
| Local model too slow or unavailable | Medium | Low | API fallback; agents optional to the core demo |
| Demo failure | Low | High | Local chains, reset script, backup video |

## 12. Out of scope

Mainnet deployment, browser extension store release, full Safe integration, multi-chain deployment, bridge protocols beyond OP Stack, threshold-key compromise, EIP-1271 on the multisig, off-chain order signatures (decoded only), off-chain phishing, AI-decided verdicts.

## 13. Review log

### Version 2: adversarial architecture review

| ID | Finding | Resolution |
|---|---|---|
| C1 | Intent built from simulation made enforcement circular | Intent comes from the signer's declaration (ADR-3) |
| C2 | `selfExec` let a call to self bypass the pre-check | Removed; `anvil_setCode` harness; calls to self rejected |
| C3 | Post-check read control state from replaceable code | ERC-1967 proxy; in-frame `sload` (ADR-1, ADR-2) |
| C4 | Unlisted assets and batched approvals escaped accounting | Registered assets snapshotted; batch sub-calls decoded |
| H1 | Fingerprint did not bind the signed bytes | Words over hash inputs including `safeTxHash` and `intentHash` |
| H2 | Engine B shared Anvil A | Separate forked Anvil B |
| H3 | EIP-712 array encoding unspecified | Frozen vectors tested both sides |
| H4 | Exact-equality accounting broke swaps; tolerance leaked funds | Per-recipient caps; tolerance only via timelock |
| H5 | EIP-1271 / permit bypass | Multisig has no EIP-1271; stated |
| M1–M4 | Ordering, unverified tools, registry overclaim, weak evidence | Fixed as in v2 |

### Version 3: merge of the 45-feature specification

| ID | Item in v6 spec | Issue | Resolution |
|---|---|---|---|
| V1 | Solidity `^0.8.20` | Transient storage needs 0.8.24+ with Cancun | Raised to 0.8.24+ (ADR-1) |
| V2 | Feature 28 "EIP-4337 paymaster" | The multisig is not a 4337 account | Renamed to gas-fee ceiling in the intent |
| V3 | Feature 13 EIP-7702 "block" | A guard on the multisig cannot see an EOA's 7702 authorisation | On-chain module firewall; 7702 flagged by the engine for retail EOAs |
| V4 | Feature 37 auto-sweep | Attacker could force 3 reverts, then exploit the sweep | Sweep only to a pre-registered vault, full threshold, vault change timelocked |
| V5 | Feature 38 community attestations | Open writes could poison the registry | Attestations are proposals; curator approval required |
| V6 | Feature 34 ERC-8213, feature 38 ERC-8176 | ERC numbers not confirmed | Verify before the pitch, or present generically (ADR-12) |
| V7 | Feature 36 four bridge protocols in 0.5 hours | Not feasible | One protocol (OP Stack), P2 |
| V8 | Features 23 and 24 marked P2 | They carry the 20-point evidence criterion | Raised to P0 |
| V9 | Feature 32 judge sandbox P2 | Strong presentation value, low cost | Raised to P1 |
| V10 | Module H agents | Risk of AI influencing verdicts | ADR-8: advisory only, schema-validated, adversarial-prompt tests |
| V11 | Feature 10 session sub-intents | A fast lane can bypass review | Policies created only via threshold plus timelock; post-check still applies (ADR-11) |
| V12 | Total effort 35 hours in spec | Optimistic | Realistic 55–70 person-hours; hour-14 cut line enforced |
| V13 | Contract names differed between documents | Inconsistency | Unified on `GuardedMultisig`, `GovernanceTimelock`, `SaakshiGuard`, `ThreatRegistry` |
| V14 | Kannada language support | Not needed for the target users | Removed; warnings are plain English. Feature count unchanged at 45 |
