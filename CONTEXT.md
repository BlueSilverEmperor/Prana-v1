# PROJECT VERO (PRANA-V1) — ARCHITECTURAL CONTEXT & REFERENCE MANUAL

**Event:** The Big Hack 2.0  
**Track:** Track 02: Cybersecurity & Blockchain  
**Problem Statement:** B1 — "Know What You're Signing"  
**Team:** WolverX  
**Role Scope:** Person 1 (Smart Contract, Security, & On-Chain Guard Lead)  
**Repository:** [BlueSilverEmperor/Prana-v1](https://github.com/BlueSilverEmperor/Prana-v1)

---

## 1. System Vision: Declare → Show → Enforce

In attacks like **WazirX (July 2024)** and **Bybit (February 2025)**, signers approved raw hex bytes presented on deceptive interfaces. The executed transaction swapped wallet implementation logic, mutated storage slots, and drained vault reserves.

Project Vero implements an on-chain zero-trust gate:
1. **Declare:** The signer explicitly signs an EIP-712 `IntentPolicy` declaring strict boundaries: allowed recipients, allowed 4-byte selectors, maximum ETH outflow, per-token spending caps, gas price ceiling, and delegation permissions.
2. **Show:** Off-chain simulation engines and independent second-device verifiers simulate the exact bytes against an independent Anvil node and show the deterministic diff between declared intent and simulated effect.
3. **Enforce:** The on-chain `VeroGuard` verifies the cryptographic intent, snapshots the vault's assets and control slots before execution, executes the inner call, and verifies the post-state. Any violation—whether an undeclared transfer, exceeded cap, or mutated control slot—reverts the entire transaction atomically.

---

## 2. Repository Architecture & File Mapping

```text
Prana-v1/
├── contracts/
│   ├── foundry.toml               # Solc 0.8.20, Cancun EVM, via_ir = true, optimizer enabled
│   ├── lib/
│   │   ├── forge-std              # Foundry standard testing library
│   │   └── openzeppelin-contracts # OpenZeppelin Contracts v5.0.2 (EIP712, ECDSA, AccessControl)
│   ├── src/
│   │   ├── VeroGuard.sol          # Main on-chain guard (Pre-check, Post-check, Firewall, DMS)
│   │   ├── GuardedMultisig.sol    # Core multisig vault (M-of-N threshold, Session keys, Slot tracking)
│   │   ├── GovernanceTimelock.sol # 24h delay timelock with single-signer veto
│   │   ├── ThreatRegistry.sol     # Malicious address/selector registry & ERC-8176 attestations
│   │   └── mocks/
│   │       ├── MockUSDT.sol       # 6 decimals, non-standard ERC-20 return handling
│   │       ├── MockWBTC.sol       # 8 decimals, standard ERC-20
│   │       └── MultiSend.sol      # Gnosis Safe byte-packed recursive transaction executor
│   ├── test/
│   │   ├── ExploitReplays.t.sol   # 9 unit & exploit replay simulations (100% pass)
│   │   └── VeroInvariants.t.sol   # Foundry invariant fuzzing (256 runs, 12,800 calls, 0 reverts)
│   └── script/
│       └── DeployVero.s.sol       # Full system deployment and configuration script
├── shared/
│   ├── abi.json                   # Consolidated ABIs for all 7 contracts
│   └── schemas.py                 # Python canonical dataclasses, EIP-712 builder, & error signatures
├── Saakshi_Blueprint.md           # 45-feature architectural blueprint specification
├── README.md                      # High-level overview & setup documentation
└── CONTEXT.md                     # Comprehensive technical context (this document)
```

---

## 3. Canonical Schema & EIP-712 Specification

### EIP-712 Domain Separator
- **Name:** `"VeroGuard"`
- **Version:** `"1"`
- **Verifying Contract:** `address(guard)`
- **Chain ID:** `block.chainid`

### IntentPolicy Struct Definition
```solidity
struct IntentPolicy {
    address vault;              // Address of the multisig vault executing the transaction
    uint256 nonce;              // Nonce of the vault at time of signing (state-drift lock)
    uint256 deadline;           // Unix timestamp after which intent expires (TOCTOU defense)
    uint256 maxGasFeeWei;       // Gas price ceiling in wei (prevents gas siphon attacks)
    bool allowDelegateCall;     // False by default; strictly required for DELEGATECALL
    address[] allowedTargets;   // Whitelist of valid call destinations
    bytes4[] allowedSelectors;  // Whitelist of valid 4-byte function selectors
    address[] tokenAddresses;   // List of ERC-20 tokens subject to spend limits
    uint256[] maxTokenSpends;   // Outflow caps corresponding to tokenAddresses
    uint256 ethValueCap;        // Maximum allowed native ETH outflow in wei
    bool sessionKeyEnabled;     // If true, enables single-signature execution by sessionAgent
    address sessionAgent;       // Designated operator or AI agent key
}
```

### TypeHash
```solidity
bytes32 public constant INTENT_POLICY_TYPEHASH = keccak256(
    "IntentPolicy(address vault,uint256 nonce,uint256 deadline,uint256 maxGasFeeWei,bool allowDelegateCall,address[] allowedTargets,bytes4[] allowedSelectors,address[] tokenAddresses,uint256[] maxTokenSpends,uint256 ethValueCap,bool sessionKeyEnabled,address sessionAgent)"
);
// Value: 0x7856e138a0a91176b50937a505b0cf8e8f815a5fbcbc0734da65b82215c2ec89
```

---

## 4. Mandatory Security Features

### Feature #10 — Session-Scoped Sub-Intents (`GuardedMultisig.sol` & `VeroGuard.sol`)
- Vault maintains rolling 24-hour spend velocity: `mapping(address => uint256) public dailySpend`.
- If `block.timestamp >= lastDailyReset + 1 days`, daily spend counter automatically resets to 0.
- When `sessionKeyEnabled == true`, a single signature from `sessionAgent` is authorized to execute transactions provided:
  - `to` is present in `policy.allowedTargets`.
  - `dailySpend + value <= dailySpendCap`.
  - Guard pre-check and post-execution snapshot rules are strictly satisfied.

### Feature #11 — On-Chain Guard Pre-Check (`VeroGuard.checkTransaction`)
Validates every transaction before execution:
1. `!paused`: Reverts if emergency freeze is active (`GuardPaused`).
2. `!deadMansSwitchActive[vault]`: Reverts if post-compromise lock is active (`DeadMansSwitchActive`).
3. `block.timestamp <= policy.deadline`: Reverts if expired (`IntentExpired`).
4. `vaultNonce == policy.nonce`: Reverts on state drift (`StateDriftDetected`).
5. `tx.gasprice <= policy.maxGasFeeWei`: Reverts if gas fee ceiling exceeded (`GasPriceTooHigh`).
6. `to != address(this) && to != policy.vault`: Prevents circular calls and self-destruct attacks (`InvalidTarget`).
7. `!threatRegistry.isBlacklisted(to)`: Reverts if target address is blacklisted (`TargetBlacklisted`).
8. If `operation == 1` (`DELEGATECALL`): Requires `allowDelegateCall == true` and `to` in `allowedTargets` (`DelegateCallNotAllowed`).
9. **MultiSend Recursive Validation:** If `to == multiSend`, unpacks every nested `(operation, target, value, dataLength, data)` item. Ensures no nested target is blacklisted, no nested target is self/vault, every nested target is in `allowedTargets`, and every nested selector is in `allowedSelectors`.

### Feature #12 — Multi-Asset Vault Snapshot (`VeroGuard.checkAfterExecution`)
- **Pre-execution Snapshot:** Captures `vault.balance`, token balances for all listed `tokenAddresses`, `vault.codehash`, slot 0 (`masterCopy`), `ownersHash`, `threshold`, and `guard`.
- **Post-execution Verification:** Reverts atomically if:
  - Inner call returned `success == false`.
  - ETH balance drop > `policy.ethValueCap` (`EthValueCapExceeded`).
  - Any token balance drop > `policy.maxTokenSpends[i]` (`TokenSpendExceeded`).
  - Any critical control slot was mutated during execution (`ControlSlotMutated`):
    - `masterCopy != preSnap.masterCopy`
    - `ownersHash != preSnap.ownersHash`
    - `threshold != preSnap.threshold`
    - `guard != preSnap.guard`
    - `vault.codehash != preSnap.walletCodeHash`

### Feature #13 — Module & EIP-7702 Delegation Firewall
- Direct invocation of `enableModule(address)` (`0x610b5925`) is strictly prohibited unless `msg.sender == governanceTimelock`. Any unauthorized call reverts with `ModuleFirewallBlocked(0x610b5925, msg.sender)`.
- Transaction calldata is inspected for EIP-7702 set-code delegation designations (`0xef0100`) or typed payload prefix `0x04`. Reverts immediately with `EIP7702DelegationBlocked()`.

### Feature #14 — Intent Expiry & State-Drift Lock (TOCTOU Defense)
- Cryptographic binding between policy verification and `keccak256(abi.encode(vaultNonce, block.chainid))`.
- If another transaction executes before this one, the nonce increments, causing an instant revert on execution attempt.

### Feature #15 — 24-Hour Governance Timelock with Single-Signer Veto (`GovernanceTimelock.sol`)
- All critical administrative calls (`setGuard`, `addOwnerWithThreshold`, `removeOwner`, `changeThreshold`, `enableModule`, `setMasterCopy`) must be queued in `GovernanceTimelock`.
- Minimum delay: `DELAY = 1 days` (86,400 seconds).
- Any single verified owner of the vault can call `vetoProposal(proposalId)` during the 24-hour window, permanently cancelling the proposal.

### Feature #16 & #38 — Threat Registry & ERC-8176 Attestations (`ThreatRegistry.sol`)
- Maintains blacklists of malicious addresses, compromised bytecode hashes (`codehash`), and malicious selectors.
- Supports decentralized curator attestations:
  `submitAttestation(address target, bytes4 selector, bytes memory signature)`
- Once `attestationCount[target] >= attestationThreshold` (default: 2), the target address and selector are automatically blacklisted.

### Feature #27 — Emergency Panic Freeze (`VeroGuard.sol`)
- Any single verified owner can call `emergencyPause()`, immediately freezing all outbound execution through the guard.
- Resuming operations (`unpause`) strictly requires M-of-N multisig signatures from authorized vault owners.

### Feature #35 — AI Agent / Bot Guardrails
- Isolated agent keys operate under `sessionKeyEnabled` mode without full multisig privileges.
- Constrained strictly by `ethValueCap`, whitelist of `allowedSelectors`, and 24h spend velocity caps.

### Feature #37 — Dead-Man's Switch / Post-Compromise Auto-Sweep
- Tracks consecutive Guard failures per vault within a rolling 600-second window:
  - If a failure occurs within 600s of the previous failure, counter increments.
  - On the 3rd consecutive failure (`consecutiveReverts >= 3`), the vault activates `deadMansSwitchActive = true`.
- Normal transactions are permanently blocked, and any party can trigger `executeAutoSweep(vault, tokensToSweep)` to transfer 100% of the vault's ETH, USDT, and WBTC reserves directly to the pre-registered `recoveryVault`.

---

## 5. Canonical Revert Error Signatures

| Custom Error | 4-Byte Selector | Parameters | Revert Condition |
|---|---|---|---|
| `IntentExpired` | `0x7c73c380` | `(uint256 deadline, uint256 currentTimestamp)` | `block.timestamp > policy.deadline` |
| `StateDriftDetected` | `0x2e06191a` | `(uint256 expectedNonce, uint256 actualNonce)` | `policy.nonce != vault.nonce` |
| `GasPriceTooHigh` | `0xdae2dbfc` | `(uint256 maxGasFeeWei, uint256 actualGasPrice)` | `tx.gasprice > policy.maxGasFeeWei` |
| `TargetBlacklisted` | `0x98f98d5c` | `(address target)` | Target address flagged in `ThreatRegistry` |
| `DelegateCallNotAllowed` | `0x9b325c7e` | `(address target)` | `operation == 1` and `allowDelegateCall == false` |
| `InvalidTarget` | `0x77ad587c` | `(address target)` | Target is self/guard or not in `allowedTargets` |
| `SelectorNotAllowed` | `0x892a0e20` | `(bytes4 selector)` | Selector blacklisted or not in `allowedSelectors` |
| `MultiSendValidationFailed` | `0x9ebccb40` | `(address target, bytes4 selector)` | Sub-call in MultiSend failed policy checks |
| `TokenSpendExceeded` | `0x0d7c2a71` | `(address token, uint256 allowed, uint256 actualOutflow)` | ERC-20 outflow exceeded policy cap |
| `EthValueCapExceeded` | `0xdf843588` | `(uint256 cap, uint256 actualOutflow)` | ETH outflow exceeded `policy.ethValueCap` |
| `ControlSlotMutated` | `0xdbe73428` | `(string slotName)` | Unauthorized mutation to `masterCopy`, `ownersHash`, etc. |
| `ModuleFirewallBlocked` | `0xd3c2d4ff` | `(bytes4 selector, address caller)` | Direct `enableModule` called outside timelock |
| `EIP7702DelegationBlocked` | `0x8382da37` | `()` | Calldata contains EIP-7702 delegation designation |
| `GuardPaused` | `0x9c313a43` | `()` | Transaction attempted while emergency pause is active |
| `DeadMansSwitchActive` | `0x05bca4a8` | `(address vault)` | Vault locked after 3 consecutive failures |
| `DailySpendCapExceeded` | `0xc5b6510f` | `(uint256 cap, uint256 requested)` | Session agent exceeded rolling 24h limit |
| `ProposalNotReady` | `0x21b332b7` | `(bytes32 proposalId, uint256 eta)` | Timelock executed before 24-hour delay |
| `ProposalAlreadyVetoed` | `0x075aee50` | `(bytes32 proposalId)` | Proposal was vetoed by a vault owner |

---

## 6. Test Suites & Empirical Verification

### A. Exploit Replays (`test/ExploitReplays.t.sol`) — 9/9 Passed
1. **WazirX Slot-0 Swap:** An unguardable multisig has its implementation pointer (`masterCopy`) overwritten via malicious delegatecall. With `VeroGuard`, the transaction reverts with `DelegateCallNotAllowed` (or `ControlSlotMutated`), keeping slot 0 untouched.
2. **Bybit DelegateCall Storage Overwrite:** Demonstrates that unconstrained delegatecalls alter multisig threshold/ownership slots on unguarded vaults. `VeroGuard` blocks the delegatecall upfront.
3. **MultiSend Hidden Batch Drain:** An attacker bundles a 100 USDT benign transfer with a hidden 50,000 USDT transfer to an attacker address. `VeroGuard` decodes the batch, enforces post-execution snapshots, and reverts with `TokenSpendExceeded`.
4. **Permit2 Phishing Replay:** An unapproved 80,000 USDT token drain succeeds on unguarded vaults, but reverts atomically on `VeroGuard` with zero token leakage.
5. **Emergency Freeze & Unpause:** Proves a single owner can freeze outbound transfers, and unfreezing requires valid M-of-N threshold signatures.
6. **Governance Timelock Delay & Veto:** Proves a queued proposal cannot execute before 24 hours, and any single owner can veto it.
7. **Threat Registry ERC-8176 Attestations:** Proves two independent curator signatures auto-blacklist an attacker address and selector.
8. **Dead-Man's Switch 3-Strike Auto-Sweep:** Proves 3 consecutive Guard failures within 600 seconds trigger emergency lock and enable one-click auto-sweep of all ETH, USDT, and WBTC to `recoveryVault`.
9. **Session-Scoped Sub-Intent:** Proves designated session agents can execute transactions within their rolling 24-hour spend cap with a single signature, but calls exceeding `dailySpendCap` revert with `DailySpendCapExceeded`.

### B. Invariant Fuzzing (`test/VeroInvariants.t.sol`) — 4/4 Invariants Passed
- **Runs:** 256  
- **Calls:** 12,800  
- **Reverts:** 0  
- **Invariants:**
  1. `invariant_ZeroUndeclaredOutflows`: Zero undeclared token/ETH leakage across all randomized execution traces.
  2. `invariant_ControlSlotImmutability`: `masterCopy`, `guard`, `ownersHash`, and `threshold` remain immutable.
  3. `invariant_GasPriceCompliance`: All executed transactions satisfy `tx.gasprice <= maxGasFeeWei`.
  4. `invariant_DirectEnableModuleAlwaysReverts`: Direct `enableModule` calls always revert for non-timelock callers.

---

## 7. Local Deployment Addresses (Dry-Run Simulation)

From `contracts/script/DeployVero.s.sol`:
- `ThreatRegistry`: `0x5FbDB2315678afecb367f032d93F642f64180aa3`
- `GovernanceTimelock`: `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512`
- `MultiSend`: `0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0`
- `VeroGuard`: `0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9`
- `MockUSDT`: `0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9`
- `MockWBTC`: `0x5FC8d32690cc91D4c39d9d3abcBD16989F875707`
- `GuardedMultisig`: `0x0165878A594ca255338adfa4d48449f69242Eb8F`
- `RecoveryVault`: `0x999999cf1046e68e36E1aA2E0E07105eDDD1f08E`

---

## 8. Integration Instructions for Teammates

### For Person 2 (Simulator & Risk Engine Lead)
- Import `shared/abi.json` to interact with `VeroGuard`, `GuardedMultisig`, and `ThreatRegistry`.
- In your Anvil fork simulator, compare declared vs. real simulation effects:
  - If simulated token outflow > `policy.maxTokenSpends[i]`, emit Rule 10 warning (`TokenSpendExceeded`).
  - If simulated target has `codehash` altered or proxy slot 0 changed, emit Rule 3 warning (`ControlSlotMutated`).
  - If top-level or MultiSend sub-call target is in `ThreatRegistry`, emit Rule 12 warning (`TargetBlacklisted`).

### For Person 3 (Signer HUD & Frontend Lead)
- Use `shared/schemas.py` or the TypeScript equivalent to construct `eth_signTypedData_v4` payloads.
- Ensure signers review:
  1. Recipient address & payment cap.
  2. Four-word BIP-39 checksum derived from `keccak256(abi.encode(vault, nonce, safeTxHash, policyHash))`.
  3. Real simulation outcome versus declared policy.

### For Person 4 (AI Agent, Eval Harness, & Forensics Lead)
- Match any on-chain revert against the 4-byte selectors listed in Section 5 table.
- When generating forensic receipts for CERT-In / security compliance, include:
  - `policyHash`
  - Signed EIP-712 digest
  - Pre- and post-snapshot control slot hashes
  - Revert error selector and decoded parameters
