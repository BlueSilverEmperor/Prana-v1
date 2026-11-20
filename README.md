# Project Vero (Prana-v1): Zero-Trust On-Chain Guard Architecture

> **The Big Hack 2.0** | Track 02: Cybersecurity & Blockchain | Problem B1: "Know What You're Signing"  
> **Team WolverX**

---

## 1. Executive Summary

In historic Web3 exploits such as **WazirX (July 2024)** and **Bybit (February 2025)**, multisig signers approved transactions whose displayed interface meaning differed fundamentally from their actual on-chain bytecode execution. Attackers swapped wallet logic, manipulated storage slots, and drained millions.

**Project Vero** enforces a strict **Declare → Show → Enforce** paradigm:
1. **Declare:** The signer declares cryptographic intent (`IntentPolicy`) under EIP-712 (caps on spend, allowed targets/selectors, no unapproved delegatecall).
2. **Show:** Simulation and independent decoders show the exact diff between declared intent and execution effect.
3. **Enforce:** The on-chain `VeroGuard` validates pre-conditions, snapshots vault state, executes, and performs atomic post-execution diff verification. Any deviation or unauthorized storage mutation reverts the entire transaction atomically.

---

## 2. Directory Structure

```text
contracts/
├── src/
│   ├── VeroGuard.sol            # On-chain guard: EIP-712 intent verification, snapshots, firewall, dead-man's switch
│   ├── GuardedMultisig.sol      # Threshold vault: session keys, rolling 24h spend cap, slot immutability, agent cooldown
│   ├── VeroSafeGuard.sol        # Drop-in Gnosis Safe (v1.3/v1.4) transaction guard adapter
│   ├── GovernanceTimelock.sol   # 24-hour delay queue with single-signer veto
│   ├── ThreatRegistry.sol       # Blacklist engine with ERC-8176 curator attestations
│   └── mocks/
│       ├── MockUSDT.sol         # 6 Decimals, non-standard return handling (matching mainnet USDT)
│       ├── MockWBTC.sol         # 8 Decimals, standard ERC-20
│       └── MultiSend.sol        # Gnosis Safe byte-packed multi-call decoder
├── test/
│   ├── ExploitReplays.t.sol     # 13 realistic end-to-end exploit replays & feature tests
│   └── VeroInvariants.t.sol     # Foundry StdInvariant fuzz suite (256 runs, 12,800 calls)
├── script/
│   └── DeployVero.s.sol         # Full system deployment and configuration script
shared/
├── abi.json                     # Synchronized ABIs for all 8 smart contracts
├── schemas.py                   # Canonical IntentPolicy dataclass, EIP-712 payload builder, & error signatures
├── checksum.py                  # 4-word dual-device BIP-39 checksum generator
└── receipt.py                   # Automated forensic incident receipt generator for CERT-In & audit reporting
```

---

## 3. Mandatory Security Features

| Feature | Component | Description |
|---|---|---|
| **#10 Session Sub-Intents** | `GuardedMultisig.sol` & `VeroGuard.sol` | Rolling 24-hour velocity spend cap (`dailySpendCap`). Valid `sessionAgent` key executes pre-approved actions without full M-of-N threshold. |
| **#11 On-Chain Guard Pre-Check** | `VeroGuard.checkTransaction` | Verifies deadline, chainId, nonce, max gas fee, blacklist status, target sanity, and recursive MultiSend batch items. |
| **#12 Multi-Asset Vault Snapshot** | `VeroGuard.checkAfterExecution` | Records pre-execution balances and critical control slots (`masterCopy`, `ownersHash`, `threshold`, `guard`, `codehash`). Reverts atomically on any excess outflow or slot mutation. |
| **#13 Module & EIP-7702 Firewall** | `GuardedMultisig.sol` & `VeroGuard.sol` | Blocks direct `enableModule` (`0x610b5925`) unless called by `GovernanceTimelock`. Reverts calldata containing EIP-7702 delegation prefixes (`0xef0100` / `0x04`). |
| **#14 Intent Expiry & State-Drift Lock** | `VeroGuard.sol` | Strict TOCTOU defense binding policy execution to `keccak256(abi.encode(vaultNonce, block.chainid))` and block timestamp. |
| **#15 24h Governance Timelock with Veto** | `GovernanceTimelock.sol` | Mandatory 24-hour queue for critical configuration changes; any single vault owner can instantly veto during the window. |
| **#16 & #38 Threat Registry & ERC-8176** | `ThreatRegistry.sol` | Maintains malicious address and selector blacklists; auto-blacklists targets upon reaching threshold curator attestations. |
| **#27 Emergency Panic Freeze** | `VeroGuard.sol` | Any single vault owner can immediately trigger `emergencyPause()`; unfreezing requires M-of-N threshold signatures. |
| **#35 AI Agent / Bot Guardrails** | `VeroGuard.sol` | Enforces tight per-tx `ethValueCap`, allowed selectors, and daily spend velocity limits for autonomous agent keys. |
| **#37 Dead-Man's Switch Auto-Sweep** | `VeroGuard.sol` | Tracks consecutive Guard failures within a 600s rolling window. 3 consecutive strikes trigger an emergency lock and enable one-click asset sweep to `recoveryVault`. |

---

## 4. Canonical Revert Error Signatures

For integration with off-chain AI agents, decoders, and transaction parsers:

| Custom Error | 4-Byte Selector | Description |
|---|---|---|
| `IntentExpired(uint256,uint256)` | `0x7c73c380` | `block.timestamp > policy.deadline` |
| `StateDriftDetected(uint256,uint256)` | `0x2e06191a` | Vault nonce mismatch (`policy.nonce != vault.nonce`) |
| `GasPriceTooHigh(uint256,uint256)` | `0xdae2dbfc` | Gas price exceeds `policy.maxGasFeeWei` |
| `TargetBlacklisted(address)` | `0x98f98d5c` | Target address blacklisted in `ThreatRegistry` |
| `DelegateCallNotAllowed(address)` | `0x9b325c7e` | Unapproved delegatecall attempted |
| `InvalidTarget(address)` | `0x77ad587c` | Target is self/guard or not in `allowedTargets` |
| `SelectorNotAllowed(bytes4)` | `0x892a0e20` | Compromised or unapproved function selector |
| `MultiSendValidationFailed(address,bytes4)` | `0x9ebccb40` | Nested MultiSend call failed policy validation |
| `TokenSpendExceeded(address,uint256,uint256)` | `0x0d7c2a71` | Token outflow exceeds `maxTokenSpends[i]` |
| `EthValueCapExceeded(uint256,uint256)` | `0xdf843588` | ETH outflow exceeds `policy.ethValueCap` |
| `ControlSlotMutated(string)` | `0xdbe73428` | Unauthorized mutation to `masterCopy`, `ownersHash`, `threshold`, `guard`, or `codehash` |
| `ModuleFirewallBlocked(bytes4,address)` | `0xd3c2d4ff` | Direct `enableModule` called outside timelock |
| `EIP7702DelegationBlocked()` | `0x8382da37` | EIP-7702 delegation designation detected in payload |
| `GuardPaused()` | `0x9c313a43` | Transaction attempted while emergency freeze active |
| `DeadMansSwitchActive(address)` | `0x05bca4a8` | Execution locked due to 3 consecutive failures |
| `DailySpendCapExceeded(uint256,uint256)` | `0xc5b6510f` | Session agent attempted spend exceeding rolling 24h cap |
| `ProposalNotReady(bytes32,uint256)` | `0x21b332b7` | Timelock execution attempted before 24-hour delay |
| `ProposalAlreadyVetoed(bytes32)` | `0x075aee50` | Timelock proposal was cancelled by single-signer veto |

---

## 5. Verification & Testing

### Test Suite Execution
```bash
cd contracts
forge test -vvv
```

### Exploit Replay Suite (`ExploitReplays.t.sol`) — 13/13 Passed
- `test_WazirX_Slot0Swap_Blocked` [PASS]
- `test_Bybit_DelegateCallOverwrite_Blocked` [PASS]
- `test_MultiSend_HiddenBatchDrain_Blocked` [PASS]
- `test_Permit2_PhishingReplay_Blocked` [PASS]
- `test_EmergencyPause_And_Unpause` [PASS]
- `test_EmergencyPause_48hAutoDecay` [PASS] (Anti-Griefing DoS defense)
- `test_GovernanceTimelock_24hDelay_And_Veto` [PASS]
- `test_ThreatRegistry_ERC8176_Attestations` [PASS]
- `test_DeadMansSwitch_3Strikes_AutoSweep` [PASS]
- `test_SessionScopedSubIntent_DailySpendCap` [PASS]
- `test_AIAgent_VelocityCooldown` [PASS] (Anti-Burst Autonomous Bot Guardrail)
- `test_4WordChecksum_Derivation` [PASS] (BIP-39 Dual-Device Verifier)
- `test_VeroSafeGuard_Adapter_Deployment` [PASS] (Gnosis Safe v1.3/v1.4 Drop-In Adapter)

### Invariant Fuzzing (`VeroInvariants.t.sol`) — 4/4 Invariants Passed
- **Runs:** 256 | **Calls:** 12,800 | **Reverts:** 0
- `invariant_ZeroUndeclaredOutflows` [PASS]
- `invariant_ControlSlotImmutability` [PASS]
- `invariant_GasPriceCompliance` [PASS]
- `invariant_DirectEnableModuleAlwaysReverts` [PASS]

---

## 6. Deployment Script
To simulate local deployment using Foundry:
```bash
cd contracts
forge script script/DeployVero.s.sol
```
