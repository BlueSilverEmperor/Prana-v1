"""
Project Vero // Diverse Web3 EVM Threat Dataset Generator
Synthesizes a realistic, diverse benchmark dataset modeled after:
- Kaggle 'Ethereum Phishing & Fraud Detection Dataset'
- DeFiHackLabs Historical Exploit Database (2021-2025)
- Standard On-Chain Benign Transaction Distribution (Etherscan Top Contracts)

Contains 15 EVM telemetry signals across 3,000 transaction samples.
Introduces realistic real-world noise, edge cases, and adversarial evasion vectors:
- Legitimate DAO upgrades vs illicit proxy swaps
- Legitimate Permit2 approvals vs phishing drainers
- Complex 1inch/CoWSwap nested delegatecalls vs malicious delegatecalls
- Flash loan arbitrage vs reentrancy exploits
"""

import math
import random
import os
from typing import List, Dict, Tuple

random.seed(1337)

FEATURE_NAMES = [
    "calldata_length",                  # Bytes of input calldata
    "calldata_entropy",                 # Shannon entropy of hex payload [0.0 - 8.0]
    "is_upgrade_selector",              # 1.0 if calling upgradeTo / upgradeToAndCall
    "is_delegatecall",                  # 1.0 if executing DELEGATECALL
    "is_infinite_allowance",            # 1.0 if approval amount > 2^128
    "target_is_contract",               # 1.0 if target has deployed bytecode
    "value_outflow_eth",                # Native ETH value transferred
    "storage_slot_mutation_expected",   # 1.0 if EIP-1967 slot 0x3608 or admin slot mutated
    "selector_frequency_score",         # Historical frequency of selector on mainnet [0.0 - 1.0]
    "sender_nonce_deviation",           # Anomaly score on safe account execution nonce
    "gas_limit_ratio",                  # Ratio of requested gas limit to typical gas profile
    "intent_declaration_mismatch",      # 1.0 if declared intent diverges from opcode action
    "call_depth",                       # Nested call execution depth (0 = direct, >0 = subcalls)
    "is_governance_timelock_origin",    # 1.0 if initiated through a 24h timelock queue
    "contract_reputation_score"         # On-chain age/reputation score [0.0 - 1.0]
]


def shannon_entropy(data_bytes: bytes) -> float:
    if not data_bytes:
        return 0.0
    freq = {}
    for b in data_bytes:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(data_bytes)
        entropy -= p * math.log2(p)
    return entropy


def generate_diverse_web3_dataset(num_samples: int = 3000) -> Tuple[List[List[float]], List[int], List[str]]:
    """
    Generates 3,000 diverse, high-variance Web3 transaction vectors
    with realistic real-world noise, edge-cases, and non-trivial decision boundaries.
    """
    X: List[List[float]] = []
    y: List[int] = []
    metadata: List[str] = []

    half = num_samples // 2

    # =========================================================================
    # CLASS 1: MALICIOUS ATTACKS (1,500 samples across 10 exploit categories)
    # =========================================================================
    attack_categories = [
        ("WazirX_Proxy_Slot_Hijack", 300),
        ("Bybit_DelegateCall_Drain", 250),
        ("Permit2_Phishing_Drainer", 250),
        ("Infinite_Allowance_Drainer", 200),
        ("Euler_Readonly_Reentrancy", 150),
        ("Curve_Pool_Price_Manipulation", 100),
        ("Stealth_Adversarial_Calldata_Evasion", 100), # Stealth attacks attempting to mimic benign transfers
        ("Ice_Phishing_Fake_Airdrop", 75),
        ("Tornado_Cash_Direct_Hop", 50),
        ("Gov_Proposal_Malicious_MultiCall", 25)
    ]

    for cat_name, count in attack_categories:
        for _ in range(count):
            metadata.append(cat_name)
            y.append(1)

            if cat_name == "WazirX_Proxy_Slot_Hijack":
                feat = [
                    random.uniform(68, 140),
                    random.uniform(3.6, 4.8),
                    1.0,                                      # is_upgrade_selector
                    random.choice([0.0, 1.0]),                # is_delegatecall
                    0.0,
                    1.0,
                    0.0,
                    1.0,                                      # storage_slot_mutation_expected
                    random.uniform(0.01, 0.06),
                    random.uniform(0.0, 0.2),
                    random.uniform(1.8, 3.2),
                    random.choice([1.0, 1.0, 1.0, 0.8]),      # intent_declaration_mismatch
                    random.randint(1, 3),
                    0.0,                                      # NOT from governance timelock
                    random.uniform(0.05, 0.25)                # unverified/new contract
                ]
            elif cat_name == "Bybit_DelegateCall_Drain":
                feat = [
                    random.uniform(128, 280),
                    random.uniform(4.0, 5.2),
                    0.0,
                    1.0,                                      # is_delegatecall = 1
                    0.0,
                    1.0,
                    random.uniform(0.0, 80.0),
                    1.0,
                    random.uniform(0.02, 0.12),
                    random.uniform(0.0, 0.4),
                    random.uniform(2.2, 4.5),
                    1.0,
                    random.randint(2, 5),
                    0.0,
                    random.uniform(0.02, 0.18)
                ]
            elif cat_name == "Permit2_Phishing_Drainer":
                feat = [
                    random.uniform(160, 260),
                    random.uniform(3.9, 4.9),
                    0.0,
                    0.0,
                    1.0,                                      # infinite allowance
                    1.0,
                    0.0,
                    0.0,
                    random.uniform(0.10, 0.25),
                    random.uniform(0.05, 0.35),
                    random.uniform(1.2, 2.0),
                    random.choice([1.0, 0.9]),
                    1,
                    0.0,
                    random.uniform(0.10, 0.40)
                ]
            elif cat_name == "Infinite_Allowance_Drainer":
                feat = [
                    68.0,
                    random.uniform(2.4, 3.3),
                    0.0,
                    0.0,
                    1.0,                                      # is_infinite_allowance
                    1.0,
                    0.0,
                    0.0,
                    0.85,                                     # approve selector is standard
                    random.uniform(0.0, 0.15),
                    random.uniform(1.0, 1.4),
                    1.0,
                    0,
                    0.0,
                    random.uniform(0.05, 0.30)
                ]
            elif cat_name == "Euler_Readonly_Reentrancy":
                feat = [
                    random.uniform(350, 850),
                    random.uniform(4.8, 6.2),
                    0.0,
                    random.choice([0.0, 1.0]),
                    0.0,
                    1.0,
                    random.uniform(50.0, 1500.0),
                    0.0,
                    random.uniform(0.05, 0.30),
                    random.uniform(0.1, 0.6),
                    random.uniform(3.5, 7.0),                 # huge gas consumption
                    random.choice([1.0, 0.7]),
                    random.randint(4, 9),
                    0.0,
                    random.uniform(0.15, 0.50)
                ]
            elif cat_name == "Stealth_Adversarial_Calldata_Evasion":
                # Real-world stealth attack crafted to mimic standard transfers (causes realistic hard boundary)
                feat = [
                    random.uniform(68, 100),
                    random.uniform(2.8, 3.6),
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                    random.uniform(0.0, 1.0),
                    0.0,
                    random.uniform(0.85, 0.95),               # standard transfer selector
                    random.uniform(0.0, 0.05),
                    random.uniform(1.0, 1.25),
                    random.uniform(0.0, 0.25),                # subtle intent mismatch
                    0,
                    0.0,
                    random.uniform(0.65, 0.85)                # aged contract (realistic false negative risk)
                ]
            else: # Other attacks
                feat = [
                    random.uniform(180, 500),
                    random.uniform(4.1, 5.5),
                    random.choice([0.0, 0.5, 1.0]),
                    random.choice([0.0, 1.0]),
                    random.choice([0.0, 1.0]),
                    1.0,
                    random.uniform(5.0, 200.0),
                    random.choice([0.0, 1.0]),
                    random.uniform(0.08, 0.40),
                    random.uniform(0.1, 0.5),
                    random.uniform(1.5, 4.0),
                    1.0,
                    random.randint(2, 6),
                    0.0,
                    random.uniform(0.05, 0.35)
                ]
            # Introduce realistic real-world noise for malicious attacks (zero-day stealth & evasion)
            attack_noise = random.random()
            if attack_noise < 0.075:
                # 7.5% of attacks mimic standard transfers closely (adversarial evasion)
                feat[11] = random.uniform(0.0, 0.06)  # intent_declaration_mismatch ~ 0
                feat[14] = random.uniform(0.70, 0.92) # aged contract reputation
                feat[10] = random.uniform(1.0, 1.25)  # normal gas ratio
                feat[8] = random.uniform(0.85, 0.98)  # standard transfer selector
                feat[0] = 68.0                        # standard calldata size
            elif attack_noise < 0.14:
                feat[11] = random.uniform(0.18, 0.38)
                feat[14] = random.uniform(0.55, 0.75)
            
            X.append(feat)

    # =========================================================================
    # CLASS 0: BENIGN TRANSACTIONS (1,500 samples across 10 protocol categories)
    # =========================================================================
    benign_categories = [
        ("Standard_ERC20_Transfer", 350),
        ("Uniswap_V3_Router_Swap", 300),
        ("1inch_Aggregator_Deep_Route", 200),          # Complex multi-call with delegatecalls (BENIGN EDGE CASE)
        ("Permit2_Legitimate_Router_Approval", 150),   # Infinite approval to official Uniswap router (BENIGN EDGE CASE)
        ("DAO_Timelock_Authorized_Upgrade", 100),      # Legitimate proxy upgrade through Timelock (BENIGN EDGE CASE)
        ("Aave_V3_Flash_Loan_Arbitrage", 100),         # High-gas legitimate arbitrage
        ("Lido_stETH_Staking_Deposit", 100),           # Large native ETH transfer
        ("OpenSea_Seaport_Batch_Transfer", 100),       # High entropy, large calldata
        ("Safe_Multisig_Routine_Rebalance", 75),
        ("Chainlink_Keepers_Automation", 25)
    ]

    for cat_name, count in benign_categories:
        for _ in range(count):
            metadata.append(cat_name)
            y.append(0)

            if cat_name == "Standard_ERC20_Transfer":
                feat = [
                    68.0,
                    random.uniform(2.7, 3.4),
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                    0.0,
                    0.96,                                     # transfer selector
                    0.0,
                    random.uniform(1.0, 1.15),
                    0.0,
                    0,
                    0.0,
                    random.uniform(0.85, 1.0)                 # highly verified token (USDT/USDC)
                ]
            elif cat_name == "1inch_Aggregator_Deep_Route":
                # Realistic Benign Edge Case: complex calldata, nested delegatecalls
                feat = [
                    random.uniform(600, 1800),                # very large calldata
                    random.uniform(5.2, 6.4),                 # high entropy
                    0.0,
                    1.0,                                      # uses DELEGATECALL to sub-dex routers
                    0.0,
                    1.0,
                    random.uniform(0.5, 15.0),
                    0.0,
                    random.uniform(0.65, 0.85),
                    random.uniform(0.0, 0.1),
                    random.uniform(1.8, 3.8),                 # high gas limit
                    random.uniform(0.0, 0.15),                # minor routing noise
                    random.randint(3, 7),                     # deep subcalls
                    0.0,
                    random.uniform(0.45, 0.75)                # exotic third-party DEX pools
                ]
            elif cat_name == "Permit2_Legitimate_Router_Approval":
                # Realistic Benign Edge Case: unbounded approval to legitimate Uniswap router
                feat = [
                    random.uniform(160, 224),
                    random.uniform(4.0, 4.8),
                    0.0,
                    0.0,
                    1.0,                                      # is_infinite_allowance = 1
                    1.0,
                    0.0,
                    0.0,
                    0.80,
                    0.0,
                    random.uniform(1.1, 1.4),
                    0.0,
                    1,
                    0.0,
                    random.uniform(0.70, 0.90)
                ]
            elif cat_name == "DAO_Timelock_Authorized_Upgrade":
                # Realistic Benign Edge Case: legitimate upgradeTo selector executed via GovernanceTimelock
                feat = [
                    random.uniform(80, 160),
                    random.uniform(3.8, 4.6),
                    1.0,                                      # is_upgrade_selector = 1
                    0.0,
                    0.0,
                    1.0,
                    0.0,
                    1.0,                                      # slot 0x3608 will be mutated legally
                    0.05,
                    0.0,
                    random.uniform(1.5, 2.5),
                    0.0,                                      # declared: "Execute passed governance proposal #42"
                    1,
                    1.0,                                      # is_governance_timelock_origin = 1.0!
                    0.90                                      # official protocol timelock
                ]
            elif cat_name == "Aave_V3_Flash_Loan_Arbitrage":
                feat = [
                    random.uniform(400, 950),
                    random.uniform(5.0, 6.1),
                    0.0,
                    random.choice([0.0, 1.0]),
                    0.0,
                    1.0,
                    random.uniform(10.0, 500.0),
                    0.0,
                    0.65,
                    random.uniform(0.05, 0.25),
                    random.uniform(2.5, 5.5),
                    0.0,
                    random.randint(4, 8),
                    0.0,
                    0.96
                ]
            else: # Standard swaps & staking
                feat = [
                    random.uniform(100, 320),
                    random.uniform(3.6, 4.7),
                    0.0,
                    0.0,
                    0.0,
                    1.0,
                    random.uniform(0.0, 10.0),
                    0.0,
                    random.uniform(0.80, 0.95),
                    0.0,
                    random.uniform(1.1, 1.6),
                    0.0,
                    random.randint(1, 3),
                    0.0,
                    random.uniform(0.85, 0.99)
                ]
            # Introduce realistic real-world noise for benign transactions (exotic DeFi & routing)
            benign_noise = random.random()
            if benign_noise < 0.065:
                # 6.5% of benign txs interact with brand new or unverified DEX pools & have complex routing
                feat[14] = random.uniform(0.15, 0.38) # low reputation pool contract
                feat[10] = random.uniform(2.8, 4.8)   # high gas limit estimation
                feat[8] = random.uniform(0.05, 0.25)  # non-standard aggregator selector
                feat[11] = random.uniform(0.35, 0.65) # aggregator route slippage deviation
            elif benign_noise < 0.12:
                feat[11] = random.uniform(0.15, 0.35)
                feat[1] = random.uniform(5.5, 6.8)
            
            X.append(feat)

    # Random shuffle
    combined = list(zip(X, y, metadata))
    random.shuffle(combined)
    X_shuffled, y_shuffled, meta_shuffled = zip(*combined)

    return list(X_shuffled), list(y_shuffled), list(meta_shuffled)
