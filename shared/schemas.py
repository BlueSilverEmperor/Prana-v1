"""
Shared Canonical Schemas and EIP-712 Types for Project Vero.
Synchronized with VeroGuard.sol and QuaiVeroAdapter.sol.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional

# Engine Subsystem Mode Toggle
class EngineMode(str, Enum):
    STANDARD_EVM = "STANDARD_EVM"
    QUAI_NATIVE = "QUAI_NATIVE"

# Quai Network Specifications & Shard Coordinate Registry
QUAI_ZONES = {
    "cyprus1": {"name": "Cyprus-1", "coords": [0, 0], "prefix": "0x00"},
    "cyprus2": {"name": "Cyprus-2", "coords": [0, 1], "prefix": "0x01"},
    "cyprus3": {"name": "Cyprus-3", "coords": [0, 2], "prefix": "0x02"},
    "pitt1": {"name": "Pitt-1", "coords": [1, 0], "prefix": "0x10"},
    "pitt2": {"name": "Pitt-2", "coords": [1, 1], "prefix": "0x11"},
    "pitt3": {"name": "Pitt-3", "coords": [1, 2], "prefix": "0x12"},
    "paxos1": {"name": "Paxos-1", "coords": [2, 0], "prefix": "0x20"},
    "paxos2": {"name": "Paxos-2", "coords": [2, 1], "prefix": "0x21"},
    "paxos3": {"name": "Paxos-3", "coords": [2, 2], "prefix": "0x22"},
}

QUAI_NETWORKS = {
    "mainnet": {
        "chain_id": 9,
        "name": "Quai Mainnet",
        "rpc": "https://rpc.quai.network/cyprus1",
        "explorer": "https://quaiscan.io",
        "default_zone": "cyprus1",
        "default_coords": [0, 0],
    },
    "orchard": {
        "chain_id": 15000,
        "name": "Quai Orchard Testnet",
        "rpc": "https://orchard.rpc.quai.network/cyprus1",
        "explorer": "https://orchard.quaiscan.io",
        "faucet": "https://orchard.faucet.quai.network",
        "default_zone": "cyprus1",
        "default_coords": [0, 0],
    },
}

def get_quai_zone_for_address(address: str) -> Optional[str]:
    """Derives Quai shard zone from the first byte of address."""
    if not address or len(address) < 4:
        return None
    clean = address.lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    prefix = "0x" + clean[:2]
    for zone_key, zone_data in QUAI_ZONES.items():
        if zone_data["prefix"].lower() == prefix:
            return zone_key
    return None

def is_quai_address_valid_for_zone(address: str, expected_zone: str = "cyprus1") -> bool:
    """Verifies that an address belongs to the expected Quai shard zone."""
    detected = get_quai_zone_for_address(address)
    return detected == expected_zone.lower()

# EIP-712 Domain Constants
EIP712_DOMAIN_NAME = "VeroGuard"
EIP712_DOMAIN_VERSION = "1"

# IntentPolicy EIP-712 Type Definition
INTENT_POLICY_TYPE_STRING = (
    "IntentPolicy("
    "address vault,"
    "uint256 nonce,"
    "uint256 deadline,"
    "uint256 maxGasFeeWei,"
    "bool allowDelegateCall,"
    "address[] allowedTargets,"
    "bytes4[] allowedSelectors,"
    "address[] tokenAddresses,"
    "uint256[] maxTokenSpends,"
    "uint256 ethValueCap,"
    "bool sessionKeyEnabled,"
    "address sessionAgent"
    ")"
)

# Standard keccak256 implementation in pure python
def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        try:
            import sha3
            k = sha3.keccak_256()
            k.update(data)
            return k.digest()
        except Exception:
            import hashlib
            return hashlib.sha3_256(data).digest()

def get_intent_policy_typehash_hex() -> str:
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256)
    k.update(INTENT_POLICY_TYPE_STRING.encode())
    return "0x" + k.digest().hex()

INTENT_POLICY_TYPEHASH = get_intent_policy_typehash_hex()

EIP712_DOMAIN_TYPE_STRING = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"


@dataclass
class IntentPolicy:
    vault: str
    nonce: int
    deadline: int
    maxGasFeeWei: int
    allowDelegateCall: bool
    allowedTargets: List[str] = field(default_factory=list)
    allowedSelectors: List[str] = field(default_factory=list)
    tokenAddresses: List[str] = field(default_factory=list)
    maxTokenSpends: List[int] = field(default_factory=list)
    ethValueCap: int = 0
    sessionKeyEnabled: bool = False
    sessionAgent: str = "0x0000000000000000000000000000000000000000"
    mode: str = "STANDARD_EVM"
    shardZone: str = "cyprus1"
    quaiValueCap: int = 0
    qiValueCap: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntentPolicy":
        return cls(
            vault=data.get("vault", "0x0000000000000000000000000000000000000000"),
            nonce=int(data.get("nonce", 0)),
            deadline=int(data.get("deadline", 0)),
            maxGasFeeWei=int(data.get("maxGasFeeWei", 0)),
            allowDelegateCall=bool(data.get("allowDelegateCall", False)),
            allowedTargets=[str(t) for t in data.get("allowedTargets", [])],
            allowedSelectors=[str(s) for s in data.get("allowedSelectors", [])],
            tokenAddresses=[str(a) for a in data.get("tokenAddresses", [])],
            maxTokenSpends=[int(s) for s in data.get("maxTokenSpends", [])],
            ethValueCap=int(data.get("ethValueCap", 0)),
            sessionKeyEnabled=bool(data.get("sessionKeyEnabled", False)),
            sessionAgent=data.get("sessionAgent", "0x0000000000000000000000000000000000000000"),
            mode=str(data.get("mode", "STANDARD_EVM")),
            shardZone=str(data.get("shardZone", "cyprus1")),
            quaiValueCap=int(data.get("quaiValueCap", 0)),
            qiValueCap=int(data.get("qiValueCap", 0)),
        )

    def to_eip712_message(self, chain_id: int, verifying_contract: str) -> Dict[str, Any]:
        """Construct the standard EIP-712 payload dictionary for eth_signTypedData_v4."""
        base_msg = {
            "vault": self.vault,
            "nonce": self.nonce,
            "deadline": self.deadline,
            "maxGasFeeWei": self.maxGasFeeWei,
            "allowDelegateCall": self.allowDelegateCall,
            "allowedTargets": self.allowedTargets,
            "allowedSelectors": self.allowedSelectors,
            "tokenAddresses": self.tokenAddresses,
            "maxTokenSpends": self.maxTokenSpends,
            "ethValueCap": self.ethValueCap,
            "sessionKeyEnabled": self.sessionKeyEnabled,
            "sessionAgent": self.sessionAgent,
        }
        return {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "IntentPolicy": [
                    {"name": "vault", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                    {"name": "maxGasFeeWei", "type": "uint256"},
                    {"name": "allowDelegateCall", "type": "bool"},
                    {"name": "allowedTargets", "type": "address[]"},
                    {"name": "allowedSelectors", "type": "bytes4[]"},
                    {"name": "tokenAddresses", "type": "address[]"},
                    {"name": "maxTokenSpends", "type": "uint256[]"},
                    {"name": "ethValueCap", "type": "uint256"},
                    {"name": "sessionKeyEnabled", "type": "bool"},
                    {"name": "sessionAgent", "type": "address"},
                ],
            },
            "primaryType": "IntentPolicy",
            "domain": {
                "name": EIP712_DOMAIN_NAME,
                "version": EIP712_DOMAIN_VERSION,
                "chainId": chain_id,
                "verifyingContract": verifying_contract,
            },
            "message": base_msg,
        }


# Canonical Revert Error Signatures for AI Parser & Off-Chain Handlers
REVERT_ERRORS = {
    "IntentExpired": "0x6f08ee6e",  # IntentExpired(uint256,uint256)
    "StateDriftDetected": "0x6017fe55",  # StateDriftDetected(uint256,uint256)
    "GasPriceTooHigh": "0x94118333",  # GasPriceTooHigh(uint256,uint256)
    "TargetBlacklisted": "0x7d7aaf3c",  # TargetBlacklisted(address)
    "DelegateCallNotAllowed": "0x5d9179f4",  # DelegateCallNotAllowed(address)
    "InvalidTarget": "0xd08525e9",  # InvalidTarget(address)
    "SelectorNotAllowed": "0x3b06e146",  # SelectorNotAllowed(bytes4)
    "MultiSendValidationFailed": "0xcdb6bdc1",  # MultiSendValidationFailed(address,bytes4)
    "TokenSpendExceeded": "0x80cca11f",  # TokenSpendExceeded(address,uint256,uint256)
    "EthValueCapExceeded": "0x133a6514",  # EthValueCapExceeded(uint256,uint256)
    "UndeclaredTokenOutflow": "0xdfe7752b",  # UndeclaredTokenOutflow(address,uint256)
    "ControlSlotMutated": "0xeb70581e",  # ControlSlotMutated(string)
    "ModuleFirewallBlocked": "0xdbba5ec3",  # ModuleFirewallBlocked(bytes4,address)
    "EIP7702DelegationBlocked": "0xa2c2b4ba",  # EIP7702DelegationBlocked()
    "GuardPaused": "0x0cd8b4b5",  # GuardPaused()
    "DeadMansSwitchActive": "0x3ad5667d",  # DeadMansSwitchActive(address)
    "DailySpendCapExceeded": "0x7d07219c",  # DailySpendCapExceeded(uint256,uint256)
    "UnauthorizedSigner": "0xe74c68bb",  # UnauthorizedSigner(address)
    "ThresholdNotMet": "0xb7842ce0",  # ThresholdNotMet(uint256,uint256)
    "ExecutionFailed": "0x15fcd675",  # ExecutionFailed(bytes)
    "RecoveryVaultNotSet": "0xba3c0ebd",  # RecoveryVaultNotSet(address)
    "AgentCooldownActive": "0xfc13362b",  # AgentCooldownActive(uint256,uint256)
    "ProposalNotReady": "0x47702f6f",  # ProposalNotReady(bytes32,uint256)
    "ProposalAlreadyVetoed": "0xe932faee",  # ProposalAlreadyVetoed(bytes32)
    "ProposalAlreadyExecuted": "0x2698e086",  # ProposalAlreadyExecuted(bytes32)
    "ProposalDoesNotExist": "0x318f5460",  # ProposalDoesNotExist(bytes32)
    "UnauthorizedVeto": "0xb69a12cd",  # UnauthorizedVeto(address)
    "UnauthorizedSweep": "0x321fb873",  # UnauthorizedSweep()
    "NoPendingPolicy": "0xe486312e",  # NoPendingPolicy(address)
    "UnauthorizedSafe": "0xf71d26f3",  # UnauthorizedSafe(address)
    # Quai Extensions
    "CrossShardReplayBlocked": "0x89e229c1", # CrossShardReplayBlocked(bytes32,bytes32)
    "QiSpendCapExceeded": "0x56a42ec7",     # QiSpendCapExceeded(uint256,uint256)
    "QuaiSpendCapExceeded": "0xd358f27a",   # QuaiSpendCapExceeded(uint256,uint256)
    "QiVelocityCapExceeded": "0x98d415b3",  # QiVelocityCapExceeded(uint256,uint256)
}

# Reverse lookup dictionary
SELECTOR_TO_ERROR_NAME = {v.lower(): k for k, v in REVERT_ERRORS.items()}

def decode_revert_error(selector_or_data: str) -> Optional[str]:
    """Decodes a 4-byte revert selector (or full error data) into human-readable error name."""
    if not selector_or_data:
        return None
    clean = selector_or_data.strip().lower()
    if clean.startswith("0x"):
        clean = clean[2:]
    if len(clean) >= 8:
        sel = "0x" + clean[:8]
        return SELECTOR_TO_ERROR_NAME.get(sel)
    return None
