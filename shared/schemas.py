"""
Shared Canonical Schemas and EIP-712 Types for Project Vero.
Synchronized with VeroGuard.sol.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

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

# Standard keccak256 implementation in pure python (or using hashlib if sha3 available)
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
            # Fallback to standard hashlib sha3_256 if keccak unavailable
            # Notice in production environment eth-hash or pycryptodome is used
            import hashlib
            return hashlib.sha3_256(data).digest()

def get_intent_policy_typehash_hex() -> str:
    # Precomputed standard keccak256 of INTENT_POLICY_TYPE_STRING
    # "IntentPolicy(address vault,uint256 nonce,uint256 deadline,uint256 maxGasFeeWei,bool allowDelegateCall,address[] allowedTargets,bytes4[] allowedSelectors,address[] tokenAddresses,uint256[] maxTokenSpends,uint256 ethValueCap,bool sessionKeyEnabled,address sessionAgent)"
    return "0x7856e138a0a91176b50937a505b0cf8e8f815a5fbcbc0734da65b82215c2ec89"

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
        )

    def to_eip712_message(self, chain_id: int, verifying_contract: str) -> Dict[str, Any]:
        """Construct the standard EIP-712 payload dictionary for eth_signTypedData_v4."""
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
            "message": self.to_dict(),
        }


# Canonical Revert Error Signatures for AI Parser & Off-Chain Handlers
REVERT_ERRORS = {
    "IntentExpired": "0x7c73c380",
    "StateDriftDetected": "0x2e06191a",
    "GasPriceTooHigh": "0xdae2dbfc",
    "TargetBlacklisted": "0x98f98d5c",
    "DelegateCallNotAllowed": "0x9b325c7e",
    "InvalidTarget": "0x77ad587c",
    "SelectorNotAllowed": "0x892a0e20",
    "MultiSendValidationFailed": "0x9ebccb40",
    "TokenSpendExceeded": "0x0d7c2a71",
    "EthValueCapExceeded": "0xdf843588",
    "UndeclaredTokenOutflow": "0x8fa838ef",
    "ControlSlotMutated": "0xdbe73428",
    "ModuleFirewallBlocked": "0xd3c2d4ff",
    "EIP7702DelegationBlocked": "0x8382da37",
    "GuardPaused": "0x9c313a43",
    "DeadMansSwitchActive": "0x05bca4a8",
    "DailySpendCapExceeded": "0xc5b6510f",
    "UnauthorizedSigner": "0x82f25459",
    "ThresholdNotMet": "0xa98877bc",
    "ProposalNotReady": "0x21b332b7",
    "ProposalAlreadyVetoed": "0x075aee50",
    "ProposalAlreadyExecuted": "0xecaa5572",
}
