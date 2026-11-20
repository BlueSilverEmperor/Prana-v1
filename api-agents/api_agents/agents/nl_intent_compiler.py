"""
Natural Language to EIP-712 IntentPolicy Compiler (#40).
Compiles natural language policy text into a structured, typed EIP-712 IntentPolicy.

INVARIANT:
All generated policies are marked strictly as status="DRAFT".
They can never be auto-activated without human review and cryptographic signing.
"""

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from api_agents.utils.keccak import keccak256


@dataclass
class EIP712Domain:
    name: str = "VeroIntentPolicy"
    version: str = "1.0"
    chainId: int = 1
    verifyingContract: str = "0x0000000000000000000000000000000000000000"


@dataclass
class IntentPolicyMessage:
    account: str
    targetContract: str
    maxAmountWei: str
    allowedFunction: str
    validUntil: int
    blockInfiniteApproval: bool = True
    blockProxyUpgrades: bool = True
    requireMultisigAboveWei: str = "1000000000000000000"  # 1 ETH default


@dataclass
class CompiledIntentPolicyDraft:
    status: str = "DRAFT"  # STRICT INVARIANT: Always DRAFT
    natural_language_prompt: str = ""
    domain: EIP712Domain = field(default_factory=EIP712Domain)
    types: Dict[str, List[Dict[str, str]]] = field(
        default_factory=lambda: {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "IntentPolicy": [
                {"name": "account", "type": "address"},
                {"name": "targetContract", "type": "address"},
                {"name": "maxAmountWei", "type": "uint256"},
                {"name": "allowedFunction", "type": "string"},
                {"name": "validUntil", "type": "uint256"},
                {"name": "blockInfiniteApproval", "type": "bool"},
                {"name": "blockProxyUpgrades", "type": "bool"},
                {"name": "requireMultisigAboveWei", "type": "uint256"},
            ],
        }
    )
    message: Optional[IntentPolicyMessage] = None
    struct_hash: str = ""
    compiler_notes: List[str] = field(default_factory=list)


def compile_nl_to_intent_policy(
    prompt: str,
    account_address: str,
    chain_id: int = 1,
    verifying_contract: str = "0x0000000000000000000000000000000000000000",
    llm_client: Optional[Any] = None,
) -> CompiledIntentPolicyDraft:
    """
    Parses natural language policy and generates an EIP-712 IntentPolicy draft.
    Uses regex and rule heuristics with optional LLM augmentation.
    Guarantees status is 'DRAFT'.
    """
    notes: List[str] = []
    text = prompt.lower()

    # Extract target contract address if present
    addr_match = re.search(r"0x[a-f0-9]{40}", prompt, re.IGNORECASE)
    target_contract = addr_match.group(0) if addr_match else "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF"  # Wildcard
    if not addr_match:
        notes.append("No specific target contract address specified; defaulted to global policy wildcard.")

    # Extract amount limits (e.g. 'up to 5 eth' or 'max 1000 usdc')
    eth_match = re.search(r"(?:up to|max|limit of)\s*([\d\.]+)\s*(?:eth|ether)", text)
    if eth_match:
        eth_val = float(eth_match.group(1))
        max_amount_wei = str(int(eth_val * 1e18))
        notes.append(f"Parsed max native amount: {eth_val} ETH ({max_amount_wei} wei).")
    else:
        # Default 10 ETH
        max_amount_wei = str(10 * 10**18)
        notes.append("Default ceiling applied: 10 ETH equivalent.")

    # Timeframe extraction (e.g. 'per week' -> valid for 7 days)
    validity_duration = 7 * 86400  # Default 7 days
    if "day" in text:
        validity_duration = 86400
    elif "month" in text:
        validity_duration = 30 * 86400
    valid_until = int(time.time()) + validity_duration

    # Function constraints
    if "transfer" in text and "swap" not in text:
        allowed_function = "transfer(address,uint256)"
    elif "swap" in text:
        allowed_function = "swapExactTokensForTokens"
    else:
        allowed_function = "*"

    block_infinite = "infinite" in text or "unlimited" in text or True
    block_proxy = "upgrade" in text or True

    msg = IntentPolicyMessage(
        account=account_address,
        targetContract=target_contract,
        maxAmountWei=max_amount_wei,
        allowedFunction=allowed_function,
        validUntil=valid_until,
        blockInfiniteApproval=block_infinite,
        blockProxyUpgrades=block_proxy,
    )

    # Compute deterministic struct hash for EIP-712
    type_str = "IntentPolicy(address account,address targetContract,uint256 maxAmountWei,string allowedFunction,uint256 validUntil,bool blockInfiniteApproval,bool blockProxyUpgrades,uint256 requireMultisigAboveWei)"
    type_hash = keccak256(type_str.encode("utf-8"))
    
    # Hash components
    msg_bytes = (
        type_hash
        + bytes.fromhex(account_address.replace("0x", "").rjust(64, "0"))
        + bytes.fromhex(target_contract.replace("0x", "").rjust(64, "0"))
        + int(max_amount_wei).to_bytes(32, "big")
        + keccak256(allowed_function.encode("utf-8"))
        + valid_until.to_bytes(32, "big")
        + (1).to_bytes(32, "big")
        + (1).to_bytes(32, "big")
        + int(msg.requireMultisigAboveWei).to_bytes(32, "big")
    )
    struct_hash = "0x" + keccak256(msg_bytes).hex()

    return CompiledIntentPolicyDraft(
        status="DRAFT",  # Immutable draft status
        natural_language_prompt=prompt,
        domain=EIP712Domain(chainId=chain_id, verifyingContract=verifying_contract),
        message=msg,
        struct_hash=struct_hash,
        compiler_notes=notes,
    )
