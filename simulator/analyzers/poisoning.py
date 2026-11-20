"""
Address Poisoning, Clipboard Hijack, and Quai Shard-Prefix Spoofing Analyzer.
Covers Feature #33 and Quai Network Shard Integrity.
"""

from typing import List, Dict, Any, Optional, Set
from shared.schemas import QUAI_ZONES, get_quai_zone_for_address, is_quai_address_valid_for_zone


def is_lookalike(a: str, b: str) -> bool:
    """True if distinct addresses share identical first 4 and last 4 hex characters."""
    a_clean = a.lower().replace("0x", "")
    b_clean = b.lower().replace("0x", "")
    if a_clean == b_clean or len(a_clean) != 40 or len(b_clean) != 40:
        return False
    return a_clean[:4] == b_clean[:4] and a_clean[-4:] == b_clean[-4:]


def detect_address_poisoning(
    candidate_address: str,
    trusted_addresses: List[str]
) -> Optional[Dict[str, Any]]:
    """Flags if candidate address is a vanity poison copy of a trusted address."""
    for trusted in trusted_addresses:
        if is_lookalike(candidate_address, trusted):
            return {
                "detected": True,
                "type": "VANITY_POISON_LOOKALIKE",
                "candidate": candidate_address,
                "imitated_target": trusted,
                "reason": f"Address {candidate_address} shares first-4 and last-4 characters with trusted contact {trusted}.",
            }
    return None


def detect_quai_shard_prefix_spoofing(
    target_address: str,
    expected_zone: str = "cyprus1"
) -> Optional[Dict[str, Any]]:
    """
    Validates Quai Network shard prefix bounds.
    E.g. Cyprus-1 requires '0x00...' prefix. If a transaction targets a non-matching
    shard or an address spoofing another zone, flags cross-shard violation.
    """
    expected_zone_lower = expected_zone.lower()
    expected_meta = QUAI_ZONES.get(expected_zone_lower)
    if not expected_meta:
        return None

    actual_zone = get_quai_zone_for_address(target_address)
    expected_prefix = expected_meta["prefix"].lower()
    actual_prefix = "0x" + target_address.lower().replace("0x", "")[:2]

    if actual_prefix != expected_prefix:
        return {
            "spoofing_detected": True,
            "type": "QUAI_SHARD_PREFIX_SPOOFING",
            "target_address": target_address,
            "expected_zone": expected_zone,
            "expected_prefix": expected_prefix,
            "actual_prefix": actual_prefix,
            "detected_zone": actual_zone or "UNKNOWN_NON_QUAI",
            "warning": (
                f"SHARD MISMATCH: Transaction claims to execute in Quai zone '{expected_zone}' "
                f"(expected prefix {expected_prefix}), but target address {target_address} has "
                f"prefix {actual_prefix} (belongs to {actual_zone or 'external chain'}). Cross-shard ETX or replay risk!"
            ),
        }
    return None
