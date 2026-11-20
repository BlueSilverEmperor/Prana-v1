"""
Threat-Intel Triage Agent (#41).
Analyzes incoming telemetry, incident reports, and suspicious contract addresses,
and drafts structured additions to the ThreatRegistry.

INVARIANT:
All drafted additions are marked strictly as status="DRAFT_PENDING_HUMAN_APPROVAL".
No threat rule can be autonomously committed into production without security officer sign-off.
"""

from dataclasses import dataclass, field
import datetime
from typing import Any, Dict, List, Optional
from api_agents.utils.keccak import keccak256


@dataclass
class ThreatRegistryEntryDraft:
    entry_id: str
    status: str = "DRAFT_PENDING_HUMAN_APPROVAL"  # STRICT INVARIANT
    ioc_type: str = ""  # "ADDRESS", "METHOD_SELECTOR", "BYTECODE_HASH", "PHISHING_ORIGIN"
    value: str = ""
    threat_category: str = ""  # "MULTISIG_HIJACK", "INFINITE_DRAINER", "FAKE_ROUTER", "PHISHING_ORIGIN"
    severity: str = "HIGH"  # "CRITICAL", "HIGH", "MEDIUM"
    proposed_firewall_action: str = "BLOCK"
    description: str = ""
    evidence_hashes: List[str] = field(default_factory=list)
    created_at: str = ""
    analyst_review_checklist: List[str] = field(default_factory=list)


def triage_threat_incident(
    indicator: str,
    threat_category: str,
    raw_payload_or_log: str,
    reporter_source: str = "ANOMALY_WATCHER",
) -> ThreatRegistryEntryDraft:
    """
    Ingests an alert or observed malicious vector and drafts a ThreatRegistry record.
    """
    clean_val = indicator.strip()
    evidence_hash = "0x" + keccak256(raw_payload_or_log.encode("utf-8")).hex()
    
    # Classify IOC type
    if clean_val.startswith("0x") and len(clean_val) == 42:
        ioc_type = "ADDRESS"
    elif clean_val.startswith("0x") and len(clean_val) == 10:
        ioc_type = "METHOD_SELECTOR"
    elif clean_val.startswith("http://") or clean_val.startswith("https://"):
        ioc_type = "PHISHING_ORIGIN"
    else:
        ioc_type = "BYTECODE_HASH"

    # Determine severity
    category_upper = threat_category.upper()
    if "MULTISIG" in category_upper or "DRAIN" in category_upper or "PROXY" in category_upper:
        severity = "CRITICAL"
        action = "BLOCK"
    elif "PHISHING" in category_upper:
        severity = "HIGH"
        action = "BLOCK"
    else:
        severity = "MEDIUM"
        action = "WARN"

    entry_id = "VTR-" + keccak256((clean_val + threat_category).encode("utf-8")).hex()[:8].upper()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    checklist = [
        "1. Confirm contract source code or decompiled opcode verification on block explorer.",
        "2. Check Dune/Arkham intelligence for illicit funding associations.",
        "3. Verify non-involvement in legitimate protocols (false positive check).",
        "4. Obtain secondary analyst cryptographic signature to promote from DRAFT to ACTIVE."
    ]

    return ThreatRegistryEntryDraft(
        entry_id=entry_id,
        status="DRAFT_PENDING_HUMAN_APPROVAL",  # Required human approval guard
        ioc_type=ioc_type,
        value=clean_val,
        threat_category=threat_category,
        severity=severity,
        proposed_firewall_action=action,
        description=f"Auto-triaged {threat_category} reported by {reporter_source}.",
        evidence_hashes=[evidence_hash],
        created_at=now_iso,
        analyst_review_checklist=checklist,
    )
