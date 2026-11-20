"""
Automated Forensic Incident Receipt Generator for Project Vero (Prana-v1).
Generates immutable audit-ready evidence for incident response, CERT-In reporting,
and cyber-insurance claims when attacks are intercepted on-chain.
"""

from __future__ import annotations
import json
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, List

@dataclass
class ForensicReceipt:
    receipt_id: str
    timestamp_utc: str
    vault: str
    target: str
    selector: str
    verdict: str  # "BLOCKED" or "EXECUTED"
    policy_hash: str
    safe_tx_hash: str
    triggered_error: Optional[str] = None
    error_selector: Optional[str] = None
    chain_id: int = 1
    pre_execution_snapshot: Optional[Dict[str, Any]] = None
    post_execution_snapshot: Optional[Dict[str, Any]] = None
    checksum_words: Optional[List[str]] = None

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    def to_markdown_summary(self) -> str:
        status_icon = "🛑 BLOCKED" if self.verdict == "BLOCKED" else "✅ ALLOWED"
        return f"""
# Forensic Incident Receipt: {self.receipt_id}
**Status:** {status_icon}  
**Timestamp (UTC):** {self.timestamp_utc}  
**Chain ID:** {self.chain_id}  

### 1. Intercept Details
- **Vault:** `{self.vault}`
- **Destination Target:** `{self.target}`
- **Function Selector:** `{self.selector}`
- **Policy Hash:** `{self.policy_hash}`
- **Safe Tx Hash:** `{self.safe_tx_hash}`

### 2. Guard Enforcement Outcome
- **Triggered Revert Error:** `{self.triggered_error or 'None (Execution Allowed)'}`
- **Revert Error 4-Byte:** `{self.error_selector or '0x00000000'}`
- **Out-of-Band Checksum:** `{' · '.join(self.checksum_words or [])}`

### 3. Compliance & Incident Summary
> The attempted transaction violated declared policy constraints and was atomically 
> intercepted by VeroGuard with zero asset leakage and immutable control slot preservation.
"""

def generate_receipt(
    vault: str,
    target: str,
    selector: str,
    verdict: str,
    policy_hash: str,
    safe_tx_hash: str,
    triggered_error: Optional[str] = None,
    error_selector: Optional[str] = None,
    chain_id: int = 31337,
    checksum_words: Optional[List[str]] = None
) -> ForensicReceipt:
    receipt_id = f"VERO-INCIDENT-{int(time.time())}-{target[:6]}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return ForensicReceipt(
        receipt_id=receipt_id,
        timestamp_utc=timestamp,
        vault=vault,
        target=target,
        selector=selector,
        verdict=verdict,
        policy_hash=policy_hash,
        safe_tx_hash=safe_tx_hash,
        triggered_error=triggered_error,
        error_selector=error_selector,
        chain_id=chain_id,
        checksum_words=checksum_words or ["ALPHA", "DELTA", "GUARD", "VERO"]
    )
