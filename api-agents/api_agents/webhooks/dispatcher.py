"""
HMAC-Signed Alert Webhook Dispatcher (#44).
Dispatches security alerts to SIEM, Slack, and Telegram endpoints.

Design Invariants:
- Webhook authenticity is secured via HMAC-SHA256 (Ed25519 is for receipts).
- Headers: X-Vero-Signature: sha256=<hex_signature>, X-Vero-Timestamp: <iso_time>.
- Exponential backoff retry logic.
"""

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional
import httpx


@dataclass
class AlertPayload:
    event_type: str  # "TRANSACTION_BLOCKED", "HIGH_RISK_WARNING", "POLICY_VIOLATION"
    chain_id: int
    safe_address: str
    target_contract: str
    decision: str
    risk_score: int
    flags: List[str]
    four_word_checksum: str
    timestamp: str


def compute_webhook_hmac(secret_key: str, payload_bytes: bytes) -> str:
    """Computes HMAC-SHA256 signature over payload bytes."""
    mac = hmac.new(secret_key.encode("utf-8"), payload_bytes, hashlib.sha256)
    return mac.hexdigest()


class WebhookDispatcher:
    def __init__(
        self,
        webhook_urls: Optional[List[str]] = None,
        secret_key: str = "vero_default_hmac_secret_2026",
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        self.webhook_urls = webhook_urls or []
        self.secret_key = secret_key
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    def dispatch(
        self,
        alert: AlertPayload,
        client: Optional[httpx.Client] = None,
    ) -> Dict[str, Any]:
        """
        Dispatches alert to all configured endpoints with HMAC-SHA256 signature and retries.
        """
        payload_dict = asdict(alert)
        payload_json = json.dumps(payload_dict, sort_keys=True)
        payload_bytes = payload_json.encode("utf-8")

        sig_hex = compute_webhook_hmac(self.secret_key, payload_bytes)
        headers = {
            "Content-Type": "application/json",
            "X-Vero-Signature": f"sha256={sig_hex}",
            "X-Vero-Timestamp": alert.timestamp,
        }

        results: Dict[str, Any] = {}

        # If no URLs configured or mock mode, return verified signature dispatch summary
        if not self.webhook_urls:
            return {
                "dispatched_count": 0,
                "signature": f"sha256={sig_hex}",
                "status": "QUEUED_LOCAL_ONLY",
            }

        should_close = False
        if client is None:
            client = httpx.Client(timeout=5.0)
            should_close = True

        try:
            for url in self.webhook_urls:
                success = False
                last_err = ""
                for attempt in range(self.max_retries):
                    try:
                        res = client.post(url, content=payload_bytes, headers=headers)
                        if res.status_code in (200, 201, 202):
                            success = True
                            results[url] = {"status": "DELIVERED", "code": res.status_code}
                            break
                        else:
                            last_err = f"HTTP {res.status_code}"
                    except Exception as e:
                        last_err = str(e)
                    time.sleep(self.backoff_factor * (2**attempt))

                if not success:
                    results[url] = {"status": "FAILED", "error": last_err}
        finally:
            if should_close:
                client.close()

        return {
            "dispatched_count": len([r for r in results.values() if r.get("status") == "DELIVERED"]),
            "signature": f"sha256={sig_hex}",
            "endpoints": results,
        }
