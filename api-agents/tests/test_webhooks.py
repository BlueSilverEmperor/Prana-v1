"""Unit tests for HMAC-signed webhook dispatcher (#44)."""

import hashlib
import hmac
import json
import unittest
from api_agents.webhooks.dispatcher import (
    AlertPayload,
    WebhookDispatcher,
    compute_webhook_hmac,
)


class TestWebhooks(unittest.TestCase):

    def test_hmac_signature_calculation(self):
        secret = "super_secret_key"
        data = b'{"decision":"BLOCK","risk":95}'
        sig = compute_webhook_hmac(secret, data)
        expected = hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()
        self.assertEqual(sig, expected)

    def test_local_dispatch_mode(self):
        dispatcher = WebhookDispatcher(secret_key="test_secret")
        alert = AlertPayload(
            event_type="TRANSACTION_BLOCKED",
            chain_id=1,
            safe_address="0x1111111111111111111111111111111111111111",
            target_contract="0x2222222222222222222222222222222222222222",
            decision="BLOCK",
            risk_score=95,
            flags=["INFINITE_TOKEN_APPROVAL"],
            four_word_checksum="alpha-beta-gamma-delta",
            timestamp="2026-11-20T12:00:00Z",
        )
        res = dispatcher.dispatch(alert)
        self.assertEqual(res["status"], "QUEUED_LOCAL_ONLY")
        self.assertTrue(res["signature"].startswith("sha256="))


if __name__ == "__main__":
    unittest.main()
