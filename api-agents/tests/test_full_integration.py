"""
End-to-End Full Integration Test (Phase 7).
Tests the entire pipeline:
SDK Payload -> Firewall API (/v1/simulate) -> Deterministic Mock Engine ->
BIP-39 Checksum -> Webhook Alert (HMAC) -> Signed Ed25519 Forensic Receipt.
"""

import os
import tempfile
import unittest
from fastapi.testclient import TestClient
from api_agents.forensics.cert_in_exporter import export_receipt_to_json
from api_agents.forensics.signer import verify
from api_agents.main import app
from api_agents.models.schemas import DecisionEnum
from api_agents.webhooks.dispatcher import AlertPayload, WebhookDispatcher


class TestFullIntegration(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_full_e2e_blocked_malicious_flow(self):
        # 1. Malicious transaction payload (WazirX-class proxy implementation replacement)
        new_impl_address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        calldata = "0x3659cfe6" + "0" * 24 + new_impl_address[2:]

        simulate_payload = {
            "chain_id": 1,
            "safe_address": "0x1111111111111111111111111111111111111111",
            "to": "0x5afe000000000000000000000000000000000001",  # was non-hex "0xSafeProxy..."; real engine validates addresses
            "value": "0",
            "data": calldata,
            "nonce": 12,
        }

        # 2. Fire request into /v1/simulate
        sim_res = self.client.post("/v1/simulate", json=simulate_payload)
        self.assertEqual(sim_res.status_code, 200)
        sim_body = sim_res.json()

        # Assert firewall blocked the malicious payload
        self.assertEqual(sim_body["decision"], DecisionEnum.BLOCK.value)
        self.assertEqual(sim_body["risk_score"], 95)
        self.assertIn("PROXY_UPGRADE_ATTEMPT", sim_body["flags"])
        self.assertTrue(len(sim_body["four_word_checksum"].split("-")) == 4)
        self.assertLess(sim_body["simulation_ms"], 150.0)

        # 3. Dispatch HMAC-signed security alert to SIEM
        dispatcher = WebhookDispatcher(secret_key="integration_test_secret")
        alert = AlertPayload(
            event_type="TRANSACTION_BLOCKED",
            chain_id=simulate_payload["chain_id"],
            safe_address=simulate_payload["safe_address"],
            target_contract=simulate_payload["to"],
            decision=sim_body["decision"],
            risk_score=sim_body["risk_score"],
            flags=sim_body["flags"],
            four_word_checksum=sim_body["four_word_checksum"],
            timestamp="2026-11-20T12:30:00Z",
        )
        dispatch_result = dispatcher.dispatch(alert)
        self.assertTrue(dispatch_result["signature"].startswith("sha256="))

        # 4. Request signed Ed25519 Forensic Audit Receipt
        receipt_req = {
            "chain_id": simulate_payload["chain_id"],
            "safe_address": simulate_payload["safe_address"],
            "target_contract": simulate_payload["to"],
            "raw_tx_hash": sim_body["raw_tx_hash"],
            "intent_hash": sim_body["intent_digest"],
            "four_word_checksum": sim_body["four_word_checksum"],
            "decision": sim_body["decision"],
            "risk_score": sim_body["risk_score"],
            "flags": sim_body["flags"],
            "human_warnings": sim_body["deterministic_human_warnings"],
        }
        receipt_res = self.client.post("/v1/audit-receipt", json=receipt_req)
        self.assertEqual(receipt_res.status_code, 200)
        receipt_body = receipt_res.json()

        # 5. Cryptographically verify the Ed25519 signature on the receipt
        signable_bytes = (
            f"{receipt_body['receipt_id']}|{receipt_body['timestamp']}|{receipt_body['chain_id']}|"
            f"{receipt_body['safe_address'].lower()}|{receipt_body['raw_tx_hash'].lower()}|"
            f"{receipt_body['decision']}|{receipt_body['risk_score']}"
        ).encode("utf-8")

        sig_bytes = bytes.fromhex(receipt_body["ed25519_signature"])
        pk_bytes = bytes.fromhex(receipt_body["public_key"])

        is_valid = verify(sig_bytes, signable_bytes, pk_bytes)
        self.assertTrue(is_valid, "Receipt signature must be cryptographically valid")


if __name__ == "__main__":
    unittest.main()
