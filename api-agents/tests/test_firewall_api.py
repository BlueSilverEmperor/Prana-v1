"""Integration tests for Firewall API endpoints: /v1/simulate and /v1/verify-intent."""

import unittest
from fastapi.testclient import TestClient
from api_agents.main import app
from api_agents.models.schemas import DecisionEnum


class TestFirewallAPI(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_health(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")

    def test_simulate_clean_transfer(self):
        payload = {
            "chain_id": 1,
            "safe_address": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "1000000000000000000",
            "data": "0x",
            "nonce": 5,
        }
        res = self.client.post("/v1/simulate", json=payload)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], DecisionEnum.ALLOW.value)
        self.assertLess(body["risk_score"], 40)
        self.assertTrue(len(body["four_word_checksum"].split("-")) == 4)
        self.assertLess(body["simulation_ms"], 150.0)

    def test_simulate_infinite_approval_blocks(self):
        # approve(spender, 2^256 - 1)
        spender = "0000000000000000000000008888888888888888888888888888888888888888"
        amount_max = "f" * 64
        data = "0x095ea7b3" + spender + amount_max

        payload = {
            "chain_id": 1,
            "safe_address": "0x1111111111111111111111111111111111111111",
            "to": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "value": "0",
            "data": data,
            "nonce": 6,
        }
        res = self.client.post("/v1/simulate", json=payload)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], DecisionEnum.BLOCK.value)
        self.assertIn("INFINITE_TOKEN_APPROVAL", body["flags"])
        self.assertGreaterEqual(body["risk_score"], 80)
        self.assertGreater(len(body["deterministic_human_warnings"]), 0)

    def test_simulate_proxy_upgrade_blocks(self):
        # upgradeTo(newImpl)
        new_impl = "0000000000000000000000004444444444444444444444444444444444444444"
        data = "0x3659cfe6" + new_impl

        payload = {
            "chain_id": 1,
            "safe_address": "0x1111111111111111111111111111111111111111",
            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "value": "0",
            "data": data,
            "nonce": 7,
        }
        res = self.client.post("/v1/simulate", json=payload)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], DecisionEnum.BLOCK.value)
        self.assertIn("PROXY_UPGRADE_ATTEMPT", body["flags"])
        self.assertEqual(body["risk_score"], 95)

    def test_verify_intent_matching(self):
        # Matching transfer
        recipient = "7777777777777777777777777777777777777777"
        recipient_padded = "000000000000000000000000" + recipient
        amount_hex = f"{1000:064x}"
        data = "0xa9059cbb" + recipient_padded + amount_hex

        payload = {
            "chain_id": 1,
            "safe_address": "0x1111111111111111111111111111111111111111",
            "raw_tx_hash": "0x" + "aa" * 32,
            "intent_hash": "0x" + "bb" * 32,
            "declared_recipient": "0x" + recipient,
            "declared_max_amount": "1000",
            "calldata": data,
        }
        res = self.client.post("/v1/verify-intent", json=payload)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["match"])
        self.assertEqual(body["decision"], DecisionEnum.ALLOW.value)
        self.assertEqual(len(body["discrepancies"]), 0)

    def test_verify_intent_wazirx_spoofing_blocked(self):
        # User declared intent is to send to Alice
        declared_alice = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        # Actual bytecode sends to Attacker
        attacker_padded = "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        amount_hex = f"{50000:064x}"
        malicious_calldata = "0xa9059cbb" + attacker_padded + amount_hex

        payload = {
            "chain_id": 1,
            "safe_address": "0x1111111111111111111111111111111111111111",
            "raw_tx_hash": "0x" + "aa" * 32,
            "intent_hash": "0x" + "bb" * 32,
            "declared_recipient": declared_alice,
            "declared_max_amount": "1000",
            "calldata": malicious_calldata,
        }
        res = self.client.post("/v1/verify-intent", json=payload)
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertFalse(body["match"])
        self.assertEqual(body["decision"], DecisionEnum.BLOCK.value)
        self.assertGreater(len(body["discrepancies"]), 0)
        self.assertTrue(any("RECIPIENT_SPOOFING" in d for d in body["discrepancies"]))


if __name__ == "__main__":
    unittest.main()
