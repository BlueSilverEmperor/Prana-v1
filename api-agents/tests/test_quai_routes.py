"""
Integration tests for Quai Network routes, X-Vero-Engine header, and the x402 PoW work gate.
"""

import unittest
from fastapi.testclient import TestClient
from api_agents.main import app
from api_agents.agents.hashference_client import solve_payment_required
from api_agents.agents.nl_intent_compiler import compile_nl_to_intent_policy


class TestQuaiRoutes(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)
        self.safe_c1 = "0x0017a140Aa3E981100a9becA4E685f962f0cF6C9"  # Cyprus-1
        self.dest_c1 = "0x0027a140Aa3E981100a9becA4E685f962f0cF6C9"  # Cyprus-1
        self.dest_p1 = "0x1017a140Aa3E981100a9becA4E685f962f0cF6C9"  # Pitt-1 (Spoofed for Cyprus-1)

    def test_health_quai_mode(self):
        """Verifies /health reports Quai subsystem mode when requested."""
        res = self.client.get("/health?engine=quai")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("QUAI", data["subsystem_mode"])
        self.assertEqual(data["quai_shard"], "cyprus1")

    def test_quai_status_endpoint(self):
        """Verifies /v1/quai/status returns active shard and dual assets, with no external telemetry."""
        res = self.client.get("/v1/quai/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "active")
        self.assertEqual(data["subsystem"], "QUAI_NATIVE")
        self.assertEqual(data["active_shard"], "cyprus1")
        self.assertEqual(data["zone_prefix"], "0x00")
        self.assertIn("quai", data["dual_assets"])
        self.assertIn("qi", data["dual_assets"])
        self.assertIn("PoEM", data["consensus"])
        self.assertNotIn("hashference_x402", data)

    def test_simulate_with_quai_header(self):
        """Verifies /v1/simulate processes Quai native transactions with X-Vero-Engine: quai."""
        payload = {
            "chain_id": 15000,
            "safe_address": self.safe_c1,
            "to": self.dest_c1,
            "value": "1000000000000000000",
            "data": "0x",
            "nonce": 1,
        }
        res = self.client.post("/v1/simulate", json=payload, headers={"X-Vero-Engine": "quai"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "ALLOW")
        self.assertEqual(len(data["four_word_checksum"].split("-")), 4)

    def test_simulate_quai_shard_prefix_spoofing_blocked(self):
        """Verifies that an address outside Cyprus-1 prefix is blocked when running in Quai Cyprus-1 mode."""
        payload = {
            "chain_id": 15000,
            "safe_address": self.safe_c1,
            "to": self.dest_p1,  # Belongs to Pitt-1 prefix 0x10, not Cyprus-1
            "value": "1000000000000000000",
            "data": "0x",
            "nonce": 1,
        }
        res = self.client.post("/v1/simulate", json=payload, headers={"X-Vero-Engine": "quai"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["decision"], "BLOCK")
        self.assertGreaterEqual(data["risk_score"], 95)
        self.assertIn("QUAI_SHARD_PREFIX_SPOOFING", data["flags"])
        self.assertTrue(any("SHARD MISMATCH" in w for w in data["deterministic_human_warnings"]))

    def test_x402_work_gate_challenge_handshake(self):
        """Verifies that X-Quai-Work-Gate: true enforces HTTP 402 with job challenge until payment signature provided."""
        payload = {
            "chain_id": 15000,
            "safe_address": self.safe_c1,
            "to": self.dest_c1,
            "value": "0",
            "data": "0x",
            "nonce": 2,
        }
        # 1. Request without PAYMENT-SIGNATURE returns HTTP 402
        res = self.client.post(
            "/v1/simulate",
            json=payload,
            headers={"X-Vero-Engine": "quai", "X-Quai-Work-Gate": "true"},
        )
        self.assertEqual(res.status_code, 402)
        self.assertIn("PAYMENT-REQUIRED", res.headers)
        job_header = res.headers["PAYMENT-REQUIRED"]
        self.assertIn("quai-workshare-v1", job_header)

        # 2. Extract job id and solve Proof-of-Work
        pow_sig = solve_payment_required(job_header)

        # 3. Request with valid PAYMENT-SIGNATURE succeeds
        res_paid = self.client.post(
            "/v1/simulate",
            json=payload,
            headers={
                "X-Vero-Engine": "quai",
                "X-Quai-Work-Gate": "true",
                "PAYMENT-SIGNATURE": pow_sig,
            },
        )
        self.assertEqual(res_paid.status_code, 200)
        self.assertEqual(res_paid.json()["decision"], "ALLOW")

    def test_quai_nl_intent_compilation_is_local(self):
        """Verifies the natural language compiler extracts Quai dual-currency caps locally, with no external service."""
        prompt = "Allow Cyprus-1 vault to send up to 5 QUAI and max 500 QI to vendor 0x0027a140Aa3E981100a9becA4E685f962f0cF6C9"
        draft = compile_nl_to_intent_policy(prompt, self.safe_c1, chain_id=15000, mode="QUAI_NATIVE")
        self.assertEqual(draft.status, "DRAFT")
        self.assertTrue(any("no external service" in note for note in draft.compiler_notes))
        self.assertEqual(draft.message.shardZone, "cyprus1")
        self.assertEqual(draft.message.qiValueCap, "500000000")  # 500 * 1e6


if __name__ == "__main__":
    unittest.main()
