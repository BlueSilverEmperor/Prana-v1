"""Unit tests for NL-to-Intent Compiler (#40) and Threat-Intel Triage Agent (#41)."""

import unittest
from api_agents.agents.nl_intent_compiler import compile_nl_to_intent_policy
from api_agents.agents.threat_triage import triage_threat_incident


class TestAgents(unittest.TestCase):

    def test_nl_intent_compiler_draft_status(self):
        prompt = "Allow up to 5 ETH transfers to 0x7a250d5630b4cf539739df2c5dacb4c659f2488d per week, block infinite approvals"
        account = "0x1111111111111111111111111111111111111111"
        draft = compile_nl_to_intent_policy(prompt, account_address=account, chain_id=1)

        # STRICT INVARIANT: Must be marked as DRAFT
        self.assertEqual(draft.status, "DRAFT")
        self.assertIsNotNone(draft.message)
        self.assertEqual(draft.message.targetContract.lower(), "0x7a250d5630b4cf539739df2c5dacb4c659f2488d")
        self.assertEqual(draft.message.maxAmountWei, str(int(5 * 1e18)))
        self.assertTrue(draft.message.blockInfiniteApproval)
        self.assertTrue(draft.struct_hash.startswith("0x"))
        self.assertEqual(len(draft.struct_hash), 66)

    def test_threat_triage_human_approval_guard(self):
        malicious_addr = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        incident = triage_threat_incident(
            indicator=malicious_addr,
            threat_category="WazirX_Multisig_Exploit_Drainer",
            raw_payload_or_log="Transaction attempted 0x3659cfe6 implementation swap",
            reporter_source="Firewall_Sensor_Node_1",
        )

        # STRICT INVARIANT: Must require human analyst approval
        self.assertEqual(incident.status, "DRAFT_PENDING_HUMAN_APPROVAL")
        self.assertEqual(incident.ioc_type, "ADDRESS")
        self.assertEqual(incident.severity, "CRITICAL")
        self.assertEqual(incident.proposed_firewall_action, "BLOCK")
        self.assertEqual(len(incident.evidence_hashes), 1)
        self.assertGreater(len(incident.analyst_review_checklist), 0)


if __name__ == "__main__":
    unittest.main()
