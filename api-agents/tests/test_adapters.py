"""Unit tests for MockAdapter and Protocol compliance."""

import asyncio
import unittest
from api_agents.adapters.mock_adapter import MockAdapter
from api_agents.adapters.simulator_protocol import (
    RuleEngineProtocol,
    SimulatorProtocol,
)
from api_agents.models.schemas import DecisionEnum, SimulateRequest


class TestMockAdapter(unittest.TestCase):

    def setUp(self):
        self.adapter = MockAdapter(artificial_latency_ms=0.0)

    def test_protocol_conformance(self):
        self.assertIsInstance(self.adapter, SimulatorProtocol)
        self.assertIsInstance(self.adapter, RuleEngineProtocol)

    def test_clean_transfer(self):
        req = SimulateRequest(
            chain_id=1,
            safe_address="0x1111111111111111111111111111111111111111",
            to="0x2222222222222222222222222222222222222222",
            value=str(10**18),  # 1 ETH
            data="0x",
            nonce=1,
        )
        sim_res = asyncio.run(self.adapter.simulate_tx(req))
        self.assertTrue(sim_res.success)
        self.assertEqual(len(sim_res.state_diffs), 1)
        self.assertIn("-1.0000 ETH", sim_res.state_diffs[0].delta_human)

        eval_res = self.adapter.evaluate(sim_res, req)
        self.assertEqual(eval_res.decision, DecisionEnum.ALLOW)
        self.assertLess(eval_res.risk_score, 40)

    def test_infinite_approval_blocked(self):
        # approve(spender, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        spender_padded = "0000000000000000000000009999999999999999999999999999999999999999"
        amount_max = "f" * 64
        calldata = "0x095ea7b3" + spender_padded + amount_max

        req = SimulateRequest(
            chain_id=1,
            safe_address="0x1111111111111111111111111111111111111111",
            to="0xUSDC000000000000000000000000000000000000",
            value="0",
            data=calldata,
            nonce=2,
        )
        sim_res = asyncio.run(self.adapter.simulate_tx(req))
        self.assertTrue(sim_res.success)
        eval_res = self.adapter.evaluate(sim_res, req)

        self.assertEqual(eval_res.decision, DecisionEnum.BLOCK)
        self.assertIn("INFINITE_TOKEN_APPROVAL", eval_res.flags)
        self.assertGreaterEqual(eval_res.risk_score, 80)

    def test_proxy_upgrade_detected_and_blocked(self):
        # upgradeTo(newImpl)
        new_impl_padded = "0000000000000000000000006666666666666666666666666666666666666666"
        calldata = "0x3659cfe6" + new_impl_padded

        req = SimulateRequest(
            chain_id=1,
            safe_address="0x1111111111111111111111111111111111111111",
            to="0xSafeProxy0000000000000000000000000000000",
            value="0",
            data=calldata,
            nonce=3,
        )
        sim_res = asyncio.run(self.adapter.simulate_tx(req))
        self.assertTrue(sim_res.success)
        eval_res = self.adapter.evaluate(sim_res, req)

        self.assertEqual(eval_res.decision, DecisionEnum.BLOCK)
        self.assertIn("PROXY_UPGRADE_ATTEMPT", eval_res.flags)
        self.assertEqual(eval_res.risk_score, 95)


if __name__ == "__main__":
    unittest.main()
