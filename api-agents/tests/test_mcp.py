"""Unit tests for FastMCP server (#42)."""

import asyncio
import unittest
from api_agents.mcp.server import VeroMCPToolServer


class TestMCP(unittest.TestCase):

    def setUp(self):
        self.server = VeroMCPToolServer()

    def test_mcp_simulate_and_verify_clean(self):
        res = asyncio.run(
            self.server.vero_simulate_and_verify(
                chain_id=1,
                safe_address="0x1111111111111111111111111111111111111111",
                to="0x2222222222222222222222222222222222222222",
                value="1000000000000000000",
                data="0x",
            )
        )
        self.assertEqual(res["decision"], "ALLOW")
        self.assertLess(res["risk_score"], 40)
        self.assertTrue(len(res["four_word_checksum"].split("-")) == 4)

    def test_mcp_simulate_and_verify_malicious(self):
        # Malicious proxy upgrade
        res = asyncio.run(
            self.server.vero_simulate_and_verify(
                chain_id=1,
                safe_address="0x1111111111111111111111111111111111111111",
                to="0xcccccccccccccccccccccccccccccccccccccccc",
                value="0",
                data="0x3659cfe6" + "0" * 24 + "4" * 40,
            )
        )
        self.assertEqual(res["decision"], "BLOCK")
        self.assertEqual(res["risk_score"], 95)
        self.assertIn("PROXY_UPGRADE_ATTEMPT", res["flags"])


if __name__ == "__main__":
    unittest.main()
