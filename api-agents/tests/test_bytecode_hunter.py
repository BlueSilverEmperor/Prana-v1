"""Unit tests for Bytecode Vulnerability Hunter (#39)."""

import unittest
from api_agents.agents.bytecode_hunter import (
    disassemble_bytecode,
    generate_security_advisory,
    scan_bytecode,
)


class TestBytecodeHunter(unittest.TestCase):

    def test_disassembler_handles_pushes(self):
        # 60 (PUSH1) 42 61 (PUSH2) 01 02 00 (STOP)
        bytecode = "0x604261010200"
        instructions = disassemble_bytecode(bytecode)
        self.assertEqual(len(instructions), 3)
        self.assertEqual(instructions[0].name, "PUSH1")
        self.assertEqual(instructions[0].operand, bytes.fromhex("42"))
        self.assertEqual(instructions[1].name, "PUSH2")
        self.assertEqual(instructions[1].operand, bytes.fromhex("0102"))
        self.assertEqual(instructions[2].name, "STOP")

    def test_detect_selfdestruct(self):
        # Bytecode with SELFDESTRUCT (0xFF)
        bytecode = "0x60006000ff"
        result = scan_bytecode(bytecode)
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(result.has_selfdestruct)
        self.assertTrue(any(f.vuln_id == "VERO-VULN-001" for f in result.findings))

    def test_detect_standalone_delegatecall(self):
        # Bytecode with DELEGATECALL (0xF4)
        bytecode = "0x600060006000600060006000f4"
        result = scan_bytecode(bytecode)
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(result.has_delegatecall)
        self.assertTrue(any("Delegatecall" in f.title for f in result.findings))

    def test_detect_tx_origin_auth(self):
        # Bytecode with ORIGIN (0x32) followed by EQ (0x14)
        bytecode = "0x32600014"
        result = scan_bytecode(bytecode)
        self.assertTrue(result.is_vulnerable)
        self.assertTrue(result.has_tx_origin)
        self.assertTrue(any("tx.origin" in f.title for f in result.findings))

    def test_advisory_deterministic_fallback(self):
        # Scan vulnerable bytecode
        bytecode = "0x6000ff"
        result = scan_bytecode(bytecode)
        advisory = generate_security_advisory(result, llm_client=None)

        self.assertEqual(advisory.source, "DETERMINISTIC_FALLBACK")
        self.assertEqual(advisory.risk_level, "CRITICAL")
        self.assertGreater(len(advisory.findings_explained), 0)
        self.assertGreater(len(advisory.remediation_plan), 0)

    def test_clean_bytecode_passes(self):
        # Standard clean contract preamble: 6080604052348015600f57600080fd5b50
        bytecode = "0x6080604052348015600f57600080fd5b5000"
        result = scan_bytecode(bytecode)
        self.assertFalse(result.is_vulnerable)
        advisory = generate_security_advisory(result, llm_client=None)
        self.assertEqual(advisory.risk_level, "LOW")


if __name__ == "__main__":
    unittest.main()
