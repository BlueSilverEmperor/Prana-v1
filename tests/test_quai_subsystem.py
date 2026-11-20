"""
Unit tests for the Quai Network Subsystem in Project Vero.
Covers:
- Quai RPC Translation & ETX Decoding
- Cyprus-1 Shard-Prefix Poisoning Detection
- Shard-bound 4-word BIP-39 Dual-Device Checksum Sensitivity
"""

import unittest
from simulator.quai_adapter import QuaiRpcAdapter
from simulator.analyzers.poisoning import (
    detect_quai_shard_prefix_spoofing,
    detect_address_poisoning,
    is_lookalike,
)
from shared.checksum import compute_4_word_checksum
from shared.schemas import QUAI_ZONES, get_quai_zone_for_address, is_quai_address_valid_for_zone


class TestQuaiSubsystem(unittest.TestCase):

    def setUp(self):
        self.adapter = QuaiRpcAdapter(chain_id=15000, default_zone="cyprus1")
        self.vault = "0x0017a140Aa3E981100a9becA4E685f962f0cF6C9"  # Cyprus-1 prefix 0x00
        self.tx_hash = "0x" + "a" * 64
        self.policy_hash = "0x" + "b" * 64

    def test_rpc_method_translation(self):
        """Verifies quai_* methods map to standard EVM JSON-RPC equivalents."""
        res_code = self.adapter.translate_quai_rpc("quai_getCode", [self.vault, "latest"])
        self.assertEqual(res_code["translated_method"], "eth_getCode")

        res_storage = self.adapter.translate_quai_rpc("quai_getStorageAt", [self.vault, "0x0", "latest"])
        self.assertEqual(res_storage["translated_method"], "eth_getStorageAt")

        res_bal = self.adapter.translate_quai_rpc("quai_getBalance", [self.vault, "latest"])
        self.assertEqual(res_bal["translated_method"], "eth_getBalance")

        res_chain = self.adapter.translate_quai_rpc("quai_chainId", [])
        self.assertEqual(res_chain["translated_method"], "eth_chainId")

    def test_etx_decoding(self):
        """Verifies External Transaction (ETX) cross-shard parsing and PoEM finality estimation."""
        # Payload starting with 0x00 (Cyprus-1) -> 0x10 (Pitt-1)
        raw_etx = "0x0010" + "ff" * 70
        decoded = self.adapter.decode_etx(raw_etx)
        self.assertTrue(decoded["is_etx"])
        self.assertEqual(decoded["from_zone"], "cyprus1")
        self.assertEqual(decoded["to_zone"], "pitt1")
        self.assertTrue(decoded["is_cross_shard"])
        self.assertEqual(decoded["estimated_poem_finality_seconds"], 15.0)

    def test_zone_metadata(self):
        """Verifies Cyprus-1 zone metadata and PoEM consensus parameters."""
        status = self.adapter.get_zone_status("cyprus1")
        self.assertEqual(status["prefix"], "0x00")
        self.assertEqual(status["coordinates"], [0, 0])
        self.assertIn("PoEM", status["consensus"])
        self.assertEqual(status["block_time_seconds"], 5.0)

    def test_shard_prefix_spoofing_detection(self):
        """Verifies that an address outside Cyprus-1 prefix is flagged as spoofing."""
        # Valid Cyprus-1 address (prefix 0x00)
        valid_addr = "0x0017a140Aa3E981100a9becA4E685f962f0cF6C9"
        self.assertTrue(is_quai_address_valid_for_zone(valid_addr, "cyprus1"))
        self.assertIsNone(detect_quai_shard_prefix_spoofing(valid_addr, "cyprus1"))

        # Spoofed address (prefix 0x10 is Pitt-1, but claimed in Cyprus-1)
        spoofed_addr = "0x1017a140Aa3E981100a9becA4E685f962f0cF6C9"
        self.assertFalse(is_quai_address_valid_for_zone(spoofed_addr, "cyprus1"))
        alert = detect_quai_shard_prefix_spoofing(spoofed_addr, "cyprus1")
        self.assertIsNotNone(alert)
        self.assertTrue(alert["spoofing_detected"])
        self.assertEqual(alert["expected_prefix"], "0x00")
        self.assertEqual(alert["actual_prefix"], "0x10")
        self.assertEqual(alert["detected_zone"], "pitt1")

    def test_address_poisoning_lookalike(self):
        """Verifies vanity address lookalike detection."""
        target = "0x0017" + "1234567890abcdef" * 2 + "F6C9"
        lookalike = "0x0017" + "f" * 32 + "F6C9"
        self.assertTrue(is_lookalike(target, lookalike))

        res = detect_address_poisoning(lookalike, [target])
        self.assertIsNotNone(res)
        self.assertTrue(res["detected"])

    def test_quai_checksum_derivation_and_sensitivity(self):
        """Verifies that Quai native mode produces 4 words and binds shard zone."""
        words_evm, indices_evm = compute_4_word_checksum(
            self.vault, 0, self.tx_hash, self.policy_hash, mode="STANDARD_EVM"
        )
        self.assertEqual(len(words_evm), 4)

        words_quai_c1, indices_quai_c1 = compute_4_word_checksum(
            self.vault, 0, self.tx_hash, self.policy_hash, mode="QUAI_NATIVE", shard_zone="cyprus1"
        )
        self.assertEqual(len(words_quai_c1), 4)

        words_quai_p1, indices_quai_p1 = compute_4_word_checksum(
            self.vault, 0, self.tx_hash, self.policy_hash, mode="QUAI_NATIVE", shard_zone="pitt1"
        )

        # Altering shard zone must alter the checksum
        self.assertNotEqual(words_quai_c1, words_quai_p1)
        # Quai native checksum must differ from standard EVM
        self.assertNotEqual(words_evm, words_quai_c1)


if __name__ == "__main__":
    unittest.main()
