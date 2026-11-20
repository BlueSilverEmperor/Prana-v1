"""Unit tests for four_word_checksum and BIP-39 mapping."""

import unittest
from api_agents.utils.bip39_wordlist import BIP39_WORDLIST
from api_agents.utils.four_word_checksum import (
    DEFAULT_WORD_COUNT,
    DEFAULT_WORD_SEPARATOR,
    compute_four_word_checksum,
    digest_to_bip39_words,
    pack_checksum_preimage,
)
from api_agents.utils.keccak import keccak256


class TestFourWordChecksum(unittest.TestCase):

    def test_bip39_wordlist_integrity(self):
        self.assertEqual(len(BIP39_WORDLIST), 2048)
        self.assertEqual(BIP39_WORDLIST[0], "abandon")
        self.assertEqual(BIP39_WORDLIST[-1], "zoo")
        self.assertEqual(len(set(BIP39_WORDLIST)), 2048, "Wordlist must have no duplicates")

    def test_preimage_packing(self):
        preimage = pack_checksum_preimage(
            chain_id=1,
            safe_address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            nonce=42,
            raw_tx_hash="0x" + "aa" * 32,
            intent_hash="0x" + "bb" * 32,
        )
        # 32 (chainId) + 20 (address) + 32 (nonce) + 32 (rawTx) + 32 (intent) = 148 bytes
        self.assertEqual(len(preimage), 148)

    def test_checksum_determinism(self):
        args = {
            "chain_id": 1,
            "safe_address": "0x1234567890123456789012345678901234567890",
            "nonce": 10,
            "raw_tx_hash": "0x" + "11" * 32,
            "intent_hash": "0x" + "22" * 32,
        }
        res1 = compute_four_word_checksum(**args)
        res2 = compute_four_word_checksum(**args)
        self.assertEqual(res1, res2)
        words = res1.split(DEFAULT_WORD_SEPARATOR)
        self.assertEqual(len(words), 4)
        for w in words:
            self.assertIn(w, BIP39_WORDLIST)

    def test_checksum_sensitivity(self):
        base_args = {
            "chain_id": 1,
            "safe_address": "0x1234567890123456789012345678901234567890",
            "nonce": 10,
            "raw_tx_hash": "0x" + "11" * 32,
            "intent_hash": "0x" + "22" * 32,
        }
        res1 = compute_four_word_checksum(**base_args)

        # Flip 1 byte in raw_tx_hash
        mod_args = dict(base_args)
        mod_args["raw_tx_hash"] = "0x12" + "11" * 31
        res2 = compute_four_word_checksum(**mod_args)

        self.assertNotEqual(res1, res2, "Single byte change must cascade into different words")

    def test_custom_word_count_and_separator(self):
        dummy_digest = keccak256(b"ProjectVeroBenchmarkPreimage")
        result = digest_to_bip39_words(dummy_digest, word_count=6, separator=" ")
        words = result.split(" ")
        self.assertEqual(len(words), 6)
        for w in words:
            self.assertIn(w, BIP39_WORDLIST)


if __name__ == "__main__":
    unittest.main()
