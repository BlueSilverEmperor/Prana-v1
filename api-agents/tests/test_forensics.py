"""Unit tests for Ed25519 signer and CERT-In aligned receipt exporter (#20)."""

import os
import tempfile
import unittest
from api_agents.forensics.cert_in_exporter import (
    create_forensic_receipt,
    export_receipt_to_json,
    export_receipt_to_pdf,
)
from api_agents.forensics.signer import generate_keypair, sign, verify
from scripts.verify_receipt import verify_receipt_file


class TestForensics(unittest.TestCase):

    def test_ed25519_sign_and_verify(self):
        sk, pk = generate_keypair()
        message = b"Vero-WazirX-Prevention-Audit-Vector"
        signature = sign(message, sk)

        # Valid verification
        self.assertTrue(verify(signature, message, pk))

        # Tampered message fails
        self.assertFalse(verify(signature, b"Tampered-Vector", pk))

        # Corrupted signature fails
        corrupted_sig = bytearray(signature)
        corrupted_sig[0] ^= 0x01
        self.assertFalse(verify(bytes(corrupted_sig), message, pk))

    def test_create_and_export_receipt(self):
        receipt = create_forensic_receipt(
            safe_address="0x1111111111111111111111111111111111111111",
            target_contract="0xMalicious0000000000000000000000000000",
            raw_tx_hash="0x" + "aa" * 32,
            intent_hash="0x" + "bb" * 32,
            four_word_checksum="apple-banana-cherry-date",
            decision="BLOCK",
            risk_score=95,
            flags=["PROXY_UPGRADE_ATTEMPT"],
            human_warnings=["CRITICAL: Detected proxy implementation replacement."],
        )

        self.assertTrue(receipt.ed25519_signature)
        self.assertTrue(receipt.public_key)
        self.assertIn("CERT-In", receipt.schema_profile)

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "receipt.json")
            pdf_path = os.path.join(tmpdir, "receipt.pdf")

            export_receipt_to_json(receipt, json_path)
            self.assertTrue(os.path.exists(json_path))

            # Test standalone verification script on the exported json
            self.assertTrue(verify_receipt_file(json_path))

            # Test PDF generation
            export_receipt_to_pdf(receipt, pdf_path)
            self.assertTrue(os.path.exists(pdf_path))
            self.assertGreater(os.path.getsize(pdf_path), 500)


if __name__ == "__main__":
    unittest.main()
