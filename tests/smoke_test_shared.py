"""
End-to-end smoke test for shared/ off-chain Python layer in Project Vero.
Tests schemas.py, checksum.py, receipt.py, and abi.json.
"""

import sys
import os
import json

# Ensure repo root is on python path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from shared.schemas import (
    IntentPolicy,
    INTENT_POLICY_TYPEHASH,
    INTENT_POLICY_TYPE_STRING,
    REVERT_ERRORS,
    decode_revert_error,
)
from shared.checksum import compute_4_word_checksum, _get_bip39_word
from shared.receipt import generate_receipt, ForensicReceipt

def test_abi_json():
    print("[1/4] Testing shared/abi.json...")
    abi_path = os.path.join(repo_root, "shared", "abi.json")
    assert os.path.exists(abi_path), "abi.json does not exist"
    with open(abi_path, "r", encoding="utf-8") as f:
        abis = json.load(f)
    
    expected_contracts = [
        "VeroGuard", "GuardedMultisig", "GovernanceTimelock",
        "ThreatRegistry", "VeroSafeGuard", "MockUSDT", "MockWBTC", "MultiSend"
    ]
    for c in expected_contracts:
        assert c in abis, f"Missing contract {c} in abi.json"
        assert len(abis[c]) > 0, f"Empty ABI for {c}"
    print(f"  ✓ abi.json contains {len(expected_contracts)} contracts with full ABIs")

def test_schemas():
    print("[2/4] Testing shared/schemas.py...")
    # Check typehash
    from Crypto.Hash import keccak
    k = keccak.new(digest_bits=256)
    k.update(INTENT_POLICY_TYPE_STRING.encode())
    expected_typehash = "0x" + k.digest().hex()
    assert INTENT_POLICY_TYPEHASH == expected_typehash, f"Typehash mismatch: {INTENT_POLICY_TYPEHASH} vs {expected_typehash}"
    print(f"  ✓ INTENT_POLICY_TYPEHASH matches canonical keccak: {INTENT_POLICY_TYPEHASH}")

    # Build IntentPolicy instance
    policy = IntentPolicy(
        vault="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
        nonce=1,
        deadline=1800000000,
        maxGasFeeWei=50000000000,
        allowDelegateCall=False,
        allowedTargets=["0xCAFE000000000000000000000000000000000001"],
        allowedSelectors=["0xa9059cbb"],
        tokenAddresses=["0xdAC17F958D2ee523a2206206994597C13D831ec7"],
        maxTokenSpends=[1000000000],
        ethValueCap=1000000000000000000,
        sessionKeyEnabled=True,
        sessionAgent="0x8270dA64f8BCA9b30050598Cb2F3Bb4925663D3e"
    )
    msg = policy.to_eip712_message(chain_id=1, verifying_contract="0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9")
    assert msg["primaryType"] == "IntentPolicy"
    assert msg["domain"]["chainId"] == 1
    assert msg["message"]["nonce"] == 1

    # Test error decoding
    for name, sel in REVERT_ERRORS.items():
        decoded = decode_revert_error(sel)
        assert decoded == name, f"Failed to decode error {sel}: expected {name}, got {decoded}"
    
    # Test decoding with payload
    sample_payload = REVERT_ERRORS["ModuleFirewallBlocked"] + "000000000000000000000000"
    assert decode_revert_error(sample_payload) == "ModuleFirewallBlocked"
    print(f"  ✓ Decoded all {len(REVERT_ERRORS)} custom error selectors successfully")

def test_checksum():
    print("[3/4] Testing shared/checksum.py...")
    vault = "0x1d1499e622D69689cdf9004d05Ec547d650Ff211"
    nonce = 0
    safe_tx_hash = "0x6b0656fc183f96c3ca988cb6c3db8c241cb115f6eedff78715fe47cb580cf08e"
    policy_hash = "0x5b0f9436c819b53dbee8ea2c97c9b239e65dc59bc3413d5d08ecbb88caf2b2db"
    
    words, indices = compute_4_word_checksum(vault, nonce, safe_tx_hash, policy_hash)
    assert len(words) == 4, f"Expected 4 words, got {len(words)}"
    assert len(indices) == 4, f"Expected 4 indices, got {len(indices)}"
    for idx in indices:
        assert 0 <= idx < 2048, f"Index {idx} out of range [0, 2047]"
    print(f"  ✓ Derived 4-word dual-device checksum: {' · '.join(words)} (Indices: {indices})")

def test_receipt():
    print("[4/4] Testing shared/receipt.py...")
    receipt = generate_receipt(
        vault="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
        target="0x3D7Ebc40AF7092E3F1C81F2e996cbA5Cae2090d7",
        selector="0x9e5faafc",
        verdict="BLOCKED",
        policy_hash="0x7956a0daf3c6f1d5c0870e04b62262faafb18a056dd74bb2c64de01bd5a54236",
        safe_tx_hash="0xe23dab905d77b15501135bc3ce11f2544f055ee2e5e3eda741fcfac740dd381f",
        triggered_error="DelegateCallNotAllowed",
        error_selector="0x5d9179f4",
        chain_id=1,
        checksum_words=["alpha", "delta", "guard", "vero"]
    )
    json_out = receipt.to_json()
    assert '"verdict": "BLOCKED"' in json_out
    assert '"triggered_error": "DelegateCallNotAllowed"' in json_out

    md_out = receipt.to_markdown_summary()
    assert "🛑 BLOCKED" in md_out
    assert "DelegateCallNotAllowed" in md_out
    assert "0x5d9179f4" in md_out
    print("  ✓ Generated forensic CERT-In incident receipt and validated Markdown/JSON output")

if __name__ == "__main__":
    test_abi_json()
    test_schemas()
    test_checksum()
    test_receipt()
    print("\n🎉 ALL OFF-CHAIN PYTHON LAYER TESTS PASSED WITH 0 ERRORS!")
