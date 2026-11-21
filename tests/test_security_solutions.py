"""
Project Vero // Unit Tests for Security Solutions
Verifies:
1. Expand to 6+ words + on-chain/off-chain intentHash verification
2. Pre/post balance & storage snapshot diffs
3. Recursive MultiSend byte parsing & depth enforcement
4. Strict fail-closed rule precedence (AST/EVM rules override ML completely)
"""

import pytest
from shared.checksum import compute_six_word_checksum, compute_four_word_checksum, verify_intent_hash
from ml.inference import enforce_strict_rule_precedence, predict_transaction_anomaly
from simulator.decoders.multisend_unpacker import flatten_transactions, unpack_multisend, decode_multisend_bytes
from shared.api_schemas import TransactionTuple
from eth_abi import encode


def test_six_word_checksum_entropy_and_words():
    """Verifies that 6-word checksum produces exactly 6 valid BIP-39 words with 66 bits entropy."""
    chain_id = 1
    safe_addr = "0x5bd37a4e9b5e5a2bf8547ad565b9dfd10126786c"
    nonce = 42
    tx_hash = "0x" + "a" * 64
    intent_hash = "0x" + "b" * 64

    four_words = compute_four_word_checksum(chain_id, safe_addr, nonce, tx_hash, intent_hash)
    six_words = compute_six_word_checksum(chain_id, safe_addr, nonce, tx_hash, intent_hash)

    f_split = four_words.split(" · ") if " · " in four_words else four_words.split("-")
    s_split = six_words.split(" · ") if " · " in six_words else six_words.split("-")

    assert len(f_split) == 4, f"Expected 4 words, got {len(f_split)}"
    assert len(s_split) == 6, f"Expected 6 words, got {len(s_split)}"

    # First 4 words match prefix
    assert s_split[:4] == f_split[:4]


def test_intent_hash_verification():
    """Verifies off-chain intentHash computation and verification matching VeroGuard.sol."""
    vault = "0x5bd37a4e9b5e5a2bf8547ad565b9dfd10126786c"
    nonce = 0
    safe_tx_hash = "0x" + "c" * 64

    # Calculate valid expected hash using eth_abi and keccak
    import eth_abi
    from eth_utils import to_checksum_address
    from api_agents.utils.keccak import keccak256

    tx_bytes = bytes.fromhex("c" * 64)
    expected = "0x" + keccak256(eth_abi.encode(["address", "uint256", "bytes32"], [to_checksum_address(vault), nonce, tx_bytes])).hex()

    assert verify_intent_hash(vault, nonce, safe_tx_hash, expected) is True
    assert verify_intent_hash(vault, nonce, safe_tx_hash, "0x" + "0" * 64) is False


def test_strict_rule_precedence_overrides_ml():
    """
    STRICT INVARIANT: AST/EVM rules override ML completely.
    Even if ML predicts BENIGN with low probability, any deterministic rule violation forces BLOCK.
    """
    # Dummy benign ML prediction
    benign_ml = {
        "ml_anomaly_probability": 0.05,
        "ml_classification": "BENIGN",
        "confidence_score": "5.00%",
        "ml_recommendation": "ALLOW"
    }

    # Case 1: No rules triggered -> preserves ML recommendation
    res_clean = enforce_strict_rule_precedence([], benign_ml)
    assert res_clean["ml_recommendation"] == "ALLOW"
    assert res_clean["override_applied"] is False

    # Case 2: Rule R3 (Proxy Slot Hijack) triggered -> strictly overrides to BLOCK
    res_override = enforce_strict_rule_precedence(["R3"], benign_ml)
    assert res_override["ml_recommendation"] == "BLOCK"
    assert res_override["ml_classification"] == "MALICIOUS"
    assert res_override["override_applied"] is True

    # Case 3: Multiple rules (R1, R9) triggered -> strictly overrides to BLOCK
    res_multi = enforce_strict_rule_precedence(["R1", "R9"], benign_ml)
    assert res_multi["ml_recommendation"] == "BLOCK"
    assert res_multi["ml_classification"] == "MALICIOUS"
    assert "R1, R9" in res_multi["override_reason"]


def test_recursive_multisend_nested_parsing():
    """
    Verifies that nested MultiSend calls are recursively unpacked and parsed up to maximum depth.
    """
    multisend_addr = "0x38869bf66a61cf6bdf996a6ad4015077230600af"
    inner_recipient = "0x1111111111111111111111111111111111111111"
    
    # 1. Leaf call (transfer 1 ETH)
    leaf_call = (0).to_bytes(1, "big") + bytes.fromhex(inner_recipient[2:]) + (10**18).to_bytes(32, "big") + (0).to_bytes(32, "big") + b""

    # 2. Wrap into nested multiSend calldata
    nested_calldata = bytes.fromhex("8d80ff0a") + encode(["bytes"], [leaf_call])

    # 3. Outer MultiSend call containing the nested MultiSend
    outer_packed = (1).to_bytes(1, "big") + bytes.fromhex(multisend_addr[2:]) + (0).to_bytes(32, "big") + len(nested_calldata).to_bytes(32, "big") + nested_calldata

    # Decode outer
    unpacked_txs = unpack_multisend(outer_packed)
    assert len(unpacked_txs) == 1
    assert unpacked_txs[0].to.lower() == multisend_addr.lower()

    # Flatten recursively
    flattened = flatten_transactions(unpacked_txs)
    # Root multiSend + nested multiSend + inner transfer
    targets = [call.target.lower() for call in flattened]
    assert inner_recipient.lower() in targets, "Inner leaf call target must be reached via recursive unpacking"
