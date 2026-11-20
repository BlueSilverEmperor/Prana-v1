"""
Standalone Ed25519 Receipt Verification Script.
Auditors can independently verify the cryptographic authenticity of any Vero receipt.
"""

import json
import sys
from api_agents.forensics.signer import verify


def verify_receipt_file(filepath: str) -> bool:
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    receipt_id = data["receipt_id"]
    now_iso = data["reported_at"]
    chain_id = data["chain_id"]
    safe_address = data["safe_address"].lower()
    raw_tx_hash = data["raw_tx_hash"].lower()
    decision = data["decision"]
    risk_score = data["risk_score"]

    signable_bytes = (
        f"{receipt_id}|{now_iso}|{chain_id}|{safe_address}|{raw_tx_hash}|{decision}|{risk_score}"
    ).encode("utf-8")

    sig_bytes = bytes.fromhex(data["ed25519_signature"])
    pk_bytes = bytes.fromhex(data["public_key"])

    is_valid = verify(sig_bytes, signable_bytes, pk_bytes)

    print("=" * 60)
    print("      PROJECT VERO // ED25519 RECEIPT VERIFIER      ")
    print("=" * 60)
    print(f" Receipt ID        : {receipt_id}")
    print(f" Timestamp         : {now_iso}")
    print(f" Decision          : {decision} (Risk: {risk_score})")
    print(f" Public Key        : {data['public_key'][:32]}...")
    print(f" Ed25519 Signature : {data['ed25519_signature'][:32]}...")
    print("-" * 60)
    if is_valid:
        print(" [VERIFICATION SUCCESS] Signature matches public key and payload.")
    else:
        print(" [VERIFICATION FAILURE] Signature does not match or payload tampered!")
    print("=" * 60)
    return is_valid


if __name__ == "__main__":
    if len(sys.argv) > 1:
        verify_receipt_file(sys.argv[1])
    else:
        print("Usage: python verify_receipt.py <path_to_receipt.json>")
