"""Builds frontend/data/attacks.json for the attack replay page from the benchmark scenarios.

Each entry is the scenario's real calldata mapped to the /v1/simulate request body. The page sends
them to the live engine one by one; nothing here contains a verdict.
Usage: python scripts/build_attack_replay.py
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "simulator" / "bench" / "scenarios"
OUT = ROOT / "frontend" / "data" / "attacks.json"
REAL = ROOT / "frontend" / "data" / "real_incidents.json"  # from scripts/fetch_real_incidents.py

# (scenario id, short incident tag, Foundry replay that reverts the same pattern on-chain or None)
PLAYLIST = [
    ("p01", "WazirX, July 2024", "test_WazirX_Slot0Swap_Blocked"),
    ("p02", "Bybit, February 2025", "test_Bybit_DelegateCallOverwrite_Blocked"),
    ("m01", "Drainer kits", None),
    ("b01", "Control", None),
    ("p03", "Radiant, October 2024", None),
    ("m05", "Permit2 phishing", "test_Permit2_PhishingReplay_Blocked"),
    ("m10", "Guard removal", None),
    ("m11", "Backdoor module", None),
    ("b02", "Control", None),
    ("m09", "Owner takeover", None),
    ("m13", "Hidden batch drain", "test_MultiSend_HiddenBatchDrain_Blocked"),
    ("h01", "Nested batch", None),
    ("m14", "Lookalike token", None),
    ("m12", "EIP-7702 drainer", None),
    ("m15", "Address poisoning", None),
    ("m17", "Interface mismatch", None),
    ("b05", "Control", None),
]


def _request(scenario: dict) -> dict:
    req = scenario["request"]
    tx = req["transactions"][0]
    intent = req.get("intentPolicy") or {}
    context = scenario.get("context") or {}
    body = {
        "chain_id": req.get("chainId", 1),
        "safe_address": req["safeAddress"],
        "to": tx["to"],
        "value": str(tx.get("value", "0")),
        "data": tx["data"],
        "operation": tx.get("operation", 0),
        "label": req.get("label"),
    }
    if tx.get("authorizationList"):
        body["authorization_list"] = [
            {"chain_id": a["chainId"], "address": a["address"], "nonce": a.get("nonce", 0)} for a in tx["authorizationList"]
        ]
    if context.get("contacts"):
        body["contacts"] = context["contacts"]
    if context.get("recipientHistory"):
        body["recipient_history"] = context["recipientHistory"]
    if intent:
        body["declared_intent"] = {
            "allowed_recipients": intent.get("allowedRecipients", []),
            "allowed_tokens": intent.get("allowedTokens", []),
            "max_outflow_wei": str(intent.get("maxOutflowWei", "0")),
        }
    return body


def main() -> None:
    paths = {p.stem: p for p in SCENARIOS.glob("*/*.json")}
    # Real mainnet transactions lead the run when they have been fetched.
    entries = json.loads(REAL.read_text()) if REAL.exists() else []
    for scenario_id, tag, replay in PLAYLIST:
        scenario = json.loads(paths[scenario_id].read_text())
        entries.append({
            "id": scenario_id,
            "tag": tag,
            "title": scenario["title"],
            "expected": "BLOCK" if scenario["label"] == "malicious" else "ALLOW",
            "claim": scenario["request"].get("label") or "",
            "foundry": replay,
            "request": _request(scenario),
        })
    OUT.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"Wrote {len(entries)} scenarios to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
