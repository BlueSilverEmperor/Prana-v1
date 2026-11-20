"""
Live WazirX replay through the real Vero stack.

1. Sends the WazirX-style payload (upgradeTo on the Safe, while the UI claims a routine transfer)
   through the same adapter /v1/simulate uses, and prints the engine's actual verdict.
2. Computes the 4-word checksum from the real transaction hash.
3. Runs the on-chain proof: the Foundry test test_WazirX_Slot0Swap_Blocked (skipped, and said so,
   when forge is not installed).
4. Issues an Ed25519-signed CERT-In receipt and verifies the signature.

Every value printed comes from code that ran; nothing is a placeholder.
Usage: python scripts/demo_wazirx_live.py [--no-pause]
"""

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
import time

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO_ROOT, os.path.join(REPO_ROOT, "api-agents")):
    if path not in sys.path:
        sys.path.insert(0, path)

from api_agents.adapters.factory import build_adapter, engine_name  # noqa: E402
from api_agents.forensics.cert_in_exporter import create_forensic_receipt  # noqa: E402
from api_agents.forensics.signer import verify  # noqa: E402
from api_agents.models.schemas import DeclaredIntent, SimulateRequest  # noqa: E402
from api_agents.routes.firewall_api import _compute_raw_tx_hash  # noqa: E402
from api_agents.utils.four_word_checksum import compute_four_word_checksum  # noqa: E402

RED, GREEN, YELLOW, CYAN, BOLD, RESET = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[0m"
SAFE = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
HOT_WALLET = "0x" + "4f" * 20
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ATTACKER_IMPL = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
PAYLOAD = "0x3659cfe6" + "0" * 24 + ATTACKER_IMPL[2:]
FORGE_TEST = "test_WazirX_Slot0Swap_Blocked"
FORGE_TIMEOUT_S = 300
ZERO_HASH = "0x" + "00" * 32


def step(title: str, pause: bool) -> None:
    if pause:
        time.sleep(0.6)
    print(f"\n{BOLD}[{title}]{RESET}")


def run_engine(req: SimulateRequest):
    adapter = build_adapter()
    t0 = time.perf_counter()
    sim = asyncio.run(adapter.simulate_tx(req))
    verdict = adapter.evaluate(sim, req)
    return adapter, sim, verdict, (time.perf_counter() - t0) * 1000.0


def run_forge_proof() -> str:
    forge = shutil.which("forge") or os.path.expanduser("~/.foundry/bin/forge")
    if not os.path.exists(forge):
        return f"{YELLOW}SKIPPED: forge not installed (run `forge test --match-test {FORGE_TEST}`){RESET}"
    try:
        out = subprocess.run([forge, "test", "--match-test", FORGE_TEST], cwd=os.path.join(REPO_ROOT, "contracts"),
                             capture_output=True, text=True, timeout=FORGE_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return f"{RED}forge test timed out after {FORGE_TIMEOUT_S}s{RESET}"
    line = next((ln.strip() for ln in out.stdout.splitlines() if FORGE_TEST in ln), out.stdout.strip()[-200:])
    color = GREEN if out.returncode == 0 and "[PASS]" in line else RED
    return f"{color}{line}{RESET}"


def main(argv=None) -> int:
    parser =argparse.ArgumentParser(description="Live WazirX replay through the Vero stack")
    parser.add_argument("--no-pause", action="store_true", help="skip the short pauses between steps")
    parser.add_argument("--skip-forge", action="store_true", help="do not run the Foundry proof")
    args = parser.parse_args(argv)
    pause = not args.no_pause

    print(f"\n{CYAN}{BOLD}{'=' * 66}\n   PROJECT VERO // WAZIRX REPLAY (live engine output)\n{'=' * 66}{RESET}")

    step("STEP 1: WHAT THE SIGNERS SAW", pause)
    print(f" UI claim             : {YELLOW}'Routine transfer: 100 USDT to hot wallet'{RESET}")
    print(f" Signer declared      : pay {HOT_WALLET[:10]}... at most 100 USDT, nothing else")
    print(f" Bytes actually signed: {RED}{PAYLOAD}{RESET}")

    req = SimulateRequest(chain_id=1, safe_address=SAFE, to=SAFE, data=PAYLOAD, nonce=0,
                          label="Routine transfer: 100 USDT to hot wallet",
                          declared_intent=DeclaredIntent(allowed_recipients=[HOT_WALLET], allowed_tokens=[USDT],
                                                         max_outflow_wei="100000000"))
    adapter, sim, verdict, latency_ms = run_engine(req)
    raw_tx_hash = _compute_raw_tx_hash(req)
    checksum = compute_four_word_checksum(req.chain_id, req.safe_address, req.nonce, raw_tx_hash, ZERO_HASH)

    step("STEP 2: VERO ENGINE VERDICT", pause)
    color = RED if verdict.decision.value == "BLOCK" else GREEN
    print(f" Engine               : {engine_name(adapter)}")
    print(f" Decision             : {color}{BOLD}{verdict.decision.value}{RESET}")
    print(f" Risk score           : {verdict.risk_score} / 100")
    print(f" Flags                : {verdict.flags}")
    for w in verdict.human_warnings:
        print(f" Warning              : {YELLOW}{w}{RESET}")
    for d in sim.state_diffs:
        print(f" State change         : {d.asset_type} {d.delta_human} {d.to_address or ''}")
    print(f" Engine latency       : {latency_ms:.2f} ms (measured)")
    print(f" 4-word checksum      : {BOLD}{checksum}{RESET}  (tx hash {raw_tx_hash[:18]}...)")

    step("STEP 3: ON-CHAIN ENFORCEMENT PROOF (Foundry)", pause)
    print(" Test                 :", FORGE_TEST)
    print(" Result               :", run_forge_proof() if not args.skip_forge else f"{YELLOW}SKIPPED (--skip-forge){RESET}")

    step("STEP 4: SIGNED CERT-In RECEIPT", pause)
    receipt = create_forensic_receipt(
        safe_address=SAFE, target_contract=SAFE, raw_tx_hash=raw_tx_hash, intent_hash=ZERO_HASH,
        four_word_checksum=checksum, decision=verdict.decision.value, risk_score=verdict.risk_score,
        flags=verdict.flags, human_warnings=verdict.human_warnings)
    signable = (f"{receipt.receipt_id}|{receipt.reported_at}|{receipt.chain_id}|{receipt.safe_address.lower()}|"
                f"{receipt.raw_tx_hash.lower()}|{receipt.decision}|{receipt.risk_score}").encode()
    valid = verify(bytes.fromhex(receipt.ed25519_signature), signable, bytes.fromhex(receipt.public_key))
    print(f" Receipt id           : {receipt.receipt_id}")
    print(f" Ed25519 signature    : {receipt.ed25519_signature[:48]}...")
    print(f" Public key           : {receipt.public_key[:48]}...")
    print(f" Signature verified   : {valid}")
    print(f"\n{CYAN}{'=' * 66}{RESET}\n")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
