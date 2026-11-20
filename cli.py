#!/usr/bin/env python3
"""
Project Vero CLI 🛡️
Command-line interface for transaction simulation, 4-word checksum verification,
bytecode scanning, latency benchmarking, and attack scenario evaluation.
"""

import sys
import os
import argparse
import json
import time

# Ensure repo root and api-agents are on python path
REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
API_AGENTS_DIR = os.path.join(REPO_ROOT, "api-agents")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if API_AGENTS_DIR not in sys.path:
    sys.path.insert(0, API_AGENTS_DIR)

def cmd_status(args):
    """Check status of the local Vero Firewall API."""
    import urllib.request
    url = f"http://{args.host}:{args.port}/health"
    print(f"\n[CLI] Checking Vero Firewall API status at {url} ...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VeroCLI/1.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode())
            print("  ✅ Status :", data.get("status", "unknown").upper())
            print("  🛡️ Service:", data.get("service"))
            print("  📦 Version:", data.get("version"))
            print("  ⚡ Engine :", data.get("engine"))
            print(f"  🌐 Docs   : http://{args.host}:{args.port}/docs\n")
    except Exception as e:
        print(f"  ❌ API not reachable on port {args.port} ({e})")
        print("  💡 Tip: Start the server with: python -m uvicorn api_agents.main:app --port 8000\n")

def cmd_simulate(args):
    """Simulate a transaction against the Vero Firewall."""
    import asyncio
    from api_agents.adapters.mock_adapter import MockAdapter
    from api_agents.models.schemas import SimulateRequest
    from api_agents.utils.four_word_checksum import compute_four_word_checksum
    from api_agents.routes.firewall_api import _compute_raw_tx_hash

    adapter = MockAdapter()
    req = SimulateRequest(
        chain_id=args.chain_id,
        safe_address=args.safe,
        to=args.to,
        value=args.value,
        data=args.data,
        nonce=args.nonce
    )

    t0 = time.perf_counter()
    sim = asyncio.run(adapter.simulate_tx(req))
    eval_res = adapter.evaluate(sim, req)
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000.0

    raw_tx_hash = _compute_raw_tx_hash(req)
    intent_hash = "0x" + "0" * 64
    checksum = compute_four_word_checksum(req.chain_id, req.safe_address, req.nonce or 0, raw_tx_hash, intent_hash)

    print("\n" + "=" * 60)
    print("           PROJECT VERO: TRANSACTION SIMULATION           ")
    print("=" * 60)
    decision = eval_res.decision.value if hasattr(eval_res.decision, "value") else str(eval_res.decision)
    decision_icon = "✅" if decision == "ALLOW" else ("⚠️" if decision == "WARN" else "🛑")
    print(f" Decision         : {decision_icon} {decision}")
    print(f" Risk Score       : {eval_res.risk_score}/100")
    print(f" 4-Word Checksum  : 🔑 {checksum}")
    print(f" Execution Time   : {latency_ms:.3f} ms (SLA < 150 ms)")
    print(f" Target Contract  : {args.to}")
    print(f" Value (Wei)      : {args.value}")

    if eval_res.flags:
        print("\n Flags Triggered  :")
        for f in eval_res.flags:
            print(f"   - {f}")

    if eval_res.human_warnings:
        print("\n Human Warnings   :")
        for w in eval_res.human_warnings:
            print(f"   • {w}")

    if sim.state_diffs:
        print("\n State Diffs      :")
        for d in sim.state_diffs:
            print(f"   • {d.asset_type}: {d.delta_human} (from {d.from_address[:10]}... to {d.to_address[:10]}...)")
    else:
        print("\n State Diffs      : None (0 balance mutations)")
    print("=" * 60 + "\n")

def cmd_checksum(args):
    """Derive 4-word dual-device verification checksum."""
    from shared.checksum import compute_4_word_checksum

    words, indices = compute_4_word_checksum(args.vault, args.nonce, args.tx, args.policy)
    print("\n" + "=" * 55)
    print("     PROJECT VERO: 4-WORD DUAL-DEVICE CHECKSUM    ")
    print("=" * 55)
    print(" Vault Address   :", args.vault)
    print(" Vault Nonce     :", args.nonce)
    print(" Safe Tx Hash    :", args.tx)
    print(" Policy Hash     :", args.policy)
    print("-------------------------------------------------------")
    print(" 🔑 Checksum Words: " + " · ".join(words))
    print(" 🔢 BIP-39 Indices: " + str(indices))
    print("=" * 55)
    print(" Display this on the signer's mobile/hardware screen to")
    print(" verify payload integrity out-of-band.\n")

def cmd_scan_bytecode(args):
    """Scan contract bytecode for critical vulnerabilities."""
    from api_agents.agents.bytecode_hunter import scan_bytecode, generate_security_advisory

    print(f"\n[CLI] Disassembling and scanning bytecode ({len(args.bytecode)} hex chars)...")
    res = scan_bytecode(args.bytecode)
    advisory = generate_security_advisory(res)

    print("\n" + "=" * 60)
    print("       PROJECT VERO: BYTECODE VULNERABILITY SCAN       ")
    print("=" * 60)
    print(" Vulnerable      :", "⚠️ YES" if res.is_vulnerable else "✅ NO")
    print(" Risk Level      :", advisory.risk_level)
    print(" Instructions    :", res.instruction_count)
    print(" Has DELEGATECALL:", res.has_delegatecall)
    print(" Has SELFDESTRUCT:", res.has_selfdestruct)
    print(" Has tx.origin   :", res.has_tx_origin)
    print("-------------------------------------------------------")
    if res.findings:
        print(" Findings:")
        for f in res.findings:
            print(f"  • [{f.severity}] {f.title} (offset {hex(f.offset)})")
            print(f"    CWE : {f.cwe}")
            print(f"    Info: {f.description}")
            print(f"    Fix : {f.remediation}")
        print("\n Remediation Plan:")
        for r in advisory.remediation_plan:
            print(f"   -> {r}")
    else:
        print("  ✅ Zero malicious opcodes detected")
    print("=" * 60 + "\n")

def cmd_bench(args):
    """Run the 55-scenario exploit evaluation benchmark."""
    print("\n[CLI] Running 55-scenario attack harness (WazirX, Bybit, Permit2, MultiSend)...")
    import simulator.bench.run_eval as eval_module
    eval_module.main()

def cmd_latency(args):
    """Run latency SLA benchmark."""
    from scripts.benchmark_latency import run_benchmark
    run_benchmark()

def cmd_interactive(args):
    """Interactive CLI menu."""
    while True:
        print("\n" + "=" * 50)
        print("           🛡️  PROJECT VERO CLI MENU  🛡️         ")
        print("=" * 50)
        print(" 1. Simulate ERC-20 Transfer (Check State Diff & Words)")
        print(" 2. Simulate WazirX-Style Malicious Delegatecall Attack")
        print(" 3. Compute 4-Word Dual-Device Checksum")
        print(" 4. Scan Bytecode for Vulnerabilities")
        print(" 5. Run 55-Scenario Exploit Detection Benchmark")
        print(" 6. Run <150ms Latency SLA Benchmark")
        print(" 7. Check Local Firewall API Health")
        print(" 8. Exit")
        print("=" * 50)
        choice = input(" Select option [1-8]: ").strip()

        if choice == "1":
            parser = argparse.Namespace(
                chain_id=1,
                safe="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
                to="0xdAC17F958D2ee523a2206206994597C13D831ec7",
                value="0",
                data="0xa9059cbb000000000000000000000000cafe0000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000005f5e100",
                nonce=0
            )
            cmd_simulate(parser)
        elif choice == "2":
            parser = argparse.Namespace(
                chain_id=1,
                safe="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
                to="0x3D7Ebc40AF7092E3F1C81F2e996cbA5Cae2090d7",
                value="0",
                data="0x9e5faafc",
                nonce=0
            )
            cmd_simulate(parser)
        elif choice == "3":
            parser = argparse.Namespace(
                vault="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
                nonce=0,
                tx="0x6b0656fc183f96c3ca988cb6c3db8c241cb115f6eedff78715fe47cb580cf08e",
                policy="0x5b0f9436c819b53dbee8ea2c97c9b239e65dc59bc3413d5d08ecbb88caf2b2db"
            )
            cmd_checksum(parser)
        elif choice == "4":
            # Bytecode with SELFDESTRUCT (0xff) and tx.origin (0x32)
            sample_bytecode = "6080604052348015600f57600080fd5b5032ff"
            parser = argparse.Namespace(bytecode=sample_bytecode)
            cmd_scan_bytecode(parser)
        elif choice == "5":
            cmd_bench(None)
        elif choice == "6":
            cmd_latency(None)
        elif choice == "7":
            parser = argparse.Namespace(host="127.0.0.1", port=8000)
            cmd_status(parser)
        elif choice == "8" or choice.lower() in ("q", "quit", "exit"):
            print("Goodbye!\n")
            break
        else:
            print("Invalid choice, please select 1-8.")

def main():
    parser = argparse.ArgumentParser(
        description="Project Vero CLI 🛡️ — Transaction Firewall & Agent Security Suite"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # status
    p_status = subparsers.add_parser("status", help="Check local API status")
    p_status.add_argument("--host", default="127.0.0.1")
    p_status.add_argument("--port", type=int, default=8000)

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Simulate a transaction")
    p_sim.add_argument("--safe", default="0x1d1499e622D69689cdf9004d05Ec547d650Ff211")
    p_sim.add_argument("--to", required=True, help="Destination contract address")
    p_sim.add_argument("--value", default="0", help="Value in wei")
    p_sim.add_argument("--data", default="0x", help="Calldata hex")
    p_sim.add_argument("--chain-id", type=int, default=1)
    p_sim.add_argument("--nonce", type=int, default=0)

    # checksum
    p_chk = subparsers.add_parser("checksum", help="Compute 4-word dual-device checksum")
    p_chk.add_argument("--vault", required=True)
    p_chk.add_argument("--nonce", type=int, default=0)
    p_chk.add_argument("--tx", required=True, help="SafeTxHash hex")
    p_chk.add_argument("--policy", required=True, help="PolicyHash hex")

    # scan-bytecode
    p_scan = subparsers.add_parser("scan-bytecode", help="Scan EVM bytecode for vulnerabilities")
    p_scan.add_argument("bytecode", help="Contract bytecode hex string")

    # bench
    subparsers.add_parser("bench", help="Run 55 attack scenario benchmark")

    # latency
    subparsers.add_parser("latency", help="Run latency SLA benchmark")

    # interactive
    subparsers.add_parser("interactive", help="Start interactive CLI menu")

    if len(sys.argv) == 1:
        # Default to interactive if no arguments provided
        cmd_interactive(None)
    else:
        args = parser.parse_args()
        if args.subcommand == "status":
            cmd_status(args)
        elif args.subcommand == "simulate":
            cmd_simulate(args)
        elif args.subcommand == "checksum":
            cmd_checksum(args)
        elif args.subcommand == "scan-bytecode":
            cmd_scan_bytecode(args)
        elif args.subcommand == "bench":
            cmd_bench(args)
        elif args.subcommand == "latency":
            cmd_latency(args)
        elif args.subcommand == "interactive":
            cmd_interactive(args)
        else:
            parser.print_help()

if __name__ == "__main__":
    main()
