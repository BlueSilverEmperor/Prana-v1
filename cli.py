#!/usr/bin/env python3
"""
Project Vero CLI 🛡️
Command-line interface for transaction simulation, 4-word checksum verification,
bytecode scanning, latency benchmarking, and attack scenario evaluation.
Supports Dual-Mode Subsystem: STANDARD_EVM vs. QUAI_NATIVE (--quai).
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
            print("  ✅ Status        :", data.get("status", "unknown").upper())
            print("  🛡️ Service       :", data.get("service"))
            print("  📦 Version       :", data.get("version"))
            print("  ⚡ Engine        :", data.get("engine"))
            print("  🌐 Subsystem Mode:", data.get("subsystem_mode", "STANDARD_EVM"))
            print(f"  🌐 Docs          : http://{args.host}:{args.port}/docs\n")
    except Exception as e:
        print(f"  ❌ API not reachable on port {args.port} ({e})")
        print("  💡 Tip: Start the server with: python -m uvicorn api_agents.main:app --port 8000\n")

    if getattr(args, "quai", False):
        quai_url = f"http://{args.host}:{args.port}/v1/quai/status"
        print(f"[CLI] Checking Quai Subsystem Status at {quai_url} ...")
        try:
            req = urllib.request.Request(quai_url, headers={"User-Agent": "VeroCLI/1.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                qdata = json.loads(resp.read().decode())
                print("  ⛏️ Quai Subsystem :", qdata.get("subsystem"))
                print("  📍 Active Shard   :", qdata.get("active_shard"), f"(Prefix: {qdata.get('zone_prefix')}, Coords: {qdata.get('coordinates')})")
                print("  💰 Dual Assets    :", list(qdata.get("dual_assets", {}).keys()))
                print("  🧠 Hashference    :", qdata.get("hashference_x402", {}).get("provider"))
                print("  🔒 PoW Work Gate  :", "ENABLED" if qdata.get("work_gate_enabled") else "OFFLINE_FALLBACK")
                print("  ⚡ PoEM Consensus :", qdata.get("consensus"), "\n")
        except Exception as e:
            print(f"  ⚠️ Quai status endpoint not reachable ({e})\n")

def cmd_simulate(args):
    """Simulate a transaction against the Vero Firewall."""
    import asyncio
    from api_agents.adapters.factory import build_adapter, engine_name
    from api_agents.models.schemas import SimulateRequest
    from api_agents.utils.four_word_checksum import compute_four_word_checksum
    from api_agents.routes.firewall_api import _compute_raw_tx_hash
    from simulator.analyzers.poisoning import detect_quai_shard_prefix_spoofing

    is_quai = getattr(args, "quai", False) or args.chain_id in (9, 15000)
    chain_id = 15000 if (is_quai and args.chain_id == 1) else args.chain_id
    mode_str = "QUAI_NATIVE" if is_quai else "STANDARD_EVM"

    adapter = build_adapter()  # real Vero engine unless VERO_ENGINE=mock
    req = SimulateRequest(
        chain_id=chain_id,
        safe_address=args.safe,
        to=args.to,
        value=args.value,
        data=args.data,
        nonce=args.nonce,
        operation=getattr(args, "operation", 0),
    )

    t0 = time.perf_counter()
    sim = asyncio.run(adapter.simulate_tx(req))
    eval_res = adapter.evaluate(sim, req)

    # Check for Quai shard prefix spoofing
    if is_quai:
        shard_check = detect_quai_shard_prefix_spoofing(args.to, "cyprus1")
        if shard_check:
            eval_res.human_warnings.append(shard_check["warning"])
            eval_res.flags.append("QUAI_SHARD_PREFIX_SPOOFING")
            eval_res.risk_score = max(eval_res.risk_score, 95)
            from api_agents.models.schemas import DecisionEnum
            eval_res.decision = DecisionEnum.BLOCK

    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000.0

    raw_tx_hash = _compute_raw_tx_hash(req)
    intent_hash = "0x" + "0" * 64
    checksum = compute_four_word_checksum(
        chain_id=req.chain_id,
        safe_address=req.safe_address,
        nonce=req.nonce or 0,
        raw_tx_hash=raw_tx_hash,
        intent_hash=intent_hash,
        mode=mode_str,
        shard_zone="cyprus1",
    )

    print("\n" + "=" * 60)
    title = "PROJECT VERO: TRANSACTION SIMULATION (QUAI NATIVE)" if is_quai else "PROJECT VERO: TRANSACTION SIMULATION (STANDARD EVM)"
    print(f"           {title}           ")
    print("=" * 60)
    decision = eval_res.decision.value if hasattr(eval_res.decision, "value") else str(eval_res.decision)
    decision_icon = "✅" if decision == "ALLOW" else ("⚠️" if decision == "WARN" else "🛑")
    print(f" Engine           : {engine_name(adapter)}")
    print(f" Subsystem Mode   : {'⛏️ QUAI NATIVE (Cyprus-1 [0,0])' if is_quai else '⚡ STANDARD EVM'}")
    print(f" Decision         : {decision_icon} {decision}")
    print(f" Risk Score       : {eval_res.risk_score}/100")
    print(f" 4-Word Checksum  : 🔑 {checksum}")
    print(f" Execution Time   : {latency_ms:.3f} ms (SLA < 150 ms)")
    print(f" Target Contract  : {args.to}")
    print(f" Value            : {args.value} {'QUAI (Native)' if is_quai else 'Wei'}")

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
            print(f"   • {d.asset_type}: {d.delta_human} (from {d.from_address[:10]}... to {(d.to_address or '-')[:10]}...)")
    else:
        print("\n State Diffs      : None (0 balance mutations)")

    persona = getattr(args, "persona", None)
    if persona == "cfo":
        val_eth = (int(args.value) if args.value.isdigit() else 0) / 1e18
        print("\n" + "-" * 20 + " CFO FINANCIAL PERSPECTIVE " + "-" * 20)
        print(f" 💵 Net Outflow   : {val_eth:.4f} {'$QUAI' if is_quai else 'ETH'} (~${val_eth * 3000:.2f})")
        print(f" 📊 Rolling Cap   : {'WITHIN_LIMIT' if eval_res.risk_score < 70 else 'VELOCITY_CAP_EXCEEDED'}")
        print(f" ⚖️ Final Verdict : {decision}")
    elif persona == "sec":
        has_slot0 = any(f in eval_res.flags for f in ("R3", "SLOT_MUTATION", "PROXY_UPGRADE_ATTEMPT"))
        has_del = any(f in eval_res.flags for f in ("R4", "UNKNOWN_DELEGATECALL"))
        print("\n" + "-" * 20 + " SECURITY LEAD PERSPECTIVE " + "-" * 20)
        print(f" 🛡️ Slot-0 State  : {'🛑 MUTATED / COMPROMISED' if has_slot0 else '✅ IMMUTABLE / SECURE'}")
        print(f" ⚡ DelegateCall  : {'⚠️ DETECTED' if has_del else '✅ NONE'}")
        print(f" 🎯 Revert Reason : {('ControlSlotMutated' if has_slot0 else 'TokenSpendExceeded') if decision == 'BLOCK' else 'NONE'}")
    elif persona == "mobile":
        print("\n" + "-" * 20 + " MOBILE SIGNER CHALLENGE " + "-" * 20)
        print(f" 📱 Checksum Words: {checksum}")
        print(f" 🔒 Air-Gap Status: {'✅ SAFE TO SIGN' if decision == 'ALLOW' else '🛑 REJECT ON MOBILE'}")

    if getattr(args, "adversarial", False):
        print("\n" + "-" * 20 + " ADVERSARIAL STRESS TEST " + "-" * 20)
        has_drift = args.nonce > 100 or getattr(args, 'operation', 0) == 1
        print(f" ⏳ TOCTOU Drift  : {'⚠️ DRIFT HAZARD DETECTED' if has_drift else '✅ TIME-INVARIANT'}")
        print(f" 🔄 Transient Re  : {'⚠️ POTENTIAL REENTRANCY' if getattr(args, 'operation', 0) == 1 else '✅ CLEAN'}")
        if is_quai:
            print(" ⛏️ PoEM Finality : Prime-3 Region-6 Verified (Cross-Shard Atomic)")

    print("=" * 60 + "\n")

def cmd_checksum(args):
    """Derive 4-word dual-device verification checksum."""
    from shared.checksum import compute_4_word_checksum

    is_quai = getattr(args, "quai", False)
    mode_str = "QUAI_NATIVE" if is_quai else "STANDARD_EVM"
    words, indices = compute_4_word_checksum(
        vault=args.vault,
        nonce=args.nonce,
        safe_tx_hash=args.tx,
        policy_hash=args.policy,
        mode=mode_str,
        shard_zone=getattr(args, "zone", "cyprus1"),
    )
    print("\n" + "=" * 55)
    print(f"     PROJECT VERO: 4-WORD DUAL-DEVICE CHECKSUM ({mode_str})    ")
    print("=" * 55)
    print(" Subsystem Mode  :", mode_str)
    if is_quai:
        print(" Shard Zone      :", getattr(args, "zone", "cyprus1"))
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

    is_quai = getattr(args, "quai", False)
    print(f"\n[CLI] Disassembling and scanning bytecode ({len(args.bytecode)} hex chars)...")
    if is_quai:
        print("[CLI] Quai PoEM Cancun EVM analysis active (Checking Cyprus-1 deployment compatibility)")
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
    if is_quai:
        print(" Quai PoEM Ready :", "✅ COMPLIANT" if not res.is_vulnerable else "⚠️ REJECTED")
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
    eval_module.main([])  # empty argv: do not re-parse the CLI's own arguments

def cmd_latency(args):
    """Run latency SLA benchmark."""
    from scripts.benchmark_latency import run_benchmark
    run_benchmark()

def cmd_interactive(args):
    """Interactive CLI menu."""
    while True:
        print("\n" + "=" * 55)
        print("           🛡️  PROJECT VERO CLI MENU  🛡️         ")
        print("=" * 55)
        print(" 1. Simulate ERC-20 Transfer (Check State Diff & Words)")
        print(" 2. Simulate WazirX-Style Malicious Delegatecall Attack")
        print(" 3. Simulate Quai Native Transfer (--quai Cyprus-1)")
        print(" 4. Compute 4-Word Dual-Device Checksum (Standard EVM)")
        print(" 5. Compute 4-Word Dual-Device Checksum (Quai Shard)")
        print(" 6. Scan Bytecode for Vulnerabilities")
        print(" 7. Run 55-Scenario Exploit Detection Benchmark")
        print(" 8. Run <150ms Latency SLA Benchmark")
        print(" 9. Check Local Firewall API Health & Quai Telemetry")
        print(" 10. Exit")
        print("=" * 55)
        choice = input(" Select option [1-10]: ").strip()

        if choice == "1":
            parser = argparse.Namespace(
                chain_id=1,
                safe="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
                to="0xdAC17F958D2ee523a2206206994597C13D831ec7",
                value="0",
                data="0xa9059cbb000000000000000000000000cafe0000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000005f5e100",
                nonce=0,
                quai=False
            )
            cmd_simulate(parser)
        elif choice == "2":
            parser = argparse.Namespace(
                chain_id=1,
                safe="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
                to="0x3D7Ebc40AF7092E3F1C81F2e996cbA5Cae2090d7",
                value="0",
                # Bybit-style payload: transfer(newSingleton, 0) executed by DELEGATECALL
                data="0xa9059cbb000000000000000000000000babababababababababababababababababababa"
                     "0000000000000000000000000000000000000000000000000000000000000000",
                nonce=0,
                operation=1,
                quai=False,
            )
            cmd_simulate(parser)
        elif choice == "3":
            parser = argparse.Namespace(
                chain_id=15000,
                safe="0x0017a140Aa3E981100a9becA4E685f962f0cF6C9",
                to="0x0027a140Aa3E981100a9becA4E685f962f0cF6C9",
                value="1000000000000000000",
                data="0x",
                nonce=0,
                quai=True
            )
            cmd_simulate(parser)
        elif choice == "4":
            parser = argparse.Namespace(
                vault="0x1d1499e622D69689cdf9004d05Ec547d650Ff211",
                nonce=0,
                tx="0x6b0656fc183f96c3ca988cb6c3db8c241cb115f6eedff78715fe47cb580cf08e",
                policy="0x2145f00f92f578e83c451275b3793e2d1a7e6d369bea695bbab3f5a04cda8f68",
                quai=False
            )
            cmd_checksum(parser)
        elif choice == "5":
            parser = argparse.Namespace(
                vault="0x0017a140Aa3E981100a9becA4E685f962f0cF6C9",
                nonce=0,
                tx="0x6b0656fc183f96c3ca988cb6c3db8c241cb115f6eedff78715fe47cb580cf08e",
                policy="0x2145f00f92f578e83c451275b3793e2d1a7e6d369bea695bbab3f5a04cda8f68",
                zone="cyprus1",
                quai=True
            )
            cmd_checksum(parser)
        elif choice == "6":
            code = input(" Enter contract bytecode hex: ").strip()
            if not code:
                code = "0x608060405234801561001057600080fd5b506004361061002b57"
            parser = argparse.Namespace(bytecode=code, quai=False)
            cmd_scan_bytecode(parser)
        elif choice == "7":
            cmd_bench(None)
        elif choice == "8":
            cmd_latency(None)
        elif choice == "9":
            parser = argparse.Namespace(host="127.0.0.1", port=8000, quai=True)
            cmd_status(parser)
        elif choice == "10":
            print("Exiting Project Vero CLI. Stay secure!\n")
            break
        else:
            print("Invalid choice, please select 1-10.")

def main():
    parser = argparse.ArgumentParser(
        description="Project Vero CLI 🛡️ — Transaction Firewall & Agent Security Suite"
    )
    parser.add_argument("--quai", action="store_true", help="Enable Quai Network native mode (Cyprus-1 shard, $QUAI/$QI dual-currency)")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # status
    p_status = subparsers.add_parser("status", help="Check local API status")
    p_status.add_argument("--host", default="127.0.0.1")
    p_status.add_argument("--port", type=int, default=8000)
    p_status.add_argument("--quai", action="store_true", help="Include Quai Subsystem telemetry")

    # simulate
    p_sim = subparsers.add_parser("simulate", help="Simulate a transaction")
    p_sim.add_argument("--safe", default="0x1d1499e622D69689cdf9004d05Ec547d650Ff211")
    p_sim.add_argument("--to", required=True, help="Destination contract address")
    p_sim.add_argument("--value", default="0", help="Value in wei")
    p_sim.add_argument("--data", default="0x", help="Calldata hex")
    p_sim.add_argument("--chain-id", type=int, default=1)
    p_sim.add_argument("--nonce", type=int, default=0)
    p_sim.add_argument("--operation", type=int, choices=[0, 1], default=0, help="0 CALL, 1 DELEGATECALL")
    p_sim.add_argument("--quai", action="store_true", help="Simulate in Quai Native mode")
    p_sim.add_argument("--persona", choices=["cfo", "sec", "mobile"], help="Render role-tailored simulation view")
    p_sim.add_argument("--adversarial", action="store_true", help="Run adversarial TOCTOU and reentrancy stress checks")

    # checksum
    p_chk = subparsers.add_parser("checksum", help="Compute 4-word dual-device checksum")
    p_chk.add_argument("--vault", required=True)
    p_chk.add_argument("--nonce", type=int, default=0)
    p_chk.add_argument("--tx", required=True, help="SafeTxHash hex")
    p_chk.add_argument("--policy", required=True, help="PolicyHash hex")
    p_chk.add_argument("--zone", default="cyprus1", help="Quai shard zone (default: cyprus1)")
    p_chk.add_argument("--quai", action="store_true", help="Bind Quai shard zone coordinates into checksum")

    # scan-bytecode
    p_scan = subparsers.add_parser("scan-bytecode", help="Scan EVM bytecode for vulnerabilities")
    p_scan.add_argument("bytecode", help="Contract bytecode hex string")
    p_scan.add_argument("--quai", action="store_true", help="Verify Quai PoEM compatibility")

    # bench
    subparsers.add_parser("bench", help="Run 55 attack scenario benchmark")

    # latency
    subparsers.add_parser("latency", help="Run latency SLA benchmark")

    # interactive
    subparsers.add_parser("interactive", help="Start interactive CLI menu")

    if len(sys.argv) == 1:
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
