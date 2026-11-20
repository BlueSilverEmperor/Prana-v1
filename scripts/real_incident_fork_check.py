"""Replays the real WazirX and Bybit transactions on an Anvil fork of mainnet at the block just before
each attack, through the same adapter /v1/simulate uses, and prints the engine's verdict.

This runs the engine against real chain state (the victim Safe's actual code and balances at that
moment), not just the calldata. Needs anvil (Foundry) and a mainnet RPC that serves historical state.

Usage: python scripts/real_incident_fork_check.py [--rpc ARCHIVE_URL] [--latest]
  The attack block needs an archive RPC (public nodes prune old state). --latest forks today's mainnet
  instead: real current state, including the attackers' contracts, but not the moment of the attack.
Run scripts/fetch_real_incidents.py first.
"""

import argparse
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "api-agents")]

from api_agents.adapters.vero_engine_adapter import VeroEngineAdapter  # noqa: E402
from api_agents.models.schemas import SimulateRequest  # noqa: E402

INCIDENTS = ROOT / "frontend" / "data" / "real_incidents.json"
DEFAULT_RPC = "https://ethereum-rpc.publicnode.com"
ANVIL_READY_TIMEOUT_S = 60


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _anvil_binary() -> str:
    found = shutil.which("anvil") or str(Path.home() / ".foundry" / "bin" / "anvil")
    if not Path(found).exists():
        raise SystemExit("anvil not found: install Foundry (https://getfoundry.sh)")
    return found


def _wait_ready(url: str, proc: subprocess.Popen) -> None:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []}).encode()
    deadline = time.time() + ANVIL_READY_TIMEOUT_S
    while time.time() < deadline:
        if proc.poll() is not None:
            detail = (proc.stderr.read() or "").strip().splitlines()
            raise RuntimeError("anvil exited: " + (detail[-1] if detail else "no output")[:300])
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3):
                return
        except OSError:
            time.sleep(0.5)
    raise RuntimeError("anvil did not become ready")


async def _check(incident: dict, rpc_url: str) -> None:
    adapter = VeroEngineAdapter(rpc_url=rpc_url)
    req = SimulateRequest(**incident["request"])
    started = time.perf_counter()
    sim = await adapter.simulate_tx(req)
    verdict = adapter.evaluate(sim, req)
    elapsed = (time.perf_counter() - started) * 1000
    print(f"  Decision     : {verdict.decision.value}  (risk {verdict.risk_score})")
    print(f"  Flags        : {verdict.flags}")
    print(f"  Fork used    : {'NO, fell back to static' if 'FORK_UNAVAILABLE' in verdict.flags else 'yes'}")
    for warning in verdict.human_warnings[:3]:
        print(f"  Warning      : {warning}")
    for diff in sim.state_diffs[:4]:
        print(f"  State change : {diff.asset_type} {diff.delta_human}")
    print(f"  Time         : {elapsed:.0f} ms (fork simulation)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc", default=DEFAULT_RPC)
    parser.add_argument("--latest", action="store_true", help="fork the latest block instead of the attack block")
    args = parser.parse_args()
    incidents = json.loads(INCIDENTS.read_text())
    anvil = _anvil_binary()

    for incident in incidents:
        block = incident["source"]["block"] - 1
        port = _free_port()
        where = "the latest block (current state)" if args.latest else f"block {block} (just before the attack)"
        print(f"\n{incident['title']}\n  tx {incident['source']['txHash']}\n  fork of mainnet at {where}")
        cmd = [anvil, "--fork-url", args.rpc, "--port", str(port), "--silent"]
        if not args.latest:
            cmd += ["--fork-block-number", str(block)]
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env={**os.environ})
        try:
            local = f"http://127.0.0.1:{port}"
            try:
                _wait_ready(local, proc)
            except RuntimeError as exc:
                print(f"  SKIPPED      : {exc}")
                continue
            asyncio.run(_check(incident, local))
        finally:
            proc.terminate()
            proc.wait(timeout=10)


if __name__ == "__main__":
    main()
