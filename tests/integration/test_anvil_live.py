"""Live tests against a real Anvil node. Skipped when Foundry is not installed.

The fixture starts a fresh Anvil on a free port, deploys tests/integration/contracts
(build them with `forge build` in that folder), and stops Anvil afterwards.
"""

import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from web3 import HTTPProvider, Web3

from shared.api_schemas import IntentPolicy, SimulationRequest, TransactionTuple
from simulator.context import EngineContext
from simulator.engine import simulate
from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator
from tests.helpers import calldata, hexbytes, multisend_calldata

ROOT = Path(__file__).parent / "contracts" / "out" / "Fixtures.sol"
ANVIL = shutil.which("anvil") or str(Path.home() / ".foundry" / "bin" / "anvil")
EVIL = "0x" + "e0" * 20
ALICE = "0x" + "a1" * 20
MAL_SINGLETON = "0x" + "ba" * 20
OLD_SINGLETON = "0x" + "11" * 20
MULTISEND = "0x40a2accbd92bca938b02010e17a5b8929b49130d"
CHAIN_ID = 31337
STARTUP_TIMEOUT_S = 10

pytestmark = pytest.mark.skipif(
    not (os.path.exists(ANVIL) and ROOT.exists()), reason="anvil or compiled fixtures missing"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _deploy(w3: Web3, name: str, *args) -> str:
    artifact = json.loads((ROOT / f"{name}.json").read_text())
    factory = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"]["object"])
    tx_hash = factory.constructor(*args).transact({"from": w3.eth.accounts[0]})
    return w3.eth.wait_for_transaction_receipt(tx_hash)["contractAddress"].lower()


@pytest.fixture(scope="module")
def chain():
    port = _free_port()
    proc = subprocess.Popen([ANVIL, "--port", str(port), "--silent"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    w3 = Web3(HTTPProvider(url))
    deadline = time.time() + STARTUP_TIMEOUT_S
    while not w3.is_connected():
        if time.time() > deadline:
            proc.kill()
            pytest.fail("anvil did not start")
        time.sleep(0.1)
    try:
        token = _deploy(w3, "MockToken", "USDT", 6)
        safe = _deploy(w3, "MockSafe", Web3.to_checksum_address(OLD_SINGLETON), 3)
        rewriter = _deploy(w3, "SlotRewriter")
        abi = json.loads((ROOT / "MockToken.json").read_text())["abi"]
        mint = w3.eth.contract(address=Web3.to_checksum_address(token), abi=abi).functions.mint(
            Web3.to_checksum_address(safe), 1_000 * 10**6)
        w3.eth.wait_for_transaction_receipt(mint.transact({"from": w3.eth.accounts[0]}))
        w3.provider.make_request("anvil_setBalance", [safe, hex(10 * 10**18)])
        yield {"url": url, "w3": w3, "token": token, "safe": safe, "rewriter": rewriter}
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@pytest.fixture
async def sim(chain):
    async with AnvilForkSimulator(chain["url"]) as simulator:
        yield simulator


def req(chain, *txs, policy=None):
    return SimulationRequest(chainId=CHAIN_ID, safeAddress=chain["safe"], transactions=list(txs), intentPolicy=policy)


def ctx(chain) -> EngineContext:
    return EngineContext(token_meta={chain["token"]: ("USDT", 6)})


def ids(result):
    return {a.ruleId for a in result.alerts}


def transfer(to, amount):
    return calldata("transfer(address,uint256)", ["address", "uint256"], [to, amount])


def safe_state(chain) -> tuple[int, int]:
    w3 = chain["w3"]
    threshold = int(w3.eth.get_storage_at(Web3.to_checksum_address(chain["safe"]), 4).hex(), 16)
    abi = json.loads((ROOT / "MockToken.json").read_text())["abi"]
    token = w3.eth.contract(address=Web3.to_checksum_address(chain["token"]), abi=abi)
    return threshold, token.functions.balanceOf(Web3.to_checksum_address(chain["safe"])).call()


async def test_single_transfer_traced_with_real_logs(chain, sim):
    policy = IntentPolicy(allowedRecipients=[ALICE], maxOutflowWei=str(100 * 10**6), allowedTokens=[chain["token"]])
    result = await simulate(req(chain, TransactionTuple(to=chain["token"], data=transfer(ALICE, 100 * 10**6)),
                                policy=policy), ctx(chain), sim)
    assert result.mode == "fork" and result.success
    assert int(result.metrics.gasUsed) > 0
    assert any(c.address == ALICE and c.delta == str(100 * 10**6) for c in result.stateDiff.balanceChanges)
    assert not {a.ruleId for a in result.alerts if a.severity in ("HIGH", "CRITICAL")}
    assert any("Transfer 100 USDT" in line for line in result.plainEnglishSummary)


async def test_unlimited_approval_seen_in_trace(chain, sim):
    data = calldata("approve(address,uint256)", ["address", "uint256"], [EVIL, 2**256 - 1])
    result = await simulate(req(chain, TransactionTuple(to=chain["token"], data=data)), ctx(chain), sim)
    assert "R1" in ids(result)
    assert result.stateDiff.approvals[0].spender == EVIL


async def test_eth_drain_to_undeclared_address(chain, sim):
    policy = IntentPolicy(allowedRecipients=[ALICE], maxOutflowWei=str(10**18), allowedTokens=["ETH"])
    result = await simulate(req(chain, TransactionTuple(to=EVIL, value=str(5 * 10**18)), policy=policy),
                            ctx(chain), sim)
    assert {"R9", "R10"} <= ids(result)
    assert any(c.address == EVIL and c.asset == "ETH" for c in result.stateDiff.balanceChanges)


async def test_batch_reverts_fork_state_afterwards(chain, sim):
    before = safe_state(chain)
    lower = calldata("changeThreshold(uint256)", ["uint256"], [1])
    result = await simulate(req(chain, TransactionTuple(to=chain["token"], data=transfer(EVIL, 500 * 10**6)),
                                TransactionTuple(to=chain["safe"], data=lower)), ctx(chain), sim)
    assert result.success
    owner_change = result.stateDiff.ownerChanges[0]
    assert (owner_change.oldThreshold, owner_change.newThreshold) == (3, 1)
    assert "R5" in ids(result)
    assert safe_state(chain) == before


async def test_bybit_style_delegatecall_rewrites_slot0(chain, sim):
    payload = transfer(MAL_SINGLETON, 0)
    result = await simulate(req(chain, TransactionTuple(to=chain["rewriter"], data=payload, operation=1)),
                            ctx(chain), sim)
    swaps = {(s.source, s.newImpl) for s in result.stateDiff.implementationSwaps}
    assert ("slot0", MAL_SINGLETON) in swaps
    assert {"R3", "R4"} <= ids(result)


async def test_erc1967_slot_written_from_empty(chain, sim):
    payload = calldata("upgrade(address)", ["address"], [MAL_SINGLETON])
    result = await simulate(req(chain, TransactionTuple(to=chain["rewriter"], data=payload, operation=1)),
                            ctx(chain), sim)
    assert ("erc1967-slot", MAL_SINGLETON) in {(s.source, s.newImpl) for s in result.stateDiff.implementationSwaps}


async def test_trusted_multisend_with_inner_safe_call_does_not_revert(chain, sim):
    before = safe_state(chain)
    add_owner = hexbytes(calldata("addOwnerWithThreshold(address,uint256)", ["address", "uint256"], [EVIL, 1]))
    batch = multisend_calldata([(0, chain["token"], 0, hexbytes(transfer(ALICE, 1))), (0, chain["safe"], 0, add_owner)])
    result = await simulate(req(chain, TransactionTuple(to=MULTISEND, data=batch, operation=1)), ctx(chain), sim)
    assert result.success, result.revertReason
    assert EVIL in result.stateDiff.ownerChanges[0].added
    assert safe_state(chain) == before


async def test_reverting_transfer_is_flagged(chain, sim):
    result = await simulate(req(chain, TransactionTuple(to=chain["token"], data=transfer(EVIL, 10**30))),
                            ctx(chain), sim)
    assert result.success is False
    assert "SIM-REVERTED" in ids(result)


async def test_simple_transfer_latency_is_reported(chain, sim):
    request = req(chain, TransactionTuple(to=chain["token"], data=transfer(ALICE, 1)))
    latencies = []
    for _ in range(20):
        latencies.append((await simulate(request, ctx(chain), sim)).simulationLatencyMs)
    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    print(f"\nlive fork latency p50={p50:.1f} ms p95={latencies[18]:.1f} ms")
    assert p50 < 1000
