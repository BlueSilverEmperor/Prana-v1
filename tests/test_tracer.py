import pytest
from eth_abi import encode

from shared.api_schemas import IntentPolicy, SimulationRequest, TransactionTuple
from simulator.constants import ERC1967_IMPLEMENTATION_SLOT
from simulator.context import EngineContext
from simulator.engine import simulate
from simulator.hexutil import topic_of
from simulator.tracer.anvil_fork_simulator import AnvilForkSimulator, SimulationRPCError
from simulator.tracer.trace_diff import build_state_diff
from tests.helpers import ALICE, EVIL, SAFE, USDT, calldata

TRANSFER = topic_of("Transfer(address,address,uint256)")
APPROVAL = topic_of("Approval(address,address,uint256)")
ADDED_OWNER = topic_of("AddedOwner(address)")


def word(addr: str) -> str:
    return "0x" + "00" * 12 + addr[2:]


def amount(n: int) -> str:
    return "0x" + n.to_bytes(32, "big").hex()


PRESTATE = {
    "pre": {SAFE: {"balance": hex(10**18)}, ALICE: {"balance": "0x0"}},
    "post": {SAFE: {"balance": hex(4 * 10**17)}, ALICE: {"balance": hex(6 * 10**17)}},
}
CALLTRACE = {
    "type": "CALL", "from": SAFE, "to": USDT, "gasUsed": "0x5208", "input": "0x",
    "logs": [
        {"address": USDT, "topics": [TRANSFER, word(SAFE), word(ALICE)], "data": amount(100)},
        {"address": USDT, "topics": [APPROVAL, word(SAFE), word(EVIL)], "data": amount(2**256 - 1)},
    ],
    "calls": [{"type": "CALL", "from": USDT, "to": ALICE, "gasUsed": "0x0", "input": "0x",
               "logs": [{"address": SAFE, "topics": [ADDED_OWNER], "data": word(EVIL)}]}],
}


class FakeProvider:
    def __init__(self, overrides=None):
        self.calls = []
        self.overrides = overrides or {}

    async def make_request(self, method, params):
        self.calls.append((method, params))
        if method in self.overrides:
            value = self.overrides[method]
            return value(params) if callable(value) else value
        if method in ("debug_traceCall", "debug_traceTransaction"):
            tracer = params[-1]["tracer"]
            return {"result": PRESTATE if tracer == "prestateTracer" else CALLTRACE}
        defaults = {
            "eth_chainId": "0x1", "eth_getCode": "0x6000", "evm_snapshot": "0x1", "evm_revert": True,
            "eth_sendTransaction": "0x" + "ab" * 32, "eth_getTransactionReceipt": {"status": "0x1"},
            "eth_blockNumber": "0x64", "eth_getBlockByNumber": {"timestamp": hex(1_700_000_000)},
            "eth_call": "0x" + "00" * 32,
        }
        return {"result": defaults.get(method, None)}


class FakeW3:
    def __init__(self, provider):
        self.provider = provider


def make_sim(provider=None):
    provider = provider or FakeProvider()
    return AnvilForkSimulator(w3=FakeW3(provider)), provider


def tx(**kw):
    return TransactionTuple(**{"to": USDT, "value": "0", "data": "0x", **kw})


class TestAnvilForkSimulator:
    async def test_single_tx_uses_two_debug_trace_calls(self):
        sim, provider = make_sim()
        trace = await sim.simulate_transaction_batch(SAFE, [tx()])
        tracers = [p[-1]["tracer"] for m, p in provider.calls if m == "debug_traceCall"]
        assert sorted(tracers) == ["callTracer", "prestateTracer"]
        assert trace.success is True
        assert trace.gas_used == 0x5208
        assert len(trace.logs) == 3
        assert trace.latency_ms >= 0

    async def test_delegatecall_swaps_safe_code_via_state_override(self):
        sim, provider = make_sim()
        await sim.simulate_transaction_batch(SAFE, [tx(to=EVIL, operation=1)])
        trace_call = next(p for m, p in provider.calls if m == "debug_traceCall")
        assert trace_call[0]["to"] == SAFE
        assert trace_call[-1]["stateOverrides"][SAFE]["code"] == "0x6000"

    async def test_rpc_error_on_infrastructure_call_raises(self):
        sim, _ = make_sim(FakeProvider({"eth_chainId": {"error": {"code": -32000, "message": "boom"}}}))
        with pytest.raises(SimulationRPCError):
            await sim.simulate_transaction_batch(SAFE, [tx()])

    async def test_trace_rejection_becomes_failed_trace(self):
        sim, _ = make_sim(FakeProvider({"debug_traceCall": {"error": {"code": -32000, "message": "boom"}}}))
        trace = await sim.simulate_transaction_batch(SAFE, [tx()])
        assert trace.success is False and "boom" in trace.error

    async def test_batch_snapshots_and_always_reverts(self):
        provider = FakeProvider({"eth_getTransactionReceipt": {"result": {"status": "0x0"}}})
        sim, _ = make_sim(provider)
        trace = await sim.simulate_transaction_batch(SAFE, [tx(), tx(to=ALICE)])
        methods = [m for m, _ in provider.calls if m != "eth_chainId"]  # chain id is fetched concurrently
        assert methods[0] == "evm_snapshot" and methods[-1] == "evm_revert"
        assert trace.success is False

    async def test_reverted_top_frame_marks_failure(self):
        failing = {**CALLTRACE, "error": "execution reverted", "revertReason": "GS013"}
        provider = FakeProvider({"debug_traceCall": lambda p: {"result": PRESTATE if p[-1]["tracer"] ==
                                                               "prestateTracer" else failing}})
        sim, _ = make_sim(provider)
        trace = await sim.simulate_transaction_batch(SAFE, [tx()])
        assert trace.success is False and "GS013" in trace.error

    async def test_inspect_proxy_reads_slots_and_code(self):
        sim, provider = make_sim(FakeProvider({"eth_getStorageAt": {"result": word(EVIL)}}))
        snap = await sim.inspect_proxy(SAFE)
        assert snap.erc1967_implementation == EVIL
        assert snap.codehash.startswith("0x")


class TestTraceDiff:
    async def test_builds_eth_token_approval_and_owner_changes(self):
        sim, _ = make_sim()
        trace = await sim.simulate_transaction_batch(SAFE, [tx()])
        diff = build_state_diff(SAFE, trace)
        eth = {(c.address, c.delta) for c in diff.balanceChanges if c.asset == "ETH"}
        assert (ALICE, str(6 * 10**17)) in eth
        assert any(c.asset == USDT and c.address == ALICE and c.delta == "100" for c in diff.balanceChanges)
        assert diff.approvals[0].spender == EVIL
        assert diff.ownerChanges[0].added == [EVIL]

    async def test_detects_erc1967_slot_change_and_7702_code(self):
        prestate = {
            "pre": {SAFE: {"storage": {ERC1967_IMPLEMENTATION_SLOT: word(ALICE)}}, ALICE: {"code": "0x"}},
            "post": {SAFE: {"storage": {ERC1967_IMPLEMENTATION_SLOT: word(EVIL)}},
                     ALICE: {"code": "0xef0100" + EVIL[2:]}},
        }
        provider = FakeProvider({"debug_traceCall": lambda p: {"result": prestate if p[-1]["tracer"] ==
                                                               "prestateTracer" else {"type": "CALL"}}})
        sim, _ = make_sim(provider)
        diff = build_state_diff(SAFE, await sim.simulate_transaction_batch(SAFE, [tx()]))
        sources = {s.source for s in diff.implementationSwaps}
        assert sources == {"erc1967-slot", "code"}


class TestForkEngine:
    async def test_simulate_end_to_end_in_fork_mode(self):
        sim, _ = make_sim()
        data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 100])
        policy = IntentPolicy(allowedRecipients=[ALICE], maxOutflowWei=str(10**18), allowedTokens=[USDT, "ETH"])
        request = SimulationRequest(chainId=1, safeAddress=SAFE, transactions=[tx(data=data)], intentPolicy=policy)
        result = await simulate(request, EngineContext(), simulator=sim)
        rule_ids = {a.ruleId for a in result.alerts}
        assert result.mode == "fork"
        assert {"R1", "R5"} <= rule_ids  # hidden approval + owner added, observed only in the trace
        assert result.metrics.gasUsed == str(0x5208)

    async def test_wrong_chain_on_node_is_flagged(self):
        sim, _ = make_sim(FakeProvider({"eth_chainId": {"result": "0xa"}}))
        request = SimulationRequest(chainId=1, safeAddress=SAFE, transactions=[tx()])
        result = await simulate(request, EngineContext(), simulator=sim)
        assert "C31-CHAIN" in {a.ruleId for a in result.alerts}

    async def test_simulate_without_simulator_falls_back_to_static(self):
        request = SimulationRequest(chainId=1, safeAddress=SAFE, transactions=[tx()])
        assert (await simulate(request)).mode == "static"

    async def test_enrich_context_fetches_symbol_and_balance(self):
        symbol = "0x" + encode(["string"], ["FAKE"]).hex()
        provider = FakeProvider({"eth_call": lambda p: {"result": symbol if p[0]["data"] == "0x95d89b41"
                                                        else "0x" + (6).to_bytes(32, "big").hex()}})
        sim, _ = make_sim(provider)
        request = SimulationRequest(chainId=1, safeAddress=SAFE, transactions=[tx(to="0x" + "fa" * 20)])
        trace = await sim.simulate_transaction_batch(SAFE, request.transactions)
        ctx = await sim.enrich_context(EngineContext(), request, trace)
        assert ctx.now == 1_700_000_000
        assert ctx.symbol_of(USDT) == "USDT"
