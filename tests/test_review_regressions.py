"""Regression tests for findings from the code review."""

import pytest
from pydantic import ValidationError

from shared.api_schemas import ApprovalChange, SimulationRequest, StateDiffSummary, TransactionTuple
from simulator.constants import ERC1967_IMPLEMENTATION_SLOT
from simulator.context import EngineContext
from simulator.diff import merge_diffs
from simulator.engine import analyze_offline, simulate
from simulator.hexutil import topic_of
from simulator.rules.twelve_rule_engine import sort_alerts
from simulator.rules.base import alert
from simulator.tracer.trace_diff import build_state_diff
from tests.helpers import ALICE, BOB, EVIL, SAFE, USDT, calldata, hexbytes, multisend_calldata
from tests.test_tracer import FakeProvider, make_sim, word

MULTISEND = "0x40a2accbd92bca938b02010e17a5b8929b49130d"


def req(*txs, **kw):
    return SimulationRequest(chainId=1, safeAddress=SAFE, transactions=list(txs), **kw)


def blocking(result):
    return {a.ruleId for a in result.alerts if a.severity in ("HIGH", "CRITICAL")}


def test_dirty_padding_on_known_selector_fails_closed():
    sel = calldata("approve(address,uint256)", ["address", "uint256"], [EVIL, 1])[:10]
    dirty = sel + "ff" * 12 + EVIL[2:] + "ff" * 32
    result = analyze_offline(req(TransactionTuple(to=USDT, data=dirty)), EngineContext())
    assert "DECODE" in blocking(result)


def test_oversized_uint_string_rejected():
    with pytest.raises(ValidationError):
        TransactionTuple(to=ALICE, value="9" * 79)


def test_merge_keeps_predicted_approval_missing_from_logs():
    observed = StateDiffSummary(approvals=[ApprovalChange(token=USDT, owner=SAFE, spender=BOB, amount="1")])
    predicted = StateDiffSummary(approvals=[
        ApprovalChange(token=USDT, owner=SAFE, spender=BOB, amount="1"),
        ApprovalChange(token=ALICE, owner=SAFE, spender=EVIL, amount=str(2**256 - 1)),
    ])
    merged = merge_diffs(observed, predicted)
    assert {a.spender for a in merged.approvals} == {BOB, EVIL}


def test_merge_fills_assets_missing_from_trace_without_double_counting():
    from shared.api_schemas import BalanceChange
    observed = StateDiffSummary(balanceChanges=[BalanceChange(address=SAFE, asset="ETH", delta="-5"),
                                                BalanceChange(address=BOB, asset="ETH", delta="5")])
    predicted = StateDiffSummary(balanceChanges=[
        BalanceChange(address=SAFE, asset="ETH", delta="-5"), BalanceChange(address=BOB, asset="ETH", delta="5"),
        BalanceChange(address=SAFE, asset=USDT, delta="-9"), BalanceChange(address=EVIL, asset=USDT, delta="9"),
    ])
    merged = merge_diffs(observed, predicted)
    assert len([c for c in merged.balanceChanges if c.asset == "ETH"]) == 2
    assert any(c.address == EVIL and c.asset == USDT for c in merged.balanceChanges)


async def test_age_check_skips_eoas_and_young_chains():
    from simulator.tracer.context_enricher import enrich_context
    sim, _ = make_sim(FakeProvider({"eth_getCode": {"result": "0x"}, "eth_blockNumber": {"result": "0x10"}}))
    request = req(TransactionTuple(to=EVIL))
    trace = await sim.simulate_transaction_batch(SAFE, request.transactions)
    ctx = await enrich_context(sim, EngineContext(), request, trace)
    assert EVIL not in ctx.deploy_times


def test_alert_dedupe_keeps_distinct_context():
    a = alert("R5", "CRITICAL", "Changes Safe owners", added=[EVIL])
    b = alert("R5", "CRITICAL", "Changes Safe owners", added=[BOB])
    assert len(sort_alerts([a, b])) == 2


async def test_upgrade_from_empty_slot_does_not_crash():
    prestate = {"pre": {SAFE: {"balance": "0x0"}},
                "post": {SAFE: {"storage": {ERC1967_IMPLEMENTATION_SLOT: word(EVIL)}}}}
    provider = FakeProvider({"debug_traceCall": lambda p: {"result": prestate if p[-1]["tracer"] ==
                                                           "prestateTracer" else {"type": "CALL"}}})
    sim, _ = make_sim(provider)
    diff = build_state_diff(SAFE, await sim.simulate_transaction_batch(SAFE, [TransactionTuple(to=USDT)]))
    assert diff.implementationSwaps[0].newImpl == EVIL


async def test_reverted_simulation_alerts_and_keeps_predicted_outflows():
    failing = {"type": "CALL", "error": "execution reverted"}
    provider = FakeProvider({"debug_traceCall": lambda p: {"result": {"pre": {}, "post": {}} if p[-1]["tracer"] ==
                                                           "prestateTracer" else failing}})
    sim, _ = make_sim(provider)
    data = calldata("transfer(address,uint256)", ["address", "uint256"], [EVIL, 10])
    result = await simulate(req(TransactionTuple(to=USDT, data=data)), EngineContext(), sim)
    assert "SIM-REVERTED" in blocking(result)
    assert any(c.address == EVIL for c in result.stateDiff.balanceChanges)


async def test_trusted_multisend_is_expanded_not_code_swapped():
    inner = hexbytes(calldata("changeThreshold(uint256)", ["uint256"], [2]))
    batch = multisend_calldata([(0, SAFE, 0, inner), (0, ALICE, 1, b"")])
    sim, provider = make_sim()
    await sim.simulate_transaction_batch(SAFE, [TransactionTuple(to=MULTISEND, data=batch, operation=1)])
    methods = [m for m, _ in provider.calls]
    assert "anvil_setCode" not in methods
    sent = [p[0]["to"] for m, p in provider.calls if m == "eth_sendTransaction"]
    assert sent == [SAFE, ALICE]


async def test_erc1155_transfer_single_from_safe_is_tracked():
    single = topic_of("TransferSingle(address,address,address,uint256,uint256)")
    data = "0x" + (7).to_bytes(32, "big").hex() + (5).to_bytes(32, "big").hex()
    trace = {"type": "CALL", "logs": [{"address": BOB, "topics": [single, word(SAFE), word(SAFE), word(EVIL)],
                                       "data": data}]}
    provider = FakeProvider({"debug_traceCall": lambda p: {"result": {"pre": {}, "post": {}} if p[-1]["tracer"] ==
                                                           "prestateTracer" else trace}})
    sim, _ = make_sim(provider)
    diff = build_state_diff(SAFE, await sim.simulate_transaction_batch(SAFE, [TransactionTuple(to=BOB)]))
    assert any(c.asset == f"{BOB}#7" and c.address == EVIL and c.delta == "5" for c in diff.balanceChanges)


@pytest.mark.parametrize("method", ["eth_sendTransaction", "debug_traceCall"])
async def test_node_rejecting_tx_is_a_failed_simulation_not_a_crash(method):
    rejected = {"error": {"code": -32003, "message": "Insufficient funds for gas * price + value"}}
    sim, _ = make_sim(FakeProvider({method: rejected}))
    txs = [TransactionTuple(to=EVIL, value="5")] * (2 if method == "eth_sendTransaction" else 1)
    result = await simulate(req(*txs), EngineContext(), sim)
    assert result.success is False
    assert "SIM-REVERTED" in blocking(result)
    assert "Insufficient funds" in (result.revertReason or "")


def test_non_ascii_token_symbol_flagged():
    fake = "0x" + "fa" * 20
    ctx = EngineContext(token_meta={fake: ("USDС", 6)})  # last char is Cyrillic
    data = calldata("transfer(address,uint256)", ["address", "uint256"], [ALICE, 1])
    assert "R11" in blocking(analyze_offline(req(TransactionTuple(to=fake, data=data)), ctx))


def test_set_fallback_handler_flagged():
    data = calldata("setFallbackHandler(address)", ["address"], [EVIL])
    assert "R6" in blocking(analyze_offline(req(TransactionTuple(to=SAFE, data=data)), EngineContext()))
