"""Tests for VeroEngineAdapter: the real simulation + rule engine behind the firewall API."""

import asyncio

import pytest
from eth_abi import encode
from eth_utils import keccak
from fastapi.testclient import TestClient

from api_agents.adapters.factory import build_adapter
from api_agents.adapters.simulator_protocol import RuleEngineProtocol, SimulatorProtocol
from api_agents.adapters.vero_engine_adapter import EngineInputError, VeroEngineAdapter
from api_agents.main import app
from api_agents.models.schemas import DecisionEnum, DeclaredIntent, SimulateRequest

SAFE = "0x" + "5a" * 20
EVIL = "0x" + "e0" * 20
ALICE = "0x" + "a1" * 20
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
MAX = 2**256 - 1


def cd(signature: str, types: list, args: list) -> str:
    return "0x" + (keccak(text=signature)[:4] + encode(types, args)).hex()


def run(adapter: VeroEngineAdapter, req: SimulateRequest):
    sim = asyncio.run(adapter.simulate_tx(req))
    return sim, adapter.evaluate(sim, req)


@pytest.fixture
def adapter():
    return VeroEngineAdapter()


def test_implements_both_protocols(adapter):
    assert isinstance(adapter, SimulatorProtocol)
    assert isinstance(adapter, RuleEngineProtocol)


@pytest.mark.parametrize("to,data,flag", [
    (SAFE, cd("enableModule(address)", ["address"], [EVIL]), "MODULE_ENABLED"),
    (SAFE, cd("addOwnerWithThreshold(address,uint256)", ["address", "uint256"], [EVIL, 1]),
     "OWNER_OR_THRESHOLD_CHANGE"),
    (SAFE, cd("setGuard(address)", ["address"], ["0x" + "00" * 20]), "GUARD_CHANGE"),
    ("0x" + "9a" * 20, cd("transferOwnership(address)", ["address"], [EVIL]), "OWNER_OR_THRESHOLD_CHANGE"),
    (USDT, cd("approve(address,uint256)", ["address", "uint256"], [EVIL, MAX]), "INFINITE_TOKEN_APPROVAL"),
    (SAFE, cd("upgradeTo(address)", ["address"], [EVIL]), "PROXY_UPGRADE_ATTEMPT"),
])
def test_critical_attacks_are_blocked_with_named_flags(adapter, to, data, flag):
    _, verdict = run(adapter, SimulateRequest(safe_address=SAFE, to=to, data=data))
    assert verdict.decision == DecisionEnum.BLOCK
    assert flag in verdict.flags
    assert verdict.risk_score >= 80
    assert verdict.human_warnings


def test_plain_transfer_without_declaration_is_allowed(adapter):
    req = SimulateRequest(safe_address=SAFE, to=USDT, data=cd("transfer(address,uint256)",
                                                              ["address", "uint256"], [ALICE, 10]))
    sim, verdict = run(adapter, req)
    assert verdict.decision == DecisionEnum.ALLOW
    assert verdict.risk_score < 40
    assert sim.state_diffs[0].asset_type == "ERC20"
    assert sim.state_diffs[0].to_address == ALICE


def test_declared_intent_catches_undeclared_recipient(adapter):
    intent = DeclaredIntent(allowed_recipients=[ALICE], allowed_tokens=[USDT], max_outflow_wei="100")
    req = SimulateRequest(safe_address=SAFE, to=USDT, declared_intent=intent,
                          data=cd("transfer(address,uint256)", ["address", "uint256"], [EVIL, 50]))
    _, verdict = run(adapter, req)
    assert verdict.decision == DecisionEnum.BLOCK
    assert "UNDECLARED_RECIPIENT" in verdict.flags


def test_delegatecall_operation_is_supported(adapter):
    req = SimulateRequest(safe_address=SAFE, to=EVIL, data="0x12345678", operation=1)
    _, verdict = run(adapter, req)
    assert "UNVERIFIED_DELEGATECALL" in verdict.flags


def test_unlimited_approval_state_diff(adapter):
    req = SimulateRequest(safe_address=SAFE, to=USDT,
                          data=cd("approve(address,uint256)", ["address", "uint256"], [EVIL, MAX]))
    sim, _ = run(adapter, req)
    diff = sim.state_diffs[0]
    assert diff.asset_type == "ERC20_ALLOWANCE"
    assert diff.delta_human == "APPROVAL GRANTED (UNLIMITED USDT)"


def test_evaluate_without_prior_simulation_still_judges(adapter):
    req = SimulateRequest(safe_address=SAFE, to=SAFE, data=cd("enableModule(address)", ["address"], [EVIL]))
    other = asyncio.run(VeroEngineAdapter().simulate_tx(req))
    assert adapter.evaluate(other, req).decision == DecisionEnum.BLOCK


def test_invalid_address_raises_input_error(adapter):
    with pytest.raises(EngineInputError):
        asyncio.run(adapter.simulate_tx(SimulateRequest(safe_address="not-an-address", to=USDT)))


def test_unreachable_fork_falls_back_to_static_and_says_so():
    adapter = VeroEngineAdapter(rpc_url="http://127.0.0.1:1")
    req = SimulateRequest(safe_address=SAFE, to=SAFE, data=cd("enableModule(address)", ["address"], [EVIL]))
    _, verdict = run(adapter, req)
    assert verdict.decision == DecisionEnum.BLOCK
    assert "FORK_UNAVAILABLE" in verdict.flags


def test_factory_defaults_to_real_engine(monkeypatch):
    monkeypatch.delenv("VERO_ENGINE", raising=False)
    assert isinstance(build_adapter(), VeroEngineAdapter)


def test_factory_mock_on_request(monkeypatch):
    from api_agents.adapters.mock_adapter import MockAdapter
    monkeypatch.setenv("VERO_ENGINE", "mock")
    assert isinstance(build_adapter(), MockAdapter)


def _break_real_engine(monkeypatch):
    import api_agents.adapters.vero_engine_adapter as engine_module

    def explode(*_args, **_kwargs):
        raise RuntimeError("engine failed to start")

    monkeypatch.setattr(engine_module, "VeroEngineAdapter", explode)


def test_factory_fails_closed_when_real_engine_cannot_start(monkeypatch):
    monkeypatch.delenv("VERO_ENGINE", raising=False)
    monkeypatch.delenv("VERO_ALLOW_MOCK_FALLBACK", raising=False)
    _break_real_engine(monkeypatch)
    with pytest.raises(RuntimeError, match="engine failed to start"):
        build_adapter()


def test_factory_mock_fallback_only_when_explicitly_allowed(monkeypatch, caplog):
    from api_agents.adapters.mock_adapter import MockAdapter
    monkeypatch.delenv("VERO_ENGINE", raising=False)
    monkeypatch.setenv("VERO_ALLOW_MOCK_FALLBACK", "1")
    _break_real_engine(monkeypatch)
    with caplog.at_level("ERROR"):
        adapter = build_adapter()
    assert isinstance(adapter, MockAdapter)
    assert "MOCK" in caplog.text


def test_api_blocks_module_attack_that_mock_allowed():
    client = TestClient(app)
    body = client.post("/v1/simulate", json={
        "chain_id": 1, "safe_address": SAFE, "to": SAFE,
        "data": cd("enableModule(address)", ["address"], [EVIL]),
    }).json()
    assert body["decision"] == "BLOCK"
    assert "MODULE_ENABLED" in body["flags"]


def test_api_rejects_invalid_address_with_422():
    res = TestClient(app).post("/v1/simulate", json={"safe_address": "nope", "to": USDT})
    assert res.status_code == 422


def test_health_reports_engine():
    assert TestClient(app).get("/health").json().get("engine") == "vero-engine"


@pytest.mark.parametrize("override", [{"nonce": -1}, {"nonce": 2**300}, {"value": str(2**300)},
                                      {"value": "0x10"}, {"chain_id": -5}])
def test_out_of_range_numbers_return_422_not_500(override):
    payload = {"chain_id": 1, "safe_address": SAFE, "to": USDT, **override}
    assert TestClient(app).post("/v1/simulate", json=payload).status_code == 422


def test_uppercase_hex_calldata_is_accepted():
    data = cd("approve(address,uint256)", ["address", "uint256"], [EVIL, MAX]).upper().replace("0X", "0x")
    res = TestClient(app).post("/v1/simulate", json={"safe_address": SAFE, "to": USDT, "data": data})
    assert res.status_code == 200 and res.json()["decision"] == "BLOCK"


def test_route_error_type_has_no_engine_dependency():
    import ast
    import api_agents.adapters.errors as errors
    tree = ast.parse(open(errors.__file__).read())
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)} | \
               {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m and (m.startswith("simulator") or m.startswith("shared")) for m in imported)
    from api_agents.routes import firewall_api
    assert firewall_api.EngineInputError is errors.EngineInputError
