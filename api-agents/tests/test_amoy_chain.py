"""Polygon Amoy: chain 80002 requests are simulated on the Amoy fork; other chains are untouched."""

from fastapi.testclient import TestClient

from api_agents.main import app

client = TestClient(app)
VAULT = "0x" + "5a" * 20
VENDOR = "0x" + "7a" * 20


def _payment(chain_id: int) -> dict:
    return {"chain_id": chain_id, "safe_address": VAULT, "to": VENDOR, "value": "1000",
            "declared_intent": {"allowed_recipients": [VENDOR], "allowed_tokens": ["ETH"], "max_outflow_wei": "10000"}}


def test_amoy_requests_use_the_amoy_fork(monkeypatch):
    monkeypatch.setenv("VERO_AMOY_RPC", "http://127.0.0.1:1")   # unreachable: proves the fork was attempted
    body = client.post("/v1/simulate", json=_payment(80002)).json()
    assert "FORK_UNAVAILABLE" in body["flags"] and body["decision"] == "WARN"   # dead fork never passes silently


def test_other_chains_stay_on_static_analysis(monkeypatch):
    monkeypatch.setenv("VERO_AMOY_RPC", "http://127.0.0.1:1")
    body = client.post("/v1/simulate", json=_payment(1)).json()
    assert "FORK_UNAVAILABLE" not in body["flags"] and body["decision"] == "ALLOW"


def test_amoy_status_reports_unavailable_without_a_fork(monkeypatch):
    monkeypatch.delenv("VERO_AMOY_RPC", raising=False)
    res = client.get("/v1/chain/amoy")
    assert res.status_code == 200 and res.json()["available"] is False
