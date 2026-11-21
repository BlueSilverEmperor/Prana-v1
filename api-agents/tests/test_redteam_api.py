"""/v1/redteam/mcmc: bounded, returns a trace, and finds no escapes or false positives today."""

from fastapi.testclient import TestClient

from api_agents.main import app

client = TestClient(app)


def test_mcmc_run_returns_trace_and_scores():
    body = client.post("/v1/redteam/mcmc", json={"steps": 120, "chains": 4, "seed": 3}).json()
    assert body["unique_variants"] > 0 and body["trace"]
    assert {e["mode"] for e in body["trace"]} == {"red", "green"}
    assert body["escapes"] == [] and body["false_positives"] == []


def test_mcmc_request_is_bounded():
    assert client.post("/v1/redteam/mcmc", json={"steps": 100000}).status_code == 422
    assert client.post("/v1/redteam/mcmc", json={"chains": 9}).status_code == 422
