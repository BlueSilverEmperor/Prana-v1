"""Innovations API: the immune-system demo runs in an isolated registry; composition cases come from the real engine."""

from fastapi.testclient import TestClient

from api_agents.main import app
from api_agents.vaccination import REGISTRY

client = TestClient(app)


def test_immune_demo_tells_the_story_and_leaves_the_shared_registry_untouched():
    body = client.post("/v1/innovations/immune-demo").json()
    steps = body["steps"]
    assert [s["decision"] for s in steps] == ["BLOCK", "ALLOW", "BLOCK", "BLOCK", "BLOCK"]
    assert [s["registry"]["status"] for s in steps] == ["provisional", "provisional", "active", "active", "active"]
    assert "R12" in steps[3]["rules"] and "R12" in steps[4]["rules"]
    assert steps[3]["vault"] == steps[1]["vault"]          # the same vault, before and after the vaccine
    assert REGISTRY.snapshot() == []                         # the demo never writes to the real registry


def test_immune_demo_is_repeatable():
    first = client.post("/v1/innovations/immune-demo").json()
    second = client.post("/v1/innovations/immune-demo").json()
    assert [s["decision"] for s in first["steps"]] == [s["decision"] for s in second["steps"]]
