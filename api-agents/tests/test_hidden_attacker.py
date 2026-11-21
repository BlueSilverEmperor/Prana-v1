"""Adaptive hidden-batch attacker: values are drawn per run, and each strategy gets sneakier after a block."""

from fastapi.testclient import TestClient

from api_agents.hidden_attacker import HiddenAttacker, lookalike_of
from api_agents.main import app

client = TestClient(app)
POL = 10**18


def _run(seed: int, tries: int = 4) -> dict:
    res = client.post("/v1/innovations/hidden-attacks", json={"seed": seed, "tries": tries})
    assert res.status_code == 200
    return res.json()


def test_values_are_generated_per_run_not_hard_coded():
    first, again, other = _run(7), _run(7), _run(8)
    amounts = lambda run: [[c["wei"] for c in a["calls"]] for a in run["attempts"]]
    assert amounts(first) == amounts(again)          # a seed replays exactly
    assert amounts(first) != amounts(other)          # a new seed draws new values
    assert first["cap_wei"] != other["cap_wei"] or first["vendor"] != other["vendor"]


def test_every_attack_moves_value_and_every_control_is_honest():
    run = _run(11)
    attacks = [a for a in run["attempts"] if a["strategy"] != "honest"]
    controls = [a for a in run["attempts"] if a["strategy"] == "honest"]
    assert {a["strategy"] for a in attacks} == {"salami", "decoy", "lookalike", "dust"}
    assert all(int(a["harm_wei"]) > 0 for a in attacks)
    assert controls and all(int(a["harm_wei"]) == 0 for a in controls)


def test_salami_shrinks_its_overage_after_each_block():
    salami = [a for a in _run(3)["attempts"] if a["strategy"] == "salami"]
    overs = [int(a["harm_wei"]) for a in salami]
    assert len(overs) >= 2 and all(b < a for a, b in zip(overs, overs[1:]))
    cap = int(_run(3)["cap_wei"])
    assert all(int(c["wei"]) < cap for a in salami for c in a["calls"])   # no single transfer looks big


def test_decoy_and_dust_stay_under_the_cap():
    run = _run(5)
    cap = int(run["cap_wei"])
    for a in run["attempts"]:
        if a["strategy"] in ("decoy", "dust"):
            assert sum(int(c["wei"]) for c in a["calls"]) <= cap


def test_no_hidden_attack_escapes_and_honest_batches_pass():
    run = _run(21, tries=5)
    assert run["summary"]["escaped"] == 0
    assert run["summary"]["false_positives"] == 0
    assert all(a["decision"] == "BLOCK" for a in run["attempts"] if a["strategy"] != "honest")


def test_lookalike_matches_the_vendor_at_both_ends():
    vendor = "0x" + "ab12" + "00" * 16 + "cd34"
    fake = lookalike_of(vendor, HiddenAttacker(seed=1).rng, chars=4)
    assert fake != vendor and fake[2:6] == vendor[2:6] and fake[-4:] == vendor[-4:]


def test_tries_are_bounded():
    assert client.post("/v1/innovations/hidden-attacks", json={"tries": 50}).status_code == 422
