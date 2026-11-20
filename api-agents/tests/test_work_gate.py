"""x402 work gate: a payment signature must solve a server-issued, unexpired, unused job."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from api_agents.agents.hashference_client import solve_payment_required, solve_x402_pow_challenge
from api_agents.main import app
from api_agents.payments.work_gate import DIFFICULTY

SAFE = "0x0017a140Aa3E981100a9becA4E685f962f0cF6C9"
DEST = "0x0027a140Aa3E981100a9becA4E685f962f0cF6C9"
PAYLOAD = {"chain_id": 15000, "safe_address": SAFE, "to": DEST, "value": "0", "data": "0x", "nonce": 2}
GATE = {"X-Vero-Engine": "quai", "X-Quai-Work-Gate": "true"}


@pytest.fixture()
def client():
    return TestClient(app)


def _challenge_header(client) -> str:
    res = client.post("/v1/simulate", json=PAYLOAD, headers=GATE)
    assert res.status_code == 402
    return res.headers["PAYMENT-REQUIRED"]


def _challenge(client) -> str:
    return _challenge_header(client).split("job=")[1].split()[0]


def _solve(job: str) -> str:
    return solve_x402_pow_challenge(job, difficulty=DIFFICULTY)


def _pay(client, signature: str):
    return client.post("/v1/simulate", json=PAYLOAD, headers={**GATE, "PAYMENT-SIGNATURE": signature})


def _failing_nonce(job_id: str) -> int:
    for nonce in range(1000):
        digest = hashlib.sha256(hashlib.sha256(f"{job_id}{nonce}".encode()).digest()).hexdigest()
        if not digest.startswith("0" * DIFFICULTY):
            return nonce
    raise AssertionError("no failing nonce found")


def test_solved_job_is_accepted(client):
    assert _pay(client, solve_payment_required(_challenge_header(client))).status_code == 200


def test_challenge_advertises_the_server_difficulty(client):
    assert f"difficulty={DIFFICULTY}" in _challenge_header(client)


def test_any_string_containing_nonce_is_rejected(client):
    assert _pay(client, "nonce=0").status_code == 402


def test_signature_must_actually_solve_the_job(client):
    job = _challenge(client)
    assert _pay(client, f"job={job};nonce={_failing_nonce(job)}").status_code == 402


def test_forged_job_is_rejected(client):
    job = _challenge(client)
    expiry, rand, _mac = job.split(".")
    forged = f"{expiry}.{rand}.{'0' * 32}"
    assert _pay(client, _solve(forged)).status_code == 402


def test_solution_cannot_be_replayed(client):
    signature = _solve(_challenge(client))
    assert _pay(client, signature).status_code == 200
    assert _pay(client, signature).status_code == 402


def test_expired_job_is_rejected(client, monkeypatch):
    signature = _solve(_challenge(client))
    from api_agents.payments import work_gate
    real_time = work_gate.time.time
    monkeypatch.setattr(work_gate.time, "time", lambda: real_time() + work_gate.JOB_TTL_SECONDS + 1)
    assert _pay(client, signature).status_code == 402
