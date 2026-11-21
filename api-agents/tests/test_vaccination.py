"""Collective vaccination: a blocked attack, reported by enough vaults, immunises every other vault via R12."""

import pytest
from eth_abi import encode
from eth_utils import keccak
from fastapi.testclient import TestClient

from api_agents.main import app
from api_agents.vaccination import REGISTRY

client = TestClient(app)
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
EVIL_IMPL = "0x" + "e1" * 20
VAULT_A, VAULT_B, VAULT_C = ("0x" + "a1" * 20), ("0x" + "b2" * 20), ("0x" + "c3" * 20)


def cd(signature: str, types: list, args: list) -> str:
    return "0x" + (keccak(text=signature)[:4] + encode(types, args)).hex()


@pytest.fixture(autouse=True)
def fresh_registry():
    REGISTRY.reset()
    yield
    REGISTRY.reset()


def logic_swap(vault: str) -> dict:
    return client.post("/v1/simulate", json={"safe_address": vault, "to": vault,
                                             "data": cd("upgradeTo(address)", ["address"], [EVIL_IMPL])}).json()


def pay_suspect(vault: str) -> dict:
    """An ordinary declared USDT payment to the address other vaults saw attacking."""
    return client.post("/v1/simulate", json={
        "safe_address": vault, "to": USDT,
        "data": cd("transfer(address,uint256)", ["address", "uint256"], [EVIL_IMPL, 1_000_000]),
        "declared_intent": {"allowed_recipients": [EVIL_IMPL], "allowed_tokens": [USDT], "max_outflow_wei": "100000000"},
    }).json()


def test_one_report_is_provisional_and_does_not_block_others():
    assert logic_swap(VAULT_A)["decision"] == "BLOCK"
    assert pay_suspect(VAULT_C)["decision"] == "ALLOW"
    vaccine = client.get("/v1/vaccines").json()["vaccines"][0]
    assert vaccine["address"] == EVIL_IMPL and vaccine["status"] == "provisional" and vaccine["reports"] == 1


def test_quorum_of_vaults_immunises_everyone():
    logic_swap(VAULT_A)
    logic_swap(VAULT_B)
    body = pay_suspect(VAULT_C)
    assert body["decision"] == "BLOCK"
    assert "THREAT_REGISTRY_HIT" in body["flags"]
    assert client.get("/v1/vaccines").json()["vaccines"][0]["status"] == "active"


def test_same_vault_reporting_twice_does_not_reach_quorum():
    logic_swap(VAULT_A)
    logic_swap(VAULT_A)
    assert pay_suspect(VAULT_C)["decision"] == "ALLOW"


def test_token_contracts_are_never_vaccinated():
    for vault in (VAULT_A, VAULT_B):
        client.post("/v1/simulate", json={"safe_address": vault, "to": USDT,
                                          "data": cd("approve(address,uint256)", ["address", "uint256"], [EVIL_IMPL, 2**256 - 1])})
    addresses = {v["address"] for v in client.get("/v1/vaccines").json()["vaccines"]}
    assert EVIL_IMPL in addresses and USDT not in addresses
