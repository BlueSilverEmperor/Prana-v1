"""Live proofs for the Innovations page.

- hidden-attacks: an adaptive attacker hides theft inside MultiSend batches with values drawn per run.
- immune-demo: replays one attacker against four vaults through the real engine and the real vaccine logic,
  but in a registry created for this request only, so the demo never touches the shared registry.
"""

from typing import List, Optional

from eth_abi import encode
from eth_utils import keccak
from fastapi import APIRouter
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from api_agents.adapters.vero_engine_adapter import AMOY_CHAIN_ID, VeroEngineAdapter
from api_agents.hidden_attacker import (MAX_TRIES, MULTISEND, Attempt, HiddenAttacker, Scene, encode_multisend,
                                        run, summarize)
from api_agents.routes.chain_api import amoy_status_sync
from api_agents.models.schemas import SimulateRequest
from api_agents.vaccination import VaccineRegistry

router = APIRouter(prefix="/v1/innovations", tags=["innovations"])

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ATTACKER = "0x" + "e7" * 20
VAULTS = {"Exchange A": "0x" + "a1" * 20, "Treasury B": "0x" + "b2" * 20,
          "DAO C": "0x" + "c3" * 20, "Fund D": "0x" + "d4" * 20}
DEMO_QUORUM = 2
REASON_MAX = 160
OFFLINE_VAULT = "0x" + "5a" * 20


def _cd(signature: str, types: list, args: list) -> str:
    return "0x" + (keccak(text=signature)[:4] + encode(types, args)).hex()


def _payment(vault: str) -> SimulateRequest:
    """A routine-looking 1 USDT payment to the attacker, declared by a signer who does not know better."""
    return SimulateRequest(safe_address=vault, to=USDT,
                           data=_cd("transfer(address,uint256)", ["address", "uint256"], [ATTACKER, 1_000_000]),
                           declared_intent={"allowed_recipients": [ATTACKER], "allowed_tokens": [USDT],
                                            "max_outflow_wei": "100000000"})


# (vault name, kind, what happens, request builder, what it shows)
STORY: List[tuple] = [
    ("Exchange A", "attack", "The attacker tries to swap Exchange A's wallet logic",
     lambda v: SimulateRequest(safe_address=v, to=v, data=_cd("upgradeTo(address)", ["address"], [ATTACKER])),
     "Blocked by Exchange A's own rules. The attacker's address is reported to the network: 1 of 2 reports."),
    ("DAO C", "payment", "DAO C, fooled, sends the attacker a routine 1 USDT payment",
     _payment,
     "Allowed: DAO C has never seen this address and the payment matches what its signer declared. "
     "This is the gap the immune system closes."),
    ("Treasury B", "attack", "The attacker tries an unlimited token approval on Treasury B",
     lambda v: SimulateRequest(safe_address=v, to=USDT,
                               data=_cd("approve(address,uint256)", ["address", "uint256"], [ATTACKER, 2**256 - 1])),
     "Blocked. A second, independent vault reports the same address: quorum reached, the vaccine is active."),
    ("DAO C", "payment", "DAO C sends the very same 1 USDT payment again",
     _payment,
     "Now blocked: DAO C was never attacked, but it is immune. Rule R12 recognises the vaccinated address."),
    ("Fund D", "attack", "The attacker moves on to Fund D with a backdoor module",
     lambda v: SimulateRequest(safe_address=v, to=v, data=_cd("enableModule(address)", ["address"], [ATTACKER])),
     "Blocked twice over: the module rule and the vaccine both fire. Every vault in the network is protected."),
]


async def _run_story() -> dict:
    registry = VaccineRegistry(quorum=DEMO_QUORUM)
    adapter = VeroEngineAdapter(vaccines=registry)
    steps = []
    for vault_name, kind, action, build, meaning in STORY:
        req: SimulateRequest = build(VAULTS[vault_name])
        sim = await adapter.simulate_tx(req)
        verdict = adapter.evaluate(sim, req)
        vaccine = next((v for v in registry.snapshot() if v["address"] == ATTACKER), None)
        rules = sorted({w.split("]")[0].lstrip("[") for w in verdict.human_warnings if w.startswith("[")})
        steps.append({
            "vault": vault_name, "kind": kind, "action": action, "meaning": meaning,
            "decision": verdict.decision.value, "risk": verdict.risk_score, "rules": rules,
            "reason": (verdict.human_warnings[0] if verdict.human_warnings else "")[:REASON_MAX],
            "registry": {"status": vaccine["status"] if vaccine else "unknown",
                         "reports": vaccine["reports"] if vaccine else 0, "quorum": DEMO_QUORUM},
        })
    return {"attacker": ATTACKER, "vaults": VAULTS, "quorum": DEMO_QUORUM, "steps": steps}


@router.post("/immune-demo")
async def immune_demo() -> dict:
    return await _run_story()


# ------------------------------------------------------------------ hidden-batch attacker --
class HiddenAttackRequest(BaseModel):
    seed: Optional[int] = Field(default=None, ge=0, le=2**32 - 1)
    tries: int = Field(default=4, ge=1, le=MAX_TRIES)


OFFLINE_CHAIN_ID = 1   # without a live fork the batch is judged from calldata alone


def _batch_request(scene: Scene, attempt: Attempt) -> SimulateRequest:
    return SimulateRequest(
        chain_id=AMOY_CHAIN_ID if scene.live else OFFLINE_CHAIN_ID, safe_address=scene.vault, to=MULTISEND, value="0",
        data=encode_multisend(attempt.calls), operation=1, contacts=[scene.vendor],
        declared_intent={"allowed_recipients": [scene.vendor], "allowed_tokens": ["ETH"],
                         "max_outflow_wei": str(scene.cap_wei)})


@router.post("/hidden-attacks")
async def hidden_attacks(req: HiddenAttackRequest) -> dict:
    """Run the adaptive hidden-batch attacker against live Amoy accounts (or synthetic ones when offline)."""
    status = await run_in_threadpool(amoy_status_sync)
    live = bool(status.get("available"))
    vault = status["vault"]["address"] if live else OFFLINE_VAULT
    balance = int(status["vault"]["balance_wei"]) if live else 0
    attacker = HiddenAttacker(req.seed)
    scene = attacker.draw_scene(vault, status.get("accounts", []) if live else [], balance, live)
    adapter = VeroEngineAdapter(vaccines=VaccineRegistry(quorum=DEMO_QUORUM))   # never vaccinates the real registry

    async def judge(s: Scene, attempt: Attempt):
        sim_req = _batch_request(s, attempt)
        verdict = adapter.evaluate(await adapter.simulate_tx(sim_req), sim_req)
        rules = sorted({w.split("]")[0].lstrip("[") for w in verdict.human_warnings if w.startswith("[")})
        reason = verdict.human_warnings[0][:REASON_MAX] if verdict.human_warnings else ""
        return verdict.decision.value, verdict.risk_score, rules, reason

    records = await run(attacker, scene, judge, req.tries)
    return {"seed": attacker.seed, "live": live, "block": status.get("block"), "chain_id": AMOY_CHAIN_ID if live else OFFLINE_CHAIN_ID,
            "vault": scene.vault, "vendor": scene.vendor, "strangers": list(scene.strangers),
            "cap_wei": str(scene.cap_wei), "attempts": records, "summary": summarize(records)}
