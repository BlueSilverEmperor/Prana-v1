"""Live proofs for the Innovations page.

- immune-demo: replays one attacker against four vaults through the real engine and the real vaccine logic,
  but in a registry created for this request only, so the demo never touches the shared registry.
- composition: the batch-composition attacks the MCMC red team generates, judged by the real engine,
  including the split-allowance attack it found (now blocked) and a legitimate split payment (still passes).
"""

from typing import Callable, List

from eth_abi import encode
from eth_utils import keccak
from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool

from api_agents.adapters.vero_engine_adapter import VeroEngineAdapter
from api_agents.models.schemas import SimulateRequest
from api_agents.vaccination import VaccineRegistry
from simulator.redteam import mcmc

router = APIRouter(prefix="/v1/innovations", tags=["innovations"])

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
ATTACKER = "0x" + "e7" * 20
VAULTS = {"Exchange A": "0x" + "a1" * 20, "Treasury B": "0x" + "b2" * 20,
          "DAO C": "0x" + "c3" * 20, "Fund D": "0x" + "d4" * 20}
DEMO_QUORUM = 2
REASON_MAX = 160


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


COMPOSITION_CASES = [
    ("split-allowance", "increaseAllowance of 200 USDT to the declared spender, split into 4 calls of 50",
     mcmc.Variant("increaseAllowance", mcmc.HOT_WALLET, mcmc.DECLARED_CAP * 2, split=4),
     "Found by the red team: each piece is under the 100 USDT ceiling, together they are double. Now summed and blocked."),
    ("decoy-over-cap", "100 USDT to the declared wallet, hidden behind a legitimate 10 USDT payment",
     mcmc.Variant("transfer", mcmc.HOT_WALLET, mcmc.DECLARED_CAP, decoy=1),
     "The decoy looks normal, but the batch moves 110 USDT against a 100 USDT ceiling."),
    ("split-drain-to-attacker", "100 USDT to the attacker, split into 3 calls behind a decoy payment",
     mcmc.Variant("transfer", mcmc.ATTACKER, mcmc.DECLARED_CAP, split=3, decoy=1),
     "Splitting does not hide an undeclared recipient."),
    ("split-payment-within-cap", "50 USDT to the declared wallet in 2 calls, plus the 10 USDT decoy",
     mcmc.Variant("transfer", mcmc.HOT_WALLET, mcmc.DECLARED_CAP // 2, split=2, decoy=1),
     "Legitimate: 60 USDT total, under the ceiling. It must pass, and it does."),
]


def _composition() -> dict:
    cases = []
    for case_id, title, variant, meaning in COMPOSITION_CASES:
        verdict = mcmc.engine_verdict(variant)
        cases.append({"id": case_id, "title": title, "meaning": meaning, "harmful": mcmc.harm(variant) > 0,
                      "decision": "BLOCK" if verdict.blocked else "ALLOW", "rules": list(verdict.rules),
                      "calls": len(mcmc.calls(variant)), "ms": verdict.ms})
    return {"declared_cap_usdt": mcmc.DECLARED_CAP / 10**6, "cases": cases}


@router.get("/composition")
async def composition() -> dict:
    return await run_in_threadpool(_composition)
