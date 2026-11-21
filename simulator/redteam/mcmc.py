"""MCMC red/green sampler: searches for transactions the engine gets wrong, in both directions.

Red chains hunt escapes: harmful variants the engine allows. Green chains hunt false positives:
harmless variants the engine blocks. Both share the same mutations, oracle and engine.

The engine stays deterministic; randomness lives only here, in the search. A Metropolis-Hastings chain
walks over mutations of attack transactions (amount, recipient, drain primitive, CALL/DELEGATECALL,
MultiSend nesting, calldata padding). Each variant gets a harm score from an oracle that reads what the
variant does by construction, independently of the engine. The target density favours variants that are
harmful AND allowed, so the chain concentrates on near-misses and escapes.

Outputs: acceptance rate, unique variants, escape rate (harmful variants the engine let through), false
positives (harmless variants it blocked), and every escape, so each can become a regression test.

Usage: python -m simulator.redteam.mcmc [--mode both|red|green] [--steps 4000] [--chains 4] [--seed 7] [--out report.json]
"""

from __future__ import annotations

import argparse
import json
import math
import random
import time
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from typing import Optional

from eth_abi import encode
from eth_utils import keccak

from shared.api_schemas import SimulationRequest
from simulator.constants import BLOCKING_SEVERITIES, TRUSTED_DELEGATECALL_TARGETS
from simulator.context import EngineContext
from simulator.engine import analyze_offline

SAFE = "0x" + "5a" * 20
HOT_WALLET = "0x" + "4f" * 20                      # the declared recipient and a saved contact
ATTACKER = "0x" + "e0" * 20
LOOKALIKE = "0x4f4f" + "00" * 16 + "4f4f"          # poisoned lookalike of the hot wallet
FRESH = "0x" + "3c" * 20                           # never-seen address
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
MULTISEND = sorted(TRUSTED_DELEGATECALL_TARGETS)[0]
DECLARED_CAP = 100_000_000                         # 100 USDT (6 decimals), also used as the wei cap
MAX_UINT = 2**256 - 1
CONTROL_HARM = 10**30                              # losing control of the Safe outweighs any single transfer
BLOCK_PENALTY = 25.0                               # score lost when the engine blocks; keeps the chain hunting escapes

TOKEN_PRIMITIVES = ("transfer", "transferFrom", "approve", "increaseAllowance")
CONTROL_PRIMITIVES = ("upgradeTo", "addOwnerWithThreshold", "enableModule", "setGuard")
PRIMITIVES = TOKEN_PRIMITIVES + ("ethSend",) + CONTROL_PRIMITIVES
RECIPIENTS = (HOT_WALLET, ATTACKER, LOOKALIKE, FRESH)
AMOUNTS = (1, DECLARED_CAP // 2, DECLARED_CAP, DECLARED_CAP * 2, 10**12, 2**128, MAX_UINT)
MAX_WRAP = 3
PADDINGS = (0, 4, 32, 96)

SIGNATURES = {
    "transfer": ("transfer(address,uint256)", ["address", "uint256"]),
    "transferFrom": ("transferFrom(address,address,uint256)", ["address", "address", "uint256"]),
    "approve": ("approve(address,uint256)", ["address", "uint256"]),
    "increaseAllowance": ("increaseAllowance(address,uint256)", ["address", "uint256"]),
    "upgradeTo": ("upgradeTo(address)", ["address"]),
    "addOwnerWithThreshold": ("addOwnerWithThreshold(address,uint256)", ["address", "uint256"]),
    "enableModule": ("enableModule(address)", ["address"]),
    "setGuard": ("setGuard(address)", ["address"]),
}


@dataclass(frozen=True)
class Variant:
    primitive: str
    recipient: str
    amount: int
    operation: int = 0
    wrap: int = 0
    padding: int = 0


# ------------------------------------------------------------------ encoding --

def _calldata(name: str, args: list) -> bytes:
    signature, types = SIGNATURES[name]
    return keccak(text=signature)[:4] + encode(types, args)


def inner_call(v: Variant) -> tuple[str, int, bytes]:
    """(to, value, data) of the call the variant makes, before any MultiSend wrapping."""
    if v.primitive == "ethSend":
        return v.recipient, v.amount, b""
    if v.primitive == "transferFrom":
        return USDT, 0, _calldata("transferFrom", [SAFE, v.recipient, v.amount])
    if v.primitive in TOKEN_PRIMITIVES:
        return USDT, 0, _calldata(v.primitive, [v.recipient, v.amount])
    args = {"upgradeTo": [v.recipient], "addOwnerWithThreshold": [v.recipient, 1],
            "enableModule": [v.recipient], "setGuard": ["0x" + "00" * 20]}[v.primitive]
    return SAFE, 0, _calldata(v.primitive, args)


def _pack(operation: int, to: str, value: int, data: bytes) -> bytes:
    return (bytes([operation]) + bytes.fromhex(to[2:]) + value.to_bytes(32, "big")
            + len(data).to_bytes(32, "big") + data)


def to_transaction(v: Variant) -> dict:
    to, value, data = inner_call(v)
    data = data + b"\x00" * v.padding if data else data
    operation = v.operation
    for _ in range(v.wrap):  # each level: the Safe delegatecalls MultiSend with the packed inner tx
        data = bytes.fromhex("8d80ff0a") + encode(["bytes"], [_pack(operation, to, value, data)])
        to, value, operation = MULTISEND, 0, 1
    return {"to": to, "value": str(value), "data": "0x" + data.hex(), "operation": operation}


# -------------------------------------------------------------------- oracle --

def harm(v: Variant) -> int:
    """What the variant does, judged from its construction, never from the engine."""
    if v.primitive in CONTROL_PRIMITIVES:
        return CONTROL_HARM
    target = inner_call(v)[0]
    if v.operation == 1 and target.lower() not in TRUSTED_DELEGATECALL_TARGETS:
        return CONTROL_HARM  # delegatecall runs foreign code with the Safe's storage
    declared = v.recipient == HOT_WALLET
    if v.primitive in ("approve", "increaseAllowance"):
        return 0 if declared and v.amount <= DECLARED_CAP else v.amount
    if not declared:
        return v.amount
    return max(0, v.amount - DECLARED_CAP)


# -------------------------------------------------------------------- engine --

_CTX = EngineContext(contacts=frozenset({HOT_WALLET}), recipient_history=frozenset({HOT_WALLET}))
_INTENT = {"allowedRecipients": [HOT_WALLET], "allowedTokens": [USDT, "ETH"], "maxOutflowWei": str(DECLARED_CAP)}


@dataclass(frozen=True)
class EngineVerdict:
    blocked: bool
    rules: tuple          # rule ids that raised a HIGH/CRITICAL alert
    ms: float             # engine time for this transaction


def engine_verdict(v: Variant) -> Optional[EngineVerdict]:
    """The engine's verdict on one variant, or None when the request itself is invalid."""
    try:
        request = SimulationRequest.model_validate({"chainId": 1, "safeAddress": SAFE,
                                                    "transactions": [to_transaction(v)], "intentPolicy": _INTENT})
    except ValueError:
        return None
    started = time.perf_counter()
    result = analyze_offline(request, _CTX)
    elapsed = (time.perf_counter() - started) * 1000
    rules = tuple(sorted({a.ruleId for a in result.alerts if a.severity in BLOCKING_SEVERITIES}))
    return EngineVerdict(blocked=bool(rules), rules=rules, ms=round(elapsed, 3))


def engine_blocks(v: Variant) -> Optional[bool]:
    """True when the engine raises a HIGH/CRITICAL alert, None when the request itself is invalid."""
    verdict = engine_verdict(v)
    return None if verdict is None else verdict.blocked


# --------------------------------------------------------------- the sampler --

def propose(v: Variant, rng: random.Random) -> Variant:
    """Symmetric proposal: re-draw one field uniformly from its finite domain."""
    field = rng.choice(("primitive", "recipient", "amount", "operation", "wrap", "padding"))
    domain = {"primitive": PRIMITIVES, "recipient": RECIPIENTS, "amount": AMOUNTS,
              "operation": (0, 1), "wrap": tuple(range(MAX_WRAP + 1)), "padding": PADDINGS}[field]
    return replace(v, **{field: rng.choice(domain)})


def score(harm_value: int, blocked: bool, mode: str = "red") -> float:
    """Red rewards harm and punishes blocks; green rewards blocks and punishes harm."""
    if mode == "green":
        return (BLOCK_PENALTY if blocked else 0.0) - math.log1p(harm_value)
    return math.log1p(harm_value) - (BLOCK_PENALTY if blocked else 0.0)


def accept(current: float, proposed: float, beta: float, rng: random.Random) -> bool:
    return proposed >= current or rng.random() < math.exp(beta * (proposed - current))


@dataclass
class Report:
    steps: int
    chains: int
    seed: int
    accepted: int = 0
    unique_variants: int = 0
    harmful_unique: int = 0
    escapes: list = None
    false_positives: list = None
    block_rate_by_primitive: dict = None
    trace: list = field(default_factory=list)
    rule_hits: Counter = field(default_factory=Counter)
    attacks_by_primitive: dict = field(default_factory=dict)
    latencies_ms: list = field(default_factory=list)

    @property
    def acceptance_rate(self) -> float:
        return self.accepted / max(1, self.steps * self.chains)

    @property
    def escape_rate(self) -> float:
        return len(self.escapes) / max(1, self.harmful_unique)


RED_STARTS = (Variant("upgradeTo", ATTACKER, 0), Variant("approve", ATTACKER, MAX_UINT),
              Variant("transfer", LOOKALIKE, DECLARED_CAP), Variant("ethSend", FRESH, 10**12))
GREEN_STARTS = (Variant("transfer", HOT_WALLET, DECLARED_CAP), Variant("approve", HOT_WALLET, DECLARED_CAP // 2),
                Variant("ethSend", HOT_WALLET, 1), Variant("transfer", HOT_WALLET, 1, wrap=1))


def describe(v: Variant) -> str:
    """Plain words for one variant, for reports and the attack-vs-defense page."""
    who = {HOT_WALLET: "the declared hot wallet", ATTACKER: "the attacker", LOOKALIKE: "a lookalike of the hot wallet",
           FRESH: "a never-seen address"}[v.recipient]
    unlimited = v.amount >= 2**128
    usdt = "unlimited USDT" if unlimited else f"{v.amount / 10**6:,.6g} USDT"
    wei = "an unlimited amount of" if unlimited else f"{v.amount / 10**18:.6g} ETH"
    if v.primitive in CONTROL_PRIMITIVES:
        text = {"upgradeTo": "swap the wallet's logic", "addOwnerWithThreshold": "add an owner and drop the threshold",
                "enableModule": "enable a backdoor module", "setGuard": "remove the guard"}[v.primitive]
    elif v.primitive == "ethSend":
        text = f"send {wei} to {who}"
    else:
        text = f"{v.primitive} {usdt} to {who}"
    extras = [e for e in ("as DELEGATECALL" if v.operation else "", f"nested {v.wrap}x in MultiSend" if v.wrap else "",
                          f"padded {v.padding}B" if v.padding else "") if e]
    return text + (f" ({', '.join(extras)})" if extras else "")


def run(steps: int = 4000, chains: int = 4, seed: int = 7, beta: float = 0.5, mode: str = "both",
        max_trace: int = 0) -> Report:
    """Chains advance in lockstep so a trace interleaves them; max_trace bounds the recorded events."""
    rng = random.Random(seed)
    seen: dict[Variant, Optional[bool]] = {}
    report = Report(steps=steps, chains=chains, seed=seed)

    def evaluate(v: Variant, chain: int, chain_mode: str, step: int) -> Optional[bool]:
        if v not in seen:
            verdict = engine_verdict(v)
            seen[v] = None if verdict is None else verdict.blocked
            if verdict is not None:
                report.rule_hits.update(verdict.rules)
                report.latencies_ms.append(verdict.ms)
                if len(report.trace) < max_trace:
                    report.trace.append({"step": step, "chain": chain, "mode": chain_mode, "attempt": describe(v),
                                         "primitive": v.primitive, "harmful": harm(v) > 0, "blocked": verdict.blocked,
                                         "rules": list(verdict.rules), "ms": verdict.ms})
        return seen[v]

    states = []
    for chain in range(chains):
        chain_mode = ("red", "green")[chain % 2] if mode == "both" else mode
        starts = GREEN_STARTS if chain_mode == "green" else RED_STARTS
        start = starts[(chain // (2 if mode == "both" else 1)) % len(starts)]
        states.append([chain_mode, start, score(harm(start), bool(evaluate(start, chain, chain_mode, 0)), chain_mode)])
    for step in range(1, steps + 1):
        for chain, state in enumerate(states):
            chain_mode, current, current_score = state
            candidate = propose(current, rng)
            blocked = evaluate(candidate, chain, chain_mode, step)
            if blocked is None:
                continue  # invalid request; the engine would reject it before simulating
            candidate_score = score(harm(candidate), blocked, chain_mode)
            if accept(current_score, candidate_score, beta, rng):
                state[1], state[2] = candidate, candidate_score
                report.accepted += 1

    valid = {v: b for v, b in seen.items() if b is not None}
    report.unique_variants = len(valid)
    report.harmful_unique = sum(1 for v in valid if harm(v) > 0)
    report.escapes = [asdict(v) for v, b in valid.items() if harm(v) > 0 and not b]
    report.false_positives = [asdict(v) for v, b in valid.items() if harm(v) == 0 and b]
    totals, blocks = Counter(), Counter()
    for v, b in valid.items():
        if harm(v) > 0:
            totals[v.primitive] += 1
            blocks[v.primitive] += int(b)
    report.block_rate_by_primitive = {p: round(blocks[p] / totals[p], 4) for p in sorted(totals)}
    report.attacks_by_primitive = {p: {"thrown": totals[p], "stopped": blocks[p]} for p in sorted(totals)}
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mode", choices=("both", "red", "green"), default="both")
    parser.add_argument("--steps", type=int, default=4000)
    parser.add_argument("--chains", type=int, default=4)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    r = run(args.steps, args.chains, args.seed, mode=args.mode)
    print(f"MCMC {args.mode}: {r.chains} chains x {r.steps} steps, seed {r.seed}")
    print(f"  acceptance rate      : {r.acceptance_rate:.1%}")
    print(f"  unique variants      : {r.unique_variants} ({r.harmful_unique} harmful)")
    print(f"  escapes              : {len(r.escapes)}  (escape rate {r.escape_rate:.2%})")
    print(f"  false positives      : {len(r.false_positives)}")
    print(f"  block rate by attack : {r.block_rate_by_primitive}")
    for e in r.escapes[:10]:
        print(f"  ESCAPE {e}")
    for f in r.false_positives[:10]:
        print(f"  FALSE POSITIVE {f}")
    if args.out:
        payload = {**asdict(r), "acceptance_rate": r.acceptance_rate, "escape_rate": r.escape_rate}
        with open(args.out, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)


if __name__ == "__main__":
    main()
