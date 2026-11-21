"""An adaptive attacker that hides theft inside Safe MultiSend batches.

Nothing is fixed in advance. Each run draws its own scene (vendor, strangers, declared cap) from live chain
accounts and a seed, and every strategy draws its own amounts. When Vero blocks an attempt, the attacker makes
the next one sneakier: a smaller overage, a skim spread thinner, a lookalike that matches more characters. An attempt escapes if it moves value the signer did not declare and is not
blocked. Honest batches run alongside as controls, so a run also measures false positives.
"""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass, field
from typing import Awaitable, Callable, List, Optional, Sequence, Tuple

MULTISEND = "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526"   # canonical Safe MultiSend 1.3.0
MULTISEND_SELECTOR = "8d80ff0a"
POL = 10**18
CENT = POL // 100
MAX_TRIES = 6
MAX_CALLS = 8
MIN_STRANGERS = 3
HONEST_CONTROLS = 2
LOOKALIKE_START_CHARS = 4
LOOKALIKE_MAX_CHARS = 10

Call = Tuple[str, int]   # (recipient, wei)


def _word(n: int) -> str:
    return format(n, "064x")


def encode_multisend(calls: Sequence[Call]) -> str:
    """multiSend(bytes), each call packed as operation(1) | to(20) | value(32) | dataLength(32)."""
    packed = "".join("00" + to[2:].lower() + _word(wei) + _word(0) for to, wei in calls)
    length = len(packed) // 2
    packed += "0" * ((64 - len(packed) % 64) % 64)
    return "0x" + MULTISEND_SELECTOR + _word(32) + _word(length) + packed


def _random_address(rng: random.Random) -> str:
    return "0x" + "".join(rng.choice("0123456789abcdef") for _ in range(40))


def lookalike_of(address: str, rng: random.Random, chars: int = LOOKALIKE_START_CHARS) -> str:
    """Same first and last `chars` hex characters as `address`, random in between."""
    body = address[2:].lower()
    while True:
        middle = "".join(rng.choice("0123456789abcdef") for _ in range(40 - 2 * chars))
        fake = "0x" + body[:chars] + middle + body[-chars:]
        if fake != "0x" + body:
            return fake


def _split(total: int, parts: int, rng: random.Random) -> List[int]:
    """Near-equal pieces (±10%) that add up to exactly `total`."""
    weights = [rng.uniform(0.9, 1.1) for _ in range(parts)]
    pieces = [int(total * w / sum(weights)) for w in weights]
    pieces[-1] += total - sum(pieces)
    return pieces


@dataclass(frozen=True)
class Scene:
    vault: str
    vendor: str
    strangers: Tuple[str, ...]
    cap_wei: int
    live: bool


@dataclass
class Attempt:
    strategy: str
    attempt: int
    calls: List[Call]
    harm_wei: int
    note: str
    labels: dict = field(default_factory=dict)


class HiddenAttacker:
    def __init__(self, seed: Optional[int] = None) -> None:
        self.seed = seed if seed is not None else secrets.randbits(32)
        self.rng = random.Random(self.seed)

    def draw_scene(self, vault: str, accounts: Sequence[str], balance_wei: int, live: bool) -> Scene:
        pool = [a.lower() for a in accounts if a.lower() != vault.lower()]
        self.rng.shuffle(pool)
        while len(pool) < MIN_STRANGERS + 1:
            pool.append(_random_address(self.rng))
        cap = self.rng.randint(50, 200) * CENT
        if balance_wei:
            cap = max(CENT, min(cap, balance_wei // 4 // CENT * CENT))
        return Scene(vault.lower(), pool[0], tuple(pool[1:MIN_STRANGERS + 1]), cap, live)

    # Each strategy returns the next attempt, given how many tries came before and what Vero said last time.
    def salami(self, s: Scene, n: int, rules: Sequence[str]) -> Attempt:
        """Overpay the vendor in small slices; after each block, the overage shrinks fourfold."""
        over = max(1, int(s.cap_wei * self.rng.uniform(0.2, 0.5) / 4 ** n))
        parts = min(3 + n + self.rng.randint(0, 1), MAX_CALLS)
        calls = [(s.vendor, w) for w in _split(s.cap_wei + over, parts, self.rng)]
        return Attempt("salami", n, calls, over, f"{parts} slices to Vendor, total just over the cap")

    def decoy(self, s: Scene, n: int, rules: Sequence[str]) -> Attempt:
        """A real vendor payment with a skim to strangers hidden among its calls, all under the cap."""
        pay = int(s.cap_wei * self.rng.uniform(0.4, 0.65))
        skim = max(1, int(s.cap_wei * self.rng.uniform(0.1, 0.3) / 3 ** n))
        hides = min(1 + n, len(s.strangers))
        calls = [(s.vendor, w) for w in _split(pay, 2, self.rng)]
        calls += [(s.strangers[i], w) for i, w in enumerate(_split(skim, hides, self.rng))]
        self.rng.shuffle(calls)
        return Attempt("decoy", n, calls, skim, f"real payment with a skim spread over {hides} stranger(s)")

    def lookalike(self, s: Scene, n: int, rules: Sequence[str]) -> Attempt:
        """Pay an address that looks like the vendor; each block, match more characters at both ends."""
        chars = min(LOOKALIKE_START_CHARS + n, LOOKALIKE_MAX_CHARS)
        fake = lookalike_of(s.vendor, self.rng, chars)
        stolen = int(s.cap_wei * self.rng.uniform(0.3, 0.6))
        calls = [(fake, w) for w in _split(stolen, 2, self.rng)]
        if n:
            calls.append((s.vendor, int(s.cap_wei * self.rng.uniform(0.1, 0.3))))
        self.rng.shuffle(calls)
        return Attempt("lookalike", n, calls, stolen, f"pays a lookalike matching {chars} characters at each end",
                       {fake: "Lookalike of Vendor"})

    def dust(self, s: Scene, n: int, rules: Sequence[str]) -> Attempt:
        """Many tiny transfers to strangers behind one honest payment; each block, more and smaller."""
        count = min(2 + 2 * n, MAX_CALLS - 1)
        crumbs = [max(1, int(s.cap_wei * self.rng.uniform(0.002, 0.01) / 2 ** n)) for _ in range(count)]
        calls = [(s.vendor, int(s.cap_wei * self.rng.uniform(0.3, 0.6)))]
        calls += [(s.strangers[i % len(s.strangers)], w) for i, w in enumerate(crumbs)]
        self.rng.shuffle(calls)
        return Attempt("dust", n, calls, sum(crumbs), f"{count} dust transfers behind a real payment")

    def honest(self, s: Scene, n: int) -> Attempt:
        total = int(s.cap_wei * self.rng.uniform(0.3, 0.95))
        parts = self.rng.randint(1, 4)
        return Attempt("honest", n, [(s.vendor, w) for w in _split(total, parts, self.rng)], 0,
                       f"honest payment to Vendor in {parts} part(s), under the cap")

    def strategies(self) -> List[Callable[[Scene, int, Sequence[str]], Attempt]]:
        return [self.salami, self.decoy, self.lookalike, self.dust]


Verdict = Tuple[str, int, List[str], str]   # decision, risk, rules, first reason
Judge = Callable[[Scene, Attempt], Awaitable[Verdict]]


async def run(attacker: HiddenAttacker, scene: Scene, judge: Judge, tries: int) -> List[dict]:
    """Every strategy keeps adapting until it escapes or runs out of tries; then the honest controls run."""
    records: List[dict] = []
    for strategy in attacker.strategies():
        rules: List[str] = []
        for n in range(tries):
            attempt = strategy(scene, n, rules)
            record = await _judge(scene, attempt, judge, rules)
            records.append(record)
            rules = record["rules"]
            if record["escaped"]:
                break
    for n in range(HONEST_CONTROLS):
        records.append(await _judge(scene, attacker.honest(scene, n), judge, []))
    return records


async def _judge(scene: Scene, attempt: Attempt, judge: Judge, saw: Sequence[str]) -> dict:
    decision, risk, rules, reason = await judge(scene, attempt)
    names = {scene.vendor: "Vendor", **{a: f"Stranger {i + 1}" for i, a in enumerate(scene.strangers)},
             **attempt.labels}
    return {
        "strategy": attempt.strategy, "attempt": attempt.attempt, "note": attempt.note,
        "learned_from": list(saw),
        "calls": [{"to": to, "label": names.get(to, "Unknown"), "wei": str(w)} for to, w in attempt.calls],
        "total_wei": str(sum(w for _, w in attempt.calls)), "harm_wei": str(attempt.harm_wei),
        "decision": decision, "risk": risk, "rules": rules, "reason": reason,
        "escaped": attempt.harm_wei > 0 and decision != "BLOCK",
        "false_positive": attempt.harm_wei == 0 and decision == "BLOCK",
    }


def summarize(records: Sequence[dict]) -> dict:
    attacks = [r for r in records if r["strategy"] != "honest"]
    return {
        "attacks": len(attacks), "blocked": sum(r["decision"] == "BLOCK" for r in attacks),
        "escaped": sum(r["escaped"] for r in attacks),
        "controls": len(records) - len(attacks), "false_positives": sum(r["false_positive"] for r in records),
        "harm_stopped_wei": str(sum(int(r["harm_wei"]) for r in attacks if not r["escaped"])),
    }
