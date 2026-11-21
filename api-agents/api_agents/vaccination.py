"""Collective threat vaccination: one vault's blocked attack immunises every vault.

When the engine blocks a transaction with a CRITICAL alert, the address that alert names as the attacker
(the spender of an unlimited approval, the new implementation of a logic swap, the delegatecall target,
the added owner or module, the lookalike recipient) is reported to a shared registry. Once QUORUM distinct
vaults have reported the same address it becomes active and is merged into the threat registry that
rule R12 reads, so any later transaction touching it, from any vault, is blocked.

Never vaccinated: the reporting vault, its contacts and declared recipients, known token contracts and
trusted libraries, and the zero address. The quorum of distinct vaults is the only defence against a
reporter vaccinating an innocent contract; production needs authenticated reporters (for example an
on-chain guard revert attestation), which this in-memory registry does not provide.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from simulator.constants import TRUSTED_DELEGATECALL_TARGETS
from simulator.context import EngineContext
from simulator.hexutil import normalize_address

QUORUM_ENV = "VERO_VACCINE_QUORUM"
DEFAULT_QUORUM = 2
ZERO = "0x" + "00" * 20
# alert field(s) that name the attacker, per rule
CULPRIT_FIELDS = {
    "R1": ("spender",), "R2": ("spender",), "R3": ("newImpl",), "R4": ("target",), "R5": ("added",),
    "R7": ("module",), "R8": ("delegate", "address"), "P33-POISON": ("target",),
}


@dataclass
class Vaccine:
    address: str
    rule: str
    reporters: set = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    activated_at: Optional[float] = None


def _addresses(value) -> list[str]:
    values = value if isinstance(value, (list, tuple)) else [value]
    out = []
    for v in values:
        if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
            out.append(normalize_address(v))
    return out


class VaccineRegistry:
    def __init__(self, quorum: Optional[int] = None) -> None:
        self._quorum = quorum
        self._vaccines: dict[str, Vaccine] = {}
        self._lock = threading.Lock()

    @property
    def quorum(self) -> int:
        return self._quorum or max(1, int(os.getenv(QUORUM_ENV, str(DEFAULT_QUORUM))))

    @staticmethod
    def protected(safe: str, ctx: EngineContext, declared: Iterable[str]) -> set:
        known_tokens = {a for addrs in ctx.canonical_tokens.values() for a in addrs} | set(ctx.token_meta)
        return ({normalize_address(safe), ZERO} | set(ctx.contacts) | {normalize_address(a) for a in declared}
                | known_tokens | set(TRUSTED_DELEGATECALL_TARGETS))

    def observe(self, safe: str, alerts: Iterable, protected: set) -> list[str]:
        """Record culprits of CRITICAL alerts from one vault; returns addresses that just became active."""
        reporter = normalize_address(safe)
        activated = []
        with self._lock:
            for a in alerts:
                if a.severity != "CRITICAL" or a.ruleId not in CULPRIT_FIELDS or not a.context:
                    continue
                for key in CULPRIT_FIELDS[a.ruleId]:
                    for addr in _addresses(a.context.get(key)):
                        if addr in protected:
                            continue
                        vaccine = self._vaccines.setdefault(addr, Vaccine(address=addr, rule=a.ruleId))
                        vaccine.reporters.add(reporter)
                        if vaccine.activated_at is None and len(vaccine.reporters) >= self.quorum:
                            vaccine.activated_at = time.time()
                            activated.append(addr)
        return activated

    def active(self) -> frozenset:
        with self._lock:
            return frozenset(a for a, v in self._vaccines.items() if v.activated_at is not None)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [{"address": v.address, "rule": v.rule, "reports": len(v.reporters), "quorum": self.quorum,
                     "status": "active" if v.activated_at is not None else "provisional",
                     "first_seen": v.first_seen, "activated_at": v.activated_at}
                    for v in sorted(self._vaccines.values(), key=lambda x: x.first_seen)]

    def reset(self) -> None:
        with self._lock:
            self._vaccines.clear()


REGISTRY = VaccineRegistry()
