"""Feature #03: declared-vs-real set difference.

Compares what the signer declared (IntentPolicy) with the effects in the state diff.
Pure function: no I/O, no randomness, no AI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from shared.api_schemas import IntentPolicy, StateDiffSummary
from simulator.diff import asset_root, recipients, safe_outflows


@dataclass(frozen=True)
class IntentDiff:
    undeclared_recipients: tuple[tuple[str, str, int], ...]  # (recipient, asset, amount)
    undeclared_assets: tuple[tuple[str, int], ...]  # (asset, outflow)
    over_cap: tuple[tuple[str, int, int], ...]  # (asset, outflow, cap)
    undeclared_spenders: tuple[tuple[str, str, str], ...]  # (token, spender, amount)

    @property
    def matches(self) -> bool:
        return not (self.undeclared_recipients or self.undeclared_assets or self.over_cap
                    or self.undeclared_spenders)


def compare_intent(policy: Optional[IntentPolicy], diff: StateDiffSummary, safe: str) -> Optional[IntentDiff]:
    if policy is None:
        return None
    allowed = set(policy.allowedRecipients)
    tokens = set(policy.allowedTokens)
    cap = int(policy.maxOutflowWei)
    outflows = safe_outflows(diff, safe)
    bridged = {}
    for b in diff.bridgeTransfers:
        key = b.token or "ETH"
        bridged[key] = max(bridged.get(key, 0), int(b.amount))
    for asset, amount in bridged.items():
        outflows.setdefault(asset, amount)
    return IntentDiff(
        undeclared_recipients=tuple(r for r in recipients(diff, safe) if r[0] not in allowed),
        undeclared_assets=tuple((a, v) for a, v in outflows.items() if asset_root(a) not in tokens),
        over_cap=tuple((a, v, cap) for a, v in outflows.items() if v > cap),
        undeclared_spenders=tuple(
            (ap.token, ap.spender, ap.amount)
            for ap in diff.approvals
            if ap.amount not in ("0", "NONE") and ap.spender not in allowed
        ),
    )
