"""Feature #04: deterministic plain-English renderer.

Every sentence comes from a fixed template filled with decoded values. There is no
generative model anywhere in this path, so the output cannot hallucinate.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Iterable, Optional, Sequence

from shared.api_schemas import RiskAlert, StateDiffSummary
from simulator.constants import BLOCKING_SEVERITIES, UNLIMITED_THRESHOLD
from simulator.context import EngineContext
from simulator.decoders.permit_and_bridge_decoders import PermitInfo, describe_permit
from simulator.hexutil import ZERO_ADDRESS, checksum

ETH_DECIMALS = 18
NO_EFFECT_LINE = "No asset movements or permission changes detected."


def _scale(amount: int, decimals: int) -> str:
    text = format(Decimal(amount) / (Decimal(10) ** decimals), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def asset_label(asset: str, ctx: EngineContext) -> str:
    if asset == "ETH":
        return "ETH"
    if "#" in asset:
        token, token_id = asset.split("#", 1)
        return f"NFT #{token_id} of {ctx.symbol_of(token) or checksum(token)}"
    return ctx.symbol_of(asset) or checksum(asset)


def format_amount(asset: str, amount: int, ctx: EngineContext) -> str:
    if "#" in asset:
        return asset_label(asset, ctx)
    if amount >= UNLIMITED_THRESHOLD:
        return f"UNLIMITED {asset_label(asset, ctx)}"
    decimals = ETH_DECIMALS if asset == "ETH" else ctx.decimals_of(asset)
    if decimals is None:
        return f"{amount} units of {checksum(asset)}"
    return f"{_scale(amount, decimals)} {asset_label(asset, ctx)}"


def _movement_lines(diff: StateDiffSummary, safe: Optional[str], ctx: EngineContext) -> list[str]:
    lines = []
    for change in diff.balanceChanges:
        delta = int(change.delta)
        if delta > 0 and change.address != safe:
            lines.append(f"Transfer {format_amount(change.asset, delta, ctx)} to {checksum(change.address)}")
        elif delta > 0:
            lines.append(f"Safe receives {format_amount(change.asset, delta, ctx)}")
    for b in diff.bridgeTransfers:
        dest = f"chain {b.destChainId}" if b.destChainId is not None else "an unrecognised chain"
        asset = b.token or "ETH"
        lines.append(f"Bridge {format_amount(asset, int(b.amount), ctx)} via {b.protocol} from chain "
                     f"{b.sourceChainId} to {dest}, recipient {checksum(b.recipient or '') or 'unknown'}")
    return lines


def _approval_lines(diff: StateDiffSummary, ctx: EngineContext) -> list[str]:
    lines = []
    for ap in diff.approvals:
        token, spender = asset_label(ap.token, ctx), checksum(ap.spender)
        if ap.amount == "ALL":
            lines.append(f"Approve {spender} to move ALL your {token} tokens")
        elif ap.amount in ("0", "NONE"):
            lines.append(f"Revoke {spender}'s approval for {token}")
        else:
            lines.append(f"Approve {spender} to spend {format_amount(ap.token, int(ap.amount), ctx)}")
    return lines


def _control_lines(diff: StateDiffSummary) -> list[str]:
    lines = []
    for oc in diff.ownerChanges:
        lines += [f"Add Safe owner {checksum(a)}" for a in oc.added]
        lines += [f"Remove Safe owner {checksum(r)}" for r in oc.removed]
        if oc.newThreshold is not None:
            old = oc.oldThreshold if oc.oldThreshold is not None else "its current value"
            lines.append(f"Change Safe owner threshold from {old} to {oc.newThreshold}")
    for mc in diff.moduleChanges:
        lines += [f"Enable module {checksum(m)}" for m in mc.enabledModules]
        lines += [f"Disable module {checksum(m)}" for m in mc.disabledModules]
    for g in diff.guardChanges:
        lines.append("Remove the Safe guard" if g.newGuard == ZERO_ADDRESS
                     else f"Change the Safe guard to {checksum(g.newGuard)}")
    for s in diff.implementationSwaps:
        lines.append(f"Replace the logic of {checksum(s.address)} from {s.oldImpl[:42]} to {s.newImpl[:42]}")
    return lines


def _alert_lines(alerts: Iterable[RiskAlert]) -> list[str]:
    return [
        f"{'Warning' if a.severity in BLOCKING_SEVERITIES else 'Note'}: {a.description}"
        for a in alerts
    ]


def render_summary(
    diff: StateDiffSummary,
    alerts: Sequence[RiskAlert],
    ctx: EngineContext,
    *,
    safe: Optional[str] = None,
    label: Optional[str] = None,
    permits: Sequence[PermitInfo] = (),
) -> list[str]:
    lines = _movement_lines(diff, safe, ctx) + _approval_lines(diff, ctx) + _control_lines(diff)
    now = ctx.now or 0
    lines += [describe_permit(p, now=now, symbol=ctx.symbol_of(p.token) if p.token else None) for p in permits]
    if not lines:
        lines.append(NO_EFFECT_LINE)
    if label and any(a.severity in BLOCKING_SEVERITIES for a in alerts):
        lines.insert(0, f'The real effect differs from what the interface claimed: "{label}"')
    return lines + _alert_lines(alerts)
