"""State-diff construction from decoded calldata, plus merge and outflow helpers.

``static_diff`` predicts effects from calldata alone (used when no fork is available
and to recover Safe control changes that emit no events). ``merge_diffs`` prefers
fork-observed balances, approvals and implementation swaps.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Iterable, Sequence

from shared.api_schemas import (
    ApprovalChange,
    BalanceChange,
    BridgeTransfer,
    GuardChange,
    ImplementationSwap,
    ModuleChange,
    OwnerChange,
    StateDiffSummary,
)
from simulator.decoders.calldata import DecodedCall
from simulator.decoders.permit_and_bridge_decoders import BridgeInfo

ETH = "ETH"
_UPGRADES = frozenset({"upgradeTo", "upgradeToAndCall", "changeMasterCopy"})


class _Ledger:
    """Accumulates signed deltas per (address, asset) in insertion order."""

    def __init__(self) -> None:
        self._deltas: OrderedDict[tuple[str, str], int] = OrderedDict()

    def move(self, asset: str, sender: str, recipient: str, amount: int) -> None:
        if amount <= 0 or sender == recipient:
            return
        self._deltas[(sender, asset)] = self._deltas.get((sender, asset), 0) - amount
        self._deltas[(recipient, asset)] = self._deltas.get((recipient, asset), 0) + amount

    def changes(self) -> list[BalanceChange]:
        return [BalanceChange(address=a, asset=s, delta=str(d)) for (a, s), d in self._deltas.items() if d]


def _token_effects(call: DecodedCall, safe: str, ledger: _Ledger, approvals: list[ApprovalChange]) -> None:
    args, token = call.args, call.target
    if call.name == "transfer":
        ledger.move(token, safe, args["to"], args["amount"])
    elif call.name == "transferFrom" and args["from"] == safe:
        ledger.move(token, safe, args["to"], args["amount"])
    elif call.name in ("safeTransferFrom", "safeTransferFromData") and args["from"] == safe:
        ledger.move(f"{token}#{args['tokenId']}", safe, args["to"], 1)
    elif call.name == "safeTransferFrom1155" and args["from"] == safe:
        ledger.move(f"{token}#{args['tokenId']}", safe, args["to"], args["amount"])
    elif call.name == "safeBatchTransferFrom" and args["from"] == safe:
        for token_id, amount in zip(args["tokenIds"], args["amounts"]):
            ledger.move(f"{token}#{token_id}", safe, args["to"], amount)
    elif call.name in ("approve", "increaseAllowance"):
        approvals.append(ApprovalChange(token=token, owner=safe, spender=args["spender"], amount=str(args["amount"])))
    elif call.name == "setApprovalForAll":
        amount = "ALL" if args["approved"] else "NONE"
        approvals.append(ApprovalChange(token=token, owner=safe, spender=args["operator"], amount=amount))


def _owner_change(call: DecodedCall, safe: str) -> OwnerChange | None:
    a = call.args
    if call.name == "addOwnerWithThreshold":
        return OwnerChange(safe=safe, added=[a["owner"]], newThreshold=a["threshold"])
    if call.name == "removeOwner":
        return OwnerChange(safe=safe, removed=[a["owner"]], newThreshold=a["threshold"])
    if call.name == "swapOwner":
        return OwnerChange(safe=safe, added=[a["newOwner"]], removed=[a["oldOwner"]])
    if call.name == "changeThreshold":
        return OwnerChange(safe=safe, newThreshold=a["threshold"])
    return None


def static_diff(safe: str, calls: Sequence[DecodedCall], bridges: Iterable[BridgeInfo] = ()) -> StateDiffSummary:
    ledger, approvals = _Ledger(), []
    owners, modules, guards, swaps = [], [], [], []
    for call in calls:
        if call.value and call.operation == 0:
            ledger.move(ETH, safe, call.target, call.value)
        _token_effects(call, safe, ledger, approvals)
        if call.name in _UPGRADES:
            swaps.append(ImplementationSwap(address=call.target, oldImpl="unknown",
                                            newImpl=call.args["implementation"], source="calldata"))
        if call.target != safe:
            continue
        owner = _owner_change(call, safe)
        owners.extend([owner] if owner else [])
        if call.name == "enableModule":
            modules.append(ModuleChange(safe=safe, enabledModules=[call.args["module"]]))
        elif call.name == "disableModule":
            modules.append(ModuleChange(safe=safe, disabledModules=[call.args["module"]]))
        elif call.name == "setGuard":
            guards.append(GuardChange(safe=safe, newGuard=call.args["guard"]))
    bridge_rows = [_bridge_row(b) for b in bridges]
    return StateDiffSummary(balanceChanges=ledger.changes(), approvals=approvals, ownerChanges=owners,
                            moduleChanges=modules, implementationSwaps=swaps, guardChanges=guards,
                            bridgeTransfers=bridge_rows)


def _bridge_row(b: BridgeInfo) -> BridgeTransfer:
    return BridgeTransfer(protocol=b.protocol, sourceChainId=b.source_chain_id, destChainId=b.dest_chain_id,
                          recipient=b.recipient, token=b.token, amount=str(b.amount))


def _dedupe(items: Iterable) -> list:
    seen, out = set(), []
    for item in items:
        key = item.model_dump_json()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _merge_approvals(observed: StateDiffSummary, predicted: StateDiffSummary) -> list[ApprovalChange]:
    """Union by (token, spender). Logs report final allowances, so observed amounts win;
    calldata-predicted approvals survive when the token emitted no event."""
    seen = {(a.token, a.spender) for a in observed.approvals}
    return list(observed.approvals) + [a for a in predicted.approvals if (a.token, a.spender) not in seen]


def _merge_balances(observed: StateDiffSummary, predicted: StateDiffSummary) -> list[BalanceChange]:
    """Observed movements are authoritative per asset. An asset the trace never shows
    (token without Transfer events) keeps its calldata prediction, so it cannot vanish."""
    seen_assets = {c.asset for c in observed.balanceChanges}
    return list(observed.balanceChanges) + [c for c in predicted.balanceChanges if c.asset not in seen_assets]


def merge_diffs(observed: StateDiffSummary, predicted: StateDiffSummary) -> StateDiffSummary:
    """Fork-observed movements win; control changes are unioned."""
    observed_impl = {s.address for s in observed.implementationSwaps}
    swaps = list(observed.implementationSwaps) + [
        s for s in predicted.implementationSwaps if s.address not in observed_impl
    ]
    return StateDiffSummary(
        balanceChanges=_merge_balances(observed, predicted),
        approvals=_merge_approvals(observed, predicted),
        ownerChanges=_dedupe([*observed.ownerChanges, *predicted.ownerChanges]),
        moduleChanges=_dedupe([*observed.moduleChanges, *predicted.moduleChanges]),
        implementationSwaps=swaps,
        guardChanges=_dedupe([*observed.guardChanges, *predicted.guardChanges]),
        bridgeTransfers=list(predicted.bridgeTransfers),
    )


def safe_outflows(diff: StateDiffSummary, safe: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for change in diff.balanceChanges:
        delta = int(change.delta)
        if change.address == safe and delta < 0:
            out[change.asset] = out.get(change.asset, 0) - delta
    return out


def recipients(diff: StateDiffSummary, safe: str) -> list[tuple[str, str, int]]:
    """(recipient, asset, amount) for every asset that left the Safe."""
    leaving = set(safe_outflows(diff, safe))
    rows = [
        (c.address, c.asset, int(c.delta))
        for c in diff.balanceChanges
        if c.address != safe and int(c.delta) > 0 and c.asset in leaving
    ]
    rows += [(b.recipient, b.token or ETH, int(b.amount)) for b in diff.bridgeTransfers if b.recipient]
    return rows


def asset_root(asset: str) -> str:
    return asset.split("#", 1)[0]
