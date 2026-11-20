"""Turn a fork trace (prestate diff + logs) into a StateDiffSummary."""

from __future__ import annotations

from typing import Any, Mapping

from eth_abi import decode
from eth_abi.exceptions import DecodingError
from eth_utils import keccak

from shared.api_schemas import (
    ApprovalChange,
    BalanceChange,
    GuardChange,
    ImplementationSwap,
    ModuleChange,
    OwnerChange,
    StateDiffSummary,
)
from simulator.constants import EIP7702_DESIGNATOR_PREFIX, ERC1967_IMPLEMENTATION_SLOT
from simulator.hexutil import hex_to_bytes, parse_int, topic_of, word_to_address
from simulator.tracer.anvil_fork_simulator import LogEntry, TraceResult

T_TRANSFER = topic_of("Transfer(address,address,uint256)")
T_APPROVAL = topic_of("Approval(address,address,uint256)")
T_APPROVAL_ALL = topic_of("ApprovalForAll(address,address,bool)")
T_TRANSFER_SINGLE = topic_of("TransferSingle(address,address,address,uint256,uint256)")
T_TRANSFER_BATCH = topic_of("TransferBatch(address,address,address,uint256[],uint256[])")
T_ADDED_OWNER = topic_of("AddedOwner(address)")
T_REMOVED_OWNER = topic_of("RemovedOwner(address)")
T_THRESHOLD = topic_of("ChangedThreshold(uint256)")
T_ENABLED_MODULE = topic_of("EnabledModule(address)")
T_DISABLED_MODULE = topic_of("DisabledModule(address)")
T_CHANGED_GUARD = topic_of("ChangedGuard(address)")
SAFE_THRESHOLD_SLOT = 4


def _slot_key(key: str) -> int:
    return parse_int(key)


def _storage(acct: Mapping[str, Any]) -> dict[int, str]:
    return {_slot_key(k): v for k, v in acct.get("storage", {}).items()}


def _arg(log: LogEntry, index: int = 0) -> str:
    """Address arg that may be indexed (topic) or not (data), as Safe 1.3 vs 1.4 differ."""
    if len(log.topics) > 1 + index:
        return word_to_address(log.topics[1 + index])
    data = hex_to_bytes(log.data)
    return word_to_address(data[32 * index : 32 * (index + 1)])


def _eth_changes(pre: Mapping, post: Mapping) -> list[BalanceChange]:
    out = []
    for addr, acct in post.items():
        if "balance" not in acct:
            continue
        delta = parse_int(acct["balance"]) - parse_int(pre.get(addr, {}).get("balance", "0x0"))
        if delta:
            out.append(BalanceChange(address=addr, asset="ETH", delta=str(delta)))
    return out


def _erc1155_moves(log: LogEntry, deltas: dict[tuple[str, str], int]) -> None:
    sender, recipient = word_to_address(log.topics[2]), word_to_address(log.topics[3])
    try:
        if log.topics[0] == T_TRANSFER_SINGLE:
            pairs = [decode(["uint256", "uint256"], hex_to_bytes(log.data))]
        else:
            ids, amounts = decode(["uint256[]", "uint256[]"], hex_to_bytes(log.data))
            pairs = list(zip(ids, amounts))
    except (DecodingError, ValueError, OverflowError):
        return
    for token_id, amount in pairs:
        asset = f"{log.address}#{token_id}"
        deltas[(sender, asset)] = deltas.get((sender, asset), 0) - amount
        deltas[(recipient, asset)] = deltas.get((recipient, asset), 0) + amount


def _token_logs(safe: str, logs: tuple[LogEntry, ...]) -> tuple[list[BalanceChange], list[ApprovalChange]]:
    deltas: dict[tuple[str, str], int] = {}
    approvals: list[ApprovalChange] = []
    for log in logs:
        topic0 = log.topics[0] if log.topics else ""
        if topic0 == T_TRANSFER and len(log.topics) in (3, 4):
            sender, recipient = word_to_address(log.topics[1]), word_to_address(log.topics[2])
            if len(log.topics) == 4:
                asset, amount = f"{log.address}#{parse_int(log.topics[3])}", 1
            else:
                asset, amount = log.address, int.from_bytes(hex_to_bytes(log.data)[:32] or b"\x00", "big")
            deltas[(sender, asset)] = deltas.get((sender, asset), 0) - amount
            deltas[(recipient, asset)] = deltas.get((recipient, asset), 0) + amount
        elif topic0 in (T_TRANSFER_SINGLE, T_TRANSFER_BATCH) and len(log.topics) == 4:
            _erc1155_moves(log, deltas)
        elif topic0 == T_APPROVAL and len(log.topics) == 3 and word_to_address(log.topics[1]) == safe:
            amount = int.from_bytes(hex_to_bytes(log.data)[:32] or b"\x00", "big")
            approvals.append(ApprovalChange(token=log.address, owner=safe,
                                            spender=word_to_address(log.topics[2]), amount=str(amount)))
        elif topic0 == T_APPROVAL_ALL and len(log.topics) == 3 and word_to_address(log.topics[1]) == safe:
            approved = int.from_bytes(hex_to_bytes(log.data)[:32] or b"\x00", "big") == 1
            approvals.append(ApprovalChange(token=log.address, owner=safe, spender=word_to_address(log.topics[2]),
                                            amount="ALL" if approved else "NONE"))
    balances = [BalanceChange(address=a, asset=s, delta=str(d)) for (a, s), d in deltas.items() if d]
    return balances, approvals


def _safe_events(safe: str, logs: tuple[LogEntry, ...], pre: Mapping) -> dict[str, list]:
    added, removed, enabled, disabled, guards, threshold = [], [], [], [], [], None
    for log in (entry for entry in logs if entry.address == safe and entry.topics):
        topic0 = log.topics[0]
        if topic0 == T_ADDED_OWNER:
            added.append(_arg(log))
        elif topic0 == T_REMOVED_OWNER:
            removed.append(_arg(log))
        elif topic0 == T_THRESHOLD:
            threshold = int.from_bytes(hex_to_bytes(log.data)[:32] or b"\x00", "big")
        elif topic0 == T_ENABLED_MODULE:
            enabled.append(_arg(log))
        elif topic0 == T_DISABLED_MODULE:
            disabled.append(_arg(log))
        elif topic0 == T_CHANGED_GUARD:
            guards.append(GuardChange(safe=safe, newGuard=_arg(log)))
    old_raw = _storage(pre.get(safe, {})).get(SAFE_THRESHOLD_SLOT)
    owners = [OwnerChange(safe=safe, added=added, removed=removed, newThreshold=threshold,
                          oldThreshold=parse_int(old_raw) if old_raw and threshold is not None else None)
              ] if added or removed or threshold is not None else []
    modules = [ModuleChange(safe=safe, enabledModules=enabled, disabledModules=disabled)] if enabled or disabled else []
    return {"owners": owners, "modules": modules, "guards": guards}


def _codehash(code: str) -> str:
    return "codehash:0x" + keccak(hex_to_bytes(code)).hex()


def _slot_address(value: str | None) -> str:
    """Address held in a storage word; missing or short words are zero-padded."""
    return word_to_address(hex_to_bytes(value or "0x0").rjust(32, b"\x00"))


def _slot_changed(before: dict[int, str], after: dict[int, str], slot: int) -> bool:
    # In diff mode a slot written to zero is present in pre and absent from post.
    if slot in after:
        return parse_int(after[slot]) != parse_int(before.get(slot, "0x0"))
    return slot in before and parse_int(before[slot]) != 0


def _implementation_swaps(safe: str, pre: Mapping, post: Mapping) -> list[ImplementationSwap]:
    swaps = []
    erc1967, slot0 = _slot_key(ERC1967_IMPLEMENTATION_SLOT), 0
    for addr, acct in post.items():
        before, after = _storage(pre.get(addr, {})), _storage(acct)
        checks = [(erc1967, "erc1967-slot")] + ([(slot0, "slot0")] if addr == safe else [])
        for slot, source in checks:
            if _slot_changed(before, after, slot):
                swaps.append(ImplementationSwap(address=addr, oldImpl=_slot_address(before.get(slot)),
                                                newImpl=_slot_address(after.get(slot)), source=source))
        if "code" in acct and acct["code"] != pre.get(addr, {}).get("code"):
            new_code = acct["code"].lower()
            new_impl = new_code if new_code.startswith(EIP7702_DESIGNATOR_PREFIX) else _codehash(new_code)
            swaps.append(ImplementationSwap(address=addr, oldImpl=_codehash(pre.get(addr, {}).get("code", "0x")),
                                            newImpl=new_impl, source="code"))
    return swaps


def build_state_diff(safe: str, trace: TraceResult) -> StateDiffSummary:
    safe = safe.lower()
    pre, post = trace.pre, trace.post
    token_balances, approvals = _token_logs(safe, trace.logs)
    events = _safe_events(safe, trace.logs, pre)
    return StateDiffSummary(
        balanceChanges=_eth_changes(pre, post) + token_balances,
        approvals=approvals,
        ownerChanges=events["owners"],
        moduleChanges=events["modules"],
        implementationSwaps=_implementation_swaps(safe, pre, post),
        guardChanges=events["guards"],
    )
