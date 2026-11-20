"""Shields #26 behavioural anomalies, #28 gas ceiling, #31 chain binding, #33 poisoning,
#36 bridge destination checks, and Quai shard prefix spoofing."""

from __future__ import annotations

from typing import Callable

from shared.api_schemas import RiskAlert
from simulator.constants import (
    GRIEFING_CALLDATA_BYTES,
    GRIEFING_GAS_LIMIT,
    NEW_CONTRACT_WINDOW_SECONDS,
    VAULT_SHARE_CRITICAL,
    VAULT_SHARE_WARN,
)
from simulator.diff import recipients, safe_outflows
from simulator.hexutil import checksum, hex_to_bytes
from simulator.rules.base import AnalysisInput, alert


def vault_share(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    for asset, outflow in safe_outflows(inp.diff, inp.safe).items():
        balance = inp.ctx.safe_balances.get(asset)
        if not balance:
            continue
        share = outflow / balance
        if share >= VAULT_SHARE_WARN:
            sev = "HIGH" if share >= VAULT_SHARE_CRITICAL else "MEDIUM"
            out.append(alert("B26-VAULT-SHARE", sev, f"Moves {share:.0%} of the Safe's {asset} balance",
                             asset=asset, share=round(share, 4)))
    return out


def first_time_recipients(inp: AnalysisInput) -> list[RiskAlert]:
    history = inp.ctx.recipient_history
    if not history:
        return []
    fresh = sorted({to for to, _a, _v in recipients(inp.diff, inp.safe) if to not in history})
    return [alert("B26-FIRST-RECIPIENT", "LOW", f"First payment from this Safe to {checksum(a)}", recipient=a)
            for a in fresh]


def new_contracts(inp: AnalysisInput) -> list[RiskAlert]:
    now = inp.ctx.now
    if now is None:
        return []
    touched = {c.target for c in inp.calls} | {r[0] for r in recipients(inp.diff, inp.safe)}
    return [
        alert("B26-NEW-CONTRACT", "MEDIUM", f"Contract {checksum(a)} was deployed less than 24 hours ago",
              address=a, deployedAt=inp.ctx.deploy_times[a])
        for a in sorted(touched)
        if a in inp.ctx.deploy_times and now - inp.ctx.deploy_times[a] < NEW_CONTRACT_WINDOW_SECONDS
    ]


def _lookalike(a: str, b: str) -> bool:
    return a != b and a[2:6] == b[2:6] and a[-4:] == b[-4:]


def address_poisoning(inp: AnalysisInput) -> list[RiskAlert]:
    contacts = inp.ctx.contacts | inp.ctx.recipient_history
    targets = {r[0] for r in recipients(inp.diff, inp.safe)} | {a.spender for a in inp.diff.approvals}
    out = []
    for target in sorted(targets - contacts):
        for contact in sorted(contacts):
            if _lookalike(target, contact):
                out.append(alert("P33-POISON", "HIGH", f"{checksum(target)} imitates known address "
                                 f"{checksum(contact)} (same first and last 4 characters)",
                                 target=target, imitates=contact))
    return out


def gas_ceiling(inp: AnalysisInput) -> list[RiskAlert]:
    op = inp.request.userOperation
    if op is None:
        return []
    total_gas = int(op.callGasLimit) + int(op.verificationGasLimit) + int(op.preVerificationGas)
    worst_fee = total_gas * int(op.maxFeePerGas)
    policy_cap = inp.policy.maxGasFeeWei if inp.policy and inp.policy.maxGasFeeWei else None
    ceiling = int(policy_cap) if policy_cap is not None else inp.ctx.max_gas_fee_wei
    out = []
    if worst_fee > ceiling:
        out.append(alert("G28-GAS-CEILING", "HIGH", f"Worst-case gas fee {worst_fee} wei exceeds ceiling "
                         f"{ceiling} wei", worstFeeWei=str(worst_fee), ceilingWei=str(ceiling)))
    if int(op.maxPriorityFeePerGas) > int(op.maxFeePerGas):
        out.append(alert("G28-MALFORMED", "MEDIUM", "Priority fee is above the max fee"))
    sponsored = len(hex_to_bytes(op.paymasterAndData)) > 0
    if sponsored and len(hex_to_bytes(op.callData)) <= GRIEFING_CALLDATA_BYTES and total_gas >= GRIEFING_GAS_LIMIT:
        out.append(alert("G28-GRIEFING", "HIGH", "Paymaster-sponsored operation reserves large gas for "
                         "almost no call data (gas-drain pattern)", totalGas=total_gas))
    return out


def chain_binding(inp: AnalysisInput) -> list[RiskAlert]:
    chain = inp.request.chainId
    out = []
    for label, expected in (("expected", inp.ctx.expected_chain_id), ("connected node", inp.observed_chain_id)):
        if expected is not None and expected != chain:
            out.append(alert("C31-CHAIN", "CRITICAL", f"Request targets chain {chain} but the {label} "
                             f"chain is {expected}", requested=chain, actual=expected))
    for tx in inp.request.transactions:
        for auth in tx.authorizationList or []:
            if auth.chainId == 0:
                out.append(alert("C31-CHAIN", "CRITICAL", "EIP-7702 authorisation uses chainId 0 and is "
                                 "replayable on every chain", delegate=auth.address))
            elif auth.chainId != chain:
                out.append(alert("C31-CHAIN", "HIGH", f"EIP-7702 authorisation is bound to chain "
                                 f"{auth.chainId}, not {chain}", delegate=auth.address))
    for p in inp.permits:
        if p.chain_id is not None and p.chain_id != chain:
            out.append(alert("C31-CHAIN", "HIGH", f"Permit is bound to chain {p.chain_id}, not {chain}"))
    return out


def bridge_destinations(inp: AnalysisInput) -> list[RiskAlert]:
    return [
        alert("B36-BRIDGE", "MEDIUM", f"{b.protocol} bridge call to an unrecognised destination chain",
              protocol=b.protocol)
        for b in inp.diff.bridgeTransfers
        if b.destChainId is None
    ]


def quai_shard_prefix_spoofing(inp: AnalysisInput) -> list[RiskAlert]:
    is_quai = (inp.request.chainId in (9, 15000)) or (getattr(inp.policy, "mode", None) in ("QUAI_NATIVE", "QUAI"))
    if not is_quai:
        return []
    expected_zone = getattr(inp.policy, "shardZone", None) or "cyprus1"
    targets = {r[0] for r in recipients(inp.diff, inp.safe)} | {a.spender for a in inp.diff.approvals} | {c.target for c in inp.calls}
    out = []
    from simulator.analyzers.poisoning import detect_quai_shard_prefix_spoofing
    for t in sorted(targets):
        res = detect_quai_shard_prefix_spoofing(t, expected_zone)
        if res:
            out.append(alert("Q33-SHARD-SPOOF", "HIGH", res["warning"], target=t, expectedZone=expected_zone))
    return out


SHIELDS: tuple[Callable[[AnalysisInput], list[RiskAlert]], ...] = (
    vault_share, first_time_recipients, new_contracts, address_poisoning, gas_ceiling, chain_binding,
    bridge_destinations, quai_shard_prefix_spoofing,
)
