"""Feature #02: deterministic 12-rule risk engine (R1..R12). Zero AI, zero randomness."""

from __future__ import annotations

import json
import unicodedata
from typing import Callable, Iterable

from shared.api_schemas import RiskAlert
from simulator.constants import LONG_PERMIT_SECONDS, SEVERITY_RANK, UNLIMITED_THRESHOLD
from simulator.diff import asset_root
from simulator.hexutil import ZERO_ADDRESS, checksum
from simulator.rules.base import AnalysisInput, alert

_TOKEN_CALLS = frozenset({"transfer", "transferFrom", "approve", "increaseAllowance", "setApprovalForAll",
                          "safeTransferFrom", "safeTransferFromData", "safeTransferFrom1155",
                          "safeBatchTransferFrom"})
_DESIGNATOR = "0xef0100"


def _is_unlimited(amount: str) -> bool:
    return amount == "ALL" or (amount.isdigit() and int(amount) >= UNLIMITED_THRESHOLD)


def r1_approvals(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    for ap in inp.diff.approvals:
        if ap.amount in ("0", "NONE"):
            continue
        unlimited, declared = _is_unlimited(ap.amount), inp.declared(ap.spender)
        # A declared spender still may not be allowed to pull more than the signer declared: an allowance
        # is a future outflow, so it is held to the same ceiling (found by the MCMC red team).
        # maxOutflowWei "0" on an approval-only intent means no ceiling was declared, so only a positive one binds.
        ceiling = int(inp.policy.maxOutflowWei) if declared else 0
        above_ceiling = ceiling > 0 and (unlimited or (ap.amount.isdigit() and int(ap.amount) > ceiling))
        if unlimited and not declared:
            sev = "CRITICAL"
        elif above_ceiling:
            sev = "HIGH"
        elif unlimited or not declared:
            sev = "MEDIUM" if declared or inp.policy is None else "HIGH"
        else:
            continue
        kind = "UNLIMITED" if unlimited else "an above-ceiling" if above_ceiling else "an undeclared"
        suffix = f" (declared ceiling {ceiling})" if above_ceiling else ""
        out.append(alert("R1", sev, f"Grants {kind} approval on {checksum(ap.token)} to {checksum(ap.spender)}{suffix}",
                         token=ap.token, spender=ap.spender, amount=ap.amount))
    return out + _r1_combined_allowances(inp, already={(a.context["token"], a.context["spender"]) for a in out})


def _r1_combined_allowances(inp: AnalysisInput, already: set) -> list[RiskAlert]:
    """Allowances to one declared spender, added up across the batch, are held to the declared ceiling.

    Found by the MCMC composition red team: several increaseAllowance calls, each under the ceiling,
    together granted twice the ceiling. Repeated approve() calls overwrite rather than add, so summing
    them over-counts; that errs on the side of blocking.
    """
    if inp.policy is None or int(inp.policy.maxOutflowWei) <= 0:
        return []
    ceiling = int(inp.policy.maxOutflowWei)
    totals: dict[tuple, int] = {}
    counts: dict[tuple, int] = {}
    for ap in inp.diff.approvals:
        if not ap.amount.isdigit() or not inp.declared(ap.spender):
            continue
        key = (ap.token, ap.spender)
        totals[key] = totals.get(key, 0) + int(ap.amount)
        counts[key] = counts.get(key, 0) + 1
    return [alert("R1", "HIGH", f"Combined allowances on {checksum(token)} to {checksum(spender)} total {total}, "
                                f"above the declared ceiling {ceiling} ({counts[(token, spender)]} approvals in one batch)",
                  token=token, spender=spender, amount=str(total))
            for (token, spender), total in totals.items()
            if counts[(token, spender)] > 1 and total > ceiling and (token, spender) not in already]


def r2_permits(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    now = inp.ctx.now
    for p in inp.permits:
        declared = inp.declared(p.spender)
        if p.unlimited and not declared:
            sev = "CRITICAL"
        elif not declared:
            sev = "HIGH" if inp.policy is not None else "MEDIUM"
        elif p.unlimited:
            sev = "MEDIUM"
        elif now is not None and (p.deadline is None or p.deadline - now > LONG_PERMIT_SECONDS):
            sev = "LOW"
        else:
            continue
        out.append(alert("R2", sev, f"Signature permit ({p.kind}) lets {checksum(p.spender)} spend "
                         f"{'UNLIMITED' if p.unlimited else p.amount} of {checksum(p.token or '')}",
                         spender=p.spender, token=p.token, amount=str(p.amount), deadline=p.deadline))
    return out


def r3_implementation(inp: AnalysisInput) -> list[RiskAlert]:
    return [
        alert("R3", "CRITICAL", f"Replaces the logic/implementation of {checksum(s.address)} "
              f"(new: {s.newImpl[:42]})", address=s.address, newImpl=s.newImpl, source=s.source)
        for s in inp.diff.implementationSwaps
        if not s.newImpl.startswith(_DESIGNATOR)
    ]


def r4_delegatecall(inp: AnalysisInput) -> list[RiskAlert]:
    return [
        alert("R4", "CRITICAL", f"Execution results in delegatecall to unverified address {checksum(c.target)}",
              target=c.target, path=list(c.path))
        for c in inp.calls
        if c.operation == 1 and c.target not in inp.ctx.trusted_delegatecall
    ]


def r5_owners(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    for oc in inp.diff.ownerChanges:
        lowered = oc.newThreshold is not None and (
            oc.newThreshold <= 1 or (oc.oldThreshold is not None and oc.newThreshold < oc.oldThreshold))
        sev = "CRITICAL" if oc.added or lowered else "HIGH"
        out.append(alert("R5", sev, "Changes Safe owners or signature threshold",
                         added=oc.added, removed=oc.removed, newThreshold=oc.newThreshold))
    for c in inp.calls:
        if c.name in ("transferOwnership", "changeAdmin"):
            new_owner = c.args.get("newOwner") or c.args.get("newAdmin")
            out.append(alert("R5", "CRITICAL", f"Transfers control of {checksum(c.target)} to {checksum(new_owner)}",
                             contract=c.target, newOwner=new_owner))
    return out


def r6_guard(inp: AnalysisInput) -> list[RiskAlert]:
    out = [
        alert("R6", "CRITICAL", "Removes the Safe transaction guard", guard=g.newGuard)
        if g.newGuard == ZERO_ADDRESS
        else alert("R6", "HIGH", f"Replaces the Safe guard with {checksum(g.newGuard)}", guard=g.newGuard)
        for g in inp.diff.guardChanges
    ]
    out += [alert("R6", "HIGH", f"Changes the Safe fallback handler to {checksum(c.args['handler'])}",
                  handler=c.args["handler"])
            for c in inp.calls if c.name == "setFallbackHandler" and c.target == inp.safe]
    return out


def r7_modules(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    for mc in inp.diff.moduleChanges:
        out += [alert("R7", "CRITICAL", f"Enables module {checksum(m)}, which can move funds without signatures",
                      module=m) for m in mc.enabledModules]
        out += [alert("R7", "LOW", f"Disables module {checksum(m)}", module=m) for m in mc.disabledModules]
    return out


def r8_eip7702(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    for tx in inp.request.transactions:
        for auth in tx.authorizationList or []:
            trusted = auth.address in inp.ctx.trusted_7702_delegates
            out.append(alert("R8", "MEDIUM" if trusted else "CRITICAL",
                             f"EIP-7702 delegates account code to {checksum(auth.address)}",
                             delegate=auth.address, chainId=auth.chainId))
    out += [alert("R8", "CRITICAL", f"Account {checksum(s.address)} gains EIP-7702 delegated code",
                  address=s.address, designator=s.newImpl)
            for s in inp.diff.implementationSwaps if s.newImpl.startswith(_DESIGNATOR)]
    return out


def r9_recipients(inp: AnalysisInput) -> list[RiskAlert]:
    if inp.intent is None:
        return []
    out = [alert("R9", "HIGH", f"Sends {amount} of {asset} to undeclared address {checksum(to)}",
                 recipient=to, asset=asset, amount=str(amount))
           for to, asset, amount in inp.intent.undeclared_recipients]
    out += [alert("R9", "HIGH", f"Moves undeclared asset {asset} ({amount})", asset=asset, amount=str(amount))
            for asset, amount in inp.intent.undeclared_assets]
    return out


def r10_outflow(inp: AnalysisInput) -> list[RiskAlert]:
    if inp.intent is None:
        return []
    return [
        alert("R10", "CRITICAL" if cap == 0 or outflow > 10 * cap else "HIGH",
              f"Outflow of {asset} is {outflow}, above the declared ceiling {cap}",
              asset=asset, outflow=str(outflow), cap=str(cap))
        for asset, outflow, cap in inp.intent.over_cap
    ]


def _touched_tokens(inp: AnalysisInput) -> set[str]:
    tokens = {c.target for c in inp.calls if c.name in _TOKEN_CALLS}
    tokens |= {asset_root(b.asset) for b in inp.diff.balanceChanges if b.asset != "ETH"}
    tokens |= {a.token for a in inp.diff.approvals}
    tokens |= {p.token for p in inp.permits if p.token}
    return tokens


def r11_lookalike_tokens(inp: AnalysisInput) -> list[RiskAlert]:
    out = []
    for token in sorted(_touched_tokens(inp)):
        raw_symbol = inp.ctx.symbol_of(token) or ""
        symbol = unicodedata.normalize("NFKC", raw_symbol).strip()
        if symbol and not symbol.isascii():
            out.append(alert("R11", "HIGH", f"Token {checksum(token)} uses non-ASCII characters in its symbol "
                             "(possible homoglyph imitation)", token=token, symbol=symbol[:32]))
            continue
        canonical = inp.ctx.canonical_tokens.get((inp.request.chainId, symbol.upper()))
        if canonical and token not in canonical:
            out.append(alert("R11", "HIGH", f"Token {checksum(token)} claims symbol {symbol} but is not the "
                             f"canonical {symbol} contract", token=token, symbol=symbol))
    return out


def _all_addresses(inp: AnalysisInput) -> set[str]:
    found = {c.target for c in inp.calls}
    for c in inp.calls:
        found |= {v for v in c.args.values() if isinstance(v, str) and len(v) == 42}
    d = inp.diff
    found |= {b.address for b in d.balanceChanges} | {a.spender for a in d.approvals}
    found |= {s.newImpl for s in d.implementationSwaps if len(s.newImpl) == 42}
    found |= {m for mc in d.moduleChanges for m in mc.enabledModules}
    found |= {o for oc in d.ownerChanges for o in oc.added} | {g.newGuard for g in d.guardChanges}
    found |= {b.recipient for b in d.bridgeTransfers if b.recipient} | {p.spender for p in inp.permits}
    found |= {a.address for tx in inp.request.transactions for a in tx.authorizationList or []}
    return found


def r12_threat_registry(inp: AnalysisInput) -> list[RiskAlert]:
    hits = sorted(_all_addresses(inp) & inp.ctx.threat_registry)
    return [alert("R12", "CRITICAL", f"Address {checksum(a)} is listed in the threat registry", address=a)
            for a in hits]


RULES: tuple[Callable[[AnalysisInput], list[RiskAlert]], ...] = (
    r1_approvals, r2_permits, r3_implementation, r4_delegatecall, r5_owners, r6_guard,
    r7_modules, r8_eip7702, r9_recipients, r10_outflow, r11_lookalike_tokens, r12_threat_registry,
)


def sort_alerts(alerts: Iterable[RiskAlert]) -> list[RiskAlert]:
    """Deduplicate and order by severity (highest first), then rule id."""
    unique = {(a.ruleId, a.severity, a.description, json.dumps(a.context, sort_keys=True, default=str)): a
              for a in alerts}
    return sorted(unique.values(), key=lambda a: (-SEVERITY_RANK[a.severity], a.ruleId, a.description))


def run_rules(inp: AnalysisInput, rules=RULES) -> list[RiskAlert]:
    return sort_alerts(a for rule in rules for a in rule(inp))
