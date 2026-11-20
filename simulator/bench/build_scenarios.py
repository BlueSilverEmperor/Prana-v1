"""Generate the 55 benchmark scenario files deterministically.

Run: python -m simulator.bench.build_scenarios
Writes simulator/bench/scenarios/{main,heldout,public}/*.json.

Honesty: every file here is team-authored. The held-out set must be replaced by an
outside author before results are presented (blueprint section 8). Public scenarios
reproduce the calldata shape of cited incidents; they are not mainnet replays.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from eth_abi import encode
from eth_utils import keccak

OUT = Path(__file__).parent / "scenarios"
NOW = 1_763_600_000
YEAR = 365 * 86_400
MAX = 2**256 - 1


def addr(byte: str) -> str:
    return "0x" + byte * 20


SAFE, HOT, VENDOR, ROUTER, NEWVENDOR = addr("5a"), addr("4f"), addr("7e"), addr("2c"), addr("6d")
ATTACKER, DRAINER, MAL_IMPL, OWNER3 = addr("e0"), addr("d4"), addr("ba"), addr("03")
NFT, OLD_MARKET, OLD_MODULE, WH_BRIDGE = addr("bc"), addr("0b"), addr("0d"), addr("3e")
FAKE_USDC = addr("fa")
LOOKALIKE_HOT = "0x4f4f" + "00" * 16 + "4f4f"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
WBTC = "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
MULTISEND = "0x40a2accbd92bca938b02010e17a5b8929b49130d"
MULTISEND_141 = "0x9641d764fc13c8b624c04430c7356c1c7c8102e2"
OP_BRIDGE = "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1"
WBTC_CONTACT = addr("1f")
WBTC_LOOKALIKE = "0x1f1f" + "ab" * 16 + "1f1f"
USD = 10**6
ETH = 10**18

BASE_CONTEXT = {
    "now": NOW,
    "threatRegistry": [DRAINER],
    "contacts": [HOT, VENDOR, WBTC_CONTACT],
    "recipientHistory": [HOT, VENDOR, ROUTER, SAFE],
    "safeBalances": {USDT: str(1_000_000 * USD), USDC: str(500_000 * USD), "ETH": str(200 * ETH)},
    "tokenMeta": {FAKE_USDC: {"symbol": "USDC", "decimals": 6}},
}


def cd(signature: str, types: list[str], args: list) -> str:
    return "0x" + (keccak(text=signature)[:4] + encode(types, args)).hex()


def transfer(to: str, amount: int) -> str:
    return cd("transfer(address,uint256)", ["address", "uint256"], [to, amount])


def approve(spender: str, amount: int) -> str:
    return cd("approve(address,uint256)", ["address", "uint256"], [spender, amount])


def batch(subs: list[tuple[int, str, int, str]]) -> str:
    packed = b"".join(bytes([op]) + bytes.fromhex(to[2:]) + v.to_bytes(32, "big")
                      + len(bytes.fromhex(d[2:])).to_bytes(32, "big") + bytes.fromhex(d[2:]) for op, to, v, d in subs)
    return cd("multiSend(bytes)", ["bytes"], [packed])


def tx(to: str, data: str = "0x", value: int = 0, op: int = 0, **extra) -> dict:
    return {"to": to, "value": str(value), "data": data, "operation": op, **extra}


def policy(recipients: list[str], cap: int, tokens: list[str]) -> dict:
    return {"allowedRecipients": recipients, "maxOutflowWei": str(cap), "allowedTokens": tokens}


PAY_HOT_100 = policy([HOT], 100 * USD, [USDT])
NOTHING = policy([], 0, [])


def sc(sid, set_, label, category, title, txs, pol=None, expected=(), label_text=None, source=None,
       ctx_extra=None, user_op=None):
    request = {"chainId": 1, "safeAddress": SAFE, "transactions": txs}
    if pol is not None:
        request["intentPolicy"] = pol
    if label_text:
        request["label"] = label_text
    if user_op:
        request["userOperation"] = user_op
    author = "PLACEHOLDER - replace with outside author" if set_ == "heldout" else "team"
    return {"id": sid, "set": set_, "label": label, "category": category, "title": title, "request": request,
            "context": {**BASE_CONTEXT, **(ctx_extra or {})}, "expectedRules": list(expected), "source": source,
            "author": author}


def main_malicious() -> list[dict]:
    m = "main"
    return [
        sc("m01", m, "malicious", "approvals", "Unlimited USDT approval to unknown spender",
           [tx(USDT, approve(ATTACKER, MAX))], PAY_HOT_100, ["R1"]),
        sc("m02", m, "malicious", "approvals", "Limited approval to undeclared spender",
           [tx(USDT, approve(ATTACKER, 5_000 * USD))], PAY_HOT_100, ["R1"]),
        sc("m03", m, "malicious", "approvals", "setApprovalForAll on NFT collection",
           [tx(NFT, cd("setApprovalForAll(address,bool)", ["address", "bool"], [ATTACKER, True]))], NOTHING, ["R1"]),
        sc("m04", m, "malicious", "approvals", "Batch hides increaseAllowance(MAX)",
           [tx(MULTISEND, batch([(0, USDT, 0, transfer(HOT, 100 * USD)),
                                 (0, USDT, 0, cd("increaseAllowance(address,uint256)", ["address", "uint256"],
                                                 [ATTACKER, MAX]))]), op=1)], PAY_HOT_100, ["R1"]),
        sc("m05", m, "malicious", "approvals", "Permit2 unlimited approval for one year",
           [tx(PERMIT2, cd("approve(address,address,uint160,uint48)", ["address", "address", "uint160", "uint48"],
                           [USDT, ATTACKER, 2**160 - 1, NOW + YEAR]))], PAY_HOT_100, ["R2"]),
        sc("m06", m, "malicious", "approvals", "EIP-2612 permit to registry-listed drainer",
           [tx(USDC, cd("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                        ["address", "address", "uint256", "uint256", "uint8", "bytes32", "bytes32"],
                        [SAFE, DRAINER, MAX, NOW + 3600, 27, b"\x00" * 32, b"\x00" * 32]))], PAY_HOT_100,
           ["R2", "R12"]),
        sc("m07", m, "malicious", "control", "Proxy implementation upgrade to attacker logic",
           [tx(SAFE, cd("upgradeTo(address)", ["address"], [MAL_IMPL]))], NOTHING, ["R3"]),
        sc("m08", m, "malicious", "control", "Delegatecall to unverified contract",
           [tx(ATTACKER, transfer(MAL_IMPL, 0), op=1)], NOTHING, ["R4"]),
        sc("m09", m, "malicious", "control", "Add attacker owner and drop threshold to 1",
           [tx(SAFE, cd("addOwnerWithThreshold(address,uint256)", ["address", "uint256"], [ATTACKER, 1]))],
           NOTHING, ["R5"]),
        sc("m10", m, "malicious", "control", "Remove the transaction guard",
           [tx(SAFE, cd("setGuard(address)", ["address"], ["0x" + "00" * 20]))], NOTHING, ["R6"]),
        sc("m11", m, "malicious", "control", "Enable attacker module",
           [tx(SAFE, cd("enableModule(address)", ["address"], [ATTACKER]))], NOTHING, ["R7"]),
        sc("m12", m, "malicious", "control", "EIP-7702 delegation to drainer",
           [tx(HOT, authorizationList=[{"chainId": 1, "address": DRAINER, "nonce": 0}])], NOTHING, ["R8", "R12"]),
        sc("m13", m, "malicious", "hidden-transfer", "Declared payment plus hidden 900k drain in batch",
           [tx(MULTISEND, batch([(0, USDT, 0, transfer(HOT, 100 * USD)),
                                 (0, USDT, 0, transfer(ATTACKER, 900_000 * USD))]), op=1)], PAY_HOT_100,
           ["R9", "R10"]),
        sc("m14", m, "malicious", "hidden-transfer", "Lookalike USDC contract",
           [tx(FAKE_USDC, transfer(HOT, 100 * USD))], policy([HOT], 100 * USD, [USDC]), ["R11"]),
        sc("m15", m, "malicious", "hidden-transfer", "Address poisoning of hot wallet",
           [tx(USDT, transfer(LOOKALIKE_HOT, 100 * USD))], policy([LOOKALIKE_HOT], 100 * USD, [USDT]),
           ["P33-POISON"]),
        sc("m16", m, "malicious", "hidden-transfer", "Amount 50x above declared cap",
           [tx(USDT, transfer(HOT, 5_000 * USD))], PAY_HOT_100, ["R10"]),
        sc("m17", m, "malicious", "interface-mismatch", "UI says 1 ETH to hot wallet, bytes send 50 ETH elsewhere",
           [tx(ATTACKER, value=50 * ETH)], policy([HOT], ETH, ["ETH"]), ["R9", "R10"],
           label_text="Send 1 ETH to hot wallet"),
        sc("m18", m, "malicious", "interface-mismatch", "UI says pay vendor, bytes pay drainer",
           [tx(USDT, transfer(DRAINER, 100 * USD))], policy([VENDOR], 100 * USD, [USDT]), ["R9", "R12"],
           label_text="Pay vendor 100 USDT"),
        sc("m19", m, "malicious", "interface-mismatch", "UI says rotate signer, bytes add attacker",
           [tx(SAFE, cd("swapOwner(address,address,address)", ["address"] * 3, [addr("01"), OWNER3, ATTACKER]))],
           NOTHING, ["R5"], label_text="Rotate signer key"),
        sc("m20", m, "malicious", "interface-mismatch", "UI says bridge to own L2 Safe, recipient is attacker",
           [tx(WH_BRIDGE, cd("transferTokens(address,uint256,uint16,bytes32,uint256,uint32)",
                             ["address", "uint256", "uint16", "bytes32", "uint256", "uint32"],
                             [USDT, 100 * USD, 23, b"\x00" * 12 + bytes.fromhex(ATTACKER[2:]), 0, 7]))],
           policy([WH_BRIDGE, SAFE], 100 * USD, [USDT]), ["R9"], label_text="Bridge 100 USDT to our Arbitrum Safe"),
    ]


def main_benign() -> list[dict]:
    m, b = "main", "benign"
    pay_three = policy([HOT, VENDOR, NEWVENDOR], 300 * USD, [USDT])
    return [
        sc("b01", m, b, "approvals", "Exact approval to declared router",
           [tx(USDT, approve(ROUTER, 100 * USD))], policy([ROUTER], 0, [])),
        sc("b02", m, b, "approvals", "Revoke old approval", [tx(USDT, approve(OLD_MARKET, 0))], NOTHING),
        sc("b03", m, b, "approvals", "Revoke NFT operator",
           [tx(NFT, cd("setApprovalForAll(address,bool)", ["address", "bool"], [OLD_MARKET, False]))], NOTHING),
        sc("b04", m, b, "approvals", "Short-lived bounded Permit2 approval to declared router",
           [tx(PERMIT2, cd("approve(address,address,uint160,uint48)", ["address", "address", "uint160", "uint48"],
                           [USDT, ROUTER, 100 * USD, NOW + 3600]))], policy([ROUTER], 0, [])),
        sc("b05", m, b, "control", "Canonical MultiSend paying two declared recipients",
           [tx(MULTISEND, batch([(0, USDT, 0, transfer(HOT, 100 * USD)), (0, USDT, 0, transfer(VENDOR, 50 * USD))]),
               op=1)], policy([HOT, VENDOR], 150 * USD, [USDT])),
        sc("b06", m, b, "control", "Disable retired module",
           [tx(SAFE, cd("disableModule(address,address)", ["address", "address"], [addr("01"), OLD_MODULE]))],
           NOTHING),
        sc("b07", m, b, "control", "MultiSendCallOnly 1.4.1: approve router and call it",
           [tx(MULTISEND_141, batch([(0, USDT, 0, approve(ROUTER, 50 * USD)), (0, ROUTER, 0, "0x12345678")]), op=1)],
           policy([ROUTER], 0, [])),
        sc("b08", m, b, "control", "OP Stack bridge of USDC to own L2 Safe",
           [tx(OP_BRIDGE, cd("depositERC20To(address,address,address,uint256,uint32,bytes)",
                             ["address", "address", "address", "uint256", "uint32", "bytes"],
                             [USDC, addr("0c"), SAFE, 1_000 * USD, 200_000, b""]))],
           policy([OP_BRIDGE, SAFE], 1_000 * USD, [USDC])),
        sc("b09", m, b, "transfer", "Pay hot wallet 100 USDT", [tx(USDT, transfer(HOT, 100 * USD))], PAY_HOT_100),
        sc("b10", m, b, "transfer", "Send 1 ETH to hot wallet", [tx(HOT, value=ETH)], policy([HOT], ETH, ["ETH"])),
        sc("b11", m, b, "transfer", "Two declared transfers within cap",
           [tx(USDT, transfer(HOT, 100 * USD)), tx(USDT, transfer(VENDOR, 200 * USD))],
           policy([HOT, VENDOR], 300 * USD, [USDT])),
        sc("b12", m, b, "transfer", "Real USDC to vendor",
           [tx(USDC, transfer(VENDOR, 100 * USD))], policy([VENDOR], 100 * USD, [USDC])),
        sc("b13", m, b, "interface-match", "Label matches bytes",
           [tx(USDT, transfer(HOT, 100 * USD))], PAY_HOT_100, label_text="Send 100 USDT to hot wallet"),
        sc("b14", m, b, "interface-match", "Transfer exactly at cap",
           [tx(USDT, transfer(VENDOR, 250 * USD))], policy([VENDOR], 250 * USD, [USDT])),
        sc("b15", m, b, "interface-match", "Pay saved contact", [tx(USDT, transfer(HOT, 10 * USD))], PAY_HOT_100),
        sc("b16", m, b, "interface-match", "Declared first payment to new vendor",
           [tx(NEWVENDOR, value=ETH // 10)], policy([NEWVENDOR], ETH // 10, ["ETH"]),
           label_text="Pay new vendor 0.1 ETH"),
        sc("b17", m, b, "normal-ops", "Session payment 10 USDT", [tx(USDT, transfer(HOT, 10 * USD))], PAY_HOT_100),
        sc("b18", m, b, "normal-ops", "Payroll batch of three",
           [tx(MULTISEND, batch([(0, USDT, 0, transfer(HOT, 100 * USD)), (0, USDT, 0, transfer(VENDOR, 100 * USD)),
                                 (0, USDT, 0, transfer(NEWVENDOR, 100 * USD))]), op=1)], pay_three),
        sc("b19", m, b, "normal-ops", "Top up hot wallet 0.5 ETH",
           [tx(HOT, value=ETH // 2)], policy([HOT], ETH // 2, ["ETH"])),
        sc("b20", m, b, "normal-ops", "Zero-value call to declared router",
           [tx(ROUTER, "0x12345678")], policy([ROUTER], 0, [])),
    ]


def heldout() -> list[dict]:
    h = "heldout"
    inner = batch([(0, USDT, 0, approve(ATTACKER, MAX))])
    return [
        sc("h01", h, "malicious", "approvals", "Approval hidden two MultiSend levels deep",
           [tx(MULTISEND, batch([(0, USDT, 0, transfer(HOT, 100 * USD)), (1, MULTISEND, 0, inner)]), op=1)],
           PAY_HOT_100, ["R1"]),
        sc("h02", h, "malicious", "control", "Delegatecall to fake MultiSend address",
           [tx(ATTACKER, batch([(0, USDT, 0, transfer(HOT, 100 * USD))]), op=1)], PAY_HOT_100, ["R4"]),
        sc("h03", h, "malicious", "hidden-transfer", "transferFrom(Safe, attacker) instead of transfer",
           [tx(USDT, cd("transferFrom(address,address,uint256)", ["address"] * 2 + ["uint256"],
                        [SAFE, ATTACKER, 100 * USD]))], PAY_HOT_100, ["R9"]),
        sc("h04", h, "malicious", "approvals", "Near-max allowance via increaseAllowance",
           [tx(USDT, cd("increaseAllowance(address,uint256)", ["address", "uint256"], [ATTACKER, 2**255]))],
           PAY_HOT_100, ["R1"]),
        sc("h05", h, "malicious", "control", "Threshold lowered to 1",
           [tx(SAFE, cd("changeThreshold(uint256)", ["uint256"], [1]))], NOTHING, ["R5"]),
        sc("h06", h, "benign", "transfer", "Nested canonical MultiSend of declared payments",
           [tx(MULTISEND, batch([(1, MULTISEND, 0, batch([(0, USDT, 0, transfer(HOT, 50 * USD))])),
                                 (0, USDT, 0, transfer(VENDOR, 50 * USD))]), op=1)],
           policy([HOT, VENDOR], 100 * USD, [USDT])),
        sc("h07", h, "benign", "transfer", "Checksummed mixed-case addresses",
           [tx("0xdAC17F958D2ee523a2206206994597C13D831ec7", transfer(HOT, 20 * USD))],
           policy([HOT.upper().replace("0X", "0x")], 20 * USD, ["0xdAC17F958D2ee523a2206206994597C13D831ec7"])),
        sc("h08", h, "benign", "approvals", "Exact approval inside batch",
           [tx(MULTISEND, batch([(0, USDC, 0, approve(ROUTER, 25 * USD))]), op=1)], policy([ROUTER], 0, [])),
        sc("h09", h, "benign", "transfer", "ETH and USDT to the same declared recipient",
           [tx(HOT, value=ETH // 10), tx(USDT, transfer(HOT, 10 * USD))],
           policy([HOT], ETH // 10, ["ETH", USDT])),
        sc("h10", h, "benign", "approvals", "Revoke operator inside batch",
           [tx(MULTISEND, batch([(0, NFT, 0, cd("setApprovalForAll(address,bool)", ["address", "bool"],
                                                [OLD_MARKET, False]))]), op=1)], NOTHING),
    ]


def public() -> list[dict]:
    p = "public"
    return [
        sc("p01", p, "malicious", "control", "WazirX-style: routine-looking tx replaces wallet logic",
           [tx(SAFE, cd("upgradeTo(address)", ["address"], [MAL_IMPL]))], PAY_HOT_100, ["R3"],
           label_text="Transfer 100 USDT to hot wallet", source="WazirX multisig incident, July 2024"),
        sc("p02", p, "malicious", "control", "Bybit-style: delegatecall transfer() rewrites singleton slot",
           [tx(ATTACKER, transfer(MAL_IMPL, 0), op=1)], PAY_HOT_100, ["R4"],
           label_text="Move ETH from cold to warm wallet", source="Bybit Safe{Wallet} incident, February 2025"),
        sc("p03", p, "malicious", "control", "Radiant-style: signers approve ownership transfer of core contract",
           [tx(addr("9a"), cd("transferOwnership(address)", ["address"], [ATTACKER]))], NOTHING, ["R5"],
           label_text="Routine emissions adjustment", source="Radiant Capital multisig incident, October 2024"),
        sc("p04", p, "malicious", "approvals", "Drainer-kit style: setApprovalForAll to operator contract",
           [tx(NFT, cd("setApprovalForAll(address,bool)", ["address", "bool"], [ATTACKER, True]))], NOTHING,
           ["R1"], label_text="Claim airdrop", source="Inferno Drainer phishing pattern, 2023-2024"),
        sc("p05", p, "malicious", "hidden-transfer", "Address poisoning: WBTC to lookalike of known contact",
           [tx(WBTC, transfer(WBTC_LOOKALIKE, 1_155 * 10**8))], policy([WBTC_LOOKALIKE], 1_155 * 10**8, [WBTC]),
           ["P33-POISON"], source="WBTC address-poisoning theft, May 2024"),
    ]


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    for scenario in main_malicious() + main_benign() + heldout() + public():
        target = OUT / scenario["set"] / f"{scenario['id']}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(scenario, indent=2) + "\n")
    print(f"wrote scenarios to {OUT}")


if __name__ == "__main__":
    main()
