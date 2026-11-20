"""Gasless permit decoders (EIP-2612, Permit2) and cross-chain bridge decoders.

Permits authorise spending without a transaction, so they are explained but cannot
be enforced on-chain (blueprint feature 18). Bridge decoding covers OP Stack,
Arbitrum gateway, Wormhole token bridge, Chainlink CCIP and LayerZero OFT v2.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

from eth_abi import decode
from eth_abi.exceptions import DecodingError

from simulator.constants import SECONDS_PER_DAY, UNLIMITED_THRESHOLD
from simulator.hexutil import normalize_address, parse_int, selector_of, short_address, word_to_address

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PermitInfo:
    kind: str  # eip2612 | permit2-approve | permit2-single | permit2-batch | permit2-transfer
    token: Optional[str]
    owner: Optional[str]
    spender: str
    amount: int
    deadline: Optional[int]
    nonce: Optional[int] = None
    chain_id: Optional[int] = None

    @property
    def unlimited(self) -> bool:
        return self.amount >= UNLIMITED_THRESHOLD


@dataclass(frozen=True)
class BridgeInfo:
    protocol: str
    source_chain_id: int
    dest_chain_id: Optional[int]
    recipient: Optional[str]
    token: Optional[str]
    amount: int


# ---------------------------------------------------------------- permit calldata

_SIG_2612 = "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"
_SIG_P2_APPROVE = "approve(address,address,uint160,uint48)"
_SIG_P2_SINGLE = "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)"
_SIG_P2_BATCH = "permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)"
_SIG_P2_TRANSFER = "permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)"


def _types_of(signature: str) -> list[str]:
    inner = signature[signature.index("(") + 1 : -1]
    types, depth, current = [], 0, ""
    for ch in inner:
        if ch == "," and depth == 0:
            types.append(current)
            current = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        current += ch
    return types + [current] if current else types


def _p2612(target: str, v: tuple) -> list[PermitInfo]:
    owner, spender, value, deadline = v[0], v[1], v[2], v[3]
    return [PermitInfo("eip2612", target, owner.lower(), spender.lower(), value, deadline)]


def _p2_approve(target: str, v: tuple) -> list[PermitInfo]:
    token, spender, amount, expiration = v
    return [PermitInfo("permit2-approve", token.lower(), None, spender.lower(), amount, expiration)]


def _p2_single(target: str, v: tuple) -> list[PermitInfo]:
    owner, ((token, amount, expiration, nonce), spender, _deadline), _sig = v
    return [PermitInfo("permit2-single", token.lower(), owner.lower(), spender.lower(), amount, expiration, nonce)]


def _p2_batch(target: str, v: tuple) -> list[PermitInfo]:
    owner, (details, spender, _deadline), _sig = v
    return [
        PermitInfo("permit2-batch", t.lower(), owner.lower(), spender.lower(), a, e, n)
        for t, a, e, n in details
    ]


def _p2_transfer(target: str, v: tuple) -> list[PermitInfo]:
    ((token, amount), nonce, deadline), (to, _requested), owner, _sig = v
    return [PermitInfo("permit2-transfer", token.lower(), owner.lower(), to.lower(), amount, deadline, nonce)]


_PERMIT_DECODERS: Mapping[str, tuple[str, Callable[[str, tuple], list[PermitInfo]]]] = MappingProxyType(
    {
        selector_of(_SIG_2612): (_SIG_2612, _p2612),
        selector_of(_SIG_P2_APPROVE): (_SIG_P2_APPROVE, _p2_approve),
        selector_of(_SIG_P2_SINGLE): (_SIG_P2_SINGLE, _p2_single),
        selector_of(_SIG_P2_BATCH): (_SIG_P2_BATCH, _p2_batch),
        selector_of(_SIG_P2_TRANSFER): (_SIG_P2_TRANSFER, _p2_transfer),
    }
)


def decode_permit_calls(target: str, data: bytes) -> tuple[PermitInfo, ...]:
    """Decode every permit carried by one call (batches yield several)."""
    entry = _PERMIT_DECODERS.get("0x" + data[:4].hex())
    if entry is None:
        return ()
    signature, builder = entry
    try:
        values = decode(_types_of(signature), data[4:])
    except (DecodingError, ValueError, OverflowError) as exc:
        logger.debug("malformed permit calldata to %s: %s", target, exc)
        return ()
    return tuple(builder(target.lower(), values))


def decode_permit_call(target: str, data: bytes) -> Optional[PermitInfo]:
    found = decode_permit_calls(target, data)
    return found[0] if found else None


# ---------------------------------------------------------------- typed data

def _require(mapping: Mapping[str, Any], key: str) -> Any:
    if key not in mapping:
        raise ValueError(f"typed data missing field {key!r}")
    return mapping[key]


def _opt_int(value: Any) -> Optional[int]:
    return None if value is None else parse_int(value)


def decode_permit_typed_data(typed: Mapping[str, Any]) -> tuple[PermitInfo, ...]:
    """Decode an ``eth_signTypedData_v4`` payload for a permit-style signature."""
    domain = typed.get("domain") or {}
    message = _require(typed, "message")
    primary = _require(typed, "primaryType")
    chain_id = _opt_int(domain.get("chainId"))
    verifying = domain.get("verifyingContract")
    if primary == "Permit":
        return (
            PermitInfo(
                "eip2612",
                normalize_address(verifying) if verifying else None,
                normalize_address(_require(message, "owner")),
                normalize_address(_require(message, "spender")),
                parse_int(_require(message, "value")),
                _opt_int(message.get("deadline")),
                _opt_int(message.get("nonce")),
                chain_id,
            ),
        )
    if primary in ("PermitSingle", "PermitBatch"):
        details = _require(message, "details")
        rows = [details] if primary == "PermitSingle" else list(details)
        kind = "permit2-single" if primary == "PermitSingle" else "permit2-batch"
        spender = normalize_address(_require(message, "spender"))
        return tuple(
            PermitInfo(kind, normalize_address(d["token"]), None, spender, parse_int(d["amount"]),
                       _opt_int(d.get("expiration")), _opt_int(d.get("nonce")), chain_id)
            for d in rows
        )
    if primary in ("PermitTransferFrom", "PermitWitnessTransferFrom", "PermitBatchTransferFrom"):
        permitted = _require(message, "permitted")
        rows = permitted if isinstance(permitted, list) else [permitted]
        spender = normalize_address(_require(message, "spender"))
        return tuple(
            PermitInfo("permit2-transfer", normalize_address(p["token"]), None, spender, parse_int(p["amount"]),
                       _opt_int(message.get("deadline")), _opt_int(message.get("nonce")), chain_id)
            for p in rows
        )
    raise ValueError(f"unsupported permit primaryType {primary!r}")


def describe_permit(info: PermitInfo, now: int, symbol: Optional[str] = None) -> str:
    """Deterministic plain-English sentence for a permit."""
    asset = symbol or (short_address(info.token) if info.token else "the token")
    amount = "UNLIMITED" if info.unlimited else f"{info.amount} units of"
    if info.deadline is None:
        expiry = "with no expiry"
    elif info.deadline <= now:
        expiry = "but it has already expired"
    else:
        days = (info.deadline - now) // SECONDS_PER_DAY
        expiry = f"and it expires in {days} days" if days >= 1 else "and it expires within 24 hours"
    return f"Signing lets {short_address(info.spender)} spend {amount} {asset} {expiry}."


# ---------------------------------------------------------------- bridges

_WORMHOLE_CHAINS = MappingProxyType({2: 1, 4: 56, 5: 137, 23: 42161, 24: 10, 30: 8453})
_CCIP_SELECTORS = MappingProxyType(
    {
        5009297550715157269: 1,
        4949039107694359620: 42161,
        3734403246176062136: 10,
        15971525489660198786: 8453,
        4051577828743386545: 137,
    }
)
_LZ_EIDS = MappingProxyType({30101: 1, 30110: 42161, 30111: 10, 30184: 8453, 30109: 137})
_OP_BRIDGES = MappingProxyType(
    {
        "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": 10,
        "0x3154cf16ccdb4c6d922629664174b904d80f2c35": 8453,
    }
)
_ARB_ROUTERS = MappingProxyType({"0x72ce9c846789fdb6fc1f34ac4ad25dd9ef7031ef": 42161})

_SIG_OP_ETH = "depositETHTo(address,uint32,bytes)"
_SIG_OP_ETH2 = "bridgeETHTo(address,uint32,bytes)"
_SIG_OP_ERC20 = "depositERC20To(address,address,address,uint256,uint32,bytes)"
_SIG_OP_ERC20_2 = "bridgeERC20To(address,address,address,uint256,uint32,bytes)"
_SIG_ARB = "outboundTransfer(address,address,uint256,uint256,uint256,bytes)"
_SIG_WH = "transferTokens(address,uint256,uint16,bytes32,uint256,uint32)"
_SIG_CCIP = "ccipSend(uint64,(bytes,bytes,(address,uint256)[],address,bytes))"
_SIG_LZ = "send((uint32,bytes32,uint256,uint256,bytes,bytes,bytes),(uint256,uint256),address)"


def _bridge_builders() -> Mapping[str, tuple[str, Callable[..., BridgeInfo]]]:
    def op_eth(target, value, src, v):
        return BridgeInfo("op-stack", src, _OP_BRIDGES.get(target), v[0].lower(), None, value)

    def op_erc20(target, value, src, v):
        return BridgeInfo("op-stack", src, _OP_BRIDGES.get(target), v[2].lower(), v[0].lower(), v[3])

    def arb(target, value, src, v):
        return BridgeInfo("arbitrum", src, _ARB_ROUTERS.get(target), v[1].lower(), v[0].lower(), v[2])

    def wormhole(target, value, src, v):
        return BridgeInfo("wormhole", src, _WORMHOLE_CHAINS.get(v[2]), word_to_address(v[3]), v[0].lower(), v[1])

    def ccip(target, value, src, v):
        receiver, _data, tokens, _fee_token, _extra = v[1]
        token, amount = (tokens[0][0].lower(), tokens[0][1]) if tokens else (None, value)
        return BridgeInfo("ccip", src, _CCIP_SELECTORS.get(v[0]), word_to_address(receiver) if receiver else None,
                          token, amount)

    def layerzero(target, value, src, v):
        dst_eid, to, amount = v[0][0], v[0][1], v[0][2]
        return BridgeInfo("layerzero", src, _LZ_EIDS.get(dst_eid), word_to_address(to), target, amount)

    pairs = [(_SIG_OP_ETH, op_eth), (_SIG_OP_ETH2, op_eth), (_SIG_OP_ERC20, op_erc20),
             (_SIG_OP_ERC20_2, op_erc20), (_SIG_ARB, arb), (_SIG_WH, wormhole), (_SIG_CCIP, ccip),
             (_SIG_LZ, layerzero)]
    return MappingProxyType({selector_of(sig): (sig, fn) for sig, fn in pairs})


_BRIDGE_DECODERS = _bridge_builders()


def is_known_permit_or_bridge_selector(data: bytes) -> bool:
    selector = "0x" + data[:4].hex()
    return selector in _PERMIT_DECODERS or selector in _BRIDGE_DECODERS


def decode_bridge_call(target: str, value: int, data: bytes, source_chain_id: int) -> Optional[BridgeInfo]:
    entry = _BRIDGE_DECODERS.get("0x" + data[:4].hex())
    if entry is None:
        return None
    signature, builder = entry
    try:
        values = decode(_types_of(signature), data[4:])
    except (DecodingError, ValueError, OverflowError) as exc:
        logger.debug("malformed bridge calldata to %s: %s", target, exc)
        return None
    return builder(target.lower(), value, source_chain_id, values)
