"""Selector-based decoder for the calls the risk engine reasons about."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from eth_abi import decode
from eth_abi.exceptions import DecodingError

from simulator.hexutil import selector_of

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FunctionSpec:
    name: str  # logical name used by the rules (unique per spec)
    types: tuple[str, ...]
    arg_names: tuple[str, ...]
    abi_name: str | None = None  # on-chain function name when it differs (overloads)

    @property
    def signature(self) -> str:
        return f"{self.abi_name or self.name}({','.join(self.types)})"


_SPECS = (
    FunctionSpec("transfer", ("address", "uint256"), ("to", "amount")),
    FunctionSpec("transferFrom", ("address", "address", "uint256"), ("from", "to", "amount")),
    FunctionSpec("approve", ("address", "uint256"), ("spender", "amount")),
    FunctionSpec("increaseAllowance", ("address", "uint256"), ("spender", "amount")),
    FunctionSpec("setApprovalForAll", ("address", "bool"), ("operator", "approved")),
    FunctionSpec("safeTransferFrom", ("address", "address", "uint256"), ("from", "to", "tokenId")),
    FunctionSpec("addOwnerWithThreshold", ("address", "uint256"), ("owner", "threshold")),
    FunctionSpec("removeOwner", ("address", "address", "uint256"), ("prevOwner", "owner", "threshold")),
    FunctionSpec("swapOwner", ("address", "address", "address"), ("prevOwner", "oldOwner", "newOwner")),
    FunctionSpec("changeThreshold", ("uint256",), ("threshold",)),
    FunctionSpec("setGuard", ("address",), ("guard",)),
    FunctionSpec("enableModule", ("address",), ("module",)),
    FunctionSpec("disableModule", ("address", "address"), ("prevModule", "module")),
    FunctionSpec("upgradeTo", ("address",), ("implementation",)),
    FunctionSpec("upgradeToAndCall", ("address", "bytes"), ("implementation", "data")),
    FunctionSpec("changeMasterCopy", ("address",), ("implementation",)),
    FunctionSpec("multiSend", ("bytes",), ("transactions",)),
    FunctionSpec("transferOwnership", ("address",), ("newOwner",)),
    FunctionSpec("changeAdmin", ("address",), ("newAdmin",)),
    FunctionSpec("setFallbackHandler", ("address",), ("handler",)),
    FunctionSpec("safeTransferFromData", ("address", "address", "uint256", "bytes"),
                 ("from", "to", "tokenId", "data"), abi_name="safeTransferFrom"),
    FunctionSpec("safeTransferFrom1155", ("address", "address", "uint256", "uint256", "bytes"),
                 ("from", "to", "tokenId", "amount", "data"), abi_name="safeTransferFrom"),
    FunctionSpec("safeBatchTransferFrom", ("address", "address", "uint256[]", "uint256[]", "bytes"),
                 ("from", "to", "tokenIds", "amounts", "data")),
)

KNOWN_FUNCTIONS: Mapping[str, FunctionSpec] = MappingProxyType(
    {selector_of(spec.signature): spec for spec in _SPECS}
)
SELECTOR_BY_NAME: Mapping[str, str] = MappingProxyType(
    {spec.name: sel for sel, spec in KNOWN_FUNCTIONS.items()}
)


@dataclass(frozen=True)
class DecodedCall:
    target: str
    value: int
    operation: int
    data: bytes
    selector: str
    name: str | None
    args: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    depth: int = 0
    path: tuple[int, ...] = ()
    malformed: bool = False


def _normalize_arg(value: Any) -> Any:
    if isinstance(value, str) and value.startswith("0x") and len(value) == 42:
        return value.lower()
    return value


def decode_call(
    target: str,
    value: int,
    data: bytes,
    operation: int = 0,
    depth: int = 0,
    path: tuple[int, ...] = (),
) -> DecodedCall:
    """Decode one call. Unknown or truncated calldata never raises."""
    selector = "0x" + data[:4].hex() if len(data) >= 4 else "0x" + data.hex()
    base = dict(target=target, value=value, operation=operation, data=data, selector=selector,
                depth=depth, path=path)
    spec = KNOWN_FUNCTIONS.get(selector)
    if spec is None:
        return DecodedCall(name=None, **base)
    try:
        values = decode(list(spec.types), data[4:])
    except (DecodingError, ValueError, OverflowError) as exc:
        logger.debug("malformed %s calldata to %s: %s", spec.name, target, exc)
        return DecodedCall(name=None, malformed=True, **base)
    args = MappingProxyType({n: _normalize_arg(v) for n, v in zip(spec.arg_names, values)})
    return DecodedCall(name=spec.name, args=args, **base)
