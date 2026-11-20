"""ERC-7730 clear-signing descriptors and the length-prefixed calldata digest.

The digest follows the formula in the Vero spec, labelled there as "ERC-8213":
``keccak256(abi.encodePacked(uint256(calldata.length), calldata))``.
Blueprint ADR-12: the ERC number is unconfirmed; present it generically as a
"calldata digest" unless verified against the official EIPs repository.

Descriptor support covers flat signatures (no tuple parameters) and the formats
raw, addressName, tokenAmount, amount and date.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping, Optional

from eth_abi import decode
from eth_abi.exceptions import DecodingError
from eth_utils import keccak

from simulator.constants import UNLIMITED_THRESHOLD
from simulator.hexutil import checksum, selector_of


class DescriptorError(ValueError):
    """Raised when an ERC-7730 descriptor is structurally invalid."""


@dataclass(frozen=True)
class FormatEntry:
    signature: str  # canonical, e.g. transfer(address,uint256)
    types: tuple[str, ...]
    names: tuple[str, ...]
    intent: str
    fields: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class ClearSignDescriptor:
    deployments: frozenset[tuple[int, str]]
    token_ticker: Optional[str]
    token_decimals: Optional[int]
    formats: Mapping[str, FormatEntry]  # selector -> entry


@dataclass(frozen=True)
class ClearSignResult:
    intent: str
    fields: tuple[tuple[str, str], ...]


def calldata_digest(data: bytes) -> str:
    return "0x" + keccak(len(data).to_bytes(32, "big") + data).hex()


def _parse_signature(human: str) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    if "(" not in human or not human.endswith(")"):
        raise DescriptorError(f"bad signature {human!r}")
    name, params = human[: human.index("(")], human[human.index("(") + 1 : -1]
    if "(" in params:
        raise DescriptorError("tuple parameters are not supported")
    types, names = [], []
    for index, part in enumerate(p.strip() for p in params.split(",") if p.strip()):
        pieces = part.split()
        types.append(pieces[0])
        names.append(pieces[-1] if len(pieces) > 1 else f"_{index}")
    return f"{name}({','.join(types)})", tuple(types), tuple(names)


def load_descriptor(source: str | Mapping[str, Any]) -> ClearSignDescriptor:
    raw = json.loads(source) if isinstance(source, str) else source
    display = raw.get("display", {}).get("formats") if isinstance(raw, Mapping) else None
    if not isinstance(display, Mapping) or not display:
        raise DescriptorError("descriptor has no display.formats")
    deployments = raw.get("context", {}).get("contract", {}).get("deployments", [])
    token = raw.get("metadata", {}).get("token", {})
    formats = {}
    for human, spec in display.items():
        signature, types, names = _parse_signature(human)
        formats[selector_of(signature)] = FormatEntry(
            signature, types, names, str(spec.get("intent", "")), tuple(spec.get("fields", []))
        )
    return ClearSignDescriptor(
        deployments=frozenset((int(d["chainId"]), d["address"].lower()) for d in deployments),
        token_ticker=token.get("ticker"),
        token_decimals=token.get("decimals"),
        formats=formats,
    )


def _scaled(amount: int, decimals: int) -> str:
    text = format(Decimal(amount) / (Decimal(10) ** decimals), "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


def _render(value: Any, fmt: str, params: Mapping[str, Any], d: ClearSignDescriptor) -> str:
    if fmt == "addressName" and isinstance(value, str):
        return checksum(value)
    if fmt == "tokenAmount" and isinstance(value, int):
        if value >= UNLIMITED_THRESHOLD:
            return f"UNLIMITED {d.token_ticker or ''}".strip()
        decimals = params.get("decimals", d.token_decimals)
        ticker = params.get("ticker", d.token_ticker) or "units"
        return f"{_scaled(value, decimals)} {ticker}" if decimals is not None else f"{value} {ticker}"
    if fmt == "amount" and isinstance(value, int):
        return f"{_scaled(value, 18)} ETH"
    if fmt == "date" and isinstance(value, int):
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(value, bytes):
        return "0x" + value.hex()
    return str(value)


def format_with_descriptor(
    descriptor: ClearSignDescriptor, to: str, data: bytes, chain_id: int
) -> Optional[ClearSignResult]:
    """Map raw calldata to labelled fields, or None if the descriptor does not apply."""
    if descriptor.deployments and (chain_id, to.lower()) not in descriptor.deployments:
        return None
    entry = descriptor.formats.get("0x" + data[:4].hex())
    if entry is None:
        return None
    try:
        values = decode(list(entry.types), data[4:])
    except (DecodingError, ValueError, OverflowError):
        return None
    by_name = {n: (v.lower() if isinstance(v, str) else v) for n, v in zip(entry.names, values)}
    rendered = tuple(
        (str(f.get("label", f.get("path"))),
         _render(by_name.get(f.get("path")), f.get("format", "raw"), f.get("params", {}), descriptor))
        for f in entry.fields
        if f.get("path") in by_name
    )
    return ClearSignResult(entry.intent, rendered)
