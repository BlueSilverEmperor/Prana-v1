"""Small, dependency-light helpers for hex, addresses and integers."""

from __future__ import annotations

import re

from eth_utils import keccak, to_checksum_address

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
ZERO_ADDRESS = "0x" + "00" * 20


def normalize_address(value: str) -> str:
    """Return a lowercase 0x address or raise ValueError."""
    if not isinstance(value, str) or not _ADDRESS_RE.match(value):
        raise ValueError(f"invalid address: {value!r}")
    return value.lower()


def hex_to_bytes(value: str) -> bytes:
    if not value or value in ("0x", "0X"):
        return b""
    text = value[2:] if value[:2] in ("0x", "0X") else value
    if len(text) % 2:
        text = "0" + text
    return bytes.fromhex(text)


def bytes_to_hex(value: bytes) -> str:
    return "0x" + value.hex()


def parse_int(value: str | int) -> int:
    """Parse a decimal or 0x-hex unsigned integer."""
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative integer")
        return value
    text = str(value).strip()
    if text.startswith("-"):
        raise ValueError(f"negative integer: {value!r}")
    return int(text, 16) if text[:2].lower() == "0x" else int(text)


def selector_of(signature: str) -> str:
    return "0x" + keccak(text=signature)[:4].hex()


def topic_of(signature: str) -> str:
    return "0x" + keccak(text=signature).hex()


def word_to_address(word: bytes | str) -> str:
    raw = hex_to_bytes(word) if isinstance(word, str) else word
    return "0x" + raw[-20:].hex()


def checksum(address: str) -> str:
    try:
        return to_checksum_address(address)
    except (ValueError, TypeError):
        return address


def short_address(address: str) -> str:
    cs = checksum(address)
    return f"{cs[:6]}…{cs[-4:]}" if len(cs) == 42 else cs
