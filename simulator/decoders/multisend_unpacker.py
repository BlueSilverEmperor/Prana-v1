"""Safe MultiSend decoder.

Packed format per sub-transaction (no ABI padding):
    operation (1 byte) | to (20) | value (32) | dataLength (32) | data (dataLength)
"""

from __future__ import annotations

from typing import Iterable

from eth_abi import decode
from eth_abi.exceptions import DecodingError

from shared.api_schemas import TransactionTuple
from simulator.constants import MAX_MULTISEND_DEPTH
from simulator.decoders.calldata import SELECTOR_BY_NAME, DecodedCall, decode_call
from simulator.hexutil import hex_to_bytes, parse_int

_HEADER = 1 + 20 + 32 + 32
MULTISEND_SELECTOR = SELECTOR_BY_NAME["multiSend"]


class MultiSendDecodeError(ValueError):
    """Raised when a MultiSend payload is malformed or nested too deeply."""


def unpack_multisend(packed: bytes) -> tuple[TransactionTuple, ...]:
    """Split the packed ``transactions`` bytes into transaction tuples."""
    txs: list[TransactionTuple] = []
    offset = 0
    while offset < len(packed):
        if offset + _HEADER > len(packed):
            raise MultiSendDecodeError(f"truncated header at byte {offset}")
        operation = packed[offset]
        if operation not in (0, 1):
            raise MultiSendDecodeError(f"invalid operation {operation} at byte {offset}")
        to = "0x" + packed[offset + 1 : offset + 21].hex()
        value = int.from_bytes(packed[offset + 21 : offset + 53], "big")
        length = int.from_bytes(packed[offset + 53 : offset + 85], "big")
        start = offset + _HEADER
        if start + length > len(packed):
            raise MultiSendDecodeError(f"data length {length} overruns payload at byte {offset}")
        data = packed[start : start + length]
        txs.append(TransactionTuple(to=to, value=str(value), data="0x" + data.hex(), operation=operation))
        offset = start + length
    return tuple(txs)


def _multisend_body(call: DecodedCall) -> bytes:
    if call.selector != MULTISEND_SELECTOR:
        raise MultiSendDecodeError("not a multiSend call")
    if call.name != "multiSend":
        raise MultiSendDecodeError(f"multiSend body to {call.target} is not ABI bytes")
    return call.args["transactions"]


def _expand(call: DecodedCall, max_depth: int) -> list[DecodedCall]:
    out = [call]
    if call.selector != MULTISEND_SELECTOR:
        return out
    if call.depth >= max_depth:
        raise MultiSendDecodeError(f"MultiSend nesting exceeds depth {max_depth}")
    try:
        children = unpack_multisend(_multisend_body(call))
    except DecodingError as exc:
        raise MultiSendDecodeError(str(exc)) from exc
    for index, child in enumerate(children):
        decoded = decode_call(
            child.to,
            parse_int(child.value),
            hex_to_bytes(child.data),
            child.operation,
            depth=call.depth + 1,
            path=(*call.path, index),
        )
        out.extend(_expand(decoded, max_depth))
    return out


def flatten_transactions(
    txs: Iterable[TransactionTuple], max_depth: int = MAX_MULTISEND_DEPTH
) -> tuple[DecodedCall, ...]:
    """Decode every top-level tx and, recursively, every MultiSend sub-call.

    Parent MultiSend calls stay in the output so delegatecall rules still see them.
    """
    calls: list[DecodedCall] = []
    for index, tx in enumerate(txs):
        root = decode_call(
            tx.to, parse_int(tx.value), hex_to_bytes(tx.data), tx.operation, depth=0, path=(index,)
        )
        calls.extend(_expand(root, max_depth))
    return tuple(calls)


def decode_multisend_bytes(data: bytes) -> bytes:
    """Return the packed body of ``multiSend(bytes)`` calldata."""
    if "0x" + data[:4].hex() != MULTISEND_SELECTOR:
        raise MultiSendDecodeError("calldata is not multiSend(bytes)")
    try:
        (body,) = decode(["bytes"], data[4:])
    except DecodingError as exc:
        raise MultiSendDecodeError(str(exc)) from exc
    return body
