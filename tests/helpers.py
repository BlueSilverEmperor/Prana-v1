"""Shared test helpers: ABI encoding and well-known addresses."""

from eth_abi import encode
from eth_utils import keccak

SAFE = "0x" + "5a" * 20
ALICE = "0x" + "a1" * 20
BOB = "0x" + "b0" * 20
EVIL = "0x" + "e0" * 20
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
MAX_UINT = 2**256 - 1


def calldata(signature: str, types: list[str], args: list) -> str:
    """Return 0x-prefixed calldata for a function signature and ABI args."""
    selector = keccak(text=signature)[:4]
    return "0x" + (selector + encode(types, args)).hex()


def pack_multisend(txs: list[tuple[int, str, int, bytes]]) -> bytes:
    """Pack (operation, to, value, data) tuples in Safe MultiSend format."""
    out = b""
    for operation, to, value, data in txs:
        out += bytes([operation])
        out += bytes.fromhex(to[2:])
        out += value.to_bytes(32, "big")
        out += len(data).to_bytes(32, "big")
        out += data
    return out


def multisend_calldata(txs: list[tuple[int, str, int, bytes]]) -> str:
    return calldata("multiSend(bytes)", ["bytes"], [pack_multisend(txs)])


def hexbytes(data_hex: str) -> bytes:
    return bytes.fromhex(data_hex[2:])
