"""
Four-Word BIP-39 Checksum Generator
SPEC: keccak256(chainId || safeAddress || nonce || rawTxHash || intentHash) -> 4 words from the BIP-39 list.

Design Decision:
- BIP-39 gives 11 bits per word.
- 4 words = 44 bits of entropy.
- Designed for human visual comparison across devices (e.g. mobile wallet vs hardware display).
- Constants exposed for word count and separator for easy synchronization with firmware/hardware.
"""

from typing import Union
from api_agents.utils.bip39_wordlist import BIP39_WORDLIST
from api_agents.utils.keccak import keccak256

DEFAULT_WORD_COUNT: int = 4
DEFAULT_WORD_SEPARATOR: str = "-"
BITS_PER_WORD: int = 11


def _normalize_hex(val: Union[str, bytes], expected_len: int = 32) -> bytes:
    if isinstance(val, bytes):
        if len(val) == expected_len:
            return val
        if len(val) < expected_len:
            return val.rjust(expected_len, b"\x00")
        return val[-expected_len:]
    s = val.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    if len(s) % 2 != 0:
        s = "0" + s
    b = bytes.fromhex(s)
    if len(b) < expected_len:
        b = b.rjust(expected_len, b"\x00")
    elif len(b) > expected_len:
        b = b[-expected_len:]
    return b


def pack_checksum_preimage(
    chain_id: Union[int, str, bytes],
    safe_address: Union[str, bytes],
    nonce: Union[int, str, bytes],
    raw_tx_hash: Union[str, bytes],
    intent_hash: Union[str, bytes],
) -> bytes:
    """
    Standard EVM tightly-packed preimage:
    chainId (uint256 -> 32 bytes)
    safeAddress (address -> 20 bytes)
    nonce (uint256 -> 32 bytes)
    rawTxHash (bytes32 -> 32 bytes)
    intentHash (bytes32 -> 32 bytes)
    Total preimage = 148 bytes.
    """
    if isinstance(chain_id, int):
        chain_id_bytes = chain_id.to_bytes(32, "big")
    else:
        chain_id_bytes = _normalize_hex(chain_id, 32)

    safe_addr_bytes = _normalize_hex(safe_address, 20)

    if isinstance(nonce, int):
        nonce_bytes = nonce.to_bytes(32, "big")
    else:
        nonce_bytes = _normalize_hex(nonce, 32)

    raw_tx_bytes = _normalize_hex(raw_tx_hash, 32)
    intent_hash_bytes = _normalize_hex(intent_hash, 32)

    return chain_id_bytes + safe_addr_bytes + nonce_bytes + raw_tx_bytes + intent_hash_bytes


def digest_to_bip39_words(
    digest: bytes,
    word_count: int = DEFAULT_WORD_COUNT,
    separator: str = DEFAULT_WORD_SEPARATOR,
) -> str:
    """
    Slices digest into 11-bit chunks and maps each chunk to the BIP-39 wordlist.
    """
    # Convert digest bytes to a large big-endian integer
    total_bits = len(digest) * 8
    int_val = int.from_bytes(digest, "big")

    words: list[str] = []
    for i in range(word_count):
        # Shift down to extract 11 bits starting from MSB
        shift = total_bits - ((i + 1) * BITS_PER_WORD)
        if shift < 0:
            raise ValueError(f"Digest length {len(digest)} bytes cannot provide {word_count * BITS_PER_WORD} bits")
        word_idx = (int_val >> shift) & 0x7FF  # 11 bits mask: 0x7FF = 2047
        words.append(BIP39_WORDLIST[word_idx])

    return separator.join(words)


def compute_four_word_checksum(
    chain_id: Union[int, str, bytes],
    safe_address: Union[str, bytes],
    nonce: Union[int, str, bytes],
    raw_tx_hash: Union[str, bytes],
    intent_hash: Union[str, bytes],
    word_count: int = DEFAULT_WORD_COUNT,
    separator: str = DEFAULT_WORD_SEPARATOR,
) -> str:
    """
    Calculates keccak256(preimage) and maps to BIP-39 words.
    """
    preimage = pack_checksum_preimage(
        chain_id=chain_id,
        safe_address=safe_address,
        nonce=nonce,
        raw_tx_hash=raw_tx_hash,
        intent_hash=intent_hash,
    )
    digest = keccak256(preimage)
    return digest_to_bip39_words(digest, word_count=word_count, separator=separator)
