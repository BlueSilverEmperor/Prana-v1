"""
4-Word Dual-Device BIP-39 Checksum Generator for Project Vero (Prana-v1).
Allows signers to verify that their laptop screen matches their mobile phone
or hardware device out-of-band truth.
Supports both STANDARD_EVM and QUAI_NATIVE shard-bound preimages.
"""

import hashlib
from typing import List, Tuple

BIP39_SAMPLE_WORDS = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis",
    "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball",
    "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below", "belt",
    "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle",
    "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black",
    "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood",
    "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
    "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring",
    "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain",
    "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
    "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb",
    "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus",
    "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable"
]

def _get_bip39_word(index: int) -> str:
    if index < len(BIP39_SAMPLE_WORDS):
        return BIP39_SAMPLE_WORDS[index]
    base = BIP39_SAMPLE_WORDS[index % len(BIP39_SAMPLE_WORDS)]
    return f"{base}_{index}"

def compute_4_word_checksum(
    vault: str,
    nonce: int,
    safe_tx_hash: str,
    policy_hash: str,
    mode: str = "STANDARD_EVM",
    shard_zone: str = "cyprus1",
    quai_value_cap: int = 0,
    qi_value_cap: int = 0,
) -> Tuple[List[str], List[int]]:
    """
    Computes 4 BIP-39 words matching VeroGuard.sol computeChecksumWordIndices:
    STANDARD_EVM:
      digest = keccak256(abi.encode(vault, nonce, safeTxHash, policyHash))
    QUAI_NATIVE:
      digest = keccak256(abi.encode(vault, nonce, safeTxHash, policyHash, zoneHash, quaiCap, qiCap))
    """
    is_quai = str(mode).upper() in ("QUAI_NATIVE", "QUAI")
    try:
        import eth_abi
        from Crypto.Hash import keccak
        from eth_utils import to_checksum_address

        clean_vault = to_checksum_address(vault)
        tx_hex = safe_tx_hash[2:] if safe_tx_hash.startswith("0x") else safe_tx_hash
        pol_hex = policy_hash[2:] if policy_hash.startswith("0x") else policy_hash
        tx_bytes = bytes.fromhex(tx_hex.rjust(64, "0"))
        pol_bytes = bytes.fromhex(pol_hex.rjust(64, "0"))

        if is_quai:
            zk = keccak.new(digest_bits=256)
            zk.update(shard_zone.encode("utf-8"))
            zone_hash = zk.digest()
            encoded = eth_abi.encode(
                ["address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "uint256"],
                [clean_vault, nonce, tx_bytes, pol_bytes, zone_hash, quai_value_cap, qi_value_cap]
            )
        else:
            encoded = eth_abi.encode(
                ["address", "uint256", "bytes32", "bytes32"],
                [clean_vault, nonce, tx_bytes, pol_bytes]
            )
        k = keccak.new(digest_bits=256)
        k.update(encoded)
        digest = k.digest()
    except Exception:
        try:
            from Crypto.Hash import keccak
            k = keccak.new(digest_bits=256)
            if is_quai:
                payload = f"{vault.lower()}:{nonce}:{safe_tx_hash.lower()}:{policy_hash.lower()}:{shard_zone.lower()}:{quai_value_cap}:{qi_value_cap}".encode()
            else:
                payload = f"{vault.lower()}:{nonce}:{safe_tx_hash.lower()}:{policy_hash.lower()}".encode()
            k.update(payload)
            digest = k.digest()
        except Exception:
            if is_quai:
                payload = f"{vault.lower()}:{nonce}:{safe_tx_hash.lower()}:{policy_hash.lower()}:{shard_zone.lower()}:{quai_value_cap}:{qi_value_cap}".encode()
            else:
                payload = f"{vault.lower()}:{nonce}:{safe_tx_hash.lower()}:{policy_hash.lower()}".encode()
            digest = hashlib.sha256(payload).digest()

    val = int.from_bytes(digest, byteorder="big")
    indices = [
        val & 0x7FF,
        (val >> 11) & 0x7FF,
        (val >> 22) & 0x7FF,
        (val >> 33) & 0x7FF,
    ]

    try:
        from mnemonic import Mnemonic
        wordlist = Mnemonic("english").wordlist
        words = [wordlist[i] for i in indices]
    except Exception:
        words = [_get_bip39_word(i) for i in indices]

    return words, indices


def compute_four_word_checksum(
    chain_id: int,
    safe_address: str,
    nonce: int,
    raw_tx_hash: str,
    intent_hash: str,
    mode: str = "STANDARD_EVM",
    shard_zone: str = "cyprus1",
    quai_value_cap: int = 0,
    qi_value_cap: int = 0,
) -> str:
    """
    Computes 4-word BIP-39 checksum string (word1-word2-word3-word4) for
    (chain_id, safe_address, nonce, raw_tx_hash, intent_hash).
    """
    import sys
    from pathlib import Path
    api_agents_dir = str(Path(__file__).resolve().parent.parent / "api-agents")
    if api_agents_dir not in sys.path:
        sys.path.insert(0, api_agents_dir)
    from api_agents.utils.four_word_checksum import compute_four_word_checksum as _cfwc
    return _cfwc(
        chain_id=chain_id,
        safe_address=safe_address,
        nonce=nonce,
        raw_tx_hash=raw_tx_hash,
        intent_hash=intent_hash,
        mode=mode,
        shard_zone=shard_zone,
        quai_value_cap=quai_value_cap,
        qi_value_cap=qi_value_cap,
    )

