"""
Keccak-256 (Ethereum) implementation in pure Python.
Conforms to original Keccak-256 specification used by EVM / Ethereum (padding 0x01).
Standard Keccak-f[1600] permutation.
"""

# Round constants
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(x: int, n: int) -> int:
    return ((x << (n % 64)) & 0xFFFFFFFFFFFFFFFF) | (x >> ((64 - (n % 64)) % 64))


def _keccak_f(state: list[int]) -> None:
    for round_idx in range(24):
        # Theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for i in range(25):
            state[i] ^= d[i % 5]

        # Rho & Pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(state[x + 5 * y], ROT[x][y])

        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])

        # Iota
        state[0] ^= RC[round_idx]


def keccak256(data: bytes) -> bytes:
    """
    Computes Keccak-256 hash of data bytes (Ethereum EVM Keccak).
    Rate = 1088 bits = 136 bytes, Capacity = 512 bits.
    Padding = 0x01 ... 0x80 (Keccak-256 standard).
    """
    rate = 136
    state = [0] * 25

    # Absorb full blocks
    block_offset = 0
    while len(data) - block_offset >= rate:
        block = data[block_offset : block_offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f(state)
        block_offset += rate

    # Suffix & padding for Keccak-256 (0x01 ... 0x80)
    remainder = data[block_offset:]
    padded = bytearray(remainder)
    padded.append(0x01)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for chunk_start in range(0, len(padded), rate):
        block = padded[chunk_start : chunk_start + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8 : (i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f(state)

    # Squeeze 32 bytes (256 bits)
    out = bytearray()
    for i in range(4):  # 4 * 8 bytes = 32 bytes
        out.extend(state[i].to_bytes(8, "little"))
    return bytes(out)
