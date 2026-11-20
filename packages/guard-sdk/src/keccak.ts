/**
 * Pure TypeScript Keccak-256 (Ethereum EVM Standard).
 * Rate = 1088 bits = 136 bytes, Capacity = 512 bits.
 * Padding = 0x01 ... 0x80.
 * Conforms 100% to EVM keccak256 opcode and Python Crypto.Hash.keccak.
 */

const RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

const ROT: number[][] = [
  [0, 36, 3, 41, 18],
  [1, 44, 10, 45, 2],
  [62, 6, 43, 15, 61],
  [28, 55, 25, 21, 56],
  [27, 20, 39, 8, 14],
];

const MASK64 = 0xffffffffffffffffn;

function rotl64(x: bigint, n: number): bigint {
  const shift = BigInt(n % 64);
  return ((x << shift) & MASK64) | ((x >> (64n - shift)) & MASK64);
}

function keccakF(state: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    // Theta
    const c: bigint[] = new Array(5);
    for (let x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    const d: bigint[] = new Array(5);
    for (let x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
    }
    for (let i = 0; i < 25; i++) {
      state[i] = (state[i] ^ d[i % 5]) & MASK64;
    }

    // Rho & Pi
    const b: bigint[] = new Array(25);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], ROT[x][y]);
      }
    }

    // Chi
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = (b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & b[((x + 2) % 5) + 5 * y])) & MASK64;
      }
    }

    // Iota
    state[0] = (state[0] ^ RC[round]) & MASK64;
  }
}

export function keccak256(data: Uint8Array): Uint8Array {
  const rate = 136;
  const state: bigint[] = new Array(25).fill(0n);

  let offset = 0;
  while (data.length - offset >= rate) {
    for (let i = 0; i < rate / 8; i++) {
      const idx = offset + i * 8;
      let lane = 0n;
      for (let b = 0; b < 8; b++) {
        lane |= BigInt(data[idx + b]) << BigInt(b * 8);
      }
      state[i] = (state[i] ^ lane) & MASK64;
    }
    keccakF(state);
    offset += rate;
  }

  // Padding: 0x01 ... 0x80
  const remainder = data.subarray(offset);
  const padded = new Uint8Array(Math.ceil((remainder.length + 1) / rate) * rate);
  padded.set(remainder, 0);
  padded[remainder.length] = 0x01;
  padded[padded.length - 1] |= 0x80;

  for (let chunk = 0; chunk < padded.length; chunk += rate) {
    for (let i = 0; i < rate / 8; i++) {
      const idx = chunk + i * 8;
      let lane = 0n;
      for (let b = 0; b < 8; b++) {
        lane |= BigInt(padded[idx + b]) << BigInt(b * 8);
      }
      state[i] = (state[i] ^ lane) & MASK64;
    }
    keccakF(state);
  }

  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lane = state[i];
    for (let b = 0; b < 8; b++) {
      out[i * 8 + b] = Number((lane >> BigInt(b * 8)) & 0xffn);
    }
  }
  return out;
}
