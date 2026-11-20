import assert from "node:assert";
import { computeFourWordChecksum } from "../src/index.ts";

console.log("\n========================================================");
console.log("   RUNNING CROSS-LANGUAGE 4-WORD CHECKSUM PARITY TEST   ");
console.log("========================================================");

const vectors = [
  {
    name: "Vector 1 (Standard EVM Mainnet)",
    params: {
      chainId: 1,
      safeAddress: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
      nonce: 0,
      rawTxHash: "0x" + "11".repeat(32),
      intentHash: "0x" + "22".repeat(32),
      mode: "STANDARD_EVM",
      shardZone: "cyprus1",
      quaiValueCap: 0,
      qiValueCap: 0,
    },
    expected: "virtual-crop-kit-juice"
  },
  {
    name: "Vector 2 (Standard EVM Polygon)",
    params: {
      chainId: 137,
      safeAddress: "0x1234567890123456789012345678901234567890",
      nonce: 42,
      rawTxHash: "0x" + "aa".repeat(32),
      intentHash: "0x" + "bb".repeat(32),
      mode: "STANDARD_EVM",
      shardZone: "cyprus1",
      quaiValueCap: 0,
      qiValueCap: 0,
    },
    expected: "sponsor-sister-timber-clap"
  },
  {
    name: "Vector 3 (Standard EVM Arbitrum)",
    params: {
      chainId: 42161,
      safeAddress: "0x0000000000000000000000000000000000000001",
      nonce: 1000,
      rawTxHash: "0x" + "de".repeat(32),
      intentHash: "0x" + "ad".repeat(32),
      mode: "STANDARD_EVM",
      shardZone: "cyprus1",
      quaiValueCap: 0,
      qiValueCap: 0,
    },
    expected: "device-mixture-turtle-betray"
  },
  {
    name: "Vector 4 (Quai Native Cyprus-1)",
    params: {
      chainId: 15000,
      safeAddress: "0x00112233445566778899aabbccddeeff00112233",
      nonce: 7,
      rawTxHash: "0x" + "33".repeat(32),
      intentHash: "0x" + "44".repeat(32),
      mode: "QUAI_NATIVE",
      shardZone: "cyprus1",
      quaiValueCap: 5000000000000000000n,
      qiValueCap: 1000000000000000000n,
    },
    expected: "slot-clinic-salmon-grab"
  },
  {
    name: "Vector 5 (Quai Native Cyprus-2)",
    params: {
      chainId: 9,
      safeAddress: "0x01112233445566778899aabbccddeeff00112233",
      nonce: 15,
      rawTxHash: "0x" + "55".repeat(32),
      intentHash: "0x" + "66".repeat(32),
      mode: "QUAI_NATIVE",
      shardZone: "cyprus2",
      quaiValueCap: 0,
      qiValueCap: 500000000000000000n,
    },
    expected: "addict-bind-cloud-forum"
  }
];

let passCount = 0;
for (const [i, v] of vectors.entries()) {
  const result = computeFourWordChecksum(v.params);
  assert.strictEqual(
    result,
    v.expected,
    `Mismatch on ${v.name}: expected '${v.expected}', got '${result}'`
  );
  console.log(`[VECTOR ${i + 1}] ${v.name}:`);
  console.log(`  ✓ Output: ${result} (100% byte-for-byte parity)`);
  passCount++;
}

console.log(`\n🎉 ALL ${passCount}/${vectors.length} CHECKSUM PARITY VECTORS PASSED IDENTICALLY!\n`);
