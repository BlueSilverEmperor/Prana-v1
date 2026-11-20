/**
 * Test Suite for @vero/guard-sdk Quai Network & Pelagus Provider Integration.
 */

import assert from 'assert';
import {
  VeroGuardProvider,
  getQuaiShardZone,
  detectQuaiProvider,
  isPelagusAvailable,
  capUnlimitedApproval,
} from '../src/index.ts';

console.log("\n========================================================");
console.log("   RUNNING @vero/guard-sdk QUAI PROVIDER TEST SUITE     ");
console.log("========================================================\n");

// Test 1: Shard zone prefix detection
console.log("[TEST 1] Shard Zone Prefix Identification");
assert.strictEqual(getQuaiShardZone("0x0017a140Aa3E981100a9becA4E685f962f0cF6C9"), "cyprus1");
assert.strictEqual(getQuaiShardZone("0x0117a140Aa3E981100a9becA4E685f962f0cF6C9"), "cyprus2");
assert.strictEqual(getQuaiShardZone("0x1017a140Aa3E981100a9becA4E685f962f0cF6C9"), "pitt1");
assert.strictEqual(getQuaiShardZone("0x2017a140Aa3E981100a9becA4E685f962f0cF6C9"), "paxos1");
console.log("  ✓ Correctly resolved Cyprus-1, Cyprus-2, Pitt-1, and Paxos-1 prefixes.\n");

// Test 2: Pelagus provider detection mock
console.log("[TEST 2] Pelagus Provider Auto-Detection");
global.window = {
  pelagus: {
    request: async (args) => ({ method: args.method, success: true }),
  },
};
assert.strictEqual(isPelagusAvailable(), true);
const detected = detectQuaiProvider();
assert.ok(detected !== null);
console.log("  ✓ Successfully detected window.pelagus instance.\n");

// Test 3: quai_sendTransaction Intercept & Auto-Capping
console.log("[TEST 3] quai_sendTransaction Interception & Header Dispatch");
let dispatchedHeaders = null;
let broadcastPayload = null;

const mockServerProvider = {
  request: async (args) => {
    broadcastPayload = args;
    return "0xquaitxhash123456789";
  },
};

// Mock global fetch to spy on headers
global.fetch = async (url, opts) => {
  dispatchedHeaders = opts.headers;
  return {
    ok: true,
    json: async () => ({
      decision: "ALLOW",
      risk_score: 5,
      flags: [],
      four_word_checksum: "apple-border-casual-depth",
      deterministic_human_warnings: [],
    }),
  };
};

const guard = new VeroGuardProvider(mockServerProvider, {
  firewallUrl: "http://127.0.0.1:8000",
  engineMode: "quai",
});

const spender = "0000000000000000000000008888888888888888888888888888888888888888";
const maxUint = "f".repeat(64);
const unlimitedData = "0x095ea7b3" + spender + maxUint;

const quaiTx = {
  from: "0x0017a140Aa3E981100a9becA4E685f962f0cF6C9",
  to: "0x0027a140Aa3E981100a9becA4E685f962f0cF6C9",
  value: "0",
  data: unlimitedData,
  chainId: 15000,
};

const txRes = await guard.request({
  method: "quai_sendTransaction",
  params: [quaiTx],
});

assert.strictEqual(txRes, "0xquaitxhash123456789");
assert.strictEqual(dispatchedHeaders["X-Vero-Engine"], "quai");
assert.ok(broadcastPayload.params[0].data !== unlimitedData, "Data should be auto-capped!");
console.log("  ✓ Intercepted quai_sendTransaction, injected X-Vero-Engine: quai, and auto-capped data.\n");

console.log("🎉 ALL @vero/guard-sdk QUAI TESTS PASSED!\n");
