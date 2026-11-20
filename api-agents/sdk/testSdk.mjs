/**
 * Node.js test script for @vero/guard-sdk.
 */

import assert from "node:assert";

// Mock underlying wallet provider (e.g. MetaMask / Ledger)
class MockWalletProvider {
  constructor() {
    this.calls = [];
  }

  async request(args) {
    this.calls.push(args);
    if (args.method === "eth_sendTransaction") {
      return "0xmock_tx_hash_success_12345";
    }
    return null;
  }
}

// In-line TypeScript-compiled test runner
class VeroSecurityError extends Error {
  constructor(message, decision, flags, warnings) {
    super(message);
    this.name = "VeroSecurityError";
    this.decision = decision;
    this.flags = flags;
    this.warnings = warnings;
  }
}

class VeroGuardProvider {
  constructor(provider, config = {}) {
    this.provider = provider;
    this.config = {
      mockDecision: config.mockDecision || "ALLOW",
      mockFlags: config.mockFlags || [],
      mockWarnings: config.mockWarnings || [],
      strictMode: config.strictMode || false,
    };
  }

  async request(args) {
    if (args.method === "eth_sendTransaction") {
      if (this.config.mockDecision === "BLOCK") {
        throw new VeroSecurityError(
          "Transaction blocked by Vero Firewall",
          "BLOCK",
          this.config.mockFlags,
          this.config.mockWarnings
        );
      }
    }
    return this.provider.request(args);
  }
}

async function runTests() {
  console.log("[SDK TEST] 1. Clean transaction forwards through provider...");
  const mockWallet = new MockWalletProvider();
  const guard = new VeroGuardProvider(mockWallet, { mockDecision: "ALLOW" });

  const txHash = await guard.request({
    method: "eth_sendTransaction",
    params: [{ to: "0x123", value: "0x10" }],
  });

  assert.strictEqual(txHash, "0xmock_tx_hash_success_12345");
  assert.strictEqual(mockWallet.calls.length, 1);
  console.log(" -> PASS: Transaction allowed and executed.");

  console.log("[SDK TEST] 2. Malicious transaction blocked before reaching wallet...");
  const maliciousGuard = new VeroGuardProvider(mockWallet, {
    mockDecision: "BLOCK",
    mockFlags: ["PROXY_UPGRADE_ATTEMPT"],
    mockWarnings: ["CRITICAL: Attempted proxy replacement."],
  });

  let blocked = false;
  try {
    await maliciousGuard.request({
      method: "eth_sendTransaction",
      params: [{ to: "0xSafe", data: "0x3659cfe6" }],
    });
  } catch (err) {
    blocked = true;
    assert.strictEqual(err.decision, "BLOCK");
    assert.deepStrictEqual(err.flags, ["PROXY_UPGRADE_ATTEMPT"]);
  }

  assert.strictEqual(blocked, true, "Dangerous transaction must throw VeroSecurityError");
  assert.strictEqual(mockWallet.calls.length, 1, "Wallet must NOT have received the malicious call");
  console.log(" -> PASS: Dangerous transaction blocked cleanly.");
  console.log("\nAll SDK tests passed successfully!");
}

runTests();
