/**
 * Tests for @vero/guard-sdk. Imports the real src/index.ts (Node >= 23.6 strips TypeScript types),
 * with a fake EIP-1193 provider and a stubbed global fetch for the firewall.
 * Run: node tests/test_retail_protections.mjs
 */

import assert from "node:assert/strict";
import {
  VeroGuardProvider,
  VeroSecurityError,
  buildRevokeCalldata,
  capUnlimitedApproval,
  decodePermits,
} from "../src/index.ts";

const SPENDER = "3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad";
const APPROVE_MAX = "0x095ea7b3" + SPENDER.padStart(64, "0") + "f".repeat(64);
const TX = { from: "0x" + "11".repeat(20), to: "0x" + "dd".repeat(20), value: "0x0", chainId: "0x1" };
const verdict = (decision, extra = {}) => ({ decision, risk_score: 0, flags: [], four_word_checksum: "a-b-c-d",
  deterministic_human_warnings: decision === "ALLOW" ? [] : ["[R1] CRITICAL: test"], ...extra });

function fakeProvider() {
  const calls = [];
  return { calls, async request(args) { calls.push(args); return args.method === "eth_chainId" ? "0x1" : "0xhash"; } };
}

function stubFetch(handler) {
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url, body: JSON.parse(init.body), signal: init.signal });
    return handler(init);
  };
  return seen;
}
const respond = (body, status = 200) => async () => ({ ok: status === 200, status, json: async () => body });

async function rejectsWith(promise, flag) {
  await assert.rejects(promise, (err) => err instanceof VeroSecurityError && err.flags.includes(flag));
}

const tests = {
  "caps approve(MAX) and leaves normal approvals alone": () => {
    const capped = capUnlimitedApproval(APPROVE_MAX, 5n);
    assert.equal(capped.modified, true);
    assert.equal(capped.calldata.slice(-64), "5".padStart(64, "0"));
    assert.equal(capped.spender, "0x" + SPENDER);
    const normal = "0x095ea7b3" + SPENDER.padStart(64, "0") + (100n).toString(16).padStart(64, "0");
    assert.equal(capUnlimitedApproval(normal).modified, false);
  },
  "revoke calldata zeroes the allowance and validates the address": () => {
    assert.equal(buildRevokeCalldata("0x" + SPENDER).slice(-64), "0".repeat(64));
    assert.throws(() => buildRevokeCalldata("0xnot-an-address"));
  },
  "decodes every token in a Permit2 batch": () => {
    const permits = decodePermits({ primaryType: "PermitBatch", message: { spender: "0x" + SPENDER, sigDeadline: 1,
      details: [{ token: "0xaa", amount: "1" }, { token: "0xbb", amount: String(2n ** 160n - 1n) }] } });
    assert.deepEqual(permits.map((p) => p.token), ["0xaa", "0xbb"]);
  },
  "firewall unreachable: blocks and does not forward": async () => {
    const provider = fakeProvider();
    stubFetch(async () => { throw new TypeError("fetch failed"); });
    await rejectsWith(new VeroGuardProvider(provider).request({ method: "eth_sendTransaction", params: [TX] }),
      "FIREWALL_UNAVAILABLE");
    assert.equal(provider.calls.filter((c) => c.method === "eth_sendTransaction").length, 0);
  },
  "failOpen is an explicit opt-in": async () => {
    const provider = fakeProvider();
    stubFetch(async () => { throw new TypeError("fetch failed"); });
    await new VeroGuardProvider(provider, { failOpen: true }).request({ method: "eth_sendTransaction", params: [TX] });
    assert.equal(provider.calls.at(-1).method, "eth_sendTransaction");
  },
  "firewall timeout blocks": async () => {
    // A real fetch keeps the event loop alive while waiting; the stub must too (the abort timer is unref'd).
    stubFetch((init) => new Promise((_, reject) => {
      const keepAlive = setTimeout(() => {}, 5000);
      init.signal.addEventListener("abort", () => { clearTimeout(keepAlive); reject(init.signal.reason); });
    }));
    await rejectsWith(new VeroGuardProvider(fakeProvider(), { timeoutMs: 30 })
      .request({ method: "eth_sendTransaction", params: [TX] }), "FIREWALL_UNAVAILABLE");
  },
  "malformed verdict blocks": async () => {
    stubFetch(respond({}));
    await rejectsWith(new VeroGuardProvider(fakeProvider()).request({ method: "eth_sendTransaction", params: [TX] }),
      "INVALID_FIREWALL_RESPONSE");
  },
  "BLOCK verdict throws and is not forwarded": async () => {
    const provider = fakeProvider();
    stubFetch(respond(verdict("BLOCK", { flags: ["MODULE_ENABLED"] })));
    await rejectsWith(new VeroGuardProvider(provider).request({ method: "eth_sendTransaction", params: [TX] }),
      "MODULE_ENABLED");
    assert.equal(provider.calls.filter((c) => c.method === "eth_sendTransaction").length, 0);
  },
  "WARN is rejected unless the user confirms": async () => {
    stubFetch(respond(verdict("WARN")));
    await assert.rejects(new VeroGuardProvider(fakeProvider()).request({ method: "eth_sendTransaction", params: [TX] }));
    const provider = fakeProvider();
    await new VeroGuardProvider(provider, { onWarning: async () => true })
      .request({ method: "eth_sendTransaction", params: [TX] });
    assert.equal(provider.calls.at(-1).method, "eth_sendTransaction");
  },
  "ALLOW forwards, and calldata in `input` is what gets simulated": async () => {
    const provider = fakeProvider();
    const seen = stubFetch(respond(verdict("ALLOW")));
    await new VeroGuardProvider(provider).request({ method: "eth_sendTransaction", params: [{ ...TX, input: "0x12345678" }] });
    assert.equal(seen[0].body.data, "0x12345678");
    assert.equal(provider.calls.at(-1).method, "eth_sendTransaction");
  },
  "capping is reported and can be declined": async () => {
    const seen = stubFetch(respond(verdict("ALLOW")));
    let info = null;
    const provider = fakeProvider();
    await new VeroGuardProvider(provider, { defaultSpendCap: 7n, onCapped: async (i) => { info = i; return true; } })
      .request({ method: "eth_sendTransaction", params: [{ ...TX, data: APPROVE_MAX }] });
    assert.equal(info.cappedAmount, 7n);
    assert.equal(seen[0].body.data.slice(-64), "7".padStart(64, "0"));
    await rejectsWith(new VeroGuardProvider(fakeProvider(), { onCapped: async () => false })
      .request({ method: "eth_sendTransaction", params: [{ ...TX, data: APPROVE_MAX }] }), "APPROVAL_CAP_DECLINED");
  },
  "unverifiable methods are blocked by default": async () => {
    for (const method of ["eth_sendRawTransaction", "eth_sign", "wallet_sendCalls"]) {
      await rejectsWith(new VeroGuardProvider(fakeProvider()).request({ method, params: [] }), "UNVERIFIABLE_METHOD");
    }
  },
  "unlimited permit (decimal amount) is blocked; bounded permit passes": async () => {
    const typed = (value) => JSON.stringify({ primaryType: "Permit", domain: { verifyingContract: "0xaa" },
      message: { owner: "0x11", spender: "0x" + SPENDER, value, nonce: 0, deadline: 1 } });
    await rejectsWith(new VeroGuardProvider(fakeProvider())
      .request({ method: "eth_signTypedData_v4", params: ["0x11", typed(String(2n ** 256n - 1n))] }), "UNLIMITED_GASLESS_PERMIT");
    const provider = fakeProvider();
    await new VeroGuardProvider(provider).request({ method: "eth_signTypedData_v4", params: ["0x11", typed("100")] });
    assert.equal(provider.calls.at(-1).method, "eth_signTypedData_v4");
  },
};

let failed = 0;
for (const [name, fn] of Object.entries(tests)) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`  ✗ ${name}\n    ${err.stack || err}`);
  }
}
console.log(`\n${Object.keys(tests).length - failed}/${Object.keys(tests).length} passed`);
process.exit(failed ? 1 : 0);
