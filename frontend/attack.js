/* Vero attack replay: sends each scenario in data/attacks.json to the live engine, one by one, and shows the defense.
   No verdict is stored here; every result shown is the engine's response to that request. */
(() => {
  "use strict";
  const API = /^(3000|4500|5173)$/.test(location.port) || location.protocol === "file:" ? "http://localhost:8000" : location.origin;
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const STEP_MS = REDUCED ? 0 : 650;      // minimum time each defense step stays visible
  const TYPE_MS = REDUCED ? 0 : 700;      // byte reveal duration
  const GAP_MS = 2600;                    // pause between attacks in an automatic run
  const TAGS = { BLOCK: "BLOCKED", ALLOW: "ALLOWED", WARN: "REVIEW" };
  const DEFENSES = {
    PROXY_UPGRADE_ATTEMPT: "Wallet logic swap stopped before anyone signed",
    UNVERIFIED_DELEGATECALL: "Delegatecall into unknown code stopped",
    OWNER_OR_THRESHOLD_CHANGE: "Owner takeover stopped",
    INFINITE_TOKEN_APPROVAL: "Unlimited token approval stopped",
    PERMIT_SIGNATURE: "Off-chain permit that hands over tokens stopped",
    GUARD_CHANGE: "Attempt to remove the guard stopped",
    MODULE_ENABLED: "Backdoor module stopped",
    OUTFLOW_CAP_EXCEEDED: "Spend above the declared cap stopped",
    UNDECLARED_RECIPIENT: "Payment to an address the signer never declared stopped",
    EIP7702_DELEGATION: "EIP-7702 hand-over of the account's code stopped",
    ADDRESS_POISONING: "Lookalike of a saved contact stopped",
    THREAT_REGISTRY_HIT: "Known drainer address stopped",
  };

  const $ = (s, root = document) => root.querySelector(s);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const short = (h) => (h && h.length > 14 ? `${h.slice(0, 10)}…${h.slice(-4)}` : h || "");

  const stage = $("[data-stage]");
  const s = { tag: $("[data-s-tag]"), title: $("[data-s-title]"), count: $("[data-s-count]"), claim: $("[data-s-claim]"),
    bytes: $("[data-s-bytes]"), meta: $("[data-s-meta]") };
  const v = { box: $("[data-s-verdict]"), badge: $("[data-v-badge]"), risk: $("[data-v-risk]"), meter: $("[data-v-meter]"),
    headline: $("[data-v-headline]"), why: $("[data-v-why]"), foot: $("[data-v-foot]") };
  const runBtn = $("[data-run]"), restartBtn = $("[data-restart]"), queue = $("[data-queue]");
  const steps = { decode: $('[data-step="decode"]'), rules: $('[data-step="rules"]'), verdict: $('[data-step="verdict"]') };

  let attacks = [], items = [], results = new Map(), cursor = 0, running = false, busy = false, runToken = 0;

  /* ------------------------------------------------------------------ data -- */
  async function load() {
    const res = await fetch("data/attacks.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`attacks.json ${res.status}`);
    attacks = await res.json();
    items = attacks.map((a, i) => {
      const li = el("li");
      const btn = el("button");
      btn.type = "button";
      const text = el("span", "q-text");
      text.append(el("span", "q-title", a.title), el("span", "q-tag", a.expected === "ALLOW" ? "Safe control transaction" : a.tag));
      btn.append(el("span", "q-dot"), text, el("span", "q-chip", "queued"));
      btn.addEventListener("click", () => playSingle(i));
      li.append(btn);
      queue.append(li);
      return li;
    });
    $("[data-k-blocked-of]").textContent = `/${attacks.filter((a) => a.expected === "BLOCK").length}`;
    $("[data-k-allowed-of]").textContent = `/${attacks.filter((a) => a.expected === "ALLOW").length}`;
  }

  async function simulate(body) {
    const res = await fetch(`${API}/v1/simulate`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error(`engine answered ${res.status}`);
    return res.json();
  }

  async function health() {
    const pill = $("[data-status]"), text = $("[data-status-text]");
    try {
      const res = await fetch(`${API}/health`);
      const h = await res.json();
      pill.classList.add("is-ok");
      text.textContent = `Engine online · ${h.engine || "vero"}`;
    } catch {
      pill.classList.add("is-down");
      text.textContent = "Engine offline";
    }
  }

  /* ----------------------------------------------------------------- stage -- */
  function setStep(name, state) {
    Object.entries(steps).forEach(([key, node]) => {
      if (state === "reset") { node.className = ""; return; }
      if (key === name) node.className = state;
    });
  }

  async function typeBytes(data) {
    if (data === "0x") { s.bytes.replaceChildren(el("span", "sel", "0x"), el("span", "dim", "  (no calldata: the attack is in the 7702 authorisation)")); return; }
    const sel = data.slice(0, 10), rest = data.slice(10);
    const selNode = el("span", "sel", sel), on = document.createTextNode(""), dim = el("span", "dim", rest);
    s.bytes.replaceChildren(selNode, on, dim);
    if (!TYPE_MS) { on.textContent = rest; dim.textContent = ""; return; }
    const start = performance.now();
    await new Promise((resolve) => {
      const tick = (now) => {
        const n = Math.round(rest.length * Math.min(1, (now - start) / TYPE_MS));
        on.textContent = rest.slice(0, n);
        dim.textContent = rest.slice(n);
        if (n < rest.length) requestAnimationFrame(tick); else resolve();
      };
      requestAnimationFrame(tick);
    });
  }

  function resetVerdict() {
    delete v.box.dataset.decision;
    delete stage.dataset.result;
    v.badge.textContent = "Checking";
    v.risk.textContent = "–";
    v.meter.style.setProperty("--s", "0");
    v.headline.textContent = "Sending the exact bytes to the engine…";
    v.why.replaceChildren();
    v.foot.textContent = "";
  }

  function headlineFor(attack, r) {
    if (r.decision === "ALLOW") return attack.expected === "ALLOW" ? "Matches what the signer declared, so it goes through" : "Let through: this attack was not caught";
    if (attack.expected === "ALLOW") return "Blocked a safe transaction (false positive)";
    const known = (r.flags || []).map((f) => DEFENSES[f]).find(Boolean);
    return known || `Stopped: ${(r.flags || []).join(", ")}`;
  }

  function showVerdict(attack, r) {
    v.box.dataset.decision = r.decision;
    stage.dataset.result = r.decision;
    v.badge.textContent = TAGS[r.decision] || r.decision;
    v.risk.textContent = String(r.risk_score);
    v.meter.style.setProperty("--s", String(Math.max(0.02, r.risk_score / 100)));
    v.headline.textContent = headlineFor(attack, r);
    const warnings = r.deterministic_human_warnings || [];
    v.why.replaceChildren(...(warnings.length ? warnings : ["The real effect matches the declared intent."]).map((t) => el("li", null, t)));
    const words = (r.four_word_checksum || "").split("-").join(" · ");
    const foot = [`engine ${r.simulation_ms} ms`, `tx ${short(r.raw_tx_hash)}`, words && `words ${words}`].filter(Boolean).join("  ·  ");
    v.foot.replaceChildren(document.createTextNode(foot));
    if (attack.foundry && r.decision === "BLOCK") {
      v.foot.append(el("br"), document.createTextNode("Also reverted on-chain in the Foundry replay "), el("b", null, attack.foundry));
    }
    if (!REDUCED) v.badge.animate([{ transform: "scale(0.85)", opacity: 0 }, { transform: "none", opacity: 1 }], { duration: 260, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
  }

  function markQueue(i, r) {
    items.forEach((li, j) => li.classList.toggle("is-current", j === i));
    if (!r) return;
    const li = items[i], attack = attacks[i];
    li.dataset.result = r.decision;
    li.classList.toggle("is-wrong", r.decision !== attack.expected);
    li.querySelector(".q-chip").textContent = TAGS[r.decision] || r.decision;
  }

  function updateTotals() {
    let blocked = 0, allowed = 0, mistakes = 0, latency = 0;
    results.forEach((r, i) => {
      const expected = attacks[i].expected;
      if (expected === "BLOCK" && r.decision === "BLOCK") blocked += 1;
      if (expected === "ALLOW" && r.decision === "ALLOW") allowed += 1;
      if (r.decision !== expected) mistakes += 1;
      latency += Number(r.simulation_ms) || 0;
    });
    $("[data-k-blocked]").textContent = String(blocked);
    $("[data-k-allowed]").textContent = String(allowed);
    $("[data-k-missed]").textContent = String(mistakes);
    $("[data-k-latency]").textContent = results.size ? (latency / results.size).toFixed(2) : "–";
  }

  async function play(i) {
    const attack = attacks[i], req = attack.request;
    busy = true;
    markQueue(i);
    s.tag.textContent = attack.expected === "ALLOW" ? "Control · safe transaction" : attack.tag;
    s.title.textContent = attack.title;
    s.count.textContent = `${i + 1} of ${attacks.length}`;
    s.claim.textContent = attack.claim ? `“${attack.claim}”` : "No warning on screen, just a Confirm button.";
    const extras = [
      req.authorization_list && `7702 delegation to ${short(req.authorization_list[0].address)}`,
      req.contacts && `${req.contacts.length} saved contacts sent as context`,
    ].filter(Boolean);
    s.meta.replaceChildren(document.createTextNode([`to ${short(req.to)}`, req.operation === 1 ? "DELEGATECALL" : "CALL", `value ${req.value} wei`, ...extras].join(" · ")));
    if (attack.source) {
      const link = el("a", null, `real mainnet tx ${short(attack.source.txHash)}, block ${attack.source.block}`);
      link.href = attack.source.etherscan;
      link.rel = "noopener";
      link.target = "_blank";
      s.meta.append(el("br"), link);
    }
    resetVerdict();
    setStep(null, "reset");

    setStep("decode", "is-active");
    await typeBytes(req.data);
    await sleep(STEP_MS / 2);
    setStep("decode", "is-done");

    setStep("rules", "is-active");
    stage.classList.add("is-scanning");
    let result;
    try {
      [result] = await Promise.all([simulate(req), sleep(STEP_MS)]);
    } finally {
      stage.classList.remove("is-scanning");
    }
    setStep("rules", "is-done");
    setStep("verdict", "is-done");
    showVerdict(attack, result);
    results.set(i, result);
    markQueue(i, result);
    updateTotals();
    document.dispatchEvent(new CustomEvent("vero:verdict", { detail: { result, label: attack.title } }));
    busy = false;
  }

  function showFailure(err) {
    busy = false;
    v.badge.textContent = "Engine unreachable";
    v.headline.textContent = `The run stopped: ${err.message}. Start the API (uvicorn api_agents.main:app) and press Start again.`;
    setRunning(false);
  }

  /* ------------------------------------------------------------------- run -- */
  function setRunning(on) {
    running = on;
    runBtn.textContent = on ? "Pause" : cursor >= attacks.length ? "Run again" : cursor ? "Resume" : "Start attack run";
  }

  async function runLoop() {
    const token = ++runToken;
    while (running && token === runToken && cursor < attacks.length) {
      try {
        await play(cursor);
      } catch (err) {
        showFailure(err);
        return;
      }
      cursor += 1;
      if (cursor < attacks.length) await sleep(GAP_MS);
    }
    if (token === runToken) {
      if (cursor >= attacks.length) {
        s.tag.textContent = "Run complete";
        markQueue(-1);
      }
      setRunning(false);
    }
  }

  function restart() {
    runToken += 1;
    cursor = 0;
    results = new Map();
    items.forEach((li) => { delete li.dataset.result; li.classList.remove("is-wrong", "is-current"); li.querySelector(".q-chip").textContent = "queued"; });
    updateTotals();
  }

  runBtn.addEventListener("click", () => {
    if (busy && !running) return;
    if (running) { setRunning(false); runToken += 1; return; }
    if (cursor >= attacks.length) restart();
    setRunning(true);
    runLoop();
  });
  restartBtn.addEventListener("click", () => { setRunning(false); restart(); setRunning(false); });

  async function playSingle(i) {
    if (busy) return;
    setRunning(false);
    runToken += 1;
    try { await play(i); } catch (err) { showFailure(err); }
  }

  health();
  load().then(() => {
    // ?autoplay starts the run immediately (for a projector or a recording)
    if (new URLSearchParams(location.search).has("autoplay")) runBtn.click();
  }).catch((err) => {
    s.title.textContent = "Could not load the attack list";
    v.headline.textContent = err.message;
  });
})();
