/* Vero innovations: live proofs. Every number comes from the engine on this page load. */
(() => {
  "use strict";
  const API = /^(3000|4500|5173)$/.test(location.port) || location.protocol === "file:" ? "http://localhost:8000" : location.origin;
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const STEP_DELAY_MS = 1400;
  const $ = (s, root = document) => root.querySelector(s);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const short = (a) => `${a.slice(0, 8)}…${a.slice(-4)}`;

  async function call(path, init) {
    const res = await fetch(`${API}${path}`, init);
    if (!res.ok) throw new Error(`engine answered ${res.status}`);
    return res.json();
  }

  /* ---------------------------------------------------------- 1. adaptive attacker -- */
  const p1Run = $("[data-p1-run]");
  async function shortBattle() {
    p1Run.disabled = true;
    p1Run.textContent = "Attacking…";
    try {
      const r = await call("/v1/redteam/mcmc", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ steps: 150, chains: 4, seed: Math.floor(Math.random() * 1e6), mode: "both" }) });
      const harmless = r.unique_variants - r.harmful_unique;
      $('[data-p1="harmful"]').textContent = r.harmful_unique.toLocaleString();
      $('[data-p1="escapes"]').textContent = String(r.escapes.length);
      $('[data-p1="passed"]').textContent = `${harmless - r.false_positives.length} / ${harmless}`;
    } catch (err) {
      $('[data-p1="harmful"]').textContent = "offline";
    }
    p1Run.disabled = false;
    p1Run.textContent = "Run it again";
  }
  p1Run.addEventListener("click", shortBattle);

  /* ---------------------------------------------------------- 2. hidden batches -- */
  // An adaptive attacker hides theft inside real Safe MultiSend batches. Nothing is preset: every run draws its
  // vendor, strangers, cap and amounts from live Polygon Amoy accounts, and each strategy gets sneakier after a block.
  const AMOY_CHAIN_ID = 80002;
  const OFFLINE_CHAIN_ID = 1;   // without the Amoy fork, batches are judged from calldata alone
  const AMOY_EXPLORER = "https://amoy.polygonscan.com";
  const MULTISEND = "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526";   // canonical Safe MultiSend 1.3.0
  const MAX_CALLS = 8;
  const FEED_STAGGER_MS = 90;
  const STRATEGY_NAME = { salami: "Salami slicing", decoy: "Skim behind a real payment", lookalike: "Lookalike recipient",
    dust: "Dust trail", honest: "Honest payment (control)" };
  const VERDICT_WORD = { BLOCK: "BLOCKED", WARN: "WARNING", ALLOW: "ALLOWED" };
  const batch = {
    chain: $("[data-b-chain]"), chainText: $("[data-b-chain-text]"), vendor: $("[data-b-vendor]"), cap: $("[data-b-cap]"),
    editor: $("[data-b-editor]"), calls: $("[data-b-calls]"), add: $("[data-b-add]"), run: $("[data-b-run]"),
    totals: $("[data-b-totals]"), verdict: $("[data-b-verdict]"),
    hRun: $("[data-h-run]"), hSummary: $("[data-h-summary]"), hFeed: $("[data-h-feed]"),
  };
  let scene = null;          // the last attacker run: live?, vault, vendor, strangers
  let recipients = {};       // address -> label, for the editor

  const WEI = 10n ** 18n;
  const toWei = (pol) => {
    const [whole, frac = ""] = String(pol).trim().split(".");
    if (!/^\d+$/.test(whole || "0") || !/^\d*$/.test(frac)) throw new Error(`"${pol}" is not a POL amount`);
    return BigInt(whole || "0") * WEI + BigInt((frac + "0".repeat(18)).slice(0, 18) || "0");
  };
  const exact = (wei) => {   // exact decimal string, for inputs
    const frac = (wei % WEI).toString().padStart(18, "0").replace(/0+$/, "");
    return `${wei / WEI}${frac ? "." + frac : ""}`;
  };
  const fromWei = (wei) => (Number(wei) / 1e18).toLocaleString(undefined, { maximumFractionDigits: 6 });
  const pol = (wei) => `${fromWei(BigInt(wei))} POL`;
  const word = (n) => n.toString(16).padStart(64, "0");
  // the engine reports wei and names the native coin ETH; on Amoy the native coin is POL
  const readablePol = (text) => text
    .replace(/Outflow of ETH is/g, "Total outflow is")
    .replace(/\b(\d{15,})\b( of ETH)?/g, (_m, wei) => pol(wei))
    .replace(/\bETH\b/g, "POL");

  function addressLink(address) {
    const link = el("a", null, short(address));
    Object.assign(link, { href: `${AMOY_EXPLORER}/address/${address}`, target: "_blank", rel: "noopener" });
    return link;
  }

  /** Live Amoy state: the fork (moved to the newest block when stale) and a real funded account from it. */
  async function connectAmoy() {
    try {
      const s = await call("/v1/chain/amoy");
      if (!s.available) throw new Error(s.reason || "Amoy fork unavailable");
      batch.chain.dataset.live = "true";
      batch.chainText.replaceChildren(
        document.createTextNode(`Live on Polygon Amoy · forked at block ${s.block.toLocaleString()} · vault `),
        addressLink(s.vault.address), document.createTextNode(` holds ${pol(s.vault.balance_wei)}`));
    } catch (err) {
      batch.chain.dataset.live = "false";
      batch.chainText.textContent = `Amoy fork offline (${err.message}). Batches are judged from calldata only.`;
    }
  }

  function rowFor(address, wei) {
    const li = el("li", "batch__call");
    const select = el("select");
    select.setAttribute("aria-label", "Recipient");
    Object.entries(recipients).forEach(([addr, label]) => {
      const opt = el("option", null, `${label} ${short(addr)}`);
      opt.value = addr;
      opt.selected = addr === address;
      select.append(opt);
    });
    const input = el("input");
    Object.assign(input, { type: "number", min: "0", step: "any", value: exact(BigInt(wei)) });
    input.setAttribute("aria-label", "Amount in POL");
    const remove = el("button", "batch__remove", "Remove");
    remove.type = "button";
    remove.addEventListener("click", () => { li.remove(); updateTotals(); });
    [select, input].forEach((n) => n.addEventListener("input", updateTotals));
    li.append(el("span", "batch__op", "send POL to"), select, input, el("span", "batch__unit", "POL"), remove);
    return li;
  }

  function readCalls() {
    return [...batch.calls.children].map((li) => ({
      to: li.querySelector("select").value, wei: toWei(li.querySelector("input").value || "0") }));
  }

  function updateTotals() {
    try {
      const calls = readCalls();
      const toVendor = calls.filter((c) => c.to === scene.vendor).reduce((a, c) => a + c.wei, 0n);
      const toOthers = calls.reduce((a, c) => a + c.wei, 0n) - toVendor;
      batch.totals.textContent = `${calls.length} transfers · ${pol(toVendor)} to Vendor · ${pol(toOthers)} to others · cap ${batch.cap.value} POL`;
    } catch (err) {
      batch.totals.textContent = err.message;
    }
    batch.add.disabled = batch.calls.children.length >= MAX_CALLS;
  }

  function loadAttempt(a) {
    a.calls.forEach((c) => { recipients[c.to] = recipients[c.to] || c.label; });
    batch.calls.replaceChildren(...a.calls.map((c) => rowFor(c.to, c.wei)));
    batch.verdict.textContent = `Loaded "${STRATEGY_NAME[a.strategy]}", try ${a.attempt + 1}. Change anything, then check it live.`;
    batch.verdict.removeAttribute("data-decision");
    batch.editor.open = true;
    updateTotals();
    batch.editor.scrollIntoView({ behavior: REDUCED ? "auto" : "smooth", block: "nearest" });
  }

  function renderAttempt(a) {
    const li = el("li", "hunt__item");
    li.dataset.decision = a.escaped ? "ESCAPED" : a.decision;
    const head = el("p", "hunt__head");
    head.append(el("b", null, STRATEGY_NAME[a.strategy] || a.strategy),
      el("span", "hunt__try", a.strategy === "honest" ? "" : `try ${a.attempt + 1}`),
      el("span", "hunt__verdict", a.escaped ? "ESCAPED" : VERDICT_WORD[a.decision] || a.decision));
    const harm = BigInt(a.harm_wei);
    const what = `${a.note[0].toUpperCase()}${a.note.slice(1)}. ${a.calls.length} transfers, ${pol(a.total_wei)}${harm ? `, hides ${pol(harm)}` : ""}.`;
    const learned = a.learned_from.length ? ` Adapted after ${a.learned_from.join(", ")}.` : "";
    const meta = el("p", "hunt__meta", `Rules: ${a.rules.join(", ") || "none"}.${learned}`);
    const edit = el("button", "hunt__edit", "Edit");
    edit.type = "button";
    edit.addEventListener("click", () => loadAttempt(a));
    li.append(head, el("p", "hunt__what", what), meta, edit);
    return li;
  }

  async function runAttacker() {
    batch.hRun.disabled = true;
    batch.hRun.textContent = "Attacking…";
    batch.hSummary.textContent = "Drawing a vendor, a cap and amounts from live Amoy accounts…";
    batch.hFeed.replaceChildren();
    try {
      const r = await call("/v1/innovations/hidden-attacks", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      scene = { live: r.live, vault: r.vault, vendor: r.vendor };
      recipients = { [r.vendor]: "Vendor", ...Object.fromEntries(r.strangers.map((a, i) => [a, `Stranger ${i + 1}`])) };
      batch.vendor.replaceChildren(addressLink(r.vendor));
      batch.cap.value = exact(BigInt(r.cap_wei));
      batch.editor.hidden = false;
      for (const a of r.attempts) {
        batch.hFeed.append(renderAttempt(a));
        if (!REDUCED) await sleep(FEED_STAGGER_MS);
      }
      const s = r.summary;
      batch.hSummary.textContent = `${s.attacks} hidden attacks · ${s.blocked} blocked · ${s.escaped} escaped · `
        + `${s.controls - s.false_positives} of ${s.controls} honest batches allowed · ${pol(s.harm_stopped_wei)} kept in the vault · `
        + `${r.live ? `Amoy block ${r.block.toLocaleString()}` : "calldata only"} · seed ${r.seed}`;
      const first = r.attempts.find((a) => a.strategy === "honest") || r.attempts[0];
      loadAttempt(first);
      batch.editor.open = false;
    } catch (err) {
      batch.hSummary.textContent = `Could not run the attacker: ${err.message}`;
    }
    batch.hRun.disabled = false;
    batch.hRun.textContent = "Run a new attack";
  }

  /** multiSend(bytes): each call packed as operation(1) | to(20) | value(32) | dataLength(32) | data. */
  function encodeMultiSend(calls) {
    const packed = calls.map((c) => "00" + c.to.slice(2).toLowerCase() + word(c.wei) + word(0n)).join("");
    const byteLength = packed.length / 2;
    const padded = packed + "0".repeat((64 - (packed.length % 64)) % 64);
    return "0x8d80ff0a" + word(32n) + word(BigInt(byteLength)) + padded;
  }

  async function checkBatch() {
    let calls;
    try {
      calls = readCalls();
      if (!calls.length) throw new Error("Add at least one transfer");
    } catch (err) {
      batch.verdict.textContent = err.message;
      return;
    }
    batch.run.disabled = true;
    batch.verdict.textContent = "Simulating the batch…";
    try {
      if (scene.live) await connectAmoy();   // moves a stale fork to the newest block first
      const r = await call("/v1/simulate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
        chain_id: scene.live ? AMOY_CHAIN_ID : OFFLINE_CHAIN_ID, safe_address: scene.vault, to: MULTISEND, value: "0",
        data: encodeMultiSend(calls), operation: 1, contacts: [scene.vendor],
        declared_intent: { allowed_recipients: [scene.vendor], allowed_tokens: ["ETH"], max_outflow_wei: toWei(batch.cap.value || "0").toString() },
      }) });
      batch.verdict.dataset.decision = r.decision;
      const head = el("p", "batch__head");
      head.append(el("b", null, VERDICT_WORD[r.decision] || r.decision), document.createTextNode(` · risk ${r.risk_score}/100 · ${r.simulation_ms} ms · rules: ${(r.flags || []).join(", ") || "none"}`));
      const why = el("ul", "batch__why");
      (r.deterministic_human_warnings.length ? r.deterministic_human_warnings : ["Every transfer stays within what the signer declared."])
        .forEach((w) => why.append(el("li", null, readablePol(w))));
      batch.verdict.replaceChildren(head, why);
    } catch (err) {
      batch.verdict.textContent = `Could not check the batch: ${err.message}`;
    }
    batch.run.disabled = false;
  }

  batch.hRun.addEventListener("click", runAttacker);
  batch.add.addEventListener("click", () => { batch.calls.append(rowFor(scene.vendor, 10n ** 17n)); updateTotals(); });
  batch.cap.addEventListener("input", updateTotals);
  batch.run.addEventListener("click", checkBatch);
  connectAmoy();

  /* ---------------------------------------------------------- 4. six words + QR -- */
  // The shared test vector, computed live; the QR carries the words and every input they come from.
  const SHARED_TX = { chain_id: 1, safe_address: "0x5bd37a4e9b5e5A2BF8547Ad565b9dFd10126786C", nonce: 42,
    raw_tx_hash: "0x" + "aa".repeat(32), intent_hash: "0x" + "bb".repeat(32) };
  async function showSixWords() {
    try {
      const r = await call("/v1/innovations/six-words", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(SHARED_TX) });
      $("[data-w-words]").replaceChildren(...r.words.map((w) => el("span", null, w)));
      const svg = new DOMParser().parseFromString(r.qr_svg, "image/svg+xml").documentElement;
      svg.removeAttribute("width");
      svg.removeAttribute("height");
      $("[data-w-qr]").replaceChildren(document.importNode(svg, true));
      const open = $("[data-w-open]");
      const tamper = $("[data-w-tamper]");
      open.href = r.verify_url;
      tamper.href = r.verify_url.replace(`nonce=${SHARED_TX.nonce}`, `nonce=${SHARED_TX.nonce + 1}`);   // same words, other tx
      open.hidden = tamper.hidden = false;
    } catch (err) {
      $("[data-w-qr]").textContent = `QR unavailable: ${err.message}`;
    }
  }
  showSixWords();

  /* ---------------------------------------------------------- 3. immune system -- */
  const net = {
    vaults: $("[data-net-vaults]"), attacker: $("[data-net-attacker]"), meter: $("[data-net-meter]"),
    status: $("[data-net-status]"), next: $("[data-net-next]"), all: $("[data-net-all]"),
    progress: $("[data-net-progress]"), story: $("[data-net-story]"),
  };
  let demo = null, cursor = 0, playing = false;
  const vaultTiles = new Map();

  function drawVaults(vaults) {
    vaultTiles.clear();
    net.vaults.replaceChildren(...Object.entries(vaults).map(([name, address]) => {
      const tile = el("div", "vault");
      tile.append(el("b", null, name), el("code", null, short(address)), el("span", "vault__state", "Not involved yet"));
      vaultTiles.set(name, tile);
      return tile;
    }));
  }

  function setVault(name, state, label) {
    const tile = vaultTiles.get(name);
    if (!tile) return;
    tile.dataset.state = state;
    tile.querySelector(".vault__state").textContent = label;
  }

  function showRegistry(reg) {
    const filled = Math.min(1, reg.reports / reg.quorum);
    net.meter.style.transform = `scaleX(${filled})`;
    net.meter.parentElement.dataset.active = String(reg.status === "active");
    net.status.textContent = reg.status === "active"
      ? `Vaccine ACTIVE: reported by ${reg.reports} vaults (${reg.quorum} needed). Every vault blocks this address.`
      : reg.reports ? `Provisional: ${reg.reports} of ${reg.quorum} vault reports. Not enforced yet.` : "Not reported yet";
  }

  function applyStep(step, index) {
    const blocked = step.decision === "BLOCK";
    if (step.kind === "attack") setVault(step.vault, "attacked", "Attack blocked");
    else setVault(step.vault, blocked ? "immune" : "exposed", blocked ? "Protected by the vaccine" : "Exposed: payment went through");
    if (step.registry.status === "active") {
      vaultTiles.forEach((tile, name) => { if (!tile.dataset.state || tile.dataset.state === "exposed") setVault(name, "immune", "Immune"); });
    }
    showRegistry(step.registry);
    const li = el("li", `story__step ${blocked ? "is-block" : "is-allow"}`);
    const head = el("div", "story__head");
    head.append(el("span", "story__n", String(index + 1)), el("b", null, step.action), el("span", "story__verdict", blocked ? "BLOCKED" : "ALLOWED"));
    li.append(head, el("p", "story__meaning", step.meaning));
    if (step.rules.length) li.append(el("p", "story__rules", `Rules that fired: ${step.rules.join(", ")}`));
    net.story.append(li);
    net.progress.textContent = `Step ${index + 1} of ${demo.steps.length}`;
  }

  async function loadDemo() {
    demo = await call("/v1/innovations/immune-demo", { method: "POST" });
    cursor = 0;
    net.attacker.textContent = short(demo.attacker);
    net.story.replaceChildren();
    drawVaults(demo.vaults);
    showRegistry({ status: "unknown", reports: 0, quorum: demo.quorum });
  }

  async function nextStep() {
    try {
      if (!demo || cursor >= demo.steps.length) await loadDemo();
      applyStep(demo.steps[cursor], cursor);
      cursor += 1;
      net.next.textContent = cursor >= demo.steps.length ? "Replay the story" : "Next step";
    } catch (err) {
      net.status.textContent = `The demo could not run: ${err.message}.`;
    }
  }

  async function playAll() {
    if (playing) return;
    playing = true;
    net.all.disabled = true;
    try {
      if (!demo || cursor >= demo.steps.length) await loadDemo();
      while (cursor < demo.steps.length) {
        await nextStep();
        if (!REDUCED && cursor < demo.steps.length) await sleep(STEP_DELAY_MS);
      }
    } catch (err) {
      net.status.textContent = `The demo could not run: ${err.message}.`;
    }
    net.all.disabled = false;
    playing = false;
  }

  net.next.addEventListener("click", nextStep);
  net.all.addEventListener("click", playAll);

  loadDemo().catch((err) => { net.status.textContent = `The demo could not load: ${err.message}.`; });
})();
