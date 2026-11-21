/* Vero landing: the chain divider (hashing, mining, refusing the bad block), the byte decode, the live verdict and the collapse.
   Reads each act's --sc-p from the scrollcraft engine; the engine itself is untouched. */
(() => {
  "use strict";
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const API = /^(3000|4500|5173)$/.test(location.port) || location.protocol === "file:" ? "http://localhost:8000" : location.origin;
  const SAFE = `0x${"1".repeat(40)}`;
  const CALLDATA = `0x3659cfe6${"ba".repeat(20).padStart(64, "0")}`; // upgradeTo(0xbaba…baba), the WazirX shape
  const PHONE_MAX = 760;
  const SCRAMBLE_MS = 420;
  const MINE_LINE = 0.55;          // an act mines its block once its top passes 55% of the viewport
  const EJECT_TRAVEL = { desktop: 190, phone: 70 };
  const TAGS = { BLOCK: "Blocked", ALLOW: "Allowed", WARN: "Review" };

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const clamp01 = (v) => Math.min(1, Math.max(0, v));
  const span = (p, a, b) => clamp01((p - a) / (b - a));
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);
  const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const progressOf = (el) => (el ? parseFloat(el.style.getPropertyValue("--sc-p")) || 0 : 0);
  const shortHash = (h) => `${h.slice(0, 4)}…${h.slice(-3)}`;
  const isPhone = () => innerWidth <= PHONE_MAX;

  const blocks = $$(".block");
  const acts = $$("[data-act]");
  const readings = $("[data-readings]"), peak = $("[data-peak]"), close = $("[data-close]");
  const spine = $("[data-spine]"), intruder = $("[data-intruder]");
  const spineLabelL = $(".spine__label--l"), spineCta = $(".spine__cta");
  const lose = $("[data-close-lose]"), win = $("[data-close-win]"), inner = $("[data-close-inner]");

  /* ------------------------------------------------ hash the chain for real -- */
  async function sha256Hex(text) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function hashChain() {
    if (!globalThis.crypto?.subtle) return; // insecure context: blocks keep their placeholder dots
    let prev = "0".repeat(64);
    for (const block of blocks) {
      const label = $("span", block).textContent;
      prev = await sha256Hex(`${block.dataset.block}|${prev}|${label}`);
      block.dataset.full = prev;
      block.title = `Block ${block.dataset.block} (${label})\nSHA-256 of its index, the previous hash and its label:\n${prev}`;
      if (block.classList.contains("is-mined")) $("[data-hash]", block).textContent = shortHash(prev);
    }
  }

  function scramble(node, final) {
    if (REDUCED) { node.textContent = final; return; }
    const hex = "0123456789abcdef";
    const start = performance.now();
    const tick = (now) => {
      const t = (now - start) / SCRAMBLE_MS;
      if (t >= 1) { node.textContent = final; return; }
      node.textContent = final.replace(/[0-9a-f]/g, (c, i) => (i < final.length * t ? c : hex[(Math.random() * 16) | 0]));
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  /* ---------------------------------------------------------------- mining -- */
  let minedTo = -1;
  function mineTo(n) {
    if (n === minedTo) return;
    blocks.forEach((block, i) => {
      const mined = i <= n;
      if (mined && !block.classList.contains("is-mined") && block.dataset.full) scramble($("[data-hash]", block), shortHash(block.dataset.full));
      block.classList.toggle("is-mined", mined);
      block.classList.toggle("is-head", i === n);
    });
    minedTo = n;
  }
  function blockFor(actTops, peakP) {
    let n = 0;
    actTops.forEach(({ index, top }) => { if (index > 0 && index < blocks.length && top < innerHeight * MINE_LINE) n = Math.max(n, index); });
    // the verdict block joins only after the refused transaction has been thrown out
    return n === 3 && peakP < 0.66 ? 2 : n;
  }

  /* ------------------------------------------------- the refused transaction -- */
  let lastIntruder = "";
  function paintIntruder(p) {
    const slot = blocks[3];
    const arrive = easeOut(span(p, 0.2, 0.36));
    const eject = easeOut(span(p, 0.46, 0.64));
    const tries = span(p, 0.36, 0.46);
    const shake = tries > 0 && tries < 1 && !REDUCED ? Math.sin(tries * Math.PI * 8) * 3 : 0;
    const y = slot.offsetTop - (1 - arrive) * 150;
    const x = shake + eject * (isPhone() ? EJECT_TRAVEL.phone : EJECT_TRAVEL.desktop);
    const opacity = span(p, 0.2, 0.26) * (1 - span(p, 0.54, 0.64));
    const link = tries > 0 && eject < 0.05 ? 16 : 0;
    const key = `${x.toFixed(1)}|${y.toFixed(1)}|${opacity.toFixed(3)}|${link}`;
    if (key === lastIntruder) return;
    lastIntruder = key;
    intruder.style.transform = `translate(${x}px, ${y}px) rotate(${eject * 26}deg)`;
    intruder.style.opacity = String(opacity);
    intruder.style.setProperty("--link", `${link}px`);
  }

  /* -------------------------------------------------------- the byte decode -- */
  const bytesOn = $("[data-bytes-on]"), bytesOff = $("[data-bytes-off]");
  let shown = -1;
  function paintBytes(p) {
    const n = REDUCED ? CALLDATA.length : Math.round(CALLDATA.length * easeOut(span(p, -0.08, 0.22)));
    if (n === shown) return;
    shown = n;
    const visible = CALLDATA.slice(0, n);
    const selector = document.createElement("span");
    selector.className = "sel";
    selector.textContent = visible.slice(0, 10);
    bytesOn.replaceChildren(selector, visible.slice(10));
    bytesOff.textContent = CALLDATA.slice(n);
  }

  /* -------------------------------------------------------------- collapse -- */
  let lastClose = -1, contentShift = 0;
  function measureClose() {
    const pad = parseFloat(getComputedStyle(win).paddingLeft) || 0;
    const gutter = Math.max(24, innerWidth * 0.06);
    contentShift = Math.max(0, pad - gutter - spine.offsetWidth);
    lastClose = -1;
  }
  function paintClose(p) {
    const k = easeInOut(span(p, 0.04, 0.5));
    if (Math.abs(k - lastClose) < 0.0005) return;
    lastClose = k;
    if (isPhone()) {
      spine.style.transform = k ? `translateX(${-spine.offsetWidth * 1.2 * k}px)` : "";
      inner.style.transform = "";
      return;
    }
    const half = innerWidth / 2, spineHalf = spine.offsetWidth / 2;
    const travel = (half - spineHalf) * k;
    const splitX = half - travel;
    spine.style.transform = k ? `translateX(${-travel}px)` : "";
    // the losing side's label and the spine's own button leave as the page resolves; the close carries the action
    const fade = String(1 - span(k, 0, 0.6));
    spineLabelL.style.opacity = fade;
    spineCta.style.opacity = fade;
    spineCta.style.pointerEvents = k > 0.5 ? "none" : "";
    lose.style.clipPath = `inset(0 ${innerWidth - splitX}px 0 0)`;
    win.style.clipPath = `inset(0 0 0 ${splitX}px)`;
    inner.style.transform = k ? `translateX(${-contentShift * k}px)` : "";
  }

  /* ---------------------------------------------------------- live verdict -- */
  const v = { box: $("[data-verdict]"), tag: $("[data-v-tag]"), risk: $("[data-v-risk]"), why: $("[data-v-why]"), words: $("[data-v-words]"), src: $("[data-v-src]") };
  async function liveVerdict() {
    try {
      const res = await fetch(`${API}/v1/simulate`, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chain_id: 1, safe_address: SAFE, to: SAFE, data: CALLDATA, value: "0", nonce: 0, operation: 0 }) });
      if (!res.ok) throw new Error(`engine answered ${res.status}`);
      const r = await res.json();
      v.box.dataset.decision = r.decision;
      v.tag.textContent = TAGS[r.decision] || r.decision;
      v.risk.textContent = String(r.risk_score);
      v.why.textContent = (r.deterministic_human_warnings || [])[0] || (r.flags || []).join(", ") || "The real effect matches what was declared.";
      v.words.textContent = (r.four_word_checksum || "").split("-").join(" · ") || "n/a";
      v.src.textContent = `Live from the Vero engine on this page load, ${r.simulation_ms} ms`;
      if (r.raw_tx_hash) $("[data-intruder-hash]").textContent = shortHash(r.raw_tx_hash.replace(/^0x/, ""));
    } catch (err) {
      v.box.dataset.decision = "BLOCK";
      v.tag.textContent = "Blocked";
      v.risk.textContent = "–";
      v.why.textContent = "Rule R3, logic swap: the transaction replaces the wallet's implementation.";
      v.words.textContent = "shown when the engine is online";
      v.src.textContent = `The engine is offline (${err.message}); this is the recorded verdict for this transaction.`;
    }
  }

  /* --------------------------------------------- proof: a live MCMC run -- */
  // Generated on this page load by the red/green sampler; no dataset or sample list is involved.
  const PROOF_RUN = { steps: 300, chains: 4, seed: 7, mode: "both" };
  async function liveProof() {
    const set = (key, text) => { const n = $(`[data-mc="${key}"]`); if (n) n.textContent = text; };
    try {
      const res = await fetch(`${API}/v1/redteam/mcmc`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(PROOF_RUN) });
      if (!res.ok) throw new Error(`engine answered ${res.status}`);
      const r = await res.json();
      const harmless = r.unique_variants - r.harmful_unique;
      set("unique", r.unique_variants.toLocaleString());
      set("harmful", r.harmful_unique.toLocaleString());
      set("harmless", harmless.toLocaleString());
      set("blocked", `${(r.harmful_unique - r.escapes.length).toLocaleString()} / ${r.harmful_unique.toLocaleString()}`);
      set("passed", `${(harmless - r.false_positives.length).toLocaleString()} / ${harmless.toLocaleString()}`);
      set("escapes-note", r.escapes.length ? `${r.escapes.length} got through` : "none got through");
      set("fp-note", r.false_positives.length ? `${r.false_positives.length} wrongly blocked` : "none wrongly blocked");
    } catch (err) {
      set("escapes-note", `run unavailable (${err.message})`);
      set("fp-note", "start the API to run it");
    }
  }

  /* ------------------------------------------------------------------ loop -- */
  function frame() {
    // read everything first, then write, so no frame forces a layout mid-paint
    const pReadings = progressOf(readings), pPeak = progressOf(peak), pClose = progressOf(close);
    const tops = acts.map((a) => ({ index: Number(a.dataset.act), top: a.getBoundingClientRect().top }));
    paintBytes(pReadings);
    paintIntruder(pPeak);
    mineTo(blockFor(tops, pPeak));
    paintClose(pClose);
    requestAnimationFrame(frame);
  }

  addEventListener("resize", measureClose, { passive: true });
  document.fonts?.ready.then(measureClose);
  measureClose();
  mineTo(0);
  hashChain().catch(() => { /* hashing is decoration on top of the page; placeholders stay */ });
  liveVerdict();
  liveProof();
  requestAnimationFrame(frame);
})();
