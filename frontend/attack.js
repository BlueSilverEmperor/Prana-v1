/* Vero attack vs defense: runs the red/green MCMC search on the server and replays it as a battle.
   Positive samples are generated attacks (should be BLOCKED); negative samples are generated safe
   transactions (should be ALLOWED). Nothing here is a stored verdict or a dataset. */
(() => {
  "use strict";
  const API = /^(3000|4500|5173)$/.test(location.port) || location.protocol === "file:" ? "http://localhost:8000" : location.origin;
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const FEED_MAX = 10;
  const REPLAY_MS = 9000;                  // whole feed replay length
  const METHOD_NAMES = { approve: "approve", increaseAllowance: "increaseAllowance", transfer: "transfer", transferFrom: "transferFrom",
    ethSend: "ETH send", upgradeTo: "logic swap", addOwnerWithThreshold: "owner takeover", enableModule: "backdoor module", setGuard: "guard removal" };

  const $ = (s, root = document) => root.querySelector(s);
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const fmt = (n) => Number(n).toLocaleString();

  const arena = $("[data-arena]");
  const ui = {
    run: $("[data-a-run]"), steps: $("[data-a-steps]"), atkFeed: $("[data-a-attack-feed]"), safeFeed: $("[data-a-safe-feed]"),
    blocked: $("[data-k-blocked]"), harmful: $("[data-k-harmful]"), escapes: $("[data-k-escapes]"),
    passed: $("[data-k-passed]"), harmless: $("[data-k-harmless]"), fp: $("[data-k-fp]"),
    tugDef: $("[data-a-tug-def]"), tugAtk: $("[data-a-tug-atk]"), types: $("[data-a-types]"),
    unique: $("[data-a-unique]"), accept: $("[data-a-accept]"), chains: $("[data-a-chains]"), seed: $("[data-a-seed]"), note: $("[data-a-note]"),
  };

  async function health() {
    const pill = $("[data-status]"), text = $("[data-status-text]");
    try {
      const h = await (await fetch(`${API}/health`)).json();
      pill.classList.add("is-ok");
      text.textContent = `Engine online · ${h.engine || "vero"}`;
    } catch {
      pill.classList.add("is-down");
      text.textContent = "Engine offline";
    }
  }

  function push(list, node) {
    list.querySelector(".feedlist__empty")?.remove();
    list.prepend(node);
    while (list.children.length > FEED_MAX) list.lastChild.remove();
  }

  function feedItem(ev) {
    const wrong = ev.harmful ? !ev.blocked : ev.blocked;
    const li = el("li", `${ev.harmful ? "is-red" : "is-green"} ${ev.blocked ? "is-blocked" : "is-allowed"}${wrong ? " is-wrong" : ""}`);
    li.append(el("b", null, ev.blocked ? "BLOCKED" : "ALLOWED"), document.createTextNode(ev.attempt));
    if (wrong) li.append(el("em", null, ev.harmful ? " · got through" : " · wrongly blocked"));
    li.title = ev.attempt;
    return li;
  }

  function setScore(t) {
    ui.blocked.textContent = fmt(t.blocked);
    ui.harmful.textContent = `/${fmt(t.harmful)}`;
    ui.escapes.textContent = fmt(t.escapes);
    ui.passed.textContent = fmt(t.passed);
    ui.harmless.textContent = `/${fmt(t.harmless)}`;
    ui.fp.textContent = fmt(t.fp);
    ui.escapes.classList.toggle("is-alert", t.escapes > 0);
    ui.fp.classList.toggle("is-alert", t.fp > 0);
    ui.tugDef.style.flexGrow = String(t.blocked + t.passed);
    ui.tugAtk.style.flexGrow = String(t.escapes + t.fp);
  }

  function renderTypes(rates) {
    ui.types.replaceChildren(...Object.entries(rates).map(([method, rate]) => {
      const li = el("li"), track = el("span", "track"), fill = el("span", "fill");
      fill.style.setProperty("--s", String(rate));
      track.append(fill);
      li.append(el("span", "name", METHOD_NAMES[method] || method), track, el("span", "n", `${Math.round(rate * 100)}%`));
      return li;
    }));
  }

  async function battle() {
    ui.run.disabled = true;
    ui.run.textContent = "Battle running…";
    arena.dataset.state = "running";
    ui.atkFeed.replaceChildren(el("li", "feedlist__empty", "Running the chains on the server…"));
    ui.safeFeed.replaceChildren(el("li", "feedlist__empty", "…"));
    setScore({ blocked: 0, harmful: 0, escapes: 0, passed: 0, harmless: 0, fp: 0 });

    let r;
    try {
      const res = await fetch(`${API}/v1/redteam/mcmc`, { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ steps: Number(ui.steps.value), chains: 4, seed: Math.floor(Math.random() * 1e6), mode: "both" }) });
      if (!res.ok) throw new Error(`server answered ${res.status}`);
      r = await res.json();
    } catch (err) {
      ui.note.textContent = `The battle could not run: ${err.message}. Start the API and try again.`;
      ui.run.disabled = false;
      ui.run.textContent = "Start the battle";
      return;
    }

    const live = { blocked: 0, harmful: 0, escapes: 0, passed: 0, harmless: 0, fp: 0 };
    const tick = REDUCED ? 0 : Math.max(10, Math.min(50, REPLAY_MS / Math.max(1, r.trace.length)));
    for (const ev of r.trace) {
      if (ev.harmful) { live.harmful += 1; live[ev.blocked ? "blocked" : "escapes"] += 1; }
      else { live.harmless += 1; live[ev.blocked ? "fp" : "passed"] += 1; }
      push(ev.harmful ? ui.atkFeed : ui.safeFeed, feedItem(ev));
      setScore(live);
      if (tick) await sleep(tick);
    }

    const harmless = r.unique_variants - r.harmful_unique;
    setScore({ blocked: r.harmful_unique - r.escapes.length, harmful: r.harmful_unique, escapes: r.escapes.length,
      passed: harmless - r.false_positives.length, harmless, fp: r.false_positives.length });
    renderTypes(r.block_rate_by_primitive);
    ui.unique.textContent = fmt(r.unique_variants);
    ui.accept.textContent = `${(r.acceptance_rate * 100).toFixed(1)}%`;
    ui.chains.textContent = `${r.chains} × ${fmt(r.steps)} steps`;
    ui.seed.textContent = String(r.seed);
    ui.note.textContent = `The feeds replay the first ${r.trace.length} distinct transactions; the score covers all ${fmt(r.unique_variants)}. ` +
      `Same seed, same run: POST /v1/redteam/mcmc {"seed": ${r.seed}, "steps": ${r.steps}}.`;
    arena.dataset.state = "done";
    ui.run.disabled = false;
    ui.run.textContent = "Run another battle";
  }

  ui.run.addEventListener("click", battle);
  health();
  if (new URLSearchParams(location.search).has("autoplay")) battle();
})();
