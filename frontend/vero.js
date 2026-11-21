/* Vero Console: renders a live red/green MCMC run (/v1/redteam/mcmc) and live checks against /v1/simulate. */
(() => {
  "use strict";
  const API = /^(3000|4500|5173)$/.test(location.port) || location.protocol === "file:" ? "http://localhost:8000" : location.origin;
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const RULE_NAMES = { R1: "Approvals", R2: "Permits", R3: "Logic swap", R4: "Delegatecall", R5: "Owners", R6: "Guard", R7: "Modules",
    R8: "EIP-7702", R9: "Undeclared recipient", R10: "Outflow cap", R11: "Lookalike token", R12: "Threat registry",
    "P33-POISON": "Address poisoning", "B26-FIRST-RECIPIENT": "First recipient", "B26-VAULT-SHARE": "Vault share", "B26-NEW-CONTRACT": "New contract" };

  /* ---------------------------------------------------------- chart helpers -- */
  function linePath(values, w, h, padY = 3) {
    const max = Math.max(...values, 1e-9), min = Math.min(...values, 0);
    const span = max - min || 1;
    return values.map((v, i) => {
      const x = values.length === 1 ? 0 : (i / (values.length - 1)) * w;
      const y = h - padY - ((v - min) / span) * (h - padY * 2);
      return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
    }).join(" ");
  }
  function drawLine(path) {
    if (REDUCED || !path.getTotalLength) return;
    const len = path.getTotalLength();
    path.style.strokeDasharray = `${len}`;
    path.style.strokeDashoffset = `${len}`;
    path.getBoundingClientRect();
    path.style.transition = "stroke-dashoffset 1200ms cubic-bezier(0.23, 1, 0.32, 1)";
    requestAnimationFrame(() => { path.style.strokeDashoffset = "0"; });
  }
  function countUp(node, end, decimals = 0) {
    if (REDUCED || !end) { node.textContent = end.toFixed(decimals); return; }
    const start = performance.now();
    const tick = (now) => {
      const t = Math.min(1, (now - start) / 900);
      node.textContent = (end * (1 - Math.pow(1 - t, 3))).toFixed(decimals);
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  /* ------------------------------------------------------ live MCMC run data -- */
  // The overview is a fresh red/green MCMC run, not a dataset: generated attacks and safe transactions,
  // judged by rules R1-R12. A fixed seed keeps the overview stable between loads; the attack page reseeds.
  const OVERVIEW_RUN = { steps: 300, chains: 4, seed: 7, mode: "both" };
  const TABLE_MAX = 120;
  const METHOD_LABELS = { approve: "approve", increaseAllowance: "increaseAllowance", transfer: "transfer", transferFrom: "transferFrom",
    ethSend: "ETH send", upgradeTo: "logic swap", addOwnerWithThreshold: "owner takeover", enableModule: "module", setGuard: "guard removal" };

  async function loadRun() {
    const res = await fetch(`${API}/v1/redteam/mcmc`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(OVERVIEW_RUN) });
    if (!res.ok) throw new Error(`MCMC run HTTP ${res.status}`);
    const r = await res.json();
    return { ...r, harmless_unique: r.unique_variants - r.harmful_unique };
  }

  // Every mechanism the engine uses, what it stops, and its id in the run's rule hits.
  const MECHANISMS = [
    ["R1", "Approvals", "Unlimited allowances, undeclared spenders, allowances above the declared ceiling"],
    ["R2", "Permits", "Off-chain permit signatures that hand over tokens"],
    ["R3", "Logic swap", "A proxy or wallet implementation being replaced"],
    ["R4", "Delegatecall", "Delegatecall into code that is not a trusted library"],
    ["R5", "Owners and threshold", "Owners added or removed, signing threshold lowered"],
    ["R6", "Guard", "The transaction guard being changed or removed"],
    ["R7", "Modules", "Modules enabled that can move funds without signatures"],
    ["R8", "EIP-7702", "The account's code delegated to another contract"],
    ["R9", "Undeclared recipient", "Value sent to an address or asset the signer never declared"],
    ["R10", "Outflow cap", "More value leaving than the declared ceiling"],
    ["R11", "Lookalike token", "A token contract imitating a known one"],
    ["R12", "Threat registry", "A target on the known-drainer registry"],
    ["P33-POISON", "Address poisoning", "A recipient that only looks like a saved contact"],
    ["B26-FIRST-RECIPIENT", "First-time recipient", "Large value to an address never paid before"],
    ["B26-VAULT-SHARE", "Vault share", "A large share of the vault leaving at once"],
    ["B26-NEW-CONTRACT", "New contract", "Calls into a contract deployed moments ago"],
    ["G28-GAS-CEILING", "Gas ceiling", "Gas fees above the signer's ceiling"],
    ["C31-CHAIN", "Chain binding", "A transaction built for a different chain"],
    ["B36-BRIDGE", "Bridge destination", "Funds bridged to an unknown destination"],
    ["DECODE", "Fail closed", "Calldata the engine cannot decode is blocked, never guessed"],
  ];

  function renderStats(r) {
    const set = (key, text) => { const n = $(`[data-st="${key}"]`); if (n) n.textContent = text; };
    const blocked = r.harmful_unique - r.escapes.length;
    const passed = r.harmless_unique - r.false_positives.length;
    set("harmful", r.harmful_unique.toLocaleString());
    set("blocked", blocked.toLocaleString());
    set("blocked-pct", r.harmful_unique ? ` · ${((blocked / r.harmful_unique) * 100).toFixed(1)}%` : "");
    set("escapes-note", `Attacks that got through: ${r.escapes.length}`);
    set("passed", passed.toLocaleString());
    set("harmless-of", `/${r.harmless_unique}`);
    set("fp-note", `Wrongly blocked: ${r.false_positives.length}`);
    set("p95", r.latency_p95_ms.toFixed(2));
    set("p50", r.latency_p50_ms.toFixed(2));
    set("mech-meta", `attacks each one stopped, across ${r.harmful_unique.toLocaleString()} generated attacks`);
    $("[data-mc-sub]").textContent = `Live MCMC run, seed ${r.seed}: ${r.unique_variants.toLocaleString()} generated transactions ` +
      `(${r.harmful_unique} attacks, ${r.harmless_unique} safe) against rules R1–R12 and the shields. No dataset, no sample list.`;
  }

  function renderDuel(r) {
    const entries = Object.entries(r.attacks_by_primitive);
    const max = Math.max(1, ...entries.map(([, c]) => c.thrown));
    $("[data-duel]").replaceChildren(...entries.map(([method, c], gi) => {
      const group = el("div", "duelbars__group");
      const cols = el("div", "duelbars__cols");
      [["attack", c.thrown], ["defense", c.stopped], ["leak", c.thrown - c.stopped]].forEach(([kind, n], ci) => {
        const col = el("span", `duelbars__col duelbars__col--${kind}`);
        col.style.height = `${Math.max(n / max, n ? 0.02 : 0.004) * 100}%`;
        col.dataset.s = "1";
        col.style.setProperty("--d", `${gi * 60 + ci * 30}ms`);
        col.title = `${kind === "attack" ? "thrown" : kind === "defense" ? "stopped" : "got through"}: ${n}`;
        col.append(el("i", null, String(n)));
        cols.append(col);
      });
      const label = el("p", "duelbars__label", METHOD_LABELS[method] || method);
      group.append(cols, label);
      return group;
    }));
  }

  function renderMechanisms(r) {
    const hits = r.rule_hits || {};
    const max = Math.max(1, ...MECHANISMS.map(([id]) => hits[id] || 0));
    $("[data-mechs]").replaceChildren(...MECHANISMS.map(([id, name, stops], i) => {
      const n = hits[id] || 0;
      const li = el("li", n ? "" : "is-idle");
      const head = el("div", "mechs__head");
      head.append(el("code", null, id), el("b", null, name), el("span", "mechs__n", n.toLocaleString()));
      const track = el("span", "track");
      const fill = el("span", "fill");
      fill.dataset.s = String(n / max);
      fill.style.setProperty("--d", `${i * 35}ms`);
      track.append(fill);
      li.append(head, el("p", "mechs__stops", stops), track);
      return li;
    }));
  }

  let tableFilter = "all", runData = null;
  function renderTable() {
    const rows = runData.trace.filter((t) => tableFilter === "all" || (tableFilter === "harmful") === t.harmful).slice(0, TABLE_MAX);
    $("[data-table]").replaceChildren(...rows.map((t, i) => {
      const tr = el("tr");
      const fired = el("td");
      (t.rules.length ? t.rules : ["none"]).forEach((r) => fired.append(el("code", null, r)));
      const verdict = t.blocked ? "BLOCK" : "ALLOW";
      const vtd = el("td"); vtd.append(el("span", `pill pill--${verdict}`, verdict === "BLOCK" ? "Blocked" : "Allowed"));
      const side = el("td"); side.append(el("span", `pill pill--${t.harmful ? "malicious" : "benign"}`, t.harmful ? "attack" : "safe"));
      tr.append(el("td", null, String(i + 1)), side, el("td", "tx-desc", t.attempt), fired, vtd, el("td", "num", `${t.ms.toFixed(2)} ms`));
      return tr;
    }));
  }
  $$("[data-filter]").forEach((b) => b.addEventListener("click", () => {
    tableFilter = b.dataset.filter;
    $$("[data-filter]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    if (runData) renderTable();
  }));

  /* -------------------------------------------- entrances trigger the charts -- */
  function reveal(tile) {
    tile.classList.add("is-in");
    $$("[data-s]", tile).forEach((n) => n.style.setProperty("--s", n.dataset.s));
    $$("[data-dash]", tile).forEach((n) => { n.style.strokeDasharray = n.dataset.dash; });
    $$("[data-spark], [data-area-line]", tile).forEach(drawLine);
    $$("[data-end]", tile).forEach((n) => countUp(n, Number(n.dataset.end)));
  }
  function observeTiles() {
    $$("[data-in]").forEach((t, i) => t.style.setProperty("--d", `${Math.min(i, 5) * 60}ms`));
    const io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { reveal(e.target); io.unobserve(e.target); } }), { threshold: 0.15 });
    $$("[data-in]").forEach((t) => io.observe(t));
  }

  /* ---------------------------------------------------------- engine status -- */
  async function health() {
    const pill = $("[data-status]");
    try {
      const r = await fetch(`${API}/health`);
      if (!r.ok) throw new Error(String(r.status));
      const h = await r.json();
      pill.classList.add("is-ok");
      $("[data-status-text]").textContent = `Engine online · ${h.engine}`;
    } catch {
      pill.classList.add("is-down");
      $("[data-status-text]").textContent = "Engine offline";
    }
  }

  /* --------------------------------------------------------- sidebar toggle -- */
  const app = $(".app"), toggle = $("[data-side-toggle]");
  const KEY = "vero.sidebar.mini";
  function setMini(mini, animate = true) {
    if (!animate) app.classList.add("no-anim");
    app.classList.toggle("is-mini", mini);
    toggle.setAttribute("aria-expanded", String(!mini));
    toggle.setAttribute("aria-label", mini ? "Expand navigation" : "Collapse navigation");
    try { localStorage.setItem(KEY, mini ? "1" : "0"); } catch { /* storage unavailable: state lasts this visit */ }
    if (!animate) requestAnimationFrame(() => requestAnimationFrame(() => app.classList.remove("no-anim")));
  }
  let startMini = false;
  try { startMini = localStorage.getItem(KEY) === "1"; } catch { /* default expanded */ }
  setMini(startMini, false);
  toggle.addEventListener("click", () => setMini(!app.classList.contains("is-mini")));
  // Keyboard shortcut toggles instantly: animating a frequent shortcut only adds delay.
  addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "b") { e.preventDefault(); setMini(!app.classList.contains("is-mini"), false); }
  });

  /* ------------------------------------------------ nav follows the scroll -- */
  const navLinks = $$(".side__nav a");
  const navIo = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return;
    navLinks.forEach((a) => (a.getAttribute("href") === `#${e.target.id}` ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current")));
  }), { rootMargin: "-45% 0px -50% 0px" });
  navLinks.map((a) => $(a.getAttribute("href"))).filter(Boolean).forEach((s) => navIo.observe(s));

  /* ------------------------------------------------------------------ boot -- */
  loadRun().then((r) => {
    runData = r;
    renderStats(r); renderDuel(r); renderMechanisms(r); renderTable();
  }).catch((err) => {
    $("[data-mc-sub]").textContent = `The live MCMC run could not load (${err.message}). Start the API and reload.`;
  }).finally(observeTiles);
  health();
})();
