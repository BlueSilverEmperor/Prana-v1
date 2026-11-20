/* Vero Console: renders the real benchmark run (data/benchmark.json) and live checks against /v1/simulate. */
(() => {
  "use strict";
  const API = /^(3000|4500|5173)$/.test(location.port) || location.protocol === "file:" ? "http://localhost:8000" : location.origin;
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SAFE = "0x1111111111111111111111111111111111111111";
  const pad = (h) => h.replace(/^0x/, "").padStart(64, "0");
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const RULE_NAMES = { R1: "Approvals", R2: "Permits", R3: "Logic swap", R4: "Delegatecall", R5: "Owners", R6: "Guard", R7: "Modules",
    R8: "EIP-7702", R9: "Undeclared recipient", R10: "Outflow cap", R11: "Lookalike token", R12: "Threat registry",
    "P33-POISON": "Address poisoning", "B26-FIRST-RECIPIENT": "First recipient", "B26-VAULT-SHARE": "Vault share", "B26-NEW-CONTRACT": "New contract" };
  const EXAMPLES = {
    wazirx: { label: "WazirX swap", to: SAFE, op: 0, data: "0x3659cfe6" + pad("babababababababababababababababababababa") },
    bybit: { label: "Bybit delegatecall", to: "0xbadc0de0badc0de0badc0de0badc0de0badc0de0", op: 1, data: "0xa9059cbb" + pad("babababababababababababababababababababa") + pad("0") },
    approve: { label: "Unlimited approval", to: "0xdac17f958d2ee523a2206206994597c13d831ec7", op: 0, data: "0x095ea7b3" + pad("e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0") + "f".repeat(64) },
    benign: { label: "Normal transfer", to: "0xdac17f958d2ee523a2206206994597c13d831ec7", op: 0, data: "0xa9059cbb" + pad("4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f") + pad("5f5e100") },
  };

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

  /* --------------------------------------------------------- benchmark data -- */
  async function loadBenchmark() {
    const res = await fetch("data/benchmark.json");
    if (!res.ok) throw new Error(`benchmark.json HTTP ${res.status}`);
    return res.json();
  }
  function renderKpis(bench) {
    const m = bench.metrics;
    $("[data-kpi-p95]").textContent = m.p95LatencyMs.toFixed(2);
    $("[data-kpi-p50]").textContent = m.p50LatencyMs.toFixed(2);
    const mal = bench.outcomes.filter((o) => o.label === "malicious");
    const ben = bench.outcomes.filter((o) => o.label === "benign");
    let a = 0, b = 0;
    const series = {
      detect: mal.map((o) => (a += o.flagged ? 1 : 0)),
      block: mal.map((o, i) => (o.flagged ? i + 1 : i)),
      fp: ben.map((o) => (b += o.flagged ? 1 : 0)),
      latency: bench.outcomes.map((o) => o.latency_ms),
    };
    $$("[data-spark]").forEach((p) => {
      const vals = series[p.dataset.spark];
      p.setAttribute("d", linePath(vals, 120, 32));
      if (p.dataset.spark === "fp") p.closest("svg").classList.add("spark--red");
    });
    $$("[data-count]").forEach((n) => { n.dataset.end = n.dataset.count; });
  }
  function renderBaselines(bench) {
    const LABELS = { "plain-wallet": "Plain wallet", "static-blocklist": "Static blocklist", "warnings-only": "Warnings only", "full-vero": "Full Vero" };
    const host = $("[data-baselines]");
    host.replaceChildren(...bench.baselines.map((b, gi) => {
      const g = el("div", "bars__group");
      const cols = el("div", "bars__cols");
      [["detect", b.detection], ["block", b.block], ["fp", b.false_positive]].forEach(([kind, r], ci) => {
        const c = el("span", `bars__col bars__col--${kind}`);
        c.style.height = `${Math.max(r.rate, 0.012) * 100}%`;
        c.dataset.s = "1";
        c.style.setProperty("--d", `${gi * 90 + ci * 40}ms`);
        c.title = `${r.successes}/${r.trials} (${(r.rate * 100).toFixed(1)}%), 95% CI ${(r.ci95[0] * 100).toFixed(1)}–${(r.ci95[1] * 100).toFixed(1)}%`;
        cols.append(c);
      });
      const label = el("p", "bars__label");
      label.append(el("b", null, `${(b.detection.rate * 100).toFixed(0)}%`), document.createTextNode(LABELS[b.name] || b.name));
      g.append(cols, label);
      return g;
    }));
  }
  function renderDonut(bench) {
    const C = 2 * Math.PI * 46;
    const blocked = bench.outcomes.filter((o) => o.flagged).length;
    const allowed = bench.outcomes.length - blocked;
    const segB = $('[data-donut="block"]'), segA = $('[data-donut="allow"]');
    segB.dataset.dash = `${(blocked / bench.outcomes.length) * C - 2} ${C}`;
    segA.dataset.dash = `${(allowed / bench.outcomes.length) * C - 2} ${C}`;
    segA.style.strokeDashoffset = `${-(blocked / bench.outcomes.length) * C}`;
  }
  function renderArea(bench) {
    const vals = bench.outcomes.map((o) => o.latency_ms);
    const line = linePath(vals, 600, 180, 12);
    $("[data-area-line]").setAttribute("d", line);
    $("[data-area-fill]").setAttribute("d", `${line} L600 180 L0 180 Z`);
    $("[data-area-max]").textContent = `peak ${Math.max(...vals).toFixed(2)} ms`;
  }
  function renderRules(bench) {
    const counts = {};
    bench.outcomes.forEach((o) => o.fired.forEach((r) => { counts[r] = (counts[r] || 0) + 1; }));
    const rows = Object.entries(counts).sort((x, y) => y[1] - x[1]).slice(0, 10);
    const max = rows[0] ? rows[0][1] : 1;
    $("[data-rules]").replaceChildren(...rows.map(([rule, n], i) => {
      const li = el("li");
      const name = el("span", "name", `${rule.startsWith("R") ? rule + " · " : ""}${RULE_NAMES[rule] || rule}`);
      const track = el("span", "track");
      const fill = el("span", `fill${rule.startsWith("R") ? "" : " fill--shield"}`);
      fill.dataset.s = String(n / max);
      fill.style.setProperty("--d", `${i * 50}ms`);
      track.append(fill);
      li.append(name, track, el("span", "n", String(n)));
      return li;
    }));
  }
  let tableFilter = "all", benchData = null;
  function renderTable() {
    const rows = benchData.outcomes.filter((o) => tableFilter === "all" || o.label === tableFilter);
    $("[data-table]").replaceChildren(...rows.map((o) => {
      const tr = el("tr");
      const fired = el("td");
      (o.fired.length ? o.fired : ["none"]).forEach((r) => fired.append(el("code", null, r)));
      const verdict = o.flagged ? "BLOCK" : "ALLOW";
      const vtd = el("td"); vtd.append(el("span", `pill pill--${verdict}`, verdict === "BLOCK" ? "Blocked" : "Allowed"));
      const ltd = el("td"); ltd.append(el("span", `pill pill--${o.label}`, o.label));
      tr.append(el("td", null, o.id), el("td", null, o.set), ltd, fired, vtd, el("td", "num", `${o.latency_ms.toFixed(2)} ms`));
      return tr;
    }));
  }
  $$("[data-filter]").forEach((b) => b.addEventListener("click", () => {
    tableFilter = b.dataset.filter;
    $$("[data-filter]").forEach((x) => x.setAttribute("aria-selected", String(x === b)));
    if (benchData) renderTable();
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

  /* -------------------------------------------------------------- live check -- */
  const input = $("[data-check-input]"), toInput = $("[data-check-to]"), delegate = $("[data-check-delegate]");
  const result = $("[data-result]"), tabs = $$("[data-example]");
  let seq = 0, currentLabel = EXAMPLES.wazirx.label;
  async function simulate(to, data, op) {
    const res = await fetch(`${API}/v1/simulate`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chain_id: 1, safe_address: SAFE, to, data, value: "0", nonce: 0, operation: op }) });
    if (!res.ok) {
      let detail = res.statusText;
      try { const b = await res.json(); detail = typeof b.detail === "string" ? b.detail : (b.detail || []).map((d) => d.msg).join("; "); } catch { /* keep */ }
      throw Object.assign(new Error(detail), { status: res.status });
    }
    return res.json();
  }
  function addFeed(r) {
    const feed = $("[data-feed]");
    $(".feed__empty", feed)?.remove();
    const li = el("li");
    li.append(el("span", `tag tag--${r.decision}`, r.decision === "BLOCK" ? "Blocked" : r.decision === "ALLOW" ? "Allowed" : "Review"),
      el("span", "what", `${currentLabel} · ${(r.flags || []).join(", ") || "no rule"}`), el("span", "ms", `${r.simulation_ms} ms`),
      el("span", "hash", `tx ${r.raw_tx_hash}`));
    feed.prepend(li);
    while (feed.children.length > 8) feed.lastChild.remove();
  }
  function render(r) {
    result.dataset.decision = r.decision;
    $("[data-result-badge]").textContent = { BLOCK: "BLOCKED", ALLOW: "ALLOWED", WARN: "REVIEW" }[r.decision] || r.decision;
    $("[data-result-risk]").textContent = String(r.risk_score);
    $("[data-result-meter]").style.setProperty("--s", String(Math.max(0.02, r.risk_score / 100)));
    const items = r.deterministic_human_warnings || [];
    $("[data-result-list]").replaceChildren(...(items.length ? items : ["The real effect matches what was sent."]).map((t) => el("li", null, t)));
    $("[data-result-words]").textContent = (r.four_word_checksum || "").split("-").join(" · ");
    addFeed(r);
    document.dispatchEvent(new CustomEvent("vero:verdict", { detail: { result: r, label: currentLabel } }));
  }
  function showProblem(title, detail) {
    delete result.dataset.decision;
    $("[data-result-badge]").textContent = title;
    $("[data-result-risk]").textContent = "–";
    $("[data-result-meter]").style.setProperty("--s", "0");
    $("[data-result-list]").replaceChildren(el("li", null, detail));
  }
  async function check() {
    const mine = ++seq;
    try {
      const r = await simulate(toInput.value.trim(), input.value.trim(), delegate.checked ? 1 : 0);
      if (mine === seq) render(r);
    } catch (err) {
      if (mine !== seq) return;
      if (err.status === 422) showProblem("INVALID", err.message);
      else showProblem("OFFLINE", "Start the API: cd api-agents && uvicorn api_agents.main:app --port 8000");
    }
  }
  function choose(key) {
    const ex = EXAMPLES[key];
    input.value = ex.data; toInput.value = ex.to; delegate.checked = ex.op === 1; currentLabel = ex.label;
    tabs.forEach((t) => t.setAttribute("aria-selected", String(t.dataset.example === key)));
    check();
  }
  tabs.forEach((t) => t.addEventListener("click", () => choose(t.dataset.example)));
  let debounce;
  [input, toInput].forEach((n) => n.addEventListener("input", () => {
    currentLabel = "Custom";
    tabs.forEach((t) => t.setAttribute("aria-selected", "false"));
    clearTimeout(debounce); debounce = setTimeout(check, 320);
  }));
  delegate.addEventListener("change", check);

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
  loadBenchmark().then((bench) => {
    benchData = bench;
    renderKpis(bench); renderBaselines(bench); renderDonut(bench); renderArea(bench); renderRules(bench); renderTable();
  }).catch((err) => {
    $(".top__sub").textContent = `Benchmark data could not be loaded (${err.message}).`;
  }).finally(observeTiles);
  health();
  choose("wazirx");
})();
