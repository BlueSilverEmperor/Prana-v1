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
  async function composition() {
    const host = $("[data-p2-cases]");
    try {
      const { cases } = await call("/v1/innovations/composition");
      host.replaceChildren(...cases.map((c) => {
        const li = el("li", `cases__item ${c.decision === "BLOCK" ? "is-block" : "is-allow"}`);
        const head = el("div", "cases__head");
        head.append(el("span", "cases__verdict", c.decision === "BLOCK" ? "BLOCKED" : "ALLOWED"),
          el("span", "cases__kind", c.harmful ? "attack" : "legitimate"));
        li.append(head, el("p", "cases__title", c.title), el("p", "cases__meaning", c.meaning));
        if (c.rules.length) li.append(el("p", "cases__rules", `rules: ${c.rules.join(", ")} · ${c.calls} calls · ${c.ms} ms`));
        return li;
      }));
    } catch (err) {
      host.replaceChildren(el("li", "cases__empty", `Could not load: ${err.message}`));
    }
  }

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

  composition();
  loadDemo().catch((err) => { net.status.textContent = `The demo could not load: ${err.message}.`; });
})();
