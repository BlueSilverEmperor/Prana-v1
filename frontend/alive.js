/* Vero Console, alive layer: sliding nav pill, scroll rim, island alert, tile spotlight, verdict motion.
   Self-contained: listens to the page (aria-current changes, scroll, the "vero:verdict" event) and never owns data. */
(() => {
  "use strict";
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const FINE_POINTER = matchMedia("(hover: hover) and (pointer: fine)").matches;
  const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
  const ISLAND_MS = 2800;
  const PILL_RADIUS = 12;
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];

  /* ---------------------------------------------- nav pill and hover layer -- */
  const side = $(".side"), nav = $(".side__nav");
  const pill = $(".side__pill"), hover = $(".side__hover");
  const links = $$("a", nav);

  // clip a full-width layer down to one link: clip-path animates on the compositor, no layout
  function clipTo(layer, link) {
    const right = nav.clientWidth - (link.offsetLeft + link.offsetWidth);
    layer.style.clipPath = `inset(0 ${right}px 0 ${link.offsetLeft}px round ${PILL_RADIUS}px)`;
  }
  function jumpTo(layer, link) {
    layer.style.transition = "none";
    clipTo(layer, link);
    void layer.offsetWidth; // commit the jump before transitions come back
    layer.style.transition = "";
  }
  function syncPill() {
    const current = links.find((a) => a.getAttribute("aria-current") === "page");
    pill.classList.toggle("is-on", Boolean(current));
    if (current) clipTo(pill, current);
  }

  if (nav && pill && hover) {
    const firstCurrent = links.find((a) => a.getAttribute("aria-current") === "page");
    if (firstCurrent) jumpTo(pill, firstCurrent);
    syncPill();
    new MutationObserver(syncPill).observe(nav, { subtree: true, attributeFilter: ["aria-current"] });
    new ResizeObserver(syncPill).observe(nav);

    if (FINE_POINTER) {
      links.forEach((a) => a.addEventListener("pointerenter", () => {
        if (hover.classList.contains("is-on")) clipTo(hover, a); else jumpTo(hover, a);
        hover.classList.add("is-on");
      }));
      nav.addEventListener("pointerleave", () => hover.classList.remove("is-on"));
    }
  }

  /* ------------------------------------------- scroll rim and notch state -- */
  const rim = $(".side__progress");
  let scrollQueued = false;
  function onScroll() {
    scrollQueued = false;
    const max = document.documentElement.scrollHeight - innerHeight;
    const progress = max > 0 ? Math.min(1, scrollY / max) : 0;
    if (rim) rim.style.transform = `scaleX(${progress})`;
    side?.classList.toggle("is-scrolled", scrollY > 8);
  }
  addEventListener("scroll", () => {
    if (!scrollQueued) { scrollQueued = true; requestAnimationFrame(onScroll); }
  }, { passive: true });
  addEventListener("resize", onScroll, { passive: true });
  onScroll();

  /* ------------------------------------------ island alert from the notch -- */
  const island = $("[data-island]");
  const TAGS = { BLOCK: "Blocked", ALLOW: "Allowed", WARN: "Review" };
  let islandTimer = 0, seenFirstVerdict = false;
  function showIsland(result, label) {
    island.dataset.decision = result.decision;
    $("[data-island-tag]", island).textContent = TAGS[result.decision] || result.decision;
    $("[data-island-text]", island).textContent = label;
    $("[data-island-risk]", island).textContent = `risk ${result.risk_score}`;
    island.classList.add("is-on");
    clearTimeout(islandTimer);
    islandTimer = setTimeout(() => island.classList.remove("is-on"), ISLAND_MS);
  }

  /* ------------------------------------------------------- verdict motion -- */
  function animateVerdict() {
    if (REDUCED) return;
    const badge = $("[data-result-badge]");
    badge?.animate([{ transform: "scale(0.9)", opacity: 0 }, { transform: "none", opacity: 1 }], { duration: 240, easing: EASE });
    $$("[data-result-list] li").forEach((li, i) => li.animate(
      [{ transform: "translateY(6px)", opacity: 0 }, { transform: "none", opacity: 1 }],
      { duration: 280, delay: i * 50, easing: EASE, fill: "backwards" },
    ));
  }

  document.addEventListener("vero:verdict", (e) => {
    const { result, label } = e.detail || {};
    if (!result) return;
    animateVerdict();
    // the first verdict is the page's own boot check; only checks the visitor runs get the island
    if (island && seenFirstVerdict) showIsland(result, label || "Live check");
    seenFirstVerdict = true;
  });

  /* ------------------------------------------------------ tile spotlight -- */
  if (FINE_POINTER && !REDUCED) {
    let target = null, x = 0, y = 0, queued = false;
    const paint = () => {
      queued = false;
      if (!target) return;
      const r = target.getBoundingClientRect();
      target.style.setProperty("--mx", `${x - r.left}px`);
      target.style.setProperty("--my", `${y - r.top}px`);
    };
    document.addEventListener("pointermove", (e) => {
      const tile = e.target instanceof Element ? e.target.closest(".tile") : null;
      if (target && target !== tile) target.classList.remove("is-lit");
      target = tile;
      if (!tile) return;
      tile.classList.add("is-lit");
      x = e.clientX; y = e.clientY;
      if (!queued) { queued = true; requestAnimationFrame(paint); }
    }, { passive: true });
    document.addEventListener("pointerleave", () => { target?.classList.remove("is-lit"); target = null; });
  }
})();
