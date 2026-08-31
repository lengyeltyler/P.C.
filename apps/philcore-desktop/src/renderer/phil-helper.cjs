(function exposePhilHelper(root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.PhilHelper = api;
})(typeof globalThis !== "undefined" ? globalThis : this, () => {
  "use strict";
  const POSITION_KEY = "phil.helper.position.v1";
  const TOPICS = Object.freeze({
    home: [
      ["What is Phil?", "Phil is your secure digital identity. Phil helps protect your assets, privacy, and sovereignty, and explains requests before protected signing."],
      ["What does locked mean?", "Your protected identity is closed. Unlock it before Phil can prepare a local approval request."],
      ["What did the Controlled Beta prove?", "A bounded demonstration on Ethereum Sepolia with test-only assets. It does not establish mainnet readiness or production custody."]
    ],
    chain: [
      ["What is Sepolia?", "Sepolia is Ethereum's test network. Its assets and fees are test-only."],
      ["What is my Ethereum account?", "The Beta account is a restricted smart account. Your Phil name is local display metadata, not its address or signing authority."],
      ["Why isn't this Mainnet?", "The Beta has a deliberately limited test scope. Mainnet connections and ENS naming are future work and unavailable here."]
    ],
    approval: [
      ["What am I approving?", "Only the action shown in the summary, for the listed destination, value, maximum cost, and expiry."],
      ["Why does my phone matter?", "Your enrolled iPhone provides a separate device-bound approval. Compare the fingerprint so you know the request belongs to this Mac."],
      ["What happens if I reject this?", "No approval is granted. The protected action does not continue."]
    ],
    recovery: [["Why is recovery unavailable?", "Recovery is intentionally unavailable in this Beta while the next recovery design is being prepared."]],
    audit: [["What is Activity?", "Activity separates completed Controlled Beta history from actions performed locally on this Mac. Viewing history grants no approval."]],
    settings: [
      ["What does post-quantum mean?", "Not currently. Today's authorization uses classical cryptography; future migration support does not make the current Beta post-quantum secure."],
      ["What is Advanced?", "Advanced shows technical details. It does not grant extra authority or enable unavailable Beta features."],
      ["Is my Phil name ENS?", "No. It is stored only on this Mac. ENS is future Mainnet integration in the Ethereum adapter; Phil identity does not depend on it."]
    ]
  });

  function normalizeName(value) {
    if (typeof value !== "string") return null;
    const name = value.trim();
    return name.length > 0 && name.length <= 64 && !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(name) ? name : null;
  }

  function clampPosition(position, viewport, size = { width: 84, height: 104 }) {
    const maxX = Math.max(0, viewport.width - size.width - 16);
    const maxY = Math.max(0, viewport.height - size.height - 16);
    return {
      x: Math.min(maxX, Math.max(Math.min(16, maxX), Number.isFinite(position?.x) ? position.x : maxX)),
      y: Math.min(maxY, Math.max(Math.min(16, maxY), Number.isFinite(position?.y) ? position.y : maxY))
    };
  }

  function overlaps(a, b) {
    return a.x < b.right + 12 && a.x + a.width > b.left - 12 && a.y < b.bottom + 12 && a.y + a.height > b.top - 12;
  }

  function safePosition(position, viewport, size, obstacles) {
    const corners = [position, { x: viewport.width, y: viewport.height }, { x: 16, y: viewport.height }, { x: viewport.width, y: 16 }, { x: 16, y: 16 }];
    for (const candidate of corners) {
      const point = clampPosition(candidate, viewport, size);
      if (!obstacles.some((rect) => overlaps({ ...point, ...size }, rect))) return point;
    }
    return null;
  }

  function readPosition(storage) {
    try {
      const value = JSON.parse(storage.getItem(POSITION_KEY));
      return value && Number.isFinite(value.x) && Number.isFinite(value.y) ? { x: value.x, y: value.y } : null;
    } catch { return null; }
  }

  function savePosition(storage, point) {
    try { storage.setItem(POSITION_KEY, JSON.stringify({ x: point.x, y: point.y })); return true; } catch { return false; }
  }

  function mount({ document, window, element }) {
    if (!element) return Object.freeze({ update() {}, reset() {} });
    let storage;
    try { storage = window.localStorage; } catch { storage = null; }
    let position = readPosition(storage), expanded = false, context = "home", blocked = true, drag = null, suppressClick = false;
    const button = document.createElement("button");
    button.type = "button";
    button.className = "phil-helper__character";
    button.setAttribute("aria-label", "Ask Phil. Drag to move, or use arrow keys while focused.");
    button.setAttribute("aria-controls", "phil-helper-content");
    const art = document.createElement("img");
    art.src = "./assets/characters/phil/phil_wave.png";
    art.alt = "";
    art.draggable = false;
    button.append(art);
    const label = document.createElement("span");
    label.textContent = "Ask Phil";
    button.append(label);
    const panel = document.createElement("section");
    panel.id = "phil-helper-content";
    panel.className = "phil-helper__content";
    panel.setAttribute("aria-label", "Contextual Phil help");
    element.append(panel, button);

    function renderContent() {
      panel.replaceChildren();
      const title = document.createElement("h3"); title.textContent = "Ask Phil"; panel.append(title);
      const explanation = document.createElement("p"); explanation.textContent = "A little guidance for this page. Local help, no AI chat."; panel.append(explanation);
      for (const [question, answer] of TOPICS[context] || TOPICS.home) {
        const details = document.createElement("details"), summary = document.createElement("summary"), copy = document.createElement("p");
        summary.textContent = question; copy.textContent = answer; details.append(summary, copy); panel.append(details);
      }
      const close = document.createElement("button"); close.type = "button"; close.className = "secondary"; close.textContent = "Close help";
      close.addEventListener("click", () => { expanded = false; layout(); button.focus(); }); panel.append(close);
    }

    function layout() {
      // The helper has no bridge access. Modals and sensitive forms always win.
      const modal = document.getElementById("approval-root")?.childElementCount > 0 || document.querySelector('dialog[open], [aria-modal="true"]');
      const unavailable = blocked || Boolean(modal) || document.body.dataset.locked === "true";
      if (unavailable) { expanded = false; drag = null; element.hidden = true; return; }
      element.hidden = false;
      panel.hidden = !expanded;
      button.setAttribute("aria-expanded", String(expanded));
      const size = { width: element.offsetWidth, height: element.offsetHeight };
      const viewport = { width: window.innerWidth, height: window.innerHeight };
      if (size.width > viewport.width || size.height > viewport.height) { element.hidden = true; return; }
      const critical = document.querySelectorAll('input[type="password"], .state-callout.warning, .state-callout.failed, .state-callout.blocked, .state-callout.unknown, .unavailable-reason, .security-warning, [data-action*="Approval"], [data-action*="Cancel"], [data-action*="Deny"], [data-action*="Reject"], [data-action*="Begin"], [data-action="startProtectedAction"], [data-action="dismissActionResult"], [data-action="runDemo"], [data-action="routineAuthorizationReplace"], [data-action="lock"], [data-action="unlock"], [data-action="platformUnlock"], [data-approval-action]');
      const obstacles = Array.from(critical, (node) => node.getBoundingClientRect()).filter((rect) => rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.top < viewport.height);
      const point = safePosition(position, viewport, size, obstacles);
      if (!point) { if (expanded) { expanded = false; layout(); return; } element.hidden = true; return; }
      element.style.left = `${point.x}px`; element.style.top = `${point.y}px`;
    }

    button.addEventListener("click", () => {
      if (suppressClick) { suppressClick = false; return; }
      expanded = !expanded; layout();
    });
    button.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      const rect = element.getBoundingClientRect();
      drag = { id: event.pointerId, x: event.clientX, y: event.clientY, origin: { x: rect.left, y: rect.top } };
      suppressClick = false; button.setPointerCapture(event.pointerId);
    });
    button.addEventListener("pointermove", (event) => {
      if (!drag || drag.id !== event.pointerId) return;
      const dx = event.clientX - drag.x, dy = event.clientY - drag.y;
      if (Math.hypot(dx, dy) < 5 && !suppressClick) return;
      suppressClick = true;
      position = clampPosition({ x: drag.origin.x + dx, y: drag.origin.y + dy }, { width: window.innerWidth, height: window.innerHeight }, { width: element.offsetWidth, height: element.offsetHeight });
      layout();
    });
    button.addEventListener("pointerup", () => { if (drag && suppressClick) savePosition(storage, position); drag = null; });
    button.addEventListener("pointercancel", () => { drag = null; suppressClick = true; });
    button.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { expanded = false; layout(); return; }
      const move = { ArrowLeft: [-24, 0], ArrowRight: [24, 0], ArrowUp: [0, -24], ArrowDown: [0, 24] }[event.key];
      if (!move) return;
      event.preventDefault();
      const rect = element.getBoundingClientRect();
      position = clampPosition({ x: rect.left + move[0], y: rect.top + move[1] }, { width: window.innerWidth, height: window.innerHeight }, { width: element.offsetWidth, height: element.offsetHeight });
      savePosition(storage, position); layout();
    });
    panel.addEventListener("toggle", layout, true);
    panel.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { expanded = false; layout(); button.focus(); }
    });
    window.addEventListener("resize", layout);
    document.addEventListener("scroll", layout, true);
    const observer = new window.MutationObserver(layout);
    for (const id of ["approval-root", "view"]) {
      const target = document.getElementById(id);
      if (target) observer.observe(target, { childList: true, subtree: true });
    }
    renderContent(); layout();
    return Object.freeze({
      update(next) { blocked = next.blocked; if (context !== next.context) { context = next.context; renderContent(); } layout(); },
      reset() { position = null; try { storage?.removeItem(POSITION_KEY); } catch {} expanded = false; layout(); }
    });
  }

  return Object.freeze({ normalizeName, clampPosition, safePosition, readPosition, savePosition, topics: TOPICS, mount });
});
