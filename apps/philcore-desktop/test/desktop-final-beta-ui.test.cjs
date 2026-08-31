const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const helper = require("../src/renderer/phil-helper.cjs");
const renderer = fs.readFileSync(path.join(__dirname, "../src/renderer/app.js"), "utf8");

test("Phil names are explicit local labels with bounded printable content", () => {
  assert.equal(helper.normalizeName("  Orbit 🌙  "), "Orbit 🌙");
  for (const value of [null, {}, "", "  ", "x".repeat(65), "Phil\nAdmin", "Phil\u202eAdmin"]) assert.equal(helper.normalizeName(value), null);
  assert.equal(helper.normalizeName("x".repeat(64)), "x".repeat(64));
  assert.match(renderer, /const label = window\.PhilHelper\.normalizeName\(formState\.create\.name\)/);
  assert.doesNotMatch(renderer, /create-label"\)\.value \|\|/);
});

test("creation preserves the chosen name across passphrase visibility and validation renders", () => {
  const formState = { create: { name: "" }, unlock: {}, platform: {} };
  const values = { "create-label": { value: "Orbit" }, "create-passphrase": { value: "test-only" } };
  const document = { getElementById: (id) => values[id] };
  const code = renderer.slice(renderer.indexOf("function captureSensitiveFormValues()"), renderer.indexOf("function passphraseField("));
  vm.runInNewContext(`${code}\ncaptureSensitiveFormValues(); clearSensitiveForm("create");`, { document, formState });
  assert.equal(formState.create.name, "Orbit");
  assert.equal(formState.create.passphrase, "");
  assert.equal(formState.create.confirm, "");
});

test("helper position survives reload, rejects corrupt storage and clamps after resize", () => {
  const entries = new Map();
  const storage = { getItem: (key) => entries.get(key), setItem: (key, value) => entries.set(key, value) };
  assert.equal(helper.readPosition(storage), null);
  assert.equal(helper.savePosition(storage, { x: 940, y: 690 }), true);
  assert.deepEqual(helper.readPosition(storage), { x: 940, y: 690 });
  assert.deepEqual(helper.clampPosition(helper.readPosition(storage), { width: 400, height: 300 }), { x: 300, y: 180 });
  storage.setItem("phil.helper.position.v1", '{"x":"unknown","y":null}');
  assert.equal(helper.readPosition(storage), null);
  assert.equal(helper.readPosition({ getItem() { throw Error("denied"); } }), null);
  assert.equal(helper.savePosition(null, { x: 20, y: 20 }), false);
  assert.deepEqual(helper.clampPosition({ x: -100, y: Infinity }, { width: 50, height: 50 }), { x: 0, y: 0 });
});

test("helper avoids critical controls and yields when no safe visible position exists", () => {
  const viewport = { width: 800, height: 600 }, size = { width: 84, height: 104 };
  const obstacle = { left: 650, top: 400, right: 800, bottom: 600 };
  const point = helper.safePosition({ x: 700, y: 460 }, viewport, size, [obstacle]);
  assert.ok(point.x + size.width < obstacle.left);
  assert.equal(helper.safePosition(null, viewport, size, [{ left: 0, top: 0, right: 800, bottom: 600 }]), null);
  const code = fs.readFileSync(path.join(__dirname, "../src/renderer/phil-helper.cjs"), "utf8");
  assert.match(code, /approval-root/);
  assert.match(code, /if \(unavailable\) \{ expanded = false; drag = null; element.hidden = true; return; \}/);
  assert.match(code, /pointercancel/);
  assert.match(code, /ArrowLeft/);
  assert.doesNotMatch(code, /window\.philcore|fetch\(|XMLHttpRequest|WebSocket|setInterval/);
});

test("contextual help is static, has a keyboard equivalent, and keeps ENS future-only", () => {
  for (const topic of ["home", "chain", "approval", "recovery", "audit", "settings"]) assert.ok(helper.topics[topic].length > 0);
  assert.notDeepEqual(helper.topics.home, helper.topics.chain);
  assert.match(JSON.stringify(helper.topics.settings), /ENS is future Mainnet integration/);
  assert.match(renderer, /settings-phil-help/);
  assert.match(renderer, /Reset Phil position/);
  assert.doesNotMatch(JSON.stringify(helper.topics), /available now|register now|lookup now/iu);
});

test("locked routing and success animation require both authenticated session and open vault", () => {
  const code = renderer.slice(renderer.indexOf("function isLockedScreen()"), renderer.indexOf("function developerSurfacesAllowed()"));
  for (const [lockState, vaultState, expected] of [["locked", "locked", true], ["partially_unlocked", "locked", true], ["unlocked", "locked", true], ["unlocked", "unlocked", false]]) {
    assert.equal(vm.runInNewContext(`${code}\nisLockedScreen()`, { snapshot: { identity: {}, session: { lockState, vaultState } } }), expected);
  }
  const transition = renderer.slice(renderer.indexOf("function playWorldTransition()"), renderer.indexOf("function bytesToBase64Url("));
  let touched = false;
  vm.runInNewContext(`${transition}\nplayWorldTransition()`, { isLockedScreen: () => true, document: { getElementById() { touched = true; } } });
  assert.equal(touched, false);
  for (const reducedMotion of [false, true]) {
    const transitions = new Set(); let timeout;
    const element = { classList: { remove: v => transitions.delete(v), add: v => transitions.add(v) }, setAttribute() {}, offsetWidth: 1 };
    const context = { isLockedScreen: () => false, snapshot: { session: { lockState: "unlocked", vaultState: "unlocked" } },
      worldTransitionTimer: null, document: { getElementById: () => element },
      window: { matchMedia: () => ({ matches: reducedMotion }) }, clearTimeout() {},
      setTimeout(callback, delay) { timeout = { callback, delay }; return 1; } };
    vm.runInNewContext(`${transition}\nplayWorldTransition()`, context);
    assert.equal(transitions.has("is-opening"), true);
    assert.equal(timeout.delay, reducedMotion ? 220 : 900);
    timeout.callback(); assert.equal(transitions.has("is-opening"), false);
  }
  const styles = fs.readFileSync(path.join(__dirname, "../src/renderer/final-beta-ui.css"), "utf8");
  assert.match(styles, /prefers-reduced-motion: reduce/);
  assert.match(styles, /animation: phil-entry-fade \.18s/);
  assert.match(styles, /clip-path: none/);
});

test("mounted helper drags, persists, collapses for modals and supports keyboard reset", () => {
  const entries = new Map(); let modal = false;
  const storage = { getItem: k => entries.get(k), setItem: (k,v) => entries.set(k,v), removeItem: k => entries.delete(k) };
  const node = () => ({ children: [], events: {}, style: {}, hidden: false, offsetWidth: 84, offsetHeight: 104,
    append(...items) { this.children.push(...items); }, replaceChildren() { this.children = []; },
    setAttribute(k,v) { this[k] = v; }, addEventListener(k,f) { this.events[k] = f; },
    setPointerCapture() {}, focus() {}, getBoundingClientRect() { return { left: Number.parseFloat(this.style.left)||16, top: Number.parseFloat(this.style.top)||16 }; } });
  const element = node(), root = { get childElementCount() { return modal ? 1 : 0; } };
  const document = { body: { dataset: {} }, createElement: node, getElementById: () => root,
    querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
  const window = { localStorage: storage, innerWidth: 800, innerHeight: 600,
    MutationObserver: class { observe() {} }, addEventListener() {} };
  const mounted = helper.mount({ document, window, element });
  mounted.update({ context: "home", blocked: false });
  const button = element.children[1];
  button.events.pointerdown({ button: 0, pointerId: 1, clientX: 740, clientY: 500 });
  button.events.pointermove({ pointerId: 1, clientX: 240, clientY: 300 });
  button.events.pointerup();
  assert.deepEqual(helper.readPosition(storage), { x: 200, y: 280 });
  button.events.click(); // The completed drag must not open help.
  assert.equal(button["aria-expanded"], "false");
  button.events.click(); assert.equal(button["aria-expanded"], "true");
  modal = true; mounted.update({ context: "home", blocked: false }); assert.equal(element.hidden, true);
  modal = false; mounted.update({ context: "home", blocked: false }); assert.equal(button["aria-expanded"], "false");
  button.events.keydown({ key: "ArrowLeft", preventDefault() {} });
  assert.deepEqual(helper.readPosition(storage), { x: 176, y: 280 });
  mounted.reset(); assert.equal(helper.readPosition(storage), null);
});
