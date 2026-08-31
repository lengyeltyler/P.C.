#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const appRoot = path.resolve(__dirname, "..");
const read = (relativePath) => fs.readFileSync(path.join(appRoot, relativePath), "utf8");

test("Pass C keeps one supported Desktop minimum and no unreachable renderer layouts", () => {
  const main = read("src/main/main.cjs");
  const styles = read("src/renderer/styles.css");

  assert.match(main, /minWidth:\s*1040/);
  assert.match(main, /minHeight:\s*720/);
  assert.match(styles, /@media \(max-width: 1040px\)/);
  assert.doesNotMatch(styles, /@media \(max-width: (?:980|760|620)px\)/);
  assert.match(styles, /\.app-shell \{[\s\S]*?height: 100vh;[\s\S]*?overflow: hidden;/);
  assert.match(styles, /\.view \{[\s\S]*?min-height: 0;[\s\S]*?overflow: auto;/);
  assert.match(main, /passCKeyboardAndMinimumWidthSmoke/);
  assert.match(main, /horizontalOverflow/);
  assert.match(main, /nextNavigation/);
  assert.match(read("src/renderer/app.js"), /if \(viewChanged\) view\.scrollTop = 0/);
});

test("Pass C state language is explicit and does not rely on color alone", () => {
  const renderer = read("src/renderer/app.js");
  const styles = read("src/renderer/styles.css");

  for (const label of ["Success", "Warning", "Blocked", "Rejected", "Failed", "Status unknown", "In progress"]) {
    assert.match(renderer, new RegExp(label));
  }
  assert.match(renderer, /state-callout__icon/);
  assert.match(renderer, /state-callout__label/);
  assert.match(renderer, /aria-busy="true"/);
  assert.match(renderer, /!active \|\| terminal \? `<aside class="phil-stage-guidance/);
  assert.match(styles, /\.state-callout\.rejected/);
  assert.match(styles, /\.state-callout\.unknown/);
  assert.match(styles, /@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.state-callout__spinner/);
});

test("Pass C ordinary Ethereum and recovery surfaces preserve their semantic boundaries", () => {
  const renderer = read("src/renderer/app.js");

  assert.match(renderer, /id="local-demonstrations-title">Local demonstrations/);
  assert.match(renderer, /These demonstrations run on this Mac and do not replay or recreate the completed Controlled Beta/);
  assert.match(renderer, /class="local-demo-options"/);
  assert.match(renderer, /tone: "blocked", label: "Deferred"/);
  assert.match(renderer, /Recovery is intentionally outside this Beta/);
  assert.match(renderer, /Public network mutation", false/);
});

test("Pass C keeps technical evidence optional and keyboard focus visible", () => {
  const renderer = read("src/renderer/app.js");
  const styles = read("src/renderer/styles.css");

  assert.match(renderer, /function details\(summary, body\)/);
  assert.match(renderer, /<details class="technical-details">/);
  assert.match(styles, /button:focus-visible[\s\S]*?outline: var\(--focus-ring\)/);
  assert.match(styles, /\.technical-details summary[\s\S]*?min-height: 2\.5rem/);
});
