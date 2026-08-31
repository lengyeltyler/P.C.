"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appRoot = path.resolve(__dirname, "..");
const rendererRoot = path.join(appRoot, "src", "renderer");
const assetRoot = path.join(rendererRoot, "assets", "philenator");
const sourceCommit = "f174dedda16a354c592e3252d9b0b5805bab59c4";
const layerOrder = [
  "bgColor", "bgNebula", "bgStars", "bgSpiral", "bgDust", "bgOverlay",
  "bodyBase", "body", "spikes", "teeth", "jawNose", "eyes", "top"
];

function responseFor(url) {
  const prefix = "./assets/philenator/";
  assert.equal(String(url).startsWith(prefix), true);
  const relative = String(url).slice(prefix.length);
  assert.equal(relative.includes(".."), false);
  const filePath = path.join(assetRoot, relative);
  const body = fs.readFileSync(filePath, "utf8");
  return Promise.resolve({
    ok: true,
    status: 200,
    json: async () => JSON.parse(body),
    text: async () => body
  });
}

async function run() {
  const context = {
    crypto: crypto.webcrypto,
    fetch: responseFor,
    btoa: (value) => Buffer.from(value, "binary").toString("base64"),
    TextEncoder,
    Uint32Array,
    Object,
    Array,
    Set,
    String,
    Math
  };
  context.globalThis = context;
  vm.runInNewContext(
    fs.readFileSync(path.join(rendererRoot, "philenator-engine.js"), "utf8"),
    context,
    { filename: "philenator-engine.js" }
  );

  assert.equal(context.PhilenatorEngine.sourceCommit, sourceCommit);
  assert.deepEqual(Array.from(context.PhilenatorEngine.layerOrder), layerOrder);
  const first = await context.PhilenatorEngine.generate();
  const second = await context.PhilenatorEngine.generate();
  assert.equal(first.sourceCommit, sourceCommit);
  assert.deepEqual(Array.from(first.layers), layerOrder);
  assert.deepEqual(Object.keys(first.traits), layerOrder);
  assert.match(first.svg, /^<svg[\s\S]*<image href="data:image\/svg\+xml;base64,/u);
  assert.match(first.backgroundSvg, /^<svg[\s\S]*<image href="data:image\/svg\+xml;base64,/u);
  assert.notDeepEqual(first.traits, second.traits);

  const traitFiles = fs.readdirSync(path.join(assetRoot, "traits"), { recursive: true })
    .filter((name) => name.endsWith(".svg"));
  assert.equal(traitFiles.length, 503);
  for (const relative of traitFiles) {
    const filePath = path.join(assetRoot, "traits", relative);
    assert.equal(fs.lstatSync(filePath).isSymbolicLink(), false);
    const svg = fs.readFileSync(filePath, "utf8");
    assert.doesNotMatch(svg, /<script|<foreignObject|javascript:|\son\w+\s*=/iu);
    assert.doesNotMatch(svg, /(?:href|xlink:href)=["'](?:https?:|\/\/|javascript:)/iu);
  }

  process.stdout.write("PhilCore Desktop Philenator engine tests passed\n");
}

run().catch((error) => {
  console.error(error);
  process.exit(1);
});
