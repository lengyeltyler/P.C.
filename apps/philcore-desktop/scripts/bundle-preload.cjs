#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { buildSync } = require("esbuild");

const appRoot = path.resolve(__dirname, "..");
const sourcePath = path.join(appRoot, "src", "preload", "preload.cjs");
const defaultOutputPath = path.join(appRoot, "build", "preload", "preload.cjs");

function bundlePreload(outputPath = defaultOutputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  buildSync({
    entryPoints: [sourcePath],
    outfile: outputPath,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node22",
    external: ["electron"],
    sourcemap: false,
    legalComments: "none",
    logLevel: "silent"
  });

  const bundled = fs.readFileSync(outputPath, "utf8");
  if (/require\(["']\.\.\/shared\/bridge-contract\.cjs["']\)/u.test(bundled)) {
    throw new Error("Sandboxed preload bundle retained a local CommonJS dependency");
  }
  if (!bundled.includes("philcore:state:getSnapshot") || !bundled.includes("exposeInMainWorld")) {
    throw new Error("Sandboxed preload bundle is missing the bridge contract or contextBridge exposure");
  }

  return { sourcePath, outputPath };
}

if (require.main === module) {
  const result = bundlePreload(process.argv[2] ? path.resolve(process.argv[2]) : defaultOutputPath);
  process.stdout.write(`Bundled sandbox-safe preload at ${path.relative(path.resolve(appRoot, "..", ".."), result.outputPath)}\n`);
}

module.exports = { bundlePreload, defaultOutputPath, sourcePath };
