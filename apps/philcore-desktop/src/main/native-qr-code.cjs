const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function resolveQrHelper({ appRoot = process.cwd(), resourcesPath = process.resourcesPath } = {}) {
  const candidates = [
    process.env.PHILCORE_QR_HELPER,
    resourcesPath && path.join(resourcesPath, "app", "bin", "darwin-arm64", "PhilCoreQRCode"),
    path.join(
      appRoot,
      "apps/philcore-desktop/build/native",
      process.arch === "arm64" ? "darwin-arm64" : "darwin-x64",
      "PhilCoreQRCode"
    )
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function createQrDataUrl(value, options = {}) {
  if (typeof value !== "string" || value.length < 32 || value.length > 8192) {
    throw new Error("QR_SAFE_PAYLOAD_INVALID");
  }
  const helper = options.helperPath || resolveQrHelper(options);
  if (!helper) throw new Error("QR_HELPER_UNAVAILABLE");
  const result = spawnSync(helper, [], {
    input: value,
    encoding: null,
    maxBuffer: 2 * 1024 * 1024,
    timeout: 10_000
  });
  if (result.status !== 0 || !Buffer.isBuffer(result.stdout) || result.stdout.length < 64) {
    throw new Error("QR_HELPER_FAILED");
  }
  return `data:image/png;base64,${result.stdout.toString("base64")}`;
}

module.exports = { createQrDataUrl, resolveQrHelper };
