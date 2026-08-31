const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "../../..");
const source = path.join(
  ROOT,
  "apps/philcore-desktop/native/macos-qr/PhilCoreQRCode.swift"
);
const outputDirectory = path.join(
  ROOT,
  "apps/philcore-desktop/build/native",
  process.arch === "arm64" ? "darwin-arm64" : "darwin-x64"
);
const output = path.join(outputDirectory, "PhilCoreQRCode");

fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o755 });
const result = spawnSync("/usr/bin/xcrun", [
  "swiftc",
  source,
  "-O",
  "-framework", "AppKit",
  "-framework", "CoreImage",
  "-o", output
], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
if (result.status !== 0) {
  process.stderr.write(result.stderr || "QR helper build failed\n");
  process.exit(result.status || 1);
}
fs.chmodSync(output, 0o755);
process.stdout.write(`${output}\n`);
