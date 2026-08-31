"use strict";

/**
 * Deterministic installer for the pinned Starknet proof toolchain.
 *
 * - Uses official GitHub release assets only
 * - Verifies SHA-256 before extraction
 * - Installs into the PhilCore cache layout expected by
 *   config/starknet-toolchain.json and scripts/starknet/activate-pinned-toolchain.sh
 *
 * This is not a floating installer and never uses curl|sh.
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const https = require("node:https");
const http = require("node:http");

const ROOT = path.resolve(__dirname, "../..");
const DEFAULT_ASSETS_PATH = path.join(ROOT, "config/ci/starknet-toolchain-assets.json");

function expandHome(value, home = process.env.HOME || os.homedir()) {
  if (!value || typeof value !== "string") return value;
  if (value === "~") return home;
  if (value.startsWith("~/")) return path.join(home, value.slice(2));
  return value;
}

function detectPlatform(platform = process.platform, arch = process.arch) {
  if (platform === "linux" && arch === "x64") return "linux-x86_64";
  if (platform === "darwin" && arch === "arm64") return "darwin-arm64";
  return null;
}

function loadAssets(assetsPath = DEFAULT_ASSETS_PATH) {
  return JSON.parse(fs.readFileSync(assetsPath, "utf8"));
}

function sha256File(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function downloadToFile(url, destPath, { fetchImpl } = {}) {
  if (typeof fetchImpl === "function") {
    return fetchImpl(url, destPath);
  }

  return new Promise((resolve, reject) => {
    const client = url.startsWith("https:") ? https : http;
    const request = client.get(url, { headers: { "User-Agent": "philcore-ci-toolchain-installer" } }, (response) => {
      if (
        response.statusCode >= 300 &&
        response.statusCode < 400 &&
        response.headers.location
      ) {
        response.resume();
        downloadToFile(response.headers.location, destPath, { fetchImpl })
          .then(resolve)
          .catch(reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`download failed: ${url} -> HTTP ${response.statusCode}`));
        return;
      }
      const out = fs.createWriteStream(destPath);
      response.pipe(out);
      out.on("finish", () => out.close(() => resolve(destPath)));
      out.on("error", reject);
    });
    request.on("error", reject);
  });
}

function runTarExtract(archivePath, destDir, archiveFormat) {
  fs.mkdirSync(destDir, { recursive: true });
  const args =
    archiveFormat === "tar.gz"
      ? ["-xzf", archivePath, "-C", destDir]
      : ["-xf", archivePath, "-C", destDir];
  const result = spawnSync("tar", args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(
      `tar extract failed for ${archivePath}: ${result.stderr || result.stdout || "unknown error"}`
    );
  }
}

function installBinaryFromArchive({
  archivePath,
  archiveFormat,
  extractRoot,
  binaryRelativePath,
  installBinDir
}) {
  runTarExtract(archivePath, extractRoot, archiveFormat);
  const sourceBinary = path.join(extractRoot, binaryRelativePath);
  if (!fs.existsSync(sourceBinary)) {
    throw new Error(`missing expected binary in archive: ${binaryRelativePath}`);
  }
  fs.mkdirSync(installBinDir, { recursive: true });
  const destBinary = path.join(installBinDir, path.basename(sourceBinary));
  fs.copyFileSync(sourceBinary, destBinary);
  fs.chmodSync(destBinary, 0o755);
  return destBinary;
}

function resolvePlatformAssets(assets, platformKey) {
  if (!platformKey) {
    throw new Error(
      "unsupported platform for pinned Starknet toolchain install (need linux-x86_64 or darwin-arm64)"
    );
  }
  const platform = assets.platforms[platformKey];
  if (!platform) {
    throw new Error(`no pinned Starknet toolchain assets for platform: ${platformKey}`);
  }
  return platform;
}

async function installComponent({
  name,
  component,
  workDir,
  installRoot,
  fetchImpl
}) {
  if (!component || !component.url || !component.sha256) {
    throw new Error(`missing asset metadata for ${name}`);
  }
  const archiveName = path.basename(new URL(component.url).pathname);
  const archivePath = path.join(workDir, archiveName);
  await downloadToFile(component.url, archivePath, { fetchImpl });
  const actual = sha256File(archivePath);
  if (actual !== component.sha256) {
    throw new Error(
      `${name} checksum mismatch for ${archiveName}: expected ${component.sha256}, got ${actual}`
    );
  }
  const extractRoot = path.join(workDir, `${name}-extract`);
  fs.rmSync(extractRoot, { recursive: true, force: true });
  const installBinDir = path.join(installRoot, component.installSubdirectory || "bin");
  const binaryPath = installBinaryFromArchive({
    archivePath,
    archiveFormat: component.archiveFormat,
    extractRoot,
    binaryRelativePath: component.binaryRelativePath,
    installBinDir
  });
  return { binaryPath, sha256: actual, url: component.url };
}

async function installPinnedStarknetToolchain(options = {}) {
  const assetsPath = options.assetsPath || DEFAULT_ASSETS_PATH;
  const assets = options.assets || loadAssets(assetsPath);
  const platformKey =
    options.platformKey || detectPlatform(options.platform, options.arch);
  const platformAssets = resolvePlatformAssets(assets, platformKey);
  const home = options.home || process.env.HOME || os.homedir();
  const scarbRoot = expandHome(assets.installRoots.scarb, home);
  const proofScarbRoot = expandHome(assets.installRoots.proofScarb, home);
  const cairoRoot = expandHome(assets.installRoots.cairo, home);
  const foundryRoot = expandHome(assets.installRoots.foundry, home);
  const universalSierraCompilerRoot = expandHome(
    assets.installRoots.universalSierraCompiler,
    home
  );
  const nargoRoot = expandHome(assets.installRoots.nargo, home);
  const barretenbergRoot = expandHome(assets.installRoots.barretenberg, home);
  const ownsWorkDir = !options.workDir;
  const workDir =
    options.workDir ||
    fs.mkdtempSync(path.join(os.tmpdir(), "philcore-starknet-toolchain-"));

  fs.mkdirSync(workDir, { recursive: true });

  try {
    const scarb = await installComponent({
      name: "scarb",
      component: platformAssets.scarb,
      workDir,
      installRoot: scarbRoot,
      fetchImpl: options.fetchImpl
    });
    const proofScarb = await installComponent({
      name: "proof-scarb",
      component: platformAssets.proofScarb,
      workDir,
      installRoot: proofScarbRoot,
      fetchImpl: options.fetchImpl
    });
    const cairo = await installComponent({
      name: "cairo",
      component: platformAssets.cairo,
      workDir,
      installRoot: cairoRoot,
      fetchImpl: options.fetchImpl
    });
    const foundry = await installComponent({
      name: "foundry",
      component: platformAssets.foundry,
      workDir,
      installRoot: foundryRoot,
      fetchImpl: options.fetchImpl
    });
    const universalSierraCompiler = await installComponent({
      name: "universal-sierra-compiler",
      component: platformAssets.universalSierraCompiler,
      workDir,
      installRoot: universalSierraCompilerRoot,
      fetchImpl: options.fetchImpl
    });
    const nargo = await installComponent({
      name: "nargo",
      component: platformAssets.nargo,
      workDir,
      installRoot: nargoRoot,
      fetchImpl: options.fetchImpl
    });
    const barretenberg = await installComponent({
      name: "barretenberg",
      component: platformAssets.barretenberg,
      workDir,
      installRoot: barretenbergRoot,
      fetchImpl: options.fetchImpl
    });

    return {
      platformKey,
      version: assets.version,
      scarb: {
        root: scarbRoot,
        binary: scarb.binaryPath,
        url: scarb.url,
        sha256: scarb.sha256
      },
      proofScarb: {
        root: proofScarbRoot,
        binary: proofScarb.binaryPath,
        url: proofScarb.url,
        sha256: proofScarb.sha256
      },
      cairo: {
        root: cairoRoot,
        binary: cairo.binaryPath,
        url: cairo.url,
        sha256: cairo.sha256
      },
      foundry: {
        root: foundryRoot,
        binary: foundry.binaryPath,
        url: foundry.url,
        sha256: foundry.sha256
      },
      universalSierraCompiler: {
        root: universalSierraCompilerRoot,
        binary: universalSierraCompiler.binaryPath,
        url: universalSierraCompiler.url,
        sha256: universalSierraCompiler.sha256
      },
      nargo: {
        root: nargoRoot,
        binary: nargo.binaryPath,
        url: nargo.url,
        sha256: nargo.sha256
      },
      barretenberg: {
        root: barretenbergRoot,
        binary: barretenberg.binaryPath,
        url: barretenberg.url,
        sha256: barretenberg.sha256
      }
    };
  } finally {
    if (ownsWorkDir) fs.rmSync(workDir, { recursive: true, force: true });
  }
}

function prependPinnedToolchainPath(env = process.env, home = process.env.HOME || os.homedir()) {
  const scarbBin = path.join(expandHome("~/.cache/philcore/toolchains/scarb-v2.15.0", home), "bin");
  const cairoBin = path.join(expandHome("~/.cache/philcore/toolchains/cairo-v2.15.0", home), "bin");
  const foundryBin = path.join(expandHome("~/.cache/philcore/toolchains/starknet-foundry-v0.53.0", home), "bin");
  const universalSierraCompilerBin = path.join(
    expandHome("~/.cache/philcore/toolchains/universal-sierra-compiler-v2.10.0", home),
    "bin"
  );
  const next = { ...env };
  next.PATH = `${scarbBin}${path.delimiter}${cairoBin}${path.delimiter}${foundryBin}${path.delimiter}${universalSierraCompilerBin}${path.delimiter}${env.PATH || ""}`;
  return next;
}

function prependPinnedProofToolchainPath(
  env = process.env,
  home = process.env.HOME || os.homedir()
) {
  const proofScarbBin = path.join(
    expandHome("~/.cache/philcore/toolchains/scarb-v2.14.0", home),
    "bin"
  );
  const next = prependPinnedToolchainPath(env, home);
  next.PATH = `${proofScarbBin}${path.delimiter}${next.PATH}`;
  return next;
}

async function main() {
  const result = await installPinnedStarknetToolchain();
  console.log("Installed pinned Starknet toolchain:");
  console.log(`- platform: ${result.platformKey}`);
  console.log(`- scarb: ${result.scarb.binary}`);
  console.log(`- proof scarb: ${result.proofScarb.binary}`);
  console.log(`- cairo-execute: ${result.cairo.binary}`);
  console.log(`- snforge: ${result.foundry.binary}`);
  console.log(`- universal-sierra-compiler: ${result.universalSierraCompiler.binary}`);
  console.log(`- nargo: ${result.nargo.binary}`);
  console.log(`- bb: ${result.barretenberg.binary}`);
  console.log(`- scarb sha256: ${result.scarb.sha256}`);
  console.log(`- proof Scarb sha256: ${result.proofScarb.sha256}`);
  console.log(`- cairo sha256: ${result.cairo.sha256}`);
  console.log(`- Starknet Foundry sha256: ${result.foundry.sha256}`);
  console.log(`- Universal Sierra Compiler sha256: ${result.universalSierraCompiler.sha256}`);
  console.log(`- Nargo sha256: ${result.nargo.sha256}`);
  console.log(`- Barretenberg sha256: ${result.barretenberg.sha256}`);

  const env = prependPinnedToolchainPath();
  const scarbVersion = spawnSync(result.scarb.binary, ["--version"], {
    encoding: "utf8",
    env
  });
  const proofScarbVersion = spawnSync(result.proofScarb.binary, ["--version"], {
    encoding: "utf8",
    env
  });
  const cairoVersion = spawnSync(result.cairo.binary, ["--version"], {
    encoding: "utf8",
    env
  });
  const foundryVersion = spawnSync(result.foundry.binary, ["--version"], {
    encoding: "utf8",
    env
  });
  const universalSierraCompilerVersion = spawnSync(
    result.universalSierraCompiler.binary,
    ["--version"],
    { encoding: "utf8", env }
  );
  const nargoVersion = spawnSync(result.nargo.binary, ["--version"], {
    encoding: "utf8",
    env
  });
  const barretenbergVersion = spawnSync(result.barretenberg.binary, ["--version"], {
    encoding: "utf8",
    env
  });
  process.stdout.write(scarbVersion.stdout || "");
  process.stderr.write(scarbVersion.stderr || "");
  process.stdout.write(proofScarbVersion.stdout || "");
  process.stderr.write(proofScarbVersion.stderr || "");
  process.stdout.write(cairoVersion.stdout || "");
  process.stderr.write(cairoVersion.stderr || "");
  process.stdout.write(foundryVersion.stdout || "");
  process.stderr.write(foundryVersion.stderr || "");
  process.stdout.write(universalSierraCompilerVersion.stdout || "");
  process.stderr.write(universalSierraCompilerVersion.stderr || "");
  process.stdout.write(nargoVersion.stdout || "");
  process.stderr.write(nargoVersion.stderr || "");
  process.stdout.write(barretenbergVersion.stdout || "");
  process.stderr.write(barretenbergVersion.stderr || "");
  if (
    scarbVersion.status !== 0 ||
    proofScarbVersion.status !== 0 ||
    cairoVersion.status !== 0 ||
    foundryVersion.status !== 0 ||
    universalSierraCompilerVersion.status !== 0 ||
    nargoVersion.status !== 0 ||
    barretenbergVersion.status !== 0
  ) {
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message || error);
    process.exit(1);
  });
}

module.exports = {
  DEFAULT_ASSETS_PATH,
  detectPlatform,
  loadAssets,
  sha256File,
  expandHome,
  resolvePlatformAssets,
  installPinnedStarknetToolchain,
  prependPinnedToolchainPath,
  prependPinnedProofToolchainPath,
  installBinaryFromArchive
};
