"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const {
  detectPlatform,
  loadAssets,
  resolvePlatformAssets,
  installPinnedStarknetToolchain,
  sha256File
} = require("../../scripts/ci/install-pinned-starknet-toolchain.cjs");
const {
  loadToolchain,
  parseVersion
} = require("../../scripts/starknet/check-starknet-toolchain.cjs");

function writeTinyTar({ archivePath, relativeBinaryPath, contents }) {
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-tar-stage-"));
  const binaryAbs = path.join(staging, relativeBinaryPath);
  fs.mkdirSync(path.dirname(binaryAbs), { recursive: true });
  fs.writeFileSync(binaryAbs, contents);
  fs.chmodSync(binaryAbs, 0o755);
  const format = archivePath.endsWith(".tar.gz") ? "tar.gz" : "tar";
  const args =
    format === "tar.gz"
      ? ["-czf", archivePath, "-C", staging, ...relativeBinaryPath.split("/").slice(0, 1)]
      : ["-cf", archivePath, "-C", staging, ...relativeBinaryPath.split("/").slice(0, 1)];
  // Include full relative tree from first path component
  const top = relativeBinaryPath.split("/")[0];
  const tarArgs =
    format === "tar.gz"
      ? ["-czf", archivePath, "-C", staging, top]
      : ["-cf", archivePath, "-C", staging, top];
  const result = spawnSync("tar", tarArgs, { encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  fs.rmSync(staging, { recursive: true, force: true });
  void args;
  return sha256File(archivePath);
}

describe("PhilCore pinned Starknet toolchain installer", function () {
  it("pins the project runtime versions used by the Starknet checker", function () {
    const toolchain = loadToolchain();
    assert.equal(toolchain.node.version, "26.0.0");
    assert.equal(toolchain.npm.version, "11.12.1");
    assert.equal(toolchain.starknetFoundry.version, "0.53.0");
    assert.equal(toolchain.starknetFoundry.required, true);
    assert.equal(toolchain.universalSierraCompiler.version, "2.10.0");
    assert.equal(toolchain.universalSierraCompiler.required, true);
    assert.equal(toolchain.proofScarb.version, "2.14.0");
    assert.equal(toolchain.nargo.version, "1.0.0-beta.16");
    assert.equal(toolchain.barretenberg.version, "3.0.0-nightly.20251104");
    assert.equal(Object.hasOwn(toolchain.node, "minimumVersion"), false);
  });

  it("preserves prerelease identifiers in exact tool versions", function () {
    assert.equal(parseVersion("nargo version = 1.0.0-beta.16"), "1.0.0-beta.16");
    assert.equal(parseVersion("3.0.0-nightly.20251104"), "3.0.0-nightly.20251104");
    assert.equal(parseVersion("scarb 2.15.0"), "2.15.0");
  });

  it("detects supported hosted and local platforms only", function () {
    assert.equal(detectPlatform("linux", "x64"), "linux-x86_64");
    assert.equal(detectPlatform("darwin", "arm64"), "darwin-arm64");
    assert.equal(detectPlatform("linux", "arm64"), null);
    assert.equal(detectPlatform("win32", "x64"), null);
  });

  it("loads committed asset pins with exact 2.15.0 URLs and sha256 values", function () {
    const assets = loadAssets();
    assert.equal(assets.version, "2.15.0");
    const linux = assets.platforms["linux-x86_64"];
    assert.equal(
      linux.scarb.url,
      "https://github.com/software-mansion/scarb/releases/download/v2.15.0/scarb-v2.15.0-x86_64-unknown-linux-gnu.tar.gz"
    );
    assert.equal(
      linux.scarb.sha256,
      "119536045813331ab24c8993b3171f26d62e471368fc305d01e4c3a0c4324eba"
    );
    assert.equal(
      linux.proofScarb.sha256,
      "46cc07f23cac9e03dedbd6ddc73f56015bbcf3bcc5905ead95dd1c8ca50044c4"
    );
    assert.equal(
      linux.cairo.url,
      "https://github.com/starkware-libs/cairo/releases/download/v2.15.0/release-x86_64-unknown-linux-musl.tar.gz"
    );
    assert.equal(
      linux.cairo.sha256,
      "1f49ace7c20d229e304243aed5e9bb2c743a2da9c056cae005215d11192aaea7"
    );
    assert.equal(
      linux.foundry.url,
      "https://github.com/foundry-rs/starknet-foundry/releases/download/v0.53.0/starknet-foundry-v0.53.0-x86_64-unknown-linux-gnu.tar.gz"
    );
    assert.equal(
      linux.foundry.sha256,
      "c86303498a104c9e82cb4b9b7141cd596c09e98ddd79cb7ea3f67faa151f64cf"
    );
    assert.equal(
      linux.universalSierraCompiler.sha256,
      "eafa433885c32947fbe640937a12543d468a0e2905b62c177f0fd8099285c1b9"
    );
    assert.equal(
      linux.nargo.sha256,
      "246b4fe8a694c085d384c74319301600e2ec5a7c337d51006398393d023eaf11"
    );
    assert.equal(
      linux.barretenberg.sha256,
      "c6dae1092fed8d1230c2345ffcf4c903a2d787d0e220e9ea8c94b0511ed29c9b"
    );
  });

  it("rejects an unsupported/wrong platform", async function () {
    await assert.rejects(
      () =>
        installPinnedStarknetToolchain({
          platformKey: "windows-x86_64",
          assets: loadAssets()
        }),
      /no pinned Starknet toolchain assets for platform/
    );
    assert.throws(
      () => resolvePlatformAssets(loadAssets(), null),
      /unsupported platform/
    );
  });

  it("rejects a wrong checksum before installation", async function () {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-home-"));
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-work-"));
    const archivePath = path.join(workDir, "scarb-fake.tar.gz");
    const sha = writeTinyTar({
      archivePath,
      relativeBinaryPath: "scarb-v2.15.0-fake/bin/scarb",
      contents: "#!/bin/sh\necho scarb 2.15.0\n"
    });
    const assets = {
      version: "2.15.0",
      installRoots: {
        scarb: path.join(home, ".cache/philcore/toolchains/scarb-v2.15.0"),
        cairo: path.join(home, ".cache/philcore/toolchains/cairo-v2.15.0")
      },
      platforms: {
        "linux-x86_64": {
          scarb: {
            url: `file://${archivePath}`,
            sha256: "0".repeat(64),
            archiveFormat: "tar.gz",
            binaryRelativePath: "scarb-v2.15.0-fake/bin/scarb"
          },
          cairo: {
            url: `file://${archivePath}`,
            sha256: sha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "cairo/bin/cairo-execute"
          }
        }
      }
    };

    await assert.rejects(
      () =>
        installPinnedStarknetToolchain({
          assets,
          platformKey: "linux-x86_64",
          home,
          workDir,
          fetchImpl: async (url, dest) => {
            const src = url.replace("file://", "");
            fs.copyFileSync(src, dest);
          }
        }),
      /checksum mismatch/
    );
  });

  it("rejects a missing asset download", async function () {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-home-"));
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-work-"));
    const assets = {
      version: "2.15.0",
      installRoots: {
        scarb: path.join(home, ".cache/philcore/toolchains/scarb-v2.15.0"),
        cairo: path.join(home, ".cache/philcore/toolchains/cairo-v2.15.0")
      },
      platforms: {
        "linux-x86_64": {
          scarb: {
            url: "https://example.invalid/missing-scarb.tar.gz",
            sha256: "11".repeat(32),
            archiveFormat: "tar.gz",
            binaryRelativePath: "scarb-v2.15.0-x86_64-unknown-linux-gnu/bin/scarb"
          },
          cairo: {
            url: "https://example.invalid/missing-cairo.tar.gz",
            sha256: "22".repeat(32),
            archiveFormat: "tar.gz",
            binaryRelativePath: "cairo/bin/cairo-execute"
          }
        }
      }
    };

    await assert.rejects(
      () =>
        installPinnedStarknetToolchain({
          assets,
          platformKey: "linux-x86_64",
          home,
          workDir,
          fetchImpl: async () => {
            throw new Error("download failed: missing asset");
          }
        }),
      /download failed: missing asset/
    );
  });

  it("installs into the expected PhilCore cache layout on successful verify", async function () {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-home-"));
    const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-work-"));
    const scarbArchive = path.join(workDir, "scarb.tar.gz");
    const proofScarbArchive = path.join(workDir, "proof-scarb.tar.gz");
    const cairoArchive = path.join(workDir, "cairo.tar.gz");
    const foundryArchive = path.join(workDir, "foundry.tar.gz");
    const universalSierraCompilerArchive = path.join(workDir, "usc.tar.gz");
    const nargoArchive = path.join(workDir, "nargo.tar.gz");
    const barretenbergArchive = path.join(workDir, "barretenberg.tar.gz");
    const scarbSha = writeTinyTar({
      archivePath: scarbArchive,
      relativeBinaryPath: "scarb-v2.15.0-fake/bin/scarb",
      contents: "#!/bin/sh\necho 'scarb 2.15.0'\n"
    });
    const proofScarbSha = writeTinyTar({
      archivePath: proofScarbArchive,
      relativeBinaryPath: "scarb-v2.14.0-fake/bin/scarb",
      contents: "#!/bin/sh\necho 'scarb 2.14.0'\n"
    });
    const cairoSha = writeTinyTar({
      archivePath: cairoArchive,
      relativeBinaryPath: "cairo/bin/cairo-execute",
      contents: "#!/bin/sh\necho 'cairo-execute 2.15.0'\n"
    });
    const foundrySha = writeTinyTar({
      archivePath: foundryArchive,
      relativeBinaryPath: "starknet-foundry-v0.53.0-fake/bin/snforge",
      contents: "#!/bin/sh\necho 'snforge 0.53.0'\n"
    });
    const universalSierraCompilerSha = writeTinyTar({
      archivePath: universalSierraCompilerArchive,
      relativeBinaryPath: "universal-sierra-compiler-v2.10.0-fake/bin/universal-sierra-compiler",
      contents: "#!/bin/sh\necho 'universal-sierra-compiler 2.10.0'\n"
    });
    const nargoSha = writeTinyTar({
      archivePath: nargoArchive,
      relativeBinaryPath: "nargo",
      contents: "#!/bin/sh\necho 'nargo 1.0.0-beta.16'\n"
    });
    const barretenbergSha = writeTinyTar({
      archivePath: barretenbergArchive,
      relativeBinaryPath: "bb",
      contents: "#!/bin/sh\necho 'bb 3.0.0-nightly.20251104'\n"
    });

    const assets = {
      version: "2.15.0",
      installRoots: {
        scarb: "~/.cache/philcore/toolchains/scarb-v2.15.0",
        proofScarb: "~/.cache/philcore/toolchains/scarb-v2.14.0",
        cairo: "~/.cache/philcore/toolchains/cairo-v2.15.0",
        foundry: "~/.cache/philcore/toolchains/starknet-foundry-v0.53.0",
        universalSierraCompiler: "~/.cache/philcore/toolchains/universal-sierra-compiler-v2.10.0",
        nargo: "~/.cache/phil-v1-step3/toolchains/nargo-1.0.0-beta.16",
        barretenberg: "~/.cache/phil-v1-step3/toolchains/bb-3.0.0-nightly.20251104"
      },
      platforms: {
        "linux-x86_64": {
          scarb: {
            url: `file://${scarbArchive}`,
            sha256: scarbSha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "scarb-v2.15.0-fake/bin/scarb"
          },
          proofScarb: {
            url: `file://${proofScarbArchive}`,
            sha256: proofScarbSha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "scarb-v2.14.0-fake/bin/scarb"
          },
          cairo: {
            url: `file://${cairoArchive}`,
            sha256: cairoSha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "cairo/bin/cairo-execute"
          },
          foundry: {
            url: `file://${foundryArchive}`,
            sha256: foundrySha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "starknet-foundry-v0.53.0-fake/bin/snforge"
          },
          universalSierraCompiler: {
            url: `file://${universalSierraCompilerArchive}`,
            sha256: universalSierraCompilerSha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "universal-sierra-compiler-v2.10.0-fake/bin/universal-sierra-compiler"
          },
          nargo: {
            url: `file://${nargoArchive}`,
            sha256: nargoSha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "nargo",
            installSubdirectory: "."
          },
          barretenberg: {
            url: `file://${barretenbergArchive}`,
            sha256: barretenbergSha,
            archiveFormat: "tar.gz",
            binaryRelativePath: "bb",
            installSubdirectory: "."
          }
        }
      }
    };

    const result = await installPinnedStarknetToolchain({
      assets,
      platformKey: "linux-x86_64",
      home,
      workDir: path.join(workDir, "extract-work"),
      fetchImpl: async (url, dest) => {
        fs.copyFileSync(url.replace("file://", ""), dest);
      }
    });

    assert.equal(
      result.scarb.binary,
      path.join(home, ".cache/philcore/toolchains/scarb-v2.15.0/bin/scarb")
    );
    assert.equal(
      result.proofScarb.binary,
      path.join(home, ".cache/philcore/toolchains/scarb-v2.14.0/bin/scarb")
    );
    assert.equal(
      result.cairo.binary,
      path.join(home, ".cache/philcore/toolchains/cairo-v2.15.0/bin/cairo-execute")
    );
    assert.equal(
      result.foundry.binary,
      path.join(home, ".cache/philcore/toolchains/starknet-foundry-v0.53.0/bin/snforge")
    );
    assert.equal(
      result.universalSierraCompiler.binary,
      path.join(
        home,
        ".cache/philcore/toolchains/universal-sierra-compiler-v2.10.0/bin/universal-sierra-compiler"
      )
    );
    assert.equal(
      result.nargo.binary,
      path.join(home, ".cache/phil-v1-step3/toolchains/nargo-1.0.0-beta.16/nargo")
    );
    assert.equal(
      result.barretenberg.binary,
      path.join(home, ".cache/phil-v1-step3/toolchains/bb-3.0.0-nightly.20251104/bb")
    );
    assert.equal(fs.existsSync(result.scarb.binary), true);
    assert.equal(fs.existsSync(result.proofScarb.binary), true);
    assert.equal(fs.existsSync(result.cairo.binary), true);
    assert.equal(fs.existsSync(result.foundry.binary), true);
    assert.equal(fs.existsSync(result.universalSierraCompiler.binary), true);
    assert.equal(fs.existsSync(result.nargo.binary), true);
    assert.equal(fs.existsSync(result.barretenberg.binary), true);
    assert.equal(result.scarb.sha256, scarbSha);
    assert.equal(result.proofScarb.sha256, proofScarbSha);
    assert.equal(result.cairo.sha256, cairoSha);
    assert.equal(result.foundry.sha256, foundrySha);
    assert.equal(result.universalSierraCompiler.sha256, universalSierraCompilerSha);
    assert.equal(result.nargo.sha256, nargoSha);
    assert.equal(result.barretenberg.sha256, barretenbergSha);
  });
});
