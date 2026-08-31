"use strict";

/**
 * After CI lanes finish, remove known disposable build outputs and prove the
 * git worktree has no unexpected dirty tracked/untracked files.
 *
 * Installed dependencies (node_modules) and other gitignored paths are excluded
 * by `git status --porcelain --untracked-files=normal` once ignored.
 *
 * `rmDisposable` may accept an explicit absolute disposable root for isolated
 * unit tests. Production invocation (no override) always uses the real
 * repository root from discovery. Temporary overrides are validated with
 * realpath so symlink escapes outside the real temporary directory are rejected
 * before any deletion.
 */

const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ROOT } = require("./discovery.cjs");

const DISPOSABLE_DIRS = Object.freeze([
  "artifacts",
  "cache",
  "typechain-types",
  "coverage",
  "proving/target",
  "apps/philcore-desktop/build/preload"
]);

function isStrictDescendant(parent, child) {
  const relative = path.relative(parent, child);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function resolveDisposableRoot(disposableRoot = ROOT) {
  if (typeof disposableRoot !== "string" || disposableRoot.trim() === "") {
    throw new Error("DISPOSABLE_ROOT_EMPTY");
  }
  if (!path.isAbsolute(disposableRoot)) {
    throw new Error("DISPOSABLE_ROOT_NOT_ABSOLUTE");
  }
  const lexical = path.resolve(disposableRoot);
  if (lexical === path.parse(lexical).root) {
    throw new Error("DISPOSABLE_ROOT_FILESYSTEM_ROOT");
  }
  if (!fs.existsSync(disposableRoot)) {
    throw new Error("DISPOSABLE_ROOT_MISSING");
  }

  let realCandidate;
  let realRepoRoot;
  let realTmp;
  let realParent;
  try {
    realCandidate = fs.realpathSync(disposableRoot);
    realRepoRoot = fs.realpathSync(ROOT);
    realTmp = fs.realpathSync(os.tmpdir());
    realParent = fs.realpathSync(path.dirname(lexical));
  } catch {
    throw new Error("DISPOSABLE_ROOT_UNRESOLVABLE");
  }

  if (realCandidate === path.parse(realCandidate).root) {
    throw new Error("DISPOSABLE_ROOT_FILESYSTEM_ROOT");
  }

  const namedUnderTmp =
    realParent === realTmp || isStrictDescendant(realTmp, realParent);

  if (realCandidate === realRepoRoot) {
    if (namedUnderTmp) {
      throw new Error("DISPOSABLE_ROOT_SYMLINK_ESCAPE");
    }
    return realCandidate;
  }

  if (!isStrictDescendant(realTmp, realCandidate)) {
    throw new Error(
      namedUnderTmp ? "DISPOSABLE_ROOT_SYMLINK_ESCAPE" : "DISPOSABLE_ROOT_OUTSIDE_TMP"
    );
  }
  return realCandidate;
}

function rmDisposable(disposableRoot = ROOT) {
  const base = resolveDisposableRoot(disposableRoot);
  for (const rel of DISPOSABLE_DIRS) {
    const abs = path.join(base, rel);
    fs.rmSync(abs, { recursive: true, force: true });
  }
}

function git(args) {
  const result = spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    shell: false
  });
  return {
    status: result.status === null ? 1 : result.status,
    stdout: result.stdout || "",
    stderr: result.stderr || ""
  };
}

function main() {
  rmDisposable();

  const diff = git(["diff", "--exit-code"]);
  if (diff.status !== 0) {
    console.error("git diff --exit-code failed; unexpected tracked modifications remain:");
    process.stdout.write(diff.stdout);
    process.stderr.write(diff.stderr);
    process.exit(1);
  }

  const status = git(["status", "--porcelain", "--untracked-files=normal"]);
  if (status.status !== 0) {
    console.error(status.stderr);
    process.exit(status.status);
  }

  const lines = status.stdout
    .split("\n")
    .map((l) => l.trimEnd())
    .filter(Boolean)
    // Local-only node_modules symlink must never be committed; treat as failure if present.
    .filter((line) => {
      // Allow nothing — any porcelain line is unexpected after disposable cleanup.
      return true;
    });

  if (lines.length > 0) {
    console.error("Unexpected dirty/untracked paths after disposable cleanup:");
    for (const line of lines) console.error(` ${line}`);
    process.exit(1);
  }

  console.log("Worktree clean after disposable build-output removal");
}

if (require.main === module) {
  main();
}

module.exports = { DISPOSABLE_DIRS, resolveDisposableRoot, rmDisposable };
