#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ELECTRON_FRAMEWORK_ROOT = "Contents/Frameworks/Electron Framework.framework";
const ELECTRON_FRAMEWORK_ALLOWED_ROOT = new Set([
  "Electron Framework",
  "Helpers",
  "Libraries",
  "Resources",
  "Versions"
]);
const ELECTRON_FRAMEWORK_SYMLINKS = Object.freeze({
  "Electron Framework": "Versions/Current/Electron Framework",
  Helpers: "Versions/Current/Helpers",
  Libraries: "Versions/Current/Libraries",
  Resources: "Versions/Current/Resources"
});

function insideSignedContainer(value) {
  return value.split("/").some((part) => /\.(app|framework|xpc)$/u.test(part));
}

function issue(stage, offendingPath, fileType, location, reason) {
  return {
    stage,
    offendingPath,
    fileType,
    location,
    insideSignedCodeContainer: insideSignedContainer(offendingPath),
    reason
  };
}

function debrisReason(relative) {
  const parts = relative.split("/");
  const base = parts.at(-1);
  if (base?.startsWith("._")) return "appledouble";
  if (base === ".DS_Store") return "finder_metadata";
  if (parts.includes("__MACOSX")) return "macos_metadata_directory";
  return null;
}

function walk(root) {
  const results = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    const stat = fs.lstatSync(current);
    results.push({ current, stat });
    if (stat.isDirectory() && !stat.isSymbolicLink()) {
      for (const entry of fs.readdirSync(current)) stack.push(path.join(current, entry));
    }
  }
  return results;
}

function fileType(stat) {
  if (stat.isSymbolicLink()) return "symlink";
  if (stat.isDirectory()) return "directory";
  if (stat.isFile()) return "file";
  return "other";
}

function frameworkRootForApp(appPath) {
  return path.join(appPath, ...ELECTRON_FRAMEWORK_ROOT.split("/"));
}

function auditFilesystem(target, options = {}) {
  const stage = options.stage || "unspecified_filesystem_stage";
  const findings = [];
  const metadata = { extendedAttributes: [], quarantinePaths: [], resourceForkPaths: [], finderInfoPaths: [] };
  if (!fs.existsSync(target)) {
    findings.push(issue(stage, target, "missing", "filesystem", "artifact_missing"));
    return result(stage, target, "filesystem", findings, metadata);
  }
  const root = path.resolve(target);
  for (const { current, stat } of walk(root)) {
    const relative = path.relative(root, current).split(path.sep).join("/") || ".";
    const debris = debrisReason(relative);
    if (debris) findings.push(issue(stage, relative, fileType(stat), "filesystem", debris));
    if (!stat.isSymbolicLink()) continue;
    const linkTarget = fs.readlinkSync(current);
    const resolved = path.resolve(path.dirname(current), linkTarget);
    if (path.isAbsolute(linkTarget)) {
      findings.push(issue(stage, relative, "symlink", "filesystem", "absolute_symlink"));
    } else if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
      findings.push(issue(stage, relative, "symlink", "filesystem", "external_symlink"));
    } else if (!fs.existsSync(resolved)) {
      findings.push(issue(stage, relative, "symlink", "filesystem", "broken_symlink"));
    }
  }

  const appPath = root.endsWith(".app") ? root : null;
  if (appPath) {
    const frameworkRoot = frameworkRootForApp(appPath);
    if (!fs.existsSync(frameworkRoot)) {
      findings.push(issue(stage, ELECTRON_FRAMEWORK_ROOT, "missing", "filesystem", "electron_framework_missing"));
    } else {
      const rootEntries = fs.readdirSync(frameworkRoot);
      for (const entry of rootEntries) {
        if (!ELECTRON_FRAMEWORK_ALLOWED_ROOT.has(entry)) {
          const entryPath = `${ELECTRON_FRAMEWORK_ROOT}/${entry}`;
          findings.push(issue(stage, entryPath, fileType(fs.lstatSync(path.join(frameworkRoot, entry))), "filesystem", "unexpected_electron_framework_root_entry"));
        }
      }
      for (const [entry, expectedTarget] of Object.entries(ELECTRON_FRAMEWORK_SYMLINKS)) {
        const entryPath = path.join(frameworkRoot, entry);
        const relative = `${ELECTRON_FRAMEWORK_ROOT}/${entry}`;
        if (!fs.existsSync(entryPath) && !fs.lstatSync(frameworkRoot).isSymbolicLink()) {
          findings.push(issue(stage, relative, "missing", "filesystem", "framework_symlink_missing"));
          continue;
        }
        if (!fs.lstatSync(entryPath).isSymbolicLink()) {
          findings.push(issue(stage, relative, fileType(fs.lstatSync(entryPath)), "filesystem", "framework_entry_not_symlink"));
          continue;
        }
        const actualTarget = fs.readlinkSync(entryPath);
        if (actualTarget !== expectedTarget) {
          findings.push(issue(stage, relative, "symlink", "filesystem", `framework_symlink_target_mismatch:${actualTarget}`));
        }
      }
    }
  }

  if (process.platform === "darwin") {
    const xattrs = spawnSync("xattr", ["-lr", root], { encoding: "utf8" });
    for (const line of (xattrs.stdout || "").split(/\r?\n/u)) {
      const match = line.match(/^(.*): (com\.apple\.[^:]+):/u);
      if (!match) continue;
      const relative = path.relative(root, match[1]).split(path.sep).join("/") || ".";
      const attribute = match[2];
      metadata.extendedAttributes.push({ path: relative, attribute });
      if (attribute === "com.apple.quarantine") metadata.quarantinePaths.push(relative);
      if (attribute === "com.apple.ResourceFork") {
        metadata.resourceForkPaths.push(relative);
        findings.push(issue(stage, relative, "extended_attribute", "filesystem", "resource_fork"));
      }
      if (attribute === "com.apple.FinderInfo") {
        metadata.finderInfoPaths.push(relative);
        findings.push(issue(stage, relative, "extended_attribute", "filesystem", "finder_info"));
      }
    }
  }
  return result(stage, target, "filesystem", findings, metadata);
}

function zipEntries(zipPath) {
  const listed = spawnSync("zipinfo", ["-1", zipPath], { encoding: "utf8", maxBuffer: 100 * 1024 * 1024 });
  if (listed.status !== 0) throw new Error(`zipinfo_failed:${(listed.stderr || "").trim()}`);
  return listed.stdout.split(/\r?\n/u).filter(Boolean);
}

function auditArchive(zipPath, options = {}) {
  const stage = options.stage || "unspecified_archive_stage";
  const findings = [];
  if (!fs.existsSync(zipPath)) {
    findings.push(issue(stage, zipPath, "missing", "archive", "artifact_missing"));
    return result(stage, zipPath, "archive", findings, { entryCount: 0 });
  }
  const entries = zipEntries(zipPath);
  for (const entry of entries) {
    const debris = debrisReason(entry.replace(/\/$/u, ""));
    if (debris) findings.push(issue(stage, entry, entry.endsWith("/") ? "directory_entry" : "archive_entry", "archive", debris));
  }
  const frameworkMarker = `${ELECTRON_FRAMEWORK_ROOT}/`;
  const frameworkEntries = entries.filter((entry) => entry.includes(frameworkMarker));
  if (!frameworkEntries.length) {
    findings.push(issue(stage, ELECTRON_FRAMEWORK_ROOT, "missing", "archive", "electron_framework_missing"));
  } else {
    const rootEntries = new Set();
    for (const entry of frameworkEntries) {
      const suffix = entry.slice(entry.indexOf(frameworkMarker) + frameworkMarker.length);
      const first = suffix.split("/")[0];
      if (first) rootEntries.add(first);
    }
    for (const entry of rootEntries) {
      if (!ELECTRON_FRAMEWORK_ALLOWED_ROOT.has(entry)) {
        findings.push(issue(stage, `${ELECTRON_FRAMEWORK_ROOT}/${entry}`, "archive_entry", "archive", "unexpected_electron_framework_root_entry"));
      }
    }
    for (const required of ELECTRON_FRAMEWORK_ALLOWED_ROOT) {
      if (!rootEntries.has(required)) findings.push(issue(stage, `${ELECTRON_FRAMEWORK_ROOT}/${required}`, "missing", "archive", "framework_root_entry_missing"));
    }
  }
  return result(stage, zipPath, "archive", findings, { entryCount: entries.length });
}

function result(stage, target, location, findings, metadata) {
  return {
    auditFormat: "philcore-release-contamination-audit-v1",
    stage,
    target,
    location,
    pass: findings.length === 0,
    findingCount: findings.length,
    findings,
    metadata
  };
}

function assertAuditPassed(audit) {
  if (!audit.pass) throw new Error(`release_contamination_audit_failed\n${JSON.stringify(audit, null, 2)}`);
  return audit;
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!["--stage", "--app", "--zip"].includes(key)) throw new Error(`unknown_argument:${key}`);
    parsed[key.slice(2)] = argv[++index];
  }
  if (!parsed.stage || Boolean(parsed.app) === Boolean(parsed.zip)) {
    throw new Error("usage: release-contamination-audit.cjs --stage STAGE (--app APP | --zip ZIP)");
  }
  return parsed;
}

if (require.main === module) {
  try {
    const args = parseArgs(process.argv.slice(2));
    const audit = args.app ? auditFilesystem(args.app, { stage: args.stage }) : auditArchive(args.zip, { stage: args.stage });
    console.log(JSON.stringify(audit, null, 2));
    if (!audit.pass) process.exitCode = 1;
  } catch (error) {
    console.error(String(error.message || error));
    process.exitCode = 64;
  }
}

module.exports = {
  ELECTRON_FRAMEWORK_ALLOWED_ROOT,
  ELECTRON_FRAMEWORK_SYMLINKS,
  assertAuditPassed,
  auditArchive,
  auditFilesystem,
  debrisReason,
  zipEntries
};
