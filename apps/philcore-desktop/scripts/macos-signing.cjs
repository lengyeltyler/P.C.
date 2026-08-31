const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  appClaimsExactKeychainGroup
} = require("./developer-id-profile-authorization.cjs");
const { appRoot, run } = require("./release-utils.cjs");

const ENTITLEMENTS = {
  application: path.join(appRoot, "build", "entitlements.mac.plist"),
  applicationAdhoc: path.join(appRoot, "build", "entitlements.mac-adhoc.plist"),
  child: path.join(appRoot, "build", "entitlements.child.plist"),
  childAdhoc: path.join(appRoot, "build", "entitlements.child-adhoc.plist"),
  binary: path.join(appRoot, "build", "entitlements.binary.plist")
};

function isMachO(filePath) {
  if (!fs.lstatSync(filePath).isFile()) return false;
  // Compiler object files are sealed as bundle resources. Signing them relies on
  // xattrs that are intentionally stripped by the release ZIP's --norsrc path.
  if (filePath.endsWith(".o")) return false;
  const fd = fs.openSync(filePath, "r");
  try {
    const value = Buffer.alloc(4);
    if (fs.readSync(fd, value, 0, 4, 0) !== 4) return false;
    return [0xfeedface, 0xcefaedfe, 0xfeedfacf, 0xcffaedfe, 0xcafebabe, 0xbebafeca].includes(value.readUInt32BE(0));
  } finally {
    fs.closeSync(fd);
  }
}

function walk(root) {
  const items = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) continue;
    items.push({ path: current, stat });
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) stack.push(path.join(current, entry));
    }
  }
  return items;
}

function discoverSignableCode(appPath) {
  const all = walk(appPath);
  const bundles = all.filter(({ path: item, stat }) => stat.isDirectory() && /\.(app|framework|xpc)$/u.test(item));
  const bundleExecutables = new Set();
  for (const { path: bundle } of bundles) {
    if (!bundle.endsWith(".app") && !bundle.endsWith(".xpc")) continue;
    const plist = path.join(bundle, "Contents", "Info.plist");
    if (!fs.existsSync(plist)) continue;
    const result = spawnSync("/usr/libexec/PlistBuddy", ["-c", "Print :CFBundleExecutable", plist], { encoding: "utf8" });
    if (result.status === 0) bundleExecutables.add(path.join(bundle, "Contents", "MacOS", result.stdout.trim()));
  }
  const macho = all
    .filter(({ path: item, stat }) => stat.isFile() && isMachO(item) && !bundleExecutables.has(item))
    .map(({ path: item }) => ({ path: item, kind: /\.node$/u.test(item) ? "native_module" : /\.dylib$/u.test(item) ? "dylib" : "macho" }));
  const nestedBundles = bundles
    .filter(({ path: item }) => item !== appPath)
    .map(({ path: item }) => ({ path: item, kind: item.endsWith(".framework") ? "framework" : item.endsWith(".xpc") ? "xpc" : "helper_app" }));
  const depth = (item) => item.split(path.sep).length;
  return [...macho, ...nestedBundles].sort((a, b) => depth(b.path) - depth(a.path) || a.path.localeCompare(b.path));
}

function entitlementFor(item, options) {
  if (["helper_app", "xpc"].includes(item.kind)) return options.identity === "-" ? ENTITLEMENTS.childAdhoc : ENTITLEMENTS.child;
  return ENTITLEMENTS.binary;
}

function signOne(item, options) {
  const args = ["--force", "--sign", options.identity];
  if (options.hardenedRuntime) args.push("--options", "runtime");
  if (options.timestamp) args.push("--timestamp");
  args.push("--entitlements", entitlementFor(item, options), item.path);
  run("codesign", args, { stdio: "inherit" });
}

function signApplication(appPath, options) {
  const inventory = discoverSignableCode(appPath);
  const standalone = inventory.filter((item) => !["framework", "helper_app", "xpc"].includes(item.kind));
  const bundles = inventory.filter((item) => ["framework", "helper_app", "xpc"].includes(item.kind));
  for (const item of standalone) signOne(item, options);
  // Release metadata may hash signed standalone tools, but must be finalized
  // before any containing bundle or the top-level application is sealed.
  if (options.beforeBundles) options.beforeBundles(inventory);
  for (const item of bundles) signOne(item, options);
  const args = ["--force", "--sign", options.identity];
  if (options.hardenedRuntime) args.push("--options", "runtime");
  if (options.timestamp) args.push("--timestamp");
  args.push(
    "--entitlements",
    options.identity === "-" ? ENTITLEMENTS.applicationAdhoc : ENTITLEMENTS.application,
    appPath
  );
  run("codesign", args, { stdio: "inherit" });
  return inventory;
}

function verifyStrict(appPath) {
  run("codesign", ["--verify", "--deep", "--strict", "--verbose=4", appPath], { stdio: "inherit" });
  for (const item of discoverSignableCode(appPath)) {
    run("codesign", ["--verify", "--strict", "--verbose=2", item.path], { stdio: "inherit" });
  }
}

function inspectSignature(target) {
  const result = spawnSync("codesign", ["-dvvv", "--entitlements", ":-", target], { encoding: "utf8" });
  const output = `${result.stdout || ""}\n${result.stderr || ""}`;
  const read = (label) => output.match(new RegExp(`^${label}=(.+)$`, "mu"))?.[1]?.trim() || null;
  return {
    validInspection: result.status === 0,
    authority: read("Authority"),
    teamIdentifier: read("TeamIdentifier"),
    timestamp: read("Timestamp"),
    runtime: /flags=.*runtime/iu.test(output),
    entitlements: (() => {
      const start = output.indexOf("<plist");
      const end = output.indexOf("</plist>", start);
      return start >= 0 && end >= 0 ? output.slice(start, end + "</plist>".length) : "";
    })()
  };
}

function parseEntitlements(plist) {
  const result = spawnSync(
    "plutil",
    ["-convert", "json", "-o", "-", "-"],
    { encoding: "utf8", input: plist }
  );
  if (result.status !== 0) throw new Error("Signed application entitlements could not be decoded");
  return JSON.parse(result.stdout);
}

function verifyDeveloperId(appPath, expectedAuthority, expectedTeamId, requiredKeychainGroup) {
  verifyStrict(appPath);
  const targets = [...discoverSignableCode(appPath).map((item) => item.path), appPath];
  const inspections = targets.map((target) => ({ target, ...inspectSignature(target) }));
  for (const item of inspections) {
    if (!item.validInspection || item.authority !== expectedAuthority || item.teamIdentifier !== expectedTeamId) {
      throw new Error(`Developer ID authority or Team ID mismatch: ${item.target}`);
    }
    if (!item.timestamp) throw new Error(`Developer ID timestamp missing: ${item.target}`);
  }
  const applicationInspection = inspections.at(-1);
  if (!applicationInspection.runtime) throw new Error("Top-level hardened runtime flag missing");
  const applicationEntitlements = parseEntitlements(applicationInspection.entitlements);
  if (
    applicationEntitlements["com.apple.application-identifier"]
      !== `${expectedTeamId}.com.philcore.desktop.localalpha`
    || !appClaimsExactKeychainGroup(
      applicationEntitlements["keychain-access-groups"],
      requiredKeychainGroup,
      expectedTeamId
    )
  ) {
    throw new Error("Signed application entitlement identity mismatch");
  }
  return inspections;
}

module.exports = { ENTITLEMENTS, discoverSignableCode, inspectSignature, signApplication, verifyDeveloperId, verifyStrict };
