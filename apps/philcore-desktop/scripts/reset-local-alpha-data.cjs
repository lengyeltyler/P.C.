#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const APPROVAL_ENV = "PHILCORE_DESKTOP_RESET_LOCAL_ALPHA_APPROVED";
const approved = process.env[APPROVAL_ENV] === "1" || process.argv.includes("--yes");
const userDataDir = path.resolve(
  process.env.PHILCORE_DESKTOP_USER_DATA_DIR
    || path.join(os.homedir(), "Library", "Application Support", "PhilCore Desktop Local Alpha")
);
const home = path.resolve(os.homedir());
const allowedDefault = path.resolve(home, "Library", "Application Support", "PhilCore Desktop Local Alpha");
const targets = [
  path.join(userDataDir, "philcore-desktop-preferences.json"),
  path.join(userDataDir, "philcore-local-identities")
];

function fail(reason) {
  console.error(JSON.stringify({ status: "blocked", reason, userDataDir, targets }, null, 2));
  process.exit(1);
}

if (!userDataDir || userDataDir === "/" || userDataDir === home) fail("ambiguous_or_unsafe_user_data_dir");
if (userDataDir !== allowedDefault && !path.basename(userDataDir).toLowerCase().includes("philcore")) {
  fail("override_user_data_dir_must_be_philcore_specific");
}
for (const target of targets) {
  const resolved = path.resolve(target);
  if (!resolved.startsWith(`${userDataDir}${path.sep}`)) fail("target_escapes_user_data_dir");
}

const existingTargets = targets.filter((target) => fs.existsSync(target));
const report = {
  status: approved ? "reset_performed" : "approval_required",
  approved,
  approval: `${APPROVAL_ENV}=1`,
  userDataDir,
  targets,
  existingTargets,
  removesPackagedApplication: false,
  removesSourceCode: false,
  removesKeychainItems: false,
  note: "Protected Mac unlock credentials stored by macOS may require separate cleanup if the platform adapter created external items."
};

if (!approved) {
  report.nextCommand = `${APPROVAL_ENV}=1 npm run desktop:reset-local-alpha-data`;
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

for (const target of existingTargets) {
  const stat = fs.lstatSync(target);
  if (stat.isDirectory()) fs.rmSync(target, { recursive: true, force: true });
  else fs.rmSync(target, { force: true });
}

console.log(JSON.stringify(report, null, 2));
