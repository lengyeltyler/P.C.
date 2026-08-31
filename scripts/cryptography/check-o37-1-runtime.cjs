const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");
const EXPECTED_NODE = "26.0.0";
const EXPECTED_NPM = "11.12.1";
const EXPECTED_PACKAGE_MANAGER = `npm@${EXPECTED_NPM}`;
const EXPECTED_LOCKFILE_VERSION = 3;

function read(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function fail(code, actual, expected) {
  throw new Error(`${code}:${String(actual)}:${String(expected)}`);
}

const packageJson = JSON.parse(read("package.json"));
const packageLock = JSON.parse(read("package-lock.json"));
const nodeVersionFile = read(".node-version").trim();
const npmUserAgent = String(process.env.npm_config_user_agent || "");
const npmVersion = /^npm\/([^\s]+)/.exec(npmUserAgent)?.[1] || "";

if (process.versions.node !== EXPECTED_NODE) {
  fail("O37_1_NODE_VERSION_MISMATCH", process.versions.node, EXPECTED_NODE);
}
if (npmVersion !== EXPECTED_NPM) {
  fail("O37_1_NPM_VERSION_MISMATCH", npmVersion || "unavailable", EXPECTED_NPM);
}
if (nodeVersionFile !== EXPECTED_NODE) {
  fail("O37_1_NODE_VERSION_FILE_MISMATCH", nodeVersionFile, EXPECTED_NODE);
}
if (packageJson.engines?.node !== EXPECTED_NODE) {
  fail("O37_1_PACKAGE_NODE_ENGINE_MISMATCH", packageJson.engines?.node, EXPECTED_NODE);
}
if (packageJson.engines?.npm !== EXPECTED_NPM) {
  fail("O37_1_PACKAGE_NPM_ENGINE_MISMATCH", packageJson.engines?.npm, EXPECTED_NPM);
}
if (packageJson.packageManager !== EXPECTED_PACKAGE_MANAGER) {
  fail(
    "O37_1_PACKAGE_MANAGER_MISMATCH",
    packageJson.packageManager,
    EXPECTED_PACKAGE_MANAGER
  );
}
if (packageLock.lockfileVersion !== EXPECTED_LOCKFILE_VERSION) {
  fail(
    "O37_1_LOCKFILE_VERSION_MISMATCH",
    packageLock.lockfileVersion,
    EXPECTED_LOCKFILE_VERSION
  );
}
if (packageLock.packages?.[""]?.engines?.node !== EXPECTED_NODE) {
  fail(
    "O37_1_LOCK_ROOT_NODE_ENGINE_MISMATCH",
    packageLock.packages?.[""]?.engines?.node,
    EXPECTED_NODE
  );
}
if (packageLock.packages?.[""]?.engines?.npm !== EXPECTED_NPM) {
  fail(
    "O37_1_LOCK_ROOT_NPM_ENGINE_MISMATCH",
    packageLock.packages?.[""]?.engines?.npm,
    EXPECTED_NPM
  );
}

process.stdout.write(
  `O.37.1 runtime verified: Node ${EXPECTED_NODE}, npm ${EXPECTED_NPM}, lockfile v${EXPECTED_LOCKFILE_VERSION}\n`
);
