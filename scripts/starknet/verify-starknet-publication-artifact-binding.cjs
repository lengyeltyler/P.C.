const path = require("node:path");
const { spawnSync } = require("node:child_process");

const REPO_ROOT = path.resolve(__dirname, "../..");

const result = spawnSync(
  "node",
  ["scripts/starknet/validate-starknet-publication-config.cjs", ...process.argv.slice(2)],
  {
    cwd: REPO_ROOT,
    stdio: "inherit",
    shell: false
  }
);

process.exit(result.status || 0);
