#!/usr/bin/env node
const { appBundlePath, run } = require("./release-utils.cjs");

try {
  const result = run("spctl", ["--assess", "--type", "execute", "--verbose=4", appBundlePath]);
  console.log(JSON.stringify({ status: "passed", gatekeeperAccepted: true, output: result.stderr || result.stdout }, null, 2));
} catch (error) {
  console.log(JSON.stringify({
    status: "blocked_or_rejected",
    gatekeeperAccepted: false,
    reason: String(error.message).slice(0, 1000)
  }, null, 2));
}
