#!/usr/bin/env node
const { spawnSync } = require("node:child_process");

const suites = [
  "apps/philcore-desktop/test/desktop-platform-webauthn.test.cjs",
  "apps/philcore-desktop/test/desktop-recovery-secure-origin.test.cjs",
  "apps/philcore-desktop/test/desktop-recovery-enrollment.test.cjs",
  "apps/philcore-desktop/test/desktop-native-iphone-pairing.test.cjs",
  "apps/philcore-desktop/test/desktop-preload-packaging.test.cjs",
  "apps/philcore-desktop/test/desktop-package-pruning.test.cjs",
  "apps/philcore-desktop/test/desktop-renderer-startup.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-authorization-ui-state.test.cjs",
  "apps/philcore-desktop/test/desktop-sepolia-mint-ui-state.test.cjs",
  "apps/philcore-desktop/test/desktop-routine-enrollment-urlsession-integration.test.cjs",
  "apps/philcore-desktop/test/desktop-alpha-product.test.cjs",
  "apps/philcore-desktop/test/desktop-controlled-beta-ui-pass-a.test.cjs",
  "apps/philcore-desktop/test/desktop-controlled-beta-ui-pass-b.test.cjs",
  "apps/philcore-desktop/test/desktop-controlled-beta-ui-pass-c.test.cjs",
  "apps/philcore-desktop/test/desktop-controlled-beta-ui-pass-d.test.cjs",
  "apps/philcore-desktop/test/desktop-release-artifact-continuity.test.cjs",
  "apps/philcore-desktop/test/desktop-philenator-engine.test.cjs",
  "apps/philcore-desktop/test/desktop-bridge.test.cjs",
  "apps/philcore-desktop/test/desktop-runtime-host.test.cjs",
  "apps/philcore-desktop/test/desktop-reset-local-alpha.test.cjs",
  "apps/philcore-desktop/test/desktop-storage-restart.test.cjs",
  "apps/philcore-desktop/test/desktop-platform-auth.test.cjs",
  "apps/philcore-desktop/test/desktop-user-presence.test.cjs",
  "apps/philcore-desktop/test/desktop-action-lifecycle.test.cjs",
  "apps/philcore-desktop/test/desktop-approval.test.cjs",
  "apps/philcore-desktop/test/desktop-real-local-authorization.test.cjs",
  "apps/philcore-desktop/test/desktop-noir-root-proof-product.test.cjs",
  "apps/philcore-desktop/test/desktop-sepolia-user-operation-preparation.test.cjs",
  "apps/philcore-desktop/test/desktop-security.test.cjs",
  "apps/philcore-desktop/test/desktop-o10-trusted-tester-ops.test.cjs",
  "apps/philcore-desktop/test/desktop-o11-trusted-tester-cycle.test.cjs",
  "apps/philcore-desktop/test/desktop-o11-1-contamination.test.cjs"
];

let failed = false;
for (const suite of suites) {
  const result = spawnSync(process.execPath, [suite], {
    cwd: process.cwd(),
    stdio: "inherit",
    env: process.env
  });
  if (result.status !== 0) failed = true;
}

if (failed) process.exit(1);
