#!/usr/bin/env node
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const {
  sha256,
  userPresenceHelperPaths
} = require("./release-utils.cjs");
const {
  createMacOsLocalAuthenticationProvider
} = require("../src/main/macos-user-presence.cjs");

const helper = userPresenceHelperPaths();
const provider = createMacOsLocalAuthenticationProvider({
  helperPath: helper.source,
  expectedSha256: require("node:fs").existsSync(helper.source) ? sha256(helper.source) : ""
});
const availability = provider.getAvailability();
const shouldPrompt = process.argv.includes("--prompt");
let request = null;
if (shouldPrompt && availability.available) {
  request = provider.requestUserPresence({
    policy: "device_owner_authentication",
    reason: "Approve PhilCore local user-presence diagnostic",
    presentationDigest: `0x${"11".repeat(32)}`
  });
}
const diagnostic = {
  phase: "O.8",
  diagnostic: "macos_user_presence",
  helperPath: path.basename(helper.source),
  availability,
  prompted: shouldPrompt,
  result: request,
  touchIdClaimed: request?.evidenceClass === "touch_id_biometric_verified",
  biometricDataReturned: false,
  rawAuthenticationMaterialReturned: false
};
if (shouldPrompt) {
  const evidencePath = path.join(__dirname, "..", "release", "evidence", "macos-user-presence-manual.json");
  const evidence = {
    phase: "O.8",
    capturedAt: new Date().toISOString(),
    provider: request?.provider || availability.provider,
    requestedPolicy: "device_owner_authentication",
    evaluatedPolicy: request?.policy || "not_evaluated",
    outcome: request?.outcome || availability.status,
    evidenceClass: request?.evidenceClass || "none",
    helperSha256: availability.helperSha256,
    os: `${os.platform()} ${os.release()}`,
    architecture: os.arch(),
    packaged: false,
    systemPromptRequested: true,
    promptVisiblyObservedByOperator: "not_confirmed_by_operator",
    touchIdClaimed: false,
    biometricDataCaptured: false,
    rawAuthenticationMaterialCaptured: false,
    secretsCaptured: false,
    sanitization: "safe_metadata_only"
  };
  fs.mkdirSync(path.dirname(evidencePath), { recursive: true });
  fs.writeFileSync(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`);
  diagnostic.evidencePath = path.relative(path.join(__dirname, "..", "..", ".."), evidencePath);
}
console.log(JSON.stringify(diagnostic, null, 2));
