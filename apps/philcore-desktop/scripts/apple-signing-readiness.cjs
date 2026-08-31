#!/usr/bin/env node
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { configReleaseRoot, writeJson } = require("./release-utils.cjs");

function commandAvailable(command, args = ["--help"]) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  return { available: !result.error && result.status !== 127, status: result.status };
}

function parseValidIdentities(output) {
  return output.split(/\r?\n/u).flatMap((line) => {
    const match = line.match(/^\s*\d+\)\s+([A-F0-9]{40})\s+"(Developer ID Application:[^"]+)"/u);
    return match ? [{ sha1Fingerprint: match[1], commonName: match[2] }] : [];
  });
}

function classifySelection(identities, selected) {
  if (identities.length === 0) return "missing_developer_id_identity";
  if (!selected) return "identity_not_selected";
  const matches = identities.filter((item) => item.commonName === selected);
  if (matches.length === 0) return "selected_identity_not_found";
  if (matches.length > 1) return "identity_ambiguous";
  if (matches[0].expired) return "certificate_expired";
  if (matches[0].chainValid === false) return "certificate_chain_invalid";
  if (matches[0].privateKeyAvailable === false) return "private_key_unavailable";
  return "ready";
}

function auditEnvironment(env = process.env) {
  const identityResult = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });
  const identities = identityResult.status === 0 ? parseValidIdentities(identityResult.stdout) : [];
  const selected = env.PHILCORE_DESKTOP_SIGNING_IDENTITY || null;
  const selectedMatches = selected ? identities.filter((item) => item.commonName === selected) : [];
  const toolStatus = {
    codesign: commandAvailable("codesign", ["--version"]).available,
    security: commandAvailable("security", ["help"]).available,
    notarytool: commandAvailable("xcrun", ["--find", "notarytool"]).available,
    stapler: commandAvailable("xcrun", ["--find", "stapler"]).available,
    spctl: commandAvailable("spctl", ["--help"]).available
  };
  const signingState = classifySelection(identities, selected);
  const notaryCredentialsConfigured = Boolean(env.PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE);
  const liveUploadAuthorized = env.PHILCORE_DESKTOP_NOTARIZE_APPROVED === "1";
  const ready = signingState === "ready" && Object.values(toolStatus).every(Boolean)
    && notaryCredentialsConfigured && liveUploadAuthorized;
  return {
    phase: "O.9",
    auditedAt: new Date().toISOString(),
    platform: { macOS: os.release(), architecture: os.arch() },
    tools: toolStatus,
    identities: {
      validDeveloperIdApplicationCount: identities.length,
      selected: selected ? "externally_selected" : "not_configured",
      selectedMatchCount: selectedMatches.length,
      privateKeyAvailability: identities.length > 0 ? "represented_by_valid_identity_result" : false,
      certificateExpiry: identities.length > 0 ? "requires_selected_certificate_inspection" : null,
      teamId: null
    },
    signingState,
    notarization: {
      credentialMode: notaryCredentialsConfigured ? "external_keychain_profile" : "not_configured",
      credentialsConfigured: notaryCredentialsConfigured,
      liveUploadAuthorized
    },
    ready,
    liveMilestones: {
      developerIdSigningPerformed: false,
      strictDeveloperIdVerificationPassed: false,
      notarizationSubmitted: false,
      notarizationAccepted: false,
      staplingPerformed: false,
      stapleValidated: false,
      gatekeeperAcceptedWorkingApp: false,
      gatekeeperAcceptedExtractedApp: false,
      controlledDistributionPackageProduced: false,
      distributedToTesters: false,
      productionApproved: false
    },
    publicNetworkMutation: false,
    baseSepoliaBetaGate: "blocked"
  };
}

if (require.main === module) {
  const result = auditEnvironment();
  fs.mkdirSync(configReleaseRoot, { recursive: true });
  writeJson(path.join(configReleaseRoot, "philcore-desktop-o9-apple-readiness.json"), result);
  console.log(JSON.stringify(result, null, 2));
  if (!result.ready) process.exitCode = 2;
}

module.exports = { auditEnvironment, classifySelection, parseValidIdentities };
