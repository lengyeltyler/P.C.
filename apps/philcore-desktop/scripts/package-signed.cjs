#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { appBundlePath, appPayloadPath, baseReleaseManifest, createCleanZip, repoRoot, run, writeJson } = require("./release-utils.cjs");
const {
  buildReleaseArtifactLineage,
  createSignedArtifactRecord,
  sourceIdentity
} = require("./release-artifact-lineage.cjs");
const {
  decodeAndValidateProvisioningProfile
} = require("./developer-id-profile-authorization.cjs");
const { signApplication, verifyDeveloperId } = require("./macos-signing.cjs");
const { assertAuditPassed, auditFilesystem } = require("./release-contamination-audit.cjs");

const identity = process.env.PHILCORE_DESKTOP_SIGNING_IDENTITY;
if (!identity || !/^Developer ID Application:/u.test(identity)) {
  console.error(JSON.stringify({ status: "blocked", reason: "developer_id_application_identity_required: PHILCORE_DESKTOP_SIGNING_IDENTITY", performed: false }, null, 2));
  process.exit(1);
}
if (!fs.existsSync(appBundlePath)) throw new Error("Package app first with npm run desktop:package-local");
const identities = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });
if (identities.status !== 0) throw new Error("Unable to inspect signing identities in the active keychain");
const matches = identities.stdout.split(/\r?\n/u).filter((line) => line.includes(`\"${identity}\"`));
if (matches.length !== 1) throw new Error(matches.length === 0 ? "Developer ID identity not found in active keychain" : "Developer ID identity is ambiguous");
const teamId = identity.match(/\(([A-Z0-9]+)\)$/u)?.[1];
if (!teamId) throw new Error("Unable to derive Team ID from selected Developer ID identity");
const provisioningProfile = process.env.PHILCORE_DESKTOP_PROVISIONING_PROFILE;
if (!provisioningProfile || !path.isAbsolute(provisioningProfile) || !fs.existsSync(provisioningProfile)) {
  console.error(JSON.stringify({
    status: "blocked",
    reason: "exact_developer_id_provisioning_profile_required: PHILCORE_DESKTOP_PROVISIONING_PROFILE",
    performed: false
  }, null, 2));
  process.exit(1);
}

const requiredKeychainGroup = `${teamId}.com.philcore.desktop.localalpha.webauthn`;
const validatedProvisioningProfile = decodeAndValidateProvisioningProfile(
  provisioningProfile,
  {
    expectedTeamId: teamId,
    expectedApplicationIdentifier: `${teamId}.com.philcore.desktop.localalpha`,
    requiredKeychainGroup
  }
);
const releaseLineage = buildReleaseArtifactLineage();
const releaseSourceIdentity = sourceIdentity(repoRoot);

// Developer ID packaging always starts from a fresh deterministic unsigned
// assembly. It never promotes or partially re-signs the O.8 ad-hoc bundle.
run(process.execPath, [path.join(__dirname, "package-local.cjs")], { stdio: "inherit" });
fs.copyFileSync(
  provisioningProfile,
  path.join(appBundlePath, "Contents", "embedded.provisionprofile")
);
assertAuditPassed(auditFilesystem(appBundlePath, { stage: "immediately_before_developer_id_signing" }));
require("./native-notice-coverage.cjs").verifyCoverage(appBundlePath, { beforeSigning: true });

const inventory = signApplication(appBundlePath, {
  identity, hardenedRuntime: true, timestamp: true,
  beforeBundles(discovered) {
    const manifest = baseReleaseManifest({
      packageProfile: "release_candidate_signed",
      signing: { method: "developer_id", codeSigned: true, hardenedRuntimeConfigured: true, developerIdSigningPerformed: true, notarized: false, stapled: false, gatekeeperAccepted: false },
      signingInventory: discovered.map((item) => ({ kind: item.kind, path: path.relative(appBundlePath, item.path) }))
    });
    writeJson(path.join(appPayloadPath, "config", "release", "philcore-desktop-local-alpha.json"), manifest);
  }
});
const inspections = verifyDeveloperId(appBundlePath, identity, teamId, requiredKeychainGroup);
assertAuditPassed(auditFilesystem(appBundlePath, { stage: "immediately_after_developer_id_signing" }));
createCleanZip(appBundlePath, releaseLineage.signedArchivePath, "pre_notarization_signed_artifact_zip");
const signedArtifact = createSignedArtifactRecord(releaseLineage, releaseSourceIdentity);
writeJson(releaseLineage.signedArtifactRecordPath, signedArtifact);
console.log(JSON.stringify({
  status: "developer_id_signed",
  performed: true,
  teamId,
  provisioningProfile: {
    embedded: true,
    applicationIdentifier: validatedProvisioningProfile.applicationIdentifier,
    expiration: validatedProvisioningProfile.expiration
  },
  nestedCodeObjects: inventory.length,
  verifiedSignatures: inspections.length,
  signedArchivePath: signedArtifact.signedArchivePath,
  archiveSha256: signedArtifact.archiveSha256,
  lineageId: signedArtifact.lineageId,
  notarized: false
}, null, 2));
