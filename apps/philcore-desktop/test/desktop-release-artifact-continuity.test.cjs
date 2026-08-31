#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const {
  EXPECTED_NOTARY_KEYCHAIN_PROFILE,
  buildReleaseArtifactLineage,
  createSignedArtifactRecord,
  createStapledArtifactRecord,
  dryRunReport,
  sha256,
  verifySignedArtifactRecord,
  verifyStapledArtifactRecord
} = require("../scripts/release-artifact-lineage.cjs");
const {
  appClaimsExactKeychainGroup,
  profileAuthorizesKeychainGroup,
  validateProvisioningProfileClaims
} = require("../scripts/developer-id-profile-authorization.cjs");

const repoRoot = path.resolve(__dirname, "..", "..", "..");
const fixedSource = Object.freeze({
  commit: "857465a459fe783881888f7f1f116f04c9a50f81",
  tree: "bb20f81d08c9bb15e6e09d2fec7a548c9abb2b0d"
});

function fixture(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-release-lineage-"));
  const lineage = buildReleaseArtifactLineage({
    repoRoot: root,
    appRoot: path.join(root, "apps", "philcore-desktop"),
    releaseRoot: path.join(root, "release"),
    version: options.version || "0.1.0",
    arch: options.arch || "arm64",
    productName: "PhilCore Desktop Local Alpha",
    executableName: "PhilCore Desktop Local Alpha"
  });
  fs.mkdirSync(path.dirname(lineage.executablePath), { recursive: true });
  fs.writeFileSync(lineage.executablePath, "signed executable fixture\n");
  return { root, lineage };
}

function read(relative) {
  return fs.readFileSync(path.join(repoRoot, relative), "utf8");
}

test("signer output and notarizer input are one canonical artifact lineage", () => {
  const lineage = buildReleaseArtifactLineage();
  const report = dryRunReport(lineage, fixedSource);
  assert.equal(lineage.signedArchivePath, lineage.notarizationInputPath);
  assert.equal(report.signedOutputPath, report.notarizationInputPath);
  assert.equal(report.signedOutputEqualsNotarizationInput, true);
  assert.equal(report.manualRenameOrCopyRequired, false);
  assert.equal(report.stages.length, 6);
});

test("version changes flow through signing, notarization, and final output", () => {
  const first = buildReleaseArtifactLineage({ version: "0.1.0", arch: "arm64" });
  const next = buildReleaseArtifactLineage({ version: "0.2.0", arch: "arm64" });
  assert.match(first.signedArchivePath, /Beta-0\.1\.0-macos-arm64-notarization\.zip$/u);
  assert.match(next.signedArchivePath, /Beta-0\.2\.0-macos-arm64-notarization\.zip$/u);
  assert.match(next.finalArchivePath, /Beta-0\.2\.0-macos-arm64\.zip$/u);
  assert.equal(next.notarizationInputPath, next.signedArchivePath);
});

test("architecture changes flow through signing, notarization, and final output", () => {
  const arm = buildReleaseArtifactLineage({ version: "0.1.0", arch: "arm64" });
  const intel = buildReleaseArtifactLineage({ version: "0.1.0", arch: "x64" });
  assert.match(arm.baseIdentity, /macos-arm64$/u);
  assert.match(intel.baseIdentity, /macos-x64$/u);
  assert.equal(intel.notarizationInputPath, intel.signedArchivePath);
  assert.match(intel.finalArchivePath, /macos-x64\.zip$/u);
});

test("missing canonical signed archive fails closed", () => {
  const { lineage } = fixture();
  assert.throws(
    () => createSignedArtifactRecord(lineage, fixedSource),
    /signed_archive_missing/u
  );
});

test("signed archive hash mismatch fails closed", () => {
  const { lineage } = fixture();
  fs.writeFileSync(lineage.signedArchivePath, "signed archive fixture\n");
  const record = createSignedArtifactRecord(lineage, fixedSource);
  fs.appendFileSync(lineage.signedArchivePath, "tampered\n");
  assert.throws(
    () => verifySignedArtifactRecord(lineage, record, fixedSource),
    /signed_archive_hash_mismatch/u
  );
});

test("stapling and finalization remain bound to the signed app lineage", () => {
  const { lineage } = fixture();
  fs.writeFileSync(lineage.signedArchivePath, "signed archive fixture\n");
  const signed = createSignedArtifactRecord(lineage, fixedSource);
  const receipt = {
    status: "Accepted",
    baseIdentity: signed.baseIdentity,
    lineageId: signed.lineageId,
    sourceCommit: signed.sourceCommit,
    sourceTree: signed.sourceTree,
    artifactFile: path.basename(lineage.notarizationInputPath),
    artifactSha256: signed.archiveSha256
  };
  fs.writeFileSync(path.join(lineage.appPath, "Contents", "notarization-ticket"), "stapled ticket fixture\n");
  const stapled = createStapledArtifactRecord(lineage, signed, receipt, fixedSource);
  assert.doesNotThrow(() => verifyStapledArtifactRecord(lineage, signed, receipt, stapled, fixedSource));
  fs.appendFileSync(lineage.executablePath, "tampered after staple\n");
  assert.throws(
    () => verifyStapledArtifactRecord(lineage, signed, receipt, stapled, fixedSource),
    /(?:signed|stapled)_executable_hash_mismatch/u
  );
});

test("manual historical RC2 artifact is never accepted as current input", () => {
  const { lineage } = fixture();
  const legacy = path.join(lineage.releaseRoot, "philcore-desktop-o11-1-trusted-tester-rc2-macos-arm64.zip");
  fs.writeFileSync(legacy, "legacy artifact fixture\n");
  assert.notEqual(legacy, lineage.notarizationInputPath);
  assert.throws(
    () => createSignedArtifactRecord(lineage, fixedSource),
    /signed_archive_missing/u
  );
  for (const script of ["package-signed.cjs", "notarize.cjs", "staple.cjs", "prepare-trusted-tester-bundle.cjs"]) {
    assert.doesNotMatch(read(`apps/philcore-desktop/scripts/${script}`), /REPLACEMENT_RELEASE_IDENTIFIER/u);
  }
});

test("Developer ID provisioning-profile validation remains exact and required", () => {
  const signer = read("apps/philcore-desktop/scripts/package-signed.cjs");
  const authorization = read(
    "apps/philcore-desktop/scripts/developer-id-profile-authorization.cjs"
  );
  const macosSigning = read("apps/philcore-desktop/scripts/macos-signing.cjs");
  assert.match(signer, /PHILCORE_DESKTOP_PROVISIONING_PROFILE/u);
  assert.match(signer, /decodeAndValidateProvisioningProfile/u);
  assert.match(signer, /com\.philcore\.desktop\.localalpha/u);
  assert.match(signer, /com\.philcore\.desktop\.localalpha\.webauthn/u);
  assert.match(authorization, /expiration\.getTime\(\) <= now\.getTime\(\)/u);
  assert.match(macosSigning, /appClaimsExactKeychainGroup/u);
  assert.match(macosSigning, /com\.apple\.application-identifier/u);
  assert.match(macosSigning, /Signed application entitlement identity mismatch/u);
  assert.match(signer, /Contents", "embedded\.provisionprofile/u);
});

const expectedTeamId = "B342738S82";
const expectedApplicationIdentifier =
  "B342738S82.com.philcore.desktop.localalpha";
const requiredKeychainGroup =
  "B342738S82.com.philcore.desktop.localalpha.webauthn";

test("exact profile group authorizes the exact Phil keychain group", () => {
  assert.equal(
    profileAuthorizesKeychainGroup(
      requiredKeychainGroup,
      requiredKeychainGroup,
      expectedTeamId
    ),
    true
  );
});

test("Apple Team-ID wildcard authorizes the exact Phil keychain group", () => {
  assert.equal(
    profileAuthorizesKeychainGroup(
      `${expectedTeamId}.*`,
      requiredKeychainGroup,
      expectedTeamId
    ),
    true
  );
});

for (const [name, entry] of [
  ["other-Team wildcard", "OTHERTEAM.*"],
  ["nearby wrong-Team wildcard", "B342738S83.*"],
  ["generic wildcard", "*"],
  ["malformed wildcard", "*.webauthn"],
  ["prefix wildcard broader than the exact Team wildcard", "B342738S82.com.philcore.*"],
  ["app-prefix wildcard", "B342738S82.com.philcore.desktop.localalpha.*"],
  ["suffix wildcard", "B342738S82*"],
  ["exact wrong group", "B342738S82.com.philcore.desktop.other.webauthn"]
]) {
  test(`${name} does not authorize the Phil keychain group`, () => {
    assert.equal(
      profileAuthorizesKeychainGroup(entry, requiredKeychainGroup, expectedTeamId),
      false
    );
  });
}

function validProfileClaims(overrides = {}) {
  return {
    profileTeamIdentifier: expectedTeamId,
    developerTeamIdentifier: expectedTeamId,
    applicationIdentifier: expectedApplicationIdentifier,
    keychainAccessGroups: [`${expectedTeamId}.*`],
    expiration: "2044-08-24T21:40:03.000Z",
    ...overrides
  };
}

const profileValidationOptions = Object.freeze({
  expectedTeamId,
  expectedApplicationIdentifier,
  requiredKeychainGroup,
  now: new Date("2026-08-29T22:00:00.000Z")
});

test("valid Team wildcard profile claims pass without broadening app identity", () => {
  assert.deepEqual(
    validateProvisioningProfileClaims(validProfileClaims(), profileValidationOptions),
    {
      teamId: expectedTeamId,
      applicationIdentifier: expectedApplicationIdentifier,
      keychainAuthorization: `${expectedTeamId}.*`,
      expiration: "2044-08-24T21:40:03.000Z"
    }
  );
});

test("correct wildcard with wrong application identifier fails closed", () => {
  assert.throws(
    () => validateProvisioningProfileClaims(
      validProfileClaims({ applicationIdentifier: `${expectedTeamId}.com.philcore.desktop.other` }),
      profileValidationOptions
    ),
    /identity or entitlement mismatch/u
  );
});

test("correct wildcard with wrong TeamIdentifier fails closed", () => {
  assert.throws(
    () => validateProvisioningProfileClaims(
      validProfileClaims({ profileTeamIdentifier: "B342738S83" }),
      profileValidationOptions
    ),
    /identity or entitlement mismatch/u
  );
});

test("correct wildcard with wrong developer-team entitlement fails closed", () => {
  assert.throws(
    () => validateProvisioningProfileClaims(
      validProfileClaims({ developerTeamIdentifier: "B342738S83" }),
      profileValidationOptions
    ),
    /identity or entitlement mismatch/u
  );
});

test("app entitlement itself cannot be the profile wildcard", () => {
  assert.equal(
    appClaimsExactKeychainGroup([`${expectedTeamId}.*`], requiredKeychainGroup, expectedTeamId),
    false
  );
});

test("app entitlement missing the exact Phil WebAuthn group fails closed", () => {
  assert.equal(
    appClaimsExactKeychainGroup([], requiredKeychainGroup, expectedTeamId),
    false
  );
  assert.equal(
    appClaimsExactKeychainGroup(
      [`${expectedTeamId}.com.philcore.desktop.other.webauthn`],
      requiredKeychainGroup,
      expectedTeamId
    ),
    false
  );
});

test("notary credentials remain external and Keychain-profile backed", () => {
  const notarizer = read("apps/philcore-desktop/scripts/notarize.cjs");
  const readiness = read("apps/philcore-desktop/scripts/notarize-check.cjs");
  assert.equal(EXPECTED_NOTARY_KEYCHAIN_PROFILE, "philcore-beta-notary");
  assert.match(notarizer, /PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE/u);
  assert.match(notarizer, /"--keychain-profile", profile/u);
  assert.doesNotMatch(`${notarizer}\n${readiness}`, /--apple-id|app-specific password|PHILCORE_DESKTOP_NOTARY_APPLE_ID/u);
});

test("historical O11.1 and O9 evidence remains byte-identical", () => {
  assert.equal(
    sha256(path.join(repoRoot, "config", "release", "philcore-desktop-o11-1-remediation.json")),
    "9aa35658ad337ad05fbc22351385af3321d2e60c86a77442f908efccdaac3dcc"
  );
  assert.equal(
    sha256(path.join(repoRoot, "config", "release", "philcore-desktop-o9-release-evidence.json")),
    "4f967b238eb13a8fafdb4c7bed6a44f748fad8b18d63b1c8913aad85d08d6038"
  );
  assert.equal(
    sha256(path.join(repoRoot, "apps", "philcore-desktop", "scripts", "release-policy.cjs")),
    "3365ae2ab16a80bf5a5a0a9deb6d26da3aac8773d00869bfeba9d2f070a04f0d"
  );
});
