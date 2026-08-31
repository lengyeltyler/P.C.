"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

// Apple TN3125 defines provisioning-profile entitlements as an allowlist and
// specifically permits TEAMID.* to authorize concrete keychain access groups
// under that Team-ID prefix. Wildcards do not belong in an app's signature.
// https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles
function profileAuthorizesKeychainGroup(profileEntry, requiredGroup, expectedTeamId) {
  if (
    typeof profileEntry !== "string"
    || typeof requiredGroup !== "string"
    || typeof expectedTeamId !== "string"
    || expectedTeamId.length === 0
    || expectedTeamId.includes("*")
    || requiredGroup.includes("*")
    || !requiredGroup.startsWith(`${expectedTeamId}.`)
  ) {
    return false;
  }
  return profileEntry === requiredGroup || profileEntry === `${expectedTeamId}.*`;
}

function appClaimsExactKeychainGroup(appGroups, requiredGroup, expectedTeamId) {
  if (!Array.isArray(appGroups) || appGroups.length !== 1) return false;
  if (
    typeof requiredGroup !== "string"
    || requiredGroup.includes("*")
    || !requiredGroup.startsWith(`${expectedTeamId}.`)
  ) {
    return false;
  }
  return appGroups[0] === requiredGroup;
}

function validateProvisioningProfileClaims(claims, options) {
  const {
    expectedTeamId,
    expectedApplicationIdentifier,
    requiredKeychainGroup,
    now = new Date()
  } = options;
  const expiration = new Date(claims.expiration);
  const developerTeamMatches = claims.developerTeamIdentifier == null
    || claims.developerTeamIdentifier === expectedTeamId;
  const keychainAuthorization = claims.keychainAccessGroups.find((entry) =>
    profileAuthorizesKeychainGroup(entry, requiredKeychainGroup, expectedTeamId)
  );
  if (
    claims.profileTeamIdentifier !== expectedTeamId
    || !developerTeamMatches
    || claims.applicationIdentifier !== expectedApplicationIdentifier
    || !keychainAuthorization
    || !Number.isFinite(expiration.getTime())
    || expiration.getTime() <= now.getTime()
  ) {
    throw new Error("Developer ID provisioning profile identity or entitlement mismatch");
  }
  return Object.freeze({
    teamId: claims.profileTeamIdentifier,
    applicationIdentifier: claims.applicationIdentifier,
    keychainAuthorization,
    expiration: expiration.toISOString()
  });
}

function readProvisioningValue(plistPath, key) {
  const result = spawnSync(
    "/usr/libexec/PlistBuddy",
    ["-c", `Print :${key}`, plistPath],
    { encoding: "utf8" }
  );
  if (result.status !== 0) throw new Error(`Provisioning profile field missing: ${key}`);
  return result.stdout.trim();
}

function readOptionalProvisioningValue(plistPath, key) {
  const result = spawnSync(
    "/usr/libexec/PlistBuddy",
    ["-c", `Print :${key}`, plistPath],
    { encoding: "utf8" }
  );
  return result.status === 0 ? result.stdout.trim() : null;
}

function readProvisioningDate(plistPath, key) {
  const result = spawnSync(
    "/usr/bin/plutil",
    ["-extract", key, "raw", "-o", "-", plistPath],
    { encoding: "utf8" }
  );
  if (result.status !== 0) throw new Error(`Provisioning profile field missing: ${key}`);
  return result.stdout.trim();
}

function readProvisioningStringArray(plistPath, key) {
  const value = readProvisioningValue(plistPath, key);
  const lines = value.split(/\r?\n/u).map((line) => line.trim());
  if (lines[0] !== "Array {" || lines.at(-1) !== "}") {
    throw new Error(`Provisioning profile field is not an array: ${key}`);
  }
  return lines.slice(1, -1).filter(Boolean);
}

function decodeAndValidateProvisioningProfile(profilePath, options) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-profile-"));
  const decodedPath = path.join(temporaryRoot, "profile.plist");
  try {
    const decoded = spawnSync(
      "/usr/bin/security",
      ["cms", "-D", "-i", profilePath],
      { encoding: "utf8" }
    );
    if (decoded.status !== 0 || !decoded.stdout.includes("<plist")) {
      throw new Error("Developer ID provisioning profile could not be decoded");
    }
    fs.writeFileSync(decodedPath, decoded.stdout, { mode: 0o600 });
    return validateProvisioningProfileClaims({
      profileTeamIdentifier: readProvisioningValue(decodedPath, "TeamIdentifier:0"),
      developerTeamIdentifier: readOptionalProvisioningValue(
        decodedPath,
        "Entitlements:com.apple.developer.team-identifier"
      ),
      applicationIdentifier: readProvisioningValue(
        decodedPath,
        "Entitlements:com.apple.application-identifier"
      ),
      keychainAccessGroups: readProvisioningStringArray(
        decodedPath,
        "Entitlements:keychain-access-groups"
      ),
      expiration: readProvisioningDate(decodedPath, "ExpirationDate")
    }, options);
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

module.exports = {
  appClaimsExactKeychainGroup,
  decodeAndValidateProvisioningProfile,
  profileAuthorizesKeychainGroup,
  validateProvisioningProfileClaims
};
