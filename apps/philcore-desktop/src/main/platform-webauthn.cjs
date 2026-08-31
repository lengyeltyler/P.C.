const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const PHILCORE_MACOS_TEAM_ID = "B342738S82";
const PHILCORE_DESKTOP_BUNDLE_ID = "com.philcore.desktop.localalpha";
const PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP =
  `${PHILCORE_MACOS_TEAM_ID}.${PHILCORE_DESKTOP_BUNDLE_ID}.webauthn`;

const CAPABILITY_RESULTS = Object.freeze({
  SUPPORTED_AND_CONFIGURED: "SUPPORTED_AND_CONFIGURED",
  SUPPORTED_CONFIGURATION_FAILED: "SUPPORTED_CONFIGURATION_FAILED",
  UNSUPPORTED_RUNTIME: "UNSUPPORTED_RUNTIME",
  UNSUPPORTED_PLATFORM: "UNSUPPORTED_PLATFORM",
  PACKAGED_IDENTITY_MISMATCH: "PACKAGED_IDENTITY_MISMATCH"
});

function readPackagedIdentity({
  execPath = process.execPath,
  spawn = spawnSync
} = {}) {
  const executableDirectory = path.dirname(execPath);
  const infoPlist = path.resolve(executableDirectory, "..", "Info.plist");
  const bundle = spawn(
    "/usr/libexec/PlistBuddy",
    ["-c", "Print :CFBundleIdentifier", infoPlist],
    { encoding: "utf8" }
  );
  const signature = spawn(
    "/usr/bin/codesign",
    ["-dvv", execPath],
    { encoding: "utf8" }
  );
  const signatureOutput = `${signature.stdout || ""}\n${signature.stderr || ""}`;
  return Object.freeze({
    bundleIdentifier: bundle.status === 0 ? bundle.stdout.trim() : null,
    teamIdentifier:
      signatureOutput.match(/^TeamIdentifier=(.+)$/mu)?.[1]?.trim() || null,
    infoPlistPresent: fs.existsSync(infoPlist),
    signatureInspected: signature.status === 0
  });
}

function configurePlatformWebAuthn({
  electronApp,
  platform = process.platform,
  electronVersion = process.versions.electron || null,
  packaged = Boolean(electronApp?.isPackaged),
  packagedIdentity = packaged ? readPackagedIdentity() : null
}) {
  const base = {
    electronVersion,
    platform,
    packaged,
    bundleIdentifier: packagedIdentity?.bundleIdentifier || null,
    teamIdentifier: packagedIdentity?.teamIdentifier || null,
    keychainAccessGroup: PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
    configuredBeforeReady: false,
    configuredAfterReady: false,
    chromiumFlagsUsed: false
  };
  if (platform !== "darwin") {
    return Object.freeze({ ...base, result: CAPABILITY_RESULTS.UNSUPPORTED_PLATFORM });
  }
  if (typeof electronApp?.configureWebAuthn !== "function") {
    return Object.freeze({ ...base, result: CAPABILITY_RESULTS.UNSUPPORTED_RUNTIME });
  }
  if (typeof electronApp?.isReady !== "function") {
    return Object.freeze({
      ...base,
      result: CAPABILITY_RESULTS.UNSUPPORTED_RUNTIME,
      errorCode: "PLATFORM_WEBAUTHN_READY_CHECK_UNSUPPORTED"
    });
  }
  let ready;
  try {
    ready = electronApp.isReady();
  } catch {
    return Object.freeze({
      ...base,
      result: CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED,
      errorCode: "PLATFORM_WEBAUTHN_READY_CHECK_REJECTED"
    });
  }
  if (ready !== true) {
    return Object.freeze({
      ...base,
      configuredBeforeReady: true,
      configuredAfterReady: false,
      result: CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED,
      errorCode: "PLATFORM_WEBAUTHN_CONFIGURATION_TOO_EARLY"
    });
  }
  if (
    packaged
    && (
      packagedIdentity?.bundleIdentifier !== PHILCORE_DESKTOP_BUNDLE_ID
      || packagedIdentity?.teamIdentifier !== PHILCORE_MACOS_TEAM_ID
    )
  ) {
    return Object.freeze({
      ...base,
      result: CAPABILITY_RESULTS.PACKAGED_IDENTITY_MISMATCH,
      errorCode: "PLATFORM_WEBAUTHN_PACKAGED_IDENTITY_MISMATCH"
    });
  }
  try {
    electronApp.configureWebAuthn({
      touchID: {
        keychainAccessGroup: PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
        promptReason: "create or use a device-bound PhilCore recovery credential for $1"
      }
    });
    return Object.freeze({
      ...base,
      configuredBeforeReady: false,
      configuredAfterReady: true,
      result: CAPABILITY_RESULTS.SUPPORTED_AND_CONFIGURED,
      developmentIdentityWarning: packaged
        ? null
        : "UNPACKAGED_RUNTIME_NOT_PRODUCTION_CREDENTIAL_IDENTITY"
    });
  } catch {
    return Object.freeze({
      ...base,
      result: CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED,
      errorCode: "PLATFORM_WEBAUTHN_CONFIGURATION_REJECTED"
    });
  }
}

module.exports = {
  CAPABILITY_RESULTS,
  PHILCORE_DESKTOP_BUNDLE_ID,
  PHILCORE_MACOS_TEAM_ID,
  PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
  configurePlatformWebAuthn,
  readPackagedIdentity
};
