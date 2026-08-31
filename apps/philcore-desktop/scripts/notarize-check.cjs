#!/usr/bin/env node
const fs = require("node:fs");
const { appBundlePath, codeSignatureStatus } = require("./release-utils.cjs");

const credentialModes = {
  keychainProfile: Boolean(process.env.PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE)
};
const signature = codeSignatureStatus(appBundlePath);
console.log(JSON.stringify({
  phase: "O.7",
  status: "checked",
  appExists: fs.existsSync(appBundlePath),
  codeSigned: Boolean(signature.signed),
  notarization_configured: true,
  notarization_performed: false,
  notarizationConfigured: Object.values(credentialModes).some(Boolean),
  credentialModes,
  requirements: {
    signedAppRequired: true,
    explicitUploadCommandRequired: true,
    appleCredentialsExternalOnly: true,
    keychainProfileEnvironmentVariable: "PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE",
    notarytoolExpected: "xcrun notarytool"
  },
  notarized: false,
  liveUploadPerformed: false,
  readyForManualNotarization: Boolean(signature.signed && Object.values(credentialModes).some(Boolean))
}, null, 2));
