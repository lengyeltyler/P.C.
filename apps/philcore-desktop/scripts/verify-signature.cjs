#!/usr/bin/env node
const { appBundlePath, codeSignatureStatus } = require("./release-utils.cjs");
const { discoverSignableCode, verifyStrict } = require("./macos-signing.cjs");

const signature = codeSignatureStatus(appBundlePath);
if (signature.signed) verifyStrict(appBundlePath);
console.log(JSON.stringify({
  phase: "O.8",
  status: "checked",
  codeSigned: Boolean(signature.signed),
  notarized: false,
  details: signature,
  nestedCode: discoverSignableCode(appBundlePath).map((item) => ({ kind: item.kind, path: item.path }))
}, null, 2));
