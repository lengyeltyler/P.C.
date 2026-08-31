#!/usr/bin/env node
const { baseReleaseManifest, manifestPath, writeJson } = require("./release-utils.cjs");

const manifest = baseReleaseManifest();
writeJson(manifestPath, manifest);
console.log(JSON.stringify({
  status: "release_manifest_written",
  path: manifestPath,
  codeSigned: manifest.signing.codeSigned,
  notarized: manifest.signing.notarized,
  productionApproved: manifest.securityStatus.productionApproved
}, null, 2));
