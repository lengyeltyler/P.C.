#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const {
  appBundlePath, appPayloadPath, baseReleaseManifest, proofBinaryPaths,
  repoRoot, run, sha256, userPresenceHelperPaths, writeJson, zipArtifactPath
} = require("./release-utils.cjs");
const { signApplication, verifyStrict } = require("./macos-signing.cjs");

if (!fs.existsSync(appBundlePath)) throw new Error("Package app first with npm run desktop:package-local");

let inventory = [];
let signedManifest;
const postArchiveEvidencePath = path.join(
  path.dirname(zipArtifactPath),
  "philcore-desktop-local-alpha-adhoc-evidence.json"
);
inventory = signApplication(appBundlePath, {
  identity: "-",
  hardenedRuntime: true,
  timestamp: false,
  beforeBundles(discovered) {
    const manifest = baseReleaseManifest({
      packageProfile: "local_alpha_adhoc",
      signing: {
        method: "ad_hoc",
        identity: "-",
        codeSigned: true,
        hardenedRuntimeConfigured: true,
        developerIdSigningPerformed: false,
        notarized: false,
        stapled: false,
        gatekeeperAccepted: false
      },
      producedArtifacts: [
        { kind: "macos_app", path: path.relative(repoRoot, appBundlePath), signed: "ad_hoc", notarized: false },
        { kind: "zip", path: path.relative(repoRoot, zipArtifactPath), signed: "ad_hoc", notarized: false }
      ],
      signingInventory: discovered.map((item) => ({ kind: item.kind, path: path.relative(appBundlePath, item.path) }))
    });
    manifest.artifact.zip = {
      path: path.relative(repoRoot, zipArtifactPath),
      sha256: null,
      bytes: null,
      finalHashEvidence: path.relative(repoRoot, postArchiveEvidencePath)
    };
    signedManifest = manifest;
    writeJson(path.join(appPayloadPath, "config", "release", "philcore-desktop-local-alpha.json"), manifest);
  }
});
verifyStrict(appBundlePath);

fs.rmSync(zipArtifactPath, { force: true });
run("ditto", ["-c", "-k", "--keepParent", path.basename(appBundlePath), zipArtifactPath], { cwd: path.dirname(appBundlePath), stdio: "inherit" });

const extractRoot = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "philcore-adhoc-verify-"));
try {
  run("ditto", ["-x", "-k", zipArtifactPath, extractRoot], { stdio: "inherit" });
  verifyStrict(path.join(extractRoot, path.basename(appBundlePath)));
} finally {
  fs.rmSync(extractRoot, { recursive: true, force: true });
}

if (!signedManifest) throw new Error("adhoc_signed_manifest_missing");
const postArchiveEvidence = {
  schemaVersion: 1,
  kind: "philcore-desktop-local-alpha-adhoc-evidence",
  generatedAt: new Date().toISOString(),
  source: {
    commit: signedManifest.sourceCommit,
    tree: execFileSync("git", ["rev-parse", "HEAD^{tree}"], { cwd: repoRoot, encoding: "utf8" }).trim(),
    clean: signedManifest.sourceTree?.dirty === false,
    excludedProtectedUntrackedFiles: signedManifest.sourceTree?.excludedProtectedUntrackedFiles || []
  },
  artifact: {
    appPath: path.relative(repoRoot, appBundlePath),
    zipPath: path.relative(repoRoot, zipArtifactPath),
    zipSha256: sha256(zipArtifactPath),
    zipBytes: fs.statSync(zipArtifactPath).size,
    embeddedManifestSha256: sha256(path.join(appPayloadPath, "config", "release", "philcore-desktop-local-alpha.json"))
  },
  signing: {
    method: "ad_hoc",
    strictVerification: true,
    postZipExtractionVerification: true,
    notarized: false
  },
  limitations: {
    sameMachineLocalAlphaOnly: true,
    productionApproved: false,
    publicNetworkMutation: false
  }
};
writeJson(postArchiveEvidencePath, postArchiveEvidence);
fs.chmodSync(postArchiveEvidencePath, 0o600);

console.log(JSON.stringify({
  status: "adhoc_signed", appPath: path.relative(repoRoot, appBundlePath), identity: "-",
  hardenedRuntime: true, nestedCodeObjects: inventory.length, strictVerification: true,
  postZipExtractionVerification: true, notarized: false, distributableAsTrustedSoftware: false,
  postArchiveEvidence: path.relative(repoRoot, postArchiveEvidencePath),
  zipSha256: postArchiveEvidence.artifact.zipSha256
}, null, 2));
