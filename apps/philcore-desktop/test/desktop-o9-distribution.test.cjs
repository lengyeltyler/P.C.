#!/usr/bin/env node
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { parseValidIdentities, auditEnvironment, classifySelection } = require("../scripts/apple-signing-readiness.cjs");

const fixture = [
  '  1) ABCDEF0123456789ABCDEF0123456789ABCDEF01 "Developer ID Application: Example One (TEAMONE123)"',
  '  2) 0123456789ABCDEF0123456789ABCDEF01234567 "Developer ID Application: Example Two (TEAMTWO456)"',
  '     2 valid identities found'
].join("\n");
const parsed = parseValidIdentities(fixture);
assert.equal(parsed.length, 2);
assert.equal(parsed[0].commonName, "Developer ID Application: Example One (TEAMONE123)");
assert.equal(classifySelection([], "x"), "missing_developer_id_identity");
assert.equal(classifySelection(parsed, null), "identity_not_selected");
assert.equal(classifySelection([...parsed, parsed[0]], parsed[0].commonName), "identity_ambiguous");
assert.equal(classifySelection([{ commonName: "x", expired: true }], "x"), "certificate_expired");
assert.equal(classifySelection([{ commonName: "x", chainValid: false }], "x"), "certificate_chain_invalid");
assert.equal(classifySelection([{ commonName: "x", privateKeyAvailable: false }], "x"), "private_key_unavailable");

const readiness = auditEnvironment({});
assert.equal(readiness.ready, false);
assert.equal(readiness.liveMilestones.developerIdSigningPerformed, false);
assert.equal(readiness.liveMilestones.notarizationSubmitted, false);
assert.equal(readiness.liveMilestones.gatekeeperAcceptedExtractedApp, false);
assert.equal(readiness.publicNetworkMutation, false);

const verifier = fs.readFileSync(path.join(__dirname, "..", "scripts", "verify-trusted-tester-artifact.sh"), "utf8");
for (const token of ["checksum_failure", "archive_contamination", "extraction_contamination", "framework_layout_failure", "framework_symlink_failure", "signature_failure", "authority_failure", "team_id_failure", "staple_failure", "gatekeeper_failure", "internal_component_hash_failure"]) {
  assert.match(verifier, new RegExp(token));
}
assert.doesNotMatch(verifier, /PHILCORE_NOTARYTOOL_KEYCHAIN_PROFILE|private.?key|password/iu);
console.log("ok - O.9 identity parsing, fail-closed readiness, truthful claims, and tester verifier");
