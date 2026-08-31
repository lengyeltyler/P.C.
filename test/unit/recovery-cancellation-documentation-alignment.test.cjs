"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "../..");

const MARKER_A = "Superseded recovery-cancellation authority";
const MARKER_B = "Scope boundary — N-series PhilCore4337Account";
const INLINE_RETIRED =
  "Retired V2 alternative — see the supersession notice at the top of this document.";

const ACTION10_AUTHORITY = /current validator plus exact 2-of-3/i;
const VALIDATOR_THRESHOLD_LIMIT =
  /validator\s+never counts toward[\s\S]{0,40}?recovery-factor\s+threshold/i;
const ACTION10_DISTINCTION =
  /Action 10 additionally requires the current validator plus exact 2-of-3/i;
const ACTIONS_8911_FACTORS =
  /Actions 8,\s*9,\s*and 11 use exact 2-of-3 current recovery factors/i;

const CANONICAL_O36_1 = "docs/reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md";
const CANONICAL_O37_1 = "docs/reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md";

const SAME_LINEAGE_V2_DOCS = Object.freeze([
  "docs/reference/O30_V2_CAPABILITY_MATRIX.md",
  "docs/reference/O30_V2_ACCOUNT_SPECIFICATION_AND_THREAT_MODEL_REFINEMENT.md",
  "docs/reference/O30_V2_ACCOUNT_INTERFACE_SPECIFICATION.md",
  "docs/reference/O31_V2_INTERFACE_SPECIFICATION.md",
  "docs/reference/O31_V2_RECOVERY_ARCHITECTURE.md"
]);

const INLINE_RETIRED_DOCS = Object.freeze([
  "docs/reference/O30_V2_ACCOUNT_INTERFACE_SPECIFICATION.md",
  "docs/reference/O31_V2_INTERFACE_SPECIFICATION.md"
]);

const N_SERIES_SECURITY_DOCS = Object.freeze([
  "docs/security/PHILCORE_BASE_SEPOLIA_BETA_SECURITY_GATE.md",
  "docs/security/PHILCORE_RECOVERY_AUTHORITY_RUNBOOK.md",
  "docs/security/PHILCORE_RECOVERY_AUTHORITY_CUSTODY.md",
  "docs/security/PHILCORE_RECOVERY_AUTHORITY_ROTATION.md",
  "docs/security/PHILCORE_ERC4337_ROTATION_AND_RECOVERY.md"
]);

const DECISION_RECORD =
  "docs/security/PHILCORE_RECOVERY_AUTHORITY_DECISION_RECORD.md";
const CANONICAL_DOCS = "docs/CANONICAL_DOCS.md";
const AUTHORITATIVE_THREAT_MODEL =
  "docs/security/O30_V2_FORMAL_THREAT_MODEL.md";
const ACP_0002 =
  "docs/architecture-changes/ACP-0002-PHILCORE-ERC4337-SMART-ACCOUNT.md";

const N4_HEADING = "## N.4 Rotation And Recovery Evidence";
const N8_HEADING = "## N.8 Recovery Authority Rotation Evidence";

const INLINE_CANCEL_TARGETS = Object.freeze([
  {
    label: "cancelRecovery",
    re: /###\s+`cancelRecovery`|\bcancelRecovery\s*\(/u
  },
  {
    label: "cancelRecoveryConfigRotation",
    re: /###\s+`cancelRecoveryConfigRotation`|\bcancelRecoveryConfigRotation\s*\(/u
  }
]);

function read(rel) {
  return fs.readFileSync(path.join(ROOT, rel), "utf8");
}

function exists(rel) {
  return fs.existsSync(path.join(ROOT, rel));
}

function relativeLinksFrom(docRel, targets) {
  const fromDir = path.posix.dirname(docRel.replace(/\\/g, "/"));
  return targets.map((target) => {
    let rel = path.posix.relative(fromDir, target.replace(/\\/g, "/"));
    if (!rel.startsWith(".")) rel = `./${rel}`;
    return rel;
  });
}

function assertContainsCanonicalLinks(docRel, text) {
  const [link36, link37] = relativeLinksFrom(docRel, [
    CANONICAL_O36_1,
    CANONICAL_O37_1
  ]);
  assert.ok(
    text.includes(link36),
    `${docRel} must contain working relative link ${link36}`
  );
  assert.ok(
    text.includes(link37),
    `${docRel} must contain working relative link ${link37}`
  );
  assert.equal(exists(CANONICAL_O36_1), true);
  assert.equal(exists(CANONICAL_O37_1), true);
}

function assertAction10AuthorityClarity(docRel, text) {
  assert.ok(
    ACTIONS_8911_FACTORS.test(text),
    `${docRel} must state actions 8, 9, and 11 use exact 2-of-3 current recovery factors`
  );
  assert.ok(
    ACTION10_DISTINCTION.test(text),
    `${docRel} must preserve the action-10 validator-plus-exact-2-of-3 distinction`
  );
  assert.ok(
    VALIDATOR_THRESHOLD_LIMIT.test(text),
    `${docRel} must state the validator never counts toward the recovery-factor threshold`
  );
}

function assertMarkerBeforeHeading(text, marker, heading) {
  const markerIdx = text.indexOf(marker);
  const headingIdx = text.indexOf(heading);
  assert.notEqual(markerIdx, -1, `missing marker near ${heading}`);
  assert.notEqual(headingIdx, -1, `missing heading ${heading}`);
  // Marker must appear immediately before the heading: no other ## between them.
  const between = text.slice(markerIdx, headingIdx);
  assert.ok(
    markerIdx < headingIdx,
    `marker must precede ${heading}`
  );
  assert.doesNotMatch(
    between.slice(marker.length),
    /\n## /u,
    `marker must be immediately before ${heading} without intervening headings`
  );
}

function inlineMarkerOffsets(text) {
  const offsets = [];
  let from = 0;
  while (from < text.length) {
    const idx = text.indexOf(INLINE_RETIRED, from);
    if (idx === -1) break;
    offsets.push(idx);
    from = idx + INLINE_RETIRED.length;
  }
  return offsets;
}

function assertInlineMarkersPrecedeCancelSections(rel, text) {
  const offsets = inlineMarkerOffsets(text);
  assert.equal(
    offsets.length,
    2,
    `${rel} must contain exactly two inline retired-alternative markers`
  );

  for (let i = 0; i < INLINE_CANCEL_TARGETS.length; i += 1) {
    const markerIdx = offsets[i];
    const { label, re } = INLINE_CANCEL_TARGETS[i];
    const afterMarker = text.slice(markerIdx + INLINE_RETIRED.length);
    const match = afterMarker.match(re);
    assert.ok(
      match,
      `${rel} marker ${i + 1} must precede ${label}`
    );
    const between = afterMarker.slice(0, match.index);
    assert.doesNotMatch(
      between,
      /\n##[#]? /u,
      `${rel} marker before ${label} must not have another same-level section intervening`
    );
  }
}

describe("PhilCore recovery cancellation documentation alignment", function () {
  it("marks same-lineage historical V2 docs with Marker A and canonical links", function () {
    for (const rel of SAME_LINEAGE_V2_DOCS) {
      assert.equal(exists(rel), true, `missing ${rel}`);
      const text = read(rel);
      assert.ok(
        text.includes(MARKER_A),
        `${rel} must contain Marker A: ${MARKER_A}`
      );
      assertAction10AuthorityClarity(rel, text);
      assertContainsCanonicalLinks(rel, text);
    }
  });

  it("places inline retired-alternative markers in O30/O31 interface docs", function () {
    for (const rel of INLINE_RETIRED_DOCS) {
      const text = read(rel);
      assertInlineMarkersPrecedeCancelSections(rel, text);
    }
  });

  it("marks N-series security docs with Marker B and canonical V2 links", function () {
    for (const rel of N_SERIES_SECURITY_DOCS) {
      assert.equal(exists(rel), true, `missing ${rel}`);
      const text = read(rel);
      assert.ok(
        text.includes(MARKER_B),
        `${rel} must contain Marker B: ${MARKER_B}`
      );
      assert.ok(
        text.includes("PhilCore4337Account"),
        `${rel} must name the separate PhilCore4337Account model`
      );
      assert.ok(
        text.includes("PhilCoreV2MinimalAccountV2"),
        `${rel} must distinguish PhilCoreV2MinimalAccountV2`
      );
      assertAction10AuthorityClarity(rel, text);
      assertContainsCanonicalLinks(rel, text);
    }
  });

  it("places Marker B immediately before ACP-0002 N.4 and N.8 recovery evidence sections", function () {
    assert.equal(exists(ACP_0002), true);
    const text = read(ACP_0002);
    assert.ok(text.includes(MARKER_B), "ACP-0002 must contain Marker B");
    assertAction10AuthorityClarity(ACP_0002, text);
    assertMarkerBeforeHeading(text, MARKER_B, N8_HEADING);
    // Second occurrence before N.4: find the marker instance nearest N.4.
    const n4Idx = text.indexOf(N4_HEADING);
    assert.notEqual(n4Idx, -1);
    const beforeN4 = text.lastIndexOf(MARKER_B, n4Idx);
    assert.notEqual(beforeN4, -1, "Marker B must appear before N.4 heading");
    assert.doesNotMatch(
      text.slice(beforeN4 + MARKER_B.length, n4Idx),
      /\n## /u,
      "Marker B must be immediately before N.4 without intervening headings"
    );
    assertContainsCanonicalLinks(ACP_0002, text);
  });

  it("records the July 31, 2026 V2 recovery-authority decision", function () {
    assert.equal(exists(DECISION_RECORD), true, "decision record must exist");
    const text = read(DECISION_RECORD);
    assert.ok(text.includes("July 31, 2026"));
    assert.ok(/exact 2-of-3/i.test(text));
    assert.ok(
      ACTION10_AUTHORITY.test(text),
      "decision record must contain precise action-10 authority: current validator plus exact 2-of-3"
    );
    assert.ok(
      VALIDATOR_THRESHOLD_LIMIT.test(text),
      "decision record must state the validator never counts toward the recovery-factor threshold"
    );
    assert.ok(text.includes("3") && text.includes("5") && text.includes("6"));
    assert.ok(
      /bitmaps?\s+3,\s*5,\s*and\s*6|bitmaps?\s*`?3`?,\s*`?5`?,\s*(and\s*)?`?6`?/i.test(text)
      || (text.includes("`3`") && text.includes("`5`") && text.includes("`6`")),
      "decision record must state valid pair bitmaps 3, 5, and 6"
    );
    assert.ok(
      /validator-only|validator-plus-one/i.test(text),
      "decision record must keep validator-only and validator-plus-one prohibited"
    );
    assert.ok(
      /two compromised|two-compromised|two-domain/i.test(text),
      "decision record must state accepted two-compromised-domain residual risk"
    );
    assert.ok(
      /actions?\s*8[–-]11|actions 8, 9, 10, and 11|actions `8`/i.test(text)
      || (text.includes("8") && text.includes("9") && text.includes("10") && text.includes("11")),
      "decision record must cover actions 8–11"
    );
    assert.ok(
      text.includes("PhilCore4337Account"),
      "decision record must keep separate N-series scope"
    );
    assert.ok(text.includes("PhilCoreV2MinimalAccountV2"));
    assertContainsCanonicalLinks(DECISION_RECORD, text);
    assert.ok(
      /does not authorize|no public deployment|ceremony/i.test(text),
      "decision record must not authorize public deployment or ceremony"
    );
  });

  it("indexes the decision record and canonical V2 sources without mislabeling N-series", function () {
    const text = read(CANONICAL_DOCS);
    assert.ok(
      text.includes("PHILCORE_RECOVERY_AUTHORITY_DECISION_RECORD.md"),
      "CANONICAL_DOCS must list the decision record"
    );
    assert.ok(
      text.includes("O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md")
    );
    assert.ok(
      text.includes("O37_1_RECOVERY_LIFECYCLE_UPDATE.md")
    );
    assert.ok(
      /current V2|V2 authority|exact 2-of-3/i.test(text),
      "CANONICAL_DOCS must identify O.36.1/O.37.1 (and decision record) as current V2 authority sources"
    );
    assert.ok(
      text.includes("PHILCORE_ERC4337_ROTATION_AND_RECOVERY.md")
      || text.includes("PhilCore ERC-4337 Rotation And Recovery")
    );
    assert.ok(
      /N-series|PhilCore4337Account|separate .*owner\/recoveryAuthority|separate contract scope/i.test(text),
      "CANONICAL_DOCS must label N-series documents with separate contract scope"
    );
    const staleSection = text.slice(text.indexOf("## 5. Stale Or Superseded Docs"));
    assert.equal(
      staleSection.includes("PHILCORE_ERC4337_ROTATION_AND_RECOVERY.md"),
      false,
      "N-series recovery docs must not be misfiled as stale solely for differing authority"
    );
    assert.equal(
      staleSection.includes("PHILCORE_RECOVERY_AUTHORITY_RUNBOOK.md"),
      false
    );
  });

  it("preserves canonical O.36.1 and O.37.1 exact action and matrix statements", function () {
    const o36 = read(CANONICAL_O36_1);
    const o37 = read(CANONICAL_O37_1);
    assert.ok(/exact\s+2-of-3/i.test(o36));
    assert.ok(/execution validator never counts/i.test(o36));
    assert.ok(o36.includes("8") || /action type/i.test(o36));
    assert.match(o36, /cancel validator recovery/i);
    assert.match(o36, /cancel recovery-config rotation/i);
    assert.ok(/No validator-only or validator-plus-one-factor cancellation exists/i.test(o36));
    assert.ok(/exact current 2-of-3 factors authorize action type `8`/i.test(o37));
    assert.ok(o37.includes("`9`") || /action type `9`/i.test(o37));
    assert.ok(o37.includes("`10`") || /action type `10`/i.test(o37));
    assert.ok(o37.includes("`11`") || /action type `11`/i.test(o37));
  });

  it("locks the authoritative V2 threat model to fixed-role exact 2-of-3 semantics", function () {
    const text = read(AUTHORITATIVE_THREAT_MODEL);
    assert.match(text, /fixed recovery roles/i);
    assert.match(text, /bitmaps are `3` .*`5` .*`6`/is);
    assert.match(text, /nonzero and pairwise distinct/i);
    assert.match(text, /not sorted by\s+numeric value or address/i);
    assert.match(text, /validator is not a recovery factor/i);
    assert.match(text, /cannot veto recovery/i);
    assert.match(text, /172800 seconds \(48 hours\)/i);
    assert.match(text, /604800 seconds \(7 days\)/i);
    assert.match(text, /independently custodied/i);
    assert.match(text, /protocol cryptography cannot prove/i);
    assert.match(text, /validator-plus-one-factor cancellation.*superseded/is);
  });
});
