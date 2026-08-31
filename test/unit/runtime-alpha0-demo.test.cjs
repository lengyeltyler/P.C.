const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");

const {
  runNonAuthoritativeAlpha0Demo
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function assertNonAuthoritative(result) {
  assert.equal(result.fixtureOnly, true);
  assert.equal(result.productionAuthenticationPerformed, false);
  assert.equal(result.productionUserConsentCollected, false);
  assert.equal(result.worldIdEnrollmentVerified, false);
  assert.equal(result.activeCapabilityCreated, false);
  assert.equal(result.authorizationCreated, false);
  assert.equal(result.proofExecuted, false);
  assert.equal(result.adapterExecuted, false);
  assert.equal(result.persisted, false);
  assert.equal(result.limitations.includes("no_active_capability"), true);
  assert.equal(result.limitations.includes("no_authorization"), true);
}

describe("PhilCore Alpha 0 non-authoritative orchestration demo", function () {
  it("successful ordinary path reaches a capability activation candidate without authority", async function () {
    const result = await runNonAuthoritativeAlpha0Demo({
      scenario: "ordinary_success"
    });

    assert.equal(result.status, "succeeded");
    assert.equal(result.finalCapabilityActivationCandidateStatus, "pending_production_consent");
    assert.equal(result.worldIdRequiredForChosenContext, false);
    assert.ok(result.artifacts.capabilityActivationCandidateId);
    assert.ok(result.artifacts.capabilityGrantDraftId);
    assert.ok(result.artifacts.boundedTrustEvaluationResultId);
    assert.ok(result.artifacts.boundedPolicyEvaluationResultId);
    assert.ok(result.artifacts.userApprovalRequestDraftId);
    assert.ok(result.artifacts.userDecisionFixtureArtifactId);
    assert.equal(result.auditDraftCount, 11);
    assert.equal(result.stages.at(-1).stage, "final_summary");
    assertNonAuthoritative(result);
  });

  it("ordinary runtime does not require World ID automatically", async function () {
    const result = await runNonAuthoritativeAlpha0Demo();

    assert.equal(result.status, "succeeded");
    assert.equal(result.worldIdRequiredForChosenContext, false);
    assert.equal(result.worldIdEnrollmentVerified, false);
  });

  it("stops each explicit failure scenario at the expected stage", async function () {
    const expectations = {
      malformed_capability_request: "capability_grant_draft",
      insufficient_public_trust_metadata: "public_trust_metadata_evaluation",
      failed_webauthn_fixture: "webauthn_fixture_verification",
      revoked_credential_lifecycle: "bounded_trust_evaluation",
      policy_denial: "bounded_policy_evaluation",
      denied_user_decision_fixture: "user_decision_fixture",
      expired_artifact_chain: "user_approval_request_draft",
      correlation_mismatch: "capability_activation_candidate"
    };

    for (const [scenario, expectedStage] of Object.entries(expectations)) {
      const result = await runNonAuthoritativeAlpha0Demo({ scenario });
      assert.equal(result.status, "failed", scenario);
      assert.equal(result.failure.stage, expectedStage, scenario);
      assert.equal(result.artifacts.capabilityActivationCandidateId, undefined, scenario);
      assertNonAuthoritative(result);
    }
  });

  it("canonical activation stops on unresolved World ID enrollment", async function () {
    const result = await runNonAuthoritativeAlpha0Demo({
      scenario: "canonical_activation_world_id_required"
    });

    assert.equal(result.status, "failed");
    assert.equal(result.failure.stage, "bounded_policy_evaluation");
    assert.equal(result.failure.outcome, "requires_world_id_enrollment");
    assert.equal(result.worldIdRequiredForChosenContext, true);
    assert.equal(result.worldIdEnrollmentVerified, false);
    assert.equal(result.artifacts.capabilityActivationCandidateId, undefined);
    assertNonAuthoritative(result);
  });

  it("returns a sanitized audit summary for facade-emitted stages", async function () {
    const result = await runNonAuthoritativeAlpha0Demo({
      scenario: "ordinary_success"
    });

    assert.equal(result.auditSummary.length, result.auditDraftCount);
    assert.equal(result.auditSummary.every((entry) => entry.eventDraftId), true);
    assert.equal(result.auditSummary.every((entry) => !("redactedDetails" in entry)), true);
    assert.equal(result.auditSummary.some((entry) => entry.category === "trust"), true);
    assert.equal(
      result.auditSummary.some((entry) => entry.category === "authorization_request"),
      true
    );
  });

  it("script entry point runs the ordinary scenario", function () {
    const output = execFileSync(
      process.execPath,
      ["--import", "tsx", "./scripts/run-philcore-alpha0-demo.cjs", "ordinary_success"],
      {
        cwd: process.cwd(),
        encoding: "utf8"
      }
    );

    assert.match(output, /PhilCore Alpha 0 demo: ordinary_success/);
    assert.match(output, /Status: succeeded/);
    assert.match(output, /activeCapabilityCreated: false/);
  });
});
