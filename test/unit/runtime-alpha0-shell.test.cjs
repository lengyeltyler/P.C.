const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const {
  formatAlpha0DemoResult,
  formatAlpha0ScenarioList,
  parseAlpha0ShellArgs,
  runAlpha0LifecycleDiagnosticAsync,
  runNonAuthoritativeAlpha0Demo,
  sanitizeAlpha0DemoResult,
  sanitizeAlpha0LifecycleDiagnosticResult
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function runShell(args) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "./scripts/run-philcore-alpha0-shell.cjs", ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8"
    }
  );
}

describe("PhilCore Alpha 0 interactive shell helpers", function () {
  it("lists supported scenarios", function () {
    const list = formatAlpha0ScenarioList();

    assert.match(list, /ordinary_success/);
    assert.match(list, /canonical_activation_world_id_required/);
    assert.match(list, /correlation_mismatch/);
  });

  it("parses scenario, json, and debug arguments", function () {
    const parsed = parseAlpha0ShellArgs([
      "--scenario",
      "ordinary_success",
      "--json",
      "--debug"
    ]);

    assert.equal(parsed.scenario, "ordinary_success");
    assert.equal(parsed.json, true);
    assert.equal(parsed.debug, true);
    assert.equal(parsed.error, undefined);
  });

  it("parses finalized Authorization Package diagnostic arguments", function () {
    const parsed = parseAlpha0ShellArgs([
      "--lifecycle",
      "--lifecycle-sequence",
      "production_finalized_authorization_package",
      "--finalized-authorization-package-scenario",
      "invalid_proof"
    ]);

    assert.equal(parsed.lifecycle, true);
    assert.equal(parsed.lifecycleSequence, "production_finalized_authorization_package");
    assert.equal(parsed.finalizedAuthorizationPackageScenario, "invalid_proof");
    assert.equal(parsed.error, undefined);
  });

  it("parses authorization execution readiness diagnostic arguments", function () {
    const parsed = parseAlpha0ShellArgs([
      "--lifecycle",
      "--lifecycle-sequence",
      "production_authorization_execution_readiness",
      "--authorization-execution-readiness-scenario",
      "nullifier_already_consumed"
    ]);

    assert.equal(parsed.lifecycle, true);
    assert.equal(parsed.lifecycleSequence, "production_authorization_execution_readiness");
    assert.equal(parsed.authorizationExecutionReadinessScenario, "nullifier_already_consumed");
    assert.equal(parsed.error, undefined);
  });

  it("formats successful scenario output without production authority language", async function () {
    const result = await runNonAuthoritativeAlpha0Demo({
      scenario: "ordinary_success"
    });
    const output = formatAlpha0DemoResult(result);

    assert.match(output, /Final status: succeeded/);
    assert.match(output, /Capability activation candidate status: pending_production_consent/);
    assert.match(output, /production authentication: not performed/);
    assert.match(output, /production user consent: not collected/);
    assert.match(output, /active capability: not created/);
    assert.match(output, /authorization: not created/);
    assert.match(output, /not production authorization/);
    assert.doesNotMatch(output, /privateKey/);
    assert.doesNotMatch(output, /authenticatorData/);
    assert.doesNotMatch(output, /clientDataJSON/);
    assert.doesNotMatch(output, /World ID verification: performed/);
  });

  it("formats World ID blocker presentation", async function () {
    const result = await runNonAuthoritativeAlpha0Demo({
      scenario: "canonical_activation_world_id_required"
    });
    const output = formatAlpha0DemoResult(result);

    assert.equal(result.status, "failed");
    assert.equal(result.failure.stage, "bounded_policy_evaluation");
    assert.match(output, /World ID required for chosen context: true/);
    assert.match(output, /requires_world_id_enrollment/);
    assert.match(output, /World ID verification: not performed/);
  });

  it("sanitizes JSON result data", async function () {
    const result = await runNonAuthoritativeAlpha0Demo({
      scenario: "ordinary_success"
    });
    const sanitized = sanitizeAlpha0DemoResult(result);
    const json = JSON.stringify(sanitized);

    assert.equal(sanitized.nonAuthority.activeCapabilityCreated, false);
    assert.equal(sanitized.nonAuthority.authorizationCreated, false);
    assert.equal(Array.isArray(sanitized.auditSummary), true);
    assert.doesNotMatch(json, /privateKey/);
    assert.doesNotMatch(json, /authenticatorData/);
    assert.doesNotMatch(json, /clientDataJSON/);
  });
});

describe("PhilCore Alpha 0 shell command", function () {
  this.timeout(120_000);

  it("runs a successful scenario non-interactively", function () {
    const result = runShell(["--scenario", "ordinary_success"]);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /PhilCore Alpha 0 shell: ordinary_success/);
    assert.match(result.stdout, /Final status: succeeded/);
    assert.match(result.stdout, /active capability: not created/);
  });

  it("runs a failure scenario non-interactively", function () {
    const result = runShell(["policy_denial"]);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /PhilCore Alpha 0 shell: policy_denial/);
    assert.match(result.stdout, /Final status: failed/);
    assert.match(result.stdout, /denied_by_policy/);
  });

  it("handles unknown scenarios without stack traces", function () {
    const result = runShell(["unknown_scenario"]);

    assert.equal(result.status, 2);
    assert.match(result.stderr, /Unknown scenario: unknown_scenario/);
    assert.match(result.stderr, /Available Alpha 0 scenarios/);
    assert.doesNotMatch(result.stderr, /at .*runAlpha0Shell/);
  });

  it("emits sanitized JSON mode", function () {
    const result = runShell(["--scenario", "ordinary_success", "--json"]);

    assert.equal(result.status, 0);
    const json = JSON.parse(result.stdout);
    assert.equal(json.scenario, "ordinary_success");
    assert.equal(json.status, "succeeded");
    assert.equal(json.nonAuthority.activeCapabilityCreated, false);
    assert.equal(json.nonAuthority.proofExecuted, false);
    assert.equal(json.nonAuthority.adapterExecuted, false);
    assert.equal(json.nonAuthority.persisted, false);
  });

  it("lists scenarios from the shell command", function () {
    const result = runShell(["--list"]);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /Available Alpha 0 scenarios/);
    assert.match(result.stdout, /ordinary_success/);
  });

  it("quarantines the ordinary finalized-package diagnostic at proof generation", async function () {
    const result = await runAlpha0LifecycleDiagnosticAsync(
      "production_finalized_authorization_package",
      { finalizedAuthorizationPackageScenario: "exact" }
    );
    const sanitized = sanitizeAlpha0LifecycleDiagnosticResult(result);
    const json = JSON.stringify(sanitized);

    assert.equal(result.finalStatus, "failed");
    assert.equal(sanitized.actionUnlockProofGeneration.status, "rejected");
    assert.equal(
      sanitized.actionUnlockProofGeneration.errorCode,
      "ACTION_UNLOCK_PROOF_REQUEST_MALFORMED"
    );
    assert.equal(sanitized.actionUnlockProofGeneration.proofGenerated, false);
    assert.equal(sanitized.actionUnlockProofVerification, undefined);
    assert.equal(sanitized.finalizedAuthorizationPackage, undefined);
    assert.doesNotMatch(json, /"proofBlob":/);
    assert.doesNotMatch(json, /"phil_secret"|nullifierSeed|privateKey/);
  });

  it("does not let an invalid-proof scenario bypass the proof-generation quarantine", async function () {
    const result = await runAlpha0LifecycleDiagnosticAsync(
      "production_finalized_authorization_package",
      { finalizedAuthorizationPackageScenario: "invalid_proof" }
    );
    const sanitized = sanitizeAlpha0LifecycleDiagnosticResult(result);

    assert.equal(result.finalStatus, "failed");
    assert.equal(sanitized.actionUnlockProofGeneration.status, "rejected");
    assert.equal(sanitized.actionUnlockProofGeneration.proofGenerated, false);
    assert.equal(sanitized.actionUnlockProofVerification, undefined);
    assert.equal(sanitized.finalizedAuthorizationPackage, undefined);
    assert.equal(sanitized.nonAuthority.proofExecuted, false);
    assert.equal(sanitized.nonAuthority.adapterExecuted, false);
  });

  it("quarantines ordinary execution-readiness diagnostics before proof export", async function () {
    const result = await runAlpha0LifecycleDiagnosticAsync(
      "production_authorization_execution_readiness",
      { authorizationExecutionReadinessScenario: "exact" }
    );
    const sanitized = sanitizeAlpha0LifecycleDiagnosticResult(result);
    const json = JSON.stringify(sanitized);

    assert.equal(result.finalStatus, "failed");
    assert.equal(sanitized.actionUnlockProofGeneration.status, "rejected");
    assert.equal(sanitized.actionUnlockProofGeneration.proofGenerated, false);
    assert.equal(sanitized.verifiedFactPublicationRequestDraft, undefined);
    assert.equal(sanitized.authorizationExecutionReadiness, undefined);
    assert.equal(sanitized.nonAuthority.proofExecuted, false);
    assert.equal(sanitized.nonAuthority.adapterExecuted, false);
    assert.doesNotMatch(json, /"proofBlob":/);
    assert.doesNotMatch(json, /"phil_secret"|nullifierSeed|privateKey/);
  });

  it("does not let alternate fact-state scenarios bypass proof quarantine", async function () {
    const result = await runAlpha0LifecycleDiagnosticAsync(
      "production_authorization_execution_readiness",
      { authorizationExecutionReadinessScenario: "fact_already_published" }
    );
    const sanitized = sanitizeAlpha0LifecycleDiagnosticResult(result);

    assert.equal(result.finalStatus, "failed");
    assert.equal(sanitized.actionUnlockProofGeneration.status, "rejected");
    assert.equal(sanitized.actionUnlockProofGeneration.proofGenerated, false);
    assert.equal(sanitized.verifiedFactPublicationRequestDraft, undefined);
    assert.equal(sanitized.authorizationExecutionReadiness, undefined);
  });
});
