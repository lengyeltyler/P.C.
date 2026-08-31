const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const {
  USER_SESSION_LIFECYCLE_TRANSITION_TABLE,
  createAuditEventDraft,
  createEphemeralUserSessionLifecycleStore,
  createInMemoryAuditDraftCollector,
  createUserSessionContext,
  createUserSessionLifecycleSnapshot,
  deriveUserSessionContextFromLifecycle,
  formatAlpha0LifecycleDiagnosticResult,
  isUserSessionLifecycleEvent,
  isUserSessionLifecycleState,
  runAlpha0LifecycleDiagnostic,
  transitionUserSessionLifecycle,
  validateUserSessionLifecycleSnapshotShape,
  validateUserSessionTransitionRequestShape
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

function shell(args) {
  return spawnSync(
    process.execPath,
    ["--import", "tsx", "./scripts/run-philcore-alpha0-shell.cjs", ...args],
    {
      cwd: process.cwd(),
      encoding: "utf8"
    }
  );
}

function initializedStore() {
  const store = createEphemeralUserSessionLifecycleStore();
  const result = store.initialize({
    sessionId: "session-1",
    transitionRequestId: "initialize-1"
  });
  assert.equal(result.status, "initialized");
  assert.equal(store.getSnapshot().state, "locked");
  return store;
}

function unlock(store) {
  store.requestTransition({
    transitionRequestId: "unlock-request-1",
    event: "request_unlock"
  });
  return store.requestTransition({
    transitionRequestId: "unlock-success-1",
    event: "unlock_succeeded",
    evidenceReferences: [{
      referenceId: "unlock-evidence-ref-1",
      kind: "unlock_evidence",
      source: "test-fixture",
      verified: false,
      rawEvidenceIncluded: false
    }]
  });
}

describe("PhilCore User Session lifecycle state model", function () {
  it("defines lifecycle states, events, and deterministic transition rules", function () {
    assert.equal(isUserSessionLifecycleState("locked"), true);
    assert.equal(isUserSessionLifecycleState("authenticated"), false);
    assert.equal(isUserSessionLifecycleEvent("request_unlock"), true);
    assert.equal(isUserSessionLifecycleEvent("authenticate"), false);
    assert.ok(USER_SESSION_LIFECYCLE_TRANSITION_TABLE.some(
      (rule) => rule.currentState === "locked"
        && rule.event === "request_unlock"
        && rule.nextState === "unlocking"
    ));
  });

  it("initializes an ephemeral lifecycle store into locked state", function () {
    const store = initializedStore();
    const snapshot = store.getSnapshot();

    assert.equal(snapshot.state, "locked");
    assert.equal(snapshot.sequence, 1);
    assert.equal(snapshot.persisted, false);
    assert.equal(snapshot.authenticatesUser, false);
    assert.equal(snapshot.unlocksVault, false);
    assert.equal(snapshot.grantsAuthority, false);
    assert.equal(Object.isFrozen(snapshot), true);
  });

  it("runs a valid unlock transition sequence without authenticating or unlocking vaults", function () {
    const store = initializedStore();
    const result = unlock(store);

    assert.equal(result.status, "transitioned");
    assert.equal(result.transitionResult.status, "transitioned");
    assert.equal(store.getSnapshot().state, "unlocked");
    assert.equal(result.transitionResult.evidenceReferencesVerified, false);
    assert.equal(result.transitionResult.futureRequirements[0].evidenceKind, "unlock_evidence");
    assert.equal(result.transitionResult.futureRequirements[0].verified, false);
    assert.equal(store.getSnapshot().authenticatesUser, false);
    assert.equal(store.getSnapshot().unlocksVault, false);
  });

  it("failed unlock returns to locked", function () {
    const store = initializedStore();
    store.requestTransition({
      transitionRequestId: "unlock-request-1",
      event: "request_unlock"
    });
    const result = store.requestTransition({
      transitionRequestId: "unlock-failed-1",
      event: "unlock_failed"
    });

    assert.equal(result.status, "transitioned");
    assert.equal(result.transitionResult.previousState, "unlocking");
    assert.equal(result.transitionResult.nextState, "locked");
    assert.equal(store.getSnapshot().state, "locked");
  });

  it("runs suspend and resume sequence", function () {
    const store = initializedStore();
    unlock(store);
    assert.equal(store.requestTransition({
      transitionRequestId: "suspend-request-1",
      event: "request_suspend"
    }).transitionResult.nextState, "suspending");
    assert.equal(store.requestTransition({
      transitionRequestId: "suspend-completed-1",
      event: "suspend_completed"
    }).transitionResult.nextState, "suspended");
    assert.equal(store.requestTransition({
      transitionRequestId: "resume-request-1",
      event: "request_resume"
    }).transitionResult.nextState, "resuming");
    const resumed = store.requestTransition({
      transitionRequestId: "resume-success-1",
      event: "resume_succeeded",
      evidenceReferences: [{
        referenceId: "user-presence-ref-1",
        kind: "user_presence_evidence",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });

    assert.equal(resumed.status, "transitioned");
    assert.equal(store.getSnapshot().state, "unlocked");
    assert.equal(resumed.transitionResult.evidenceReferencesVerified, false);
  });

  it("runs timeout and expiry sequence", function () {
    const store = initializedStore();
    unlock(store);
    const warning = store.requestTransition({
      transitionRequestId: "timeout-warning-1",
      event: "timeout_warning",
      evidenceReferences: [{
        referenceId: "timeout-source-ref-1",
        kind: "timeout_source",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });
    const expired = store.requestTransition({
      transitionRequestId: "timeout-reached-1",
      event: "timeout_reached",
      evidenceReferences: [{
        referenceId: "timeout-source-ref-2",
        kind: "timeout_source",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });

    assert.equal(warning.transitionResult.nextState, "expiring");
    assert.equal(expired.transitionResult.nextState, "expired");
    assert.equal(store.getSnapshot().state, "expired");
    assert.equal(store.requestTransition({
      transitionRequestId: "lock-after-expired-1",
      event: "request_lock"
    }).transitionResult.nextState, "locked");
  });

  it("runs explicit lock sequence from unlocked state", function () {
    const store = initializedStore();
    unlock(store);
    const result = store.requestTransition({
      transitionRequestId: "request-lock-1",
      event: "request_lock"
    });

    assert.equal(result.status, "transitioned");
    assert.equal(result.transitionResult.previousState, "unlocked");
    assert.equal(result.transitionResult.nextState, "locked");
    assert.equal(result.transitionResult.guard.futureActiveCapabilityRevocationRequired, true);
  });

  it("runs recovery enter and cancel sequence", function () {
    const store = initializedStore();
    const entered = store.requestTransition({
      transitionRequestId: "recovery-request-1",
      event: "request_recovery",
      evidenceReferences: [{
        referenceId: "recovery-reference-1",
        kind: "recovery_evidence",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });
    const cancelled = store.requestTransition({
      transitionRequestId: "recovery-cancelled-1",
      event: "recovery_cancelled"
    });

    assert.equal(entered.transitionResult.nextState, "recovery_mode");
    assert.equal(cancelled.transitionResult.nextState, "locked");
  });

  it("runs recovery enter and complete sequence", function () {
    const store = initializedStore();
    store.requestTransition({
      transitionRequestId: "recovery-request-1",
      event: "request_recovery",
      evidenceReferences: [{
        referenceId: "recovery-reference-1",
        kind: "recovery_evidence",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });
    const completed = store.requestTransition({
      transitionRequestId: "recovery-completed-1",
      event: "recovery_completed",
      evidenceReferences: [{
        referenceId: "recovery-reference-2",
        kind: "recovery_evidence",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });

    assert.equal(completed.transitionResult.nextState, "locked");
    assert.equal(completed.transitionResult.evidenceReferencesVerified, false);
  });

  it("runs close sequence", function () {
    const store = initializedStore();
    const closing = store.requestTransition({
      transitionRequestId: "close-request-1",
      event: "request_close"
    });
    const closed = store.requestTransition({
      transitionRequestId: "close-completed-1",
      event: "close_completed"
    });

    assert.equal(closing.transitionResult.nextState, "closing");
    assert.equal(closed.transitionResult.nextState, "closed");
    assert.equal(store.getSnapshot().state, "closed");
  });

  it("rejects illegal transitions explicitly without coercion", function () {
    const store = initializedStore();
    const result = store.requestTransition({
      transitionRequestId: "bad-transition-1",
      event: "unlock_succeeded"
    });

    assert.equal(result.status, "rejected");
    assert.equal(result.transitionResult.status, "rejected");
    assert.equal(result.transitionResult.reason, "illegal-transition");
    assert.equal(result.transitionResult.previousState, "locked");
    assert.equal(result.transitionResult.nextState, "locked");
    assert.equal(store.getSnapshot().state, "locked");
  });

  it("rejects duplicate transition request IDs without advancing sequence", function () {
    const store = initializedStore();
    const before = store.getSnapshot().sequence;
    const result = store.requestTransition({
      transitionRequestId: "initialize-1",
      event: "request_unlock"
    });

    assert.equal(result.status, "rejected");
    assert.equal(result.transitionResult.reason, "duplicate-transition-request");
    assert.equal(store.getSnapshot().sequence, before);
  });

  it("keeps snapshots immutable and advances sequence on legal transitions", function () {
    const store = initializedStore();
    const before = store.getSnapshot();
    const result = store.requestTransition({
      transitionRequestId: "unlock-request-1",
      event: "request_unlock"
    });

    try {
      before.state = "unlocked";
    } catch {
      // Frozen snapshots may throw; either way state must remain unchanged.
    }
    assert.equal(before.state, "locked");
    assert.equal(result.transitionResult.snapshot.sequence, before.sequence + 1);
    assert.equal(Object.isFrozen(result.transitionResult.snapshot), true);
  });

  it("models evidence references only and rejects raw evidence payload fields", function () {
    const valid = validateUserSessionTransitionRequestShape({
      event: "unlock_succeeded",
      evidenceReferences: [{
        referenceId: "unlock-evidence-ref-1",
        kind: "unlock_evidence",
        verified: false,
        rawEvidenceIncluded: false
      }]
    });
    const invalid = validateUserSessionTransitionRequestShape({
      event: "unlock_succeeded",
      evidenceReferences: [{
        referenceId: "unlock-evidence-ref-1",
        kind: "unlock_evidence",
        authenticatorData: "raw"
      }]
    });

    assert.equal(valid.valid, true);
    assert.equal(invalid.valid, false);
    assert.ok(invalid.errors.some((error) => error.includes("raw evidence field")));
  });

  it("validates snapshot shape and rejects secret-shaped metadata", function () {
    const snapshot = createUserSessionLifecycleSnapshot({
      sessionId: "session-secret",
      metadata: {
        requestMetadata: {
          phil_secret: "must-not-appear"
        }
      }
    });
    const validation = validateUserSessionLifecycleSnapshotShape(snapshot);

    assert.equal(validation.valid, false);
    assert.equal(JSON.stringify(snapshot).includes("must-not-appear"), false);
  });

  it("derives User Session context without mutating active capabilities", function () {
    const session = createUserSessionContext({
      sessionId: "session-1",
      status: "locked",
      activeApplicationId: "ethereum-net",
      activeCapabilityIds: ["capability-existing"],
      pendingIntentIds: ["intent-existing"],
      policyMode: "default"
    }).context;
    const store = initializedStore();
    unlock(store);

    const result = deriveUserSessionContextFromLifecycle({
      userSessionContext: session,
      lifecycleSnapshot: store.getSnapshot()
    });

    assert.equal(result.status, "approved");
    assert.equal(result.context.status, "unlocked");
    assert.deepEqual(result.context.activeCapabilityIds, ["capability-existing"]);
    assert.deepEqual(session.activeCapabilityIds, ["capability-existing"]);
    assert.equal(result.context.metadata.lifecycleState, "unlocked");
    assert.equal(result.context.metadata.requestMetadata.lifecycleUnlocksVault, false);
  });

  it("creates audit drafts for lifecycle transitions without persistence or raw evidence", function () {
    const collector = createInMemoryAuditDraftCollector();
    const store = createEphemeralUserSessionLifecycleStore({
      auditDraftCollector: collector
    });
    const init = store.initialize({
      sessionId: "session-audit",
      transitionRequestId: "initialize-1"
    });
    const unlockRequest = store.requestTransition({
      transitionRequestId: "unlock-request-1",
      event: "request_unlock"
    });

    assert.equal(init.auditDraftCollectionResult.status, "collected");
    assert.equal(unlockRequest.transitionResult.auditEventDraft.category, "runtime");
    assert.equal(unlockRequest.transitionResult.auditEventDraft.persisted, false);
    assert.equal(collector.count(), 2);
    assert.equal(JSON.stringify(collector.getAll()).includes("authenticatorData"), false);
  });

  it("does not call vault, storage, WebAuthn, biometrics, World ID, proof, or adapter hooks", function () {
    const hooks = {
      vaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      biometricCalls: 0,
      worldIdCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    };
    const snapshot = createUserSessionLifecycleSnapshot({
      sessionId: "session-hooks",
      state: "locked",
      sequence: 1,
      version: 1
    });

    const result = transitionUserSessionLifecycle(snapshot, {
      transitionRequestId: "unlock-request-1",
      event: "request_unlock",
      metadata: { hooks }
    });

    assert.equal(result.status, "transitioned");
    assert.deepEqual(hooks, {
      vaultCalls: 0,
      storageCalls: 0,
      webAuthnCalls: 0,
      biometricCalls: 0,
      worldIdCalls: 0,
      proofCalls: 0,
      adapterCalls: 0
    });
  });

  it("preserves unrelated audit helper behavior", function () {
    const draft = createAuditEventDraft({
      category: "runtime",
      outcome: "validation_succeeded",
      summary: "independent draft"
    });

    assert.equal(draft.persisted, false);
  });
});

describe("PhilCore Alpha 0 lifecycle shell diagnostics", function () {
  it("runs lifecycle states diagnostic", function () {
    const result = runAlpha0LifecycleDiagnostic("states");
    const output = formatAlpha0LifecycleDiagnosticResult(result);

    assert.equal(result.finalStatus, "succeeded");
    assert.ok(result.stateList.includes("locked"));
    assert.match(output, /lifecycle states/);
    assert.match(output, /does not authenticate users or unlock vaults/);
  });

  it("runs valid lifecycle diagnostic sequence without authority", function () {
    const result = runAlpha0LifecycleDiagnostic("valid_unlock");

    assert.equal(result.finalStatus, "succeeded");
    assert.equal(result.finalState, "unlocked");
    assert.equal(result.productionAuthenticationPerformed, false);
    assert.equal(result.vaultUnlocked, false);
    assert.equal(result.activeCapabilityCreated, false);
    assert.equal(result.authorizationCreated, false);
  });

  it("runs invalid lifecycle diagnostic sequence as an expected rejection", function () {
    const result = runAlpha0LifecycleDiagnostic("invalid_transition");

    assert.equal(result.finalStatus, "succeeded");
    assert.equal(result.transitions.at(-1).status, "rejected");
    assert.equal(result.transitions.at(-1).reason, "illegal-transition");
  });

  it("runs shell lifecycle mode non-interactively", function () {
    const result = shell(["--lifecycle", "--lifecycle-sequence", "valid_unlock"]);

    assert.equal(result.status, 0);
    assert.match(result.stdout, /PhilCore Alpha 0 lifecycle diagnostic: valid_unlock/);
    assert.match(result.stdout, /Final lifecycle state: unlocked/);
    assert.match(result.stdout, /production authentication: not performed/);
    assert.match(result.stdout, /vault unlock: not performed/);
  });

  it("emits lifecycle diagnostic JSON", function () {
    const result = shell(["--lifecycle", "--lifecycle-sequence", "timeout", "--json"]);

    assert.equal(result.status, 0);
    const json = JSON.parse(result.stdout);
    assert.equal(json.sequence, "timeout");
    assert.equal(json.nonAuthority.vaultUnlocked, false);
    assert.equal(json.nonAuthority.proofExecuted, false);
    assert.equal(json.nonAuthority.adapterExecuted, false);
  });

  it("rejects unknown lifecycle sequence without running scenarios", function () {
    const result = shell(["--lifecycle", "--lifecycle-sequence", "unknown"]);

    assert.equal(result.status, 2);
    assert.match(result.stderr, /Unknown lifecycle sequence: unknown/);
  });
});
