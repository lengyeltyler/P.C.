const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {
  ALLOWED_CHANNELS,
  CHANNELS,
  containsForbiddenKey,
  isAllowedChannel,
  validateBridgePayload,
  validateNewIdentityPassphrase
} = require("../src/shared/bridge-contract.cjs");

function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error);
    process.exitCode = 1;
  }
}

test("bridge exposes only allowlisted channels", () => {
  assert.equal(isAllowedChannel(CHANNELS.GET_SNAPSHOT), true);
  assert.equal(isAllowedChannel("philcore:rpc:send"), false);
  assert.equal(ALLOWED_CHANNELS.some((channel) => channel.includes("public") || channel.includes("rpc")), false);
});

test("bridge rejects malformed payloads", () => {
  assert.equal(validateBridgePayload(CHANNELS.CREATE_LOCAL_IDENTITY, "bad").ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RUN_RECOVERY_DEMO, { scenario: "arbitrary_call" }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.UPDATE_SETTINGS, { sessionTimeoutMinutes: 0 }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.UPDATE_SETTINGS, { presentationMode: "developer" }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RENAME_LOCAL_IDENTITY, { label: "" }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RENAME_LOCAL_IDENTITY, { label: "My Phil" }).ok, true);
});

test("recovery enrollment bridge is exact and path/origin agnostic", () => {
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_PREFLIGHT, {
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true
  }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_PREFLIGHT, {
    profile: "STANDARD",
    origin: "https://caller-selected.example"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_STATUS, {
    method: "readAllSecrets"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_RESTORE_OFFLINE, {
    restorationInput: "x".repeat(257)
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_DELETE_FACTOR, {
    reference: "../../outside"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_STORE_CREDENTIAL, {
    role: 0,
    registration: { response: {} },
    generation: 1,
    custodyDomainCommitment: `0x${"11".repeat(32)}`,
    filePath: "/tmp/no"
  }).ok, false);
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC),
    true
  );
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION),
    true
  );
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION),
    true
  );
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC),
    true
  );
  assert.equal(
    CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC,
    "philcore:recoveryEnrollment:beginDisposableDiagnostic"
  );
  assert.equal(
    CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION,
    "philcore:recoveryEnrollment:verifyDisposableRegistration"
  );
  assert.equal(
    CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION,
    "philcore:recoveryEnrollment:verifyDisposableAssertion"
  );
  assert.equal(
    CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC,
    "philcore:recoveryEnrollment:cancelDisposableDiagnostic"
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC, {}).ok,
    true
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC, {}).ok,
    true
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC, {
      force: true
    }).ok,
    false
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC, {
      policyAccepted: true
    }).ok,
    false
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION, {
      policyAccepted: true
    }).ok,
    false
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION, {
      policyAccepted: true
    }).ok,
    false
  );
  const validRegistration = {
    id: "synthetic-disposable-registration",
    rawId: "AAAAAAAAAAAAAAAAAAAAAA",
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      attestationObject: "AAAAAAAAAAAAAAAAAAAAAA",
      clientDataJSON: "AAAAAAAAAAAAAAAAAAAAAA",
      publicKey: "AAAAAAAAAAAAAAAAAAAAAA",
      publicKeyAlgorithm: -7,
      transports: ["internal"]
    },
    clientExtensionResults: {}
  };
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION, {
      registration: validRegistration
    }).ok,
    true
  );
  const validAssertion = {
    id: "synthetic-disposable-assertion",
    rawId: "AAAAAAAAAAAAAAAAAAAAAA",
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: "AAAAAAAAAAAAAAAAAAAAAA",
      clientDataJSON: "AAAAAAAAAAAAAAAAAAAAAA",
      signature: "AAAAAAAAAAAAAAAAAAAAAA",
      userHandle: null
    },
    clientExtensionResults: {}
  };
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION, {
      assertion: validAssertion
    }).ok,
    true
  );
  const preloadSource = fs.readFileSync(
    path.resolve(__dirname, "../src/preload/preload.cjs"),
    "utf8"
  );
  assert.match(preloadSource, /cancelDisposableDiagnostic\s*:\s*\(\)\s*=>\s*invoke\(/u);
  assert.match(
    preloadSource,
    /CHANNELS\.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC/u
  );
});

test("new identity passphrase policy is stronger without breaking legacy unlock payloads", () => {
  assert.equal(validateNewIdentityPassphrase("short").ok, false);
  assert.deepEqual(validateNewIdentityPassphrase("lowercaseonlypassphrase").missing.sort(), ["number", "special", "uppercase"].sort());
  assert.equal(validateNewIdentityPassphrase("Valid-local-alpha!1").ok, true);
  assert.equal(validateBridgePayload(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Weak",
    passphrase: "legacy-passphrase",
    createRecoveryAuthority: true
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Strong",
    passphrase: "Valid-local-alpha!1",
    createRecoveryAuthority: true
  }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.AUTHENTICATE_LOCAL, {
    passphrase: "legacy-passphrase"
  }).ok, true);
});

test("Phil preview metadata is narrow local-only decoration", () => {
  const valid = validateBridgePayload(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Preview Phil",
    passphrase: "Valid-local-alpha!1",
    createRecoveryAuthority: true,
    philPreview: {
      selectionId: "local-philenator-07",
      sequence: 7,
      traits: {
        bgColor: "bgColor-12345678", bgNebula: "bgNebula-12345678", bgStars: "bgStars-12345678",
        bgSpiral: "bgSpiral-12345678", bgDust: "bgDust-12345678", bgOverlay: "bgOverlay-12345678",
        bodyBase: "bodyBase-12345678", body: "body-12345678", spikes: "spikes-12345678",
        teeth: "teeth-12345678", jawNose: "jawNose-12345678", eyes: "eyes-12345678", top: "top-12345678"
      },
      source: "philenator-local",
      artworkSource: "philenator-local",
      generatorRevision: "f174dedda16a354c592e3252d9b0b5805bab59c4",
      mintStatus: "not-minted",
      publicToken: null
    }
  });
  assert.equal(valid.ok, true);
  assert.equal(valid.value.philPreview.selectionId, "local-philenator-07");
  assert.equal(valid.value.philPreview.publicToken, null);
  assert.equal(validateBridgePayload(CHANNELS.CREATE_LOCAL_IDENTITY, {
    label: "Remote Phil",
    passphrase: "Valid-local-alpha!1",
    createRecoveryAuthority: true,
    philPreview: {
      selectionId: "local-philenator-07",
      sequence: 7,
      traits: {
        bgColor: "bgColor-12345678", bgNebula: "bgNebula-12345678", bgStars: "bgStars-12345678",
        bgSpiral: "bgSpiral-12345678", bgDust: "bgDust-12345678", bgOverlay: "bgOverlay-12345678",
        bodyBase: "bodyBase-12345678", body: "body-12345678", spikes: "spikes-12345678",
        teeth: "teeth-12345678", jawNose: "jawNose-12345678", eyes: "eyes-12345678", top: "top-12345678"
      },
      source: "onchain",
      artworkSource: "onchain",
      mintStatus: "minted",
      publicToken: "7"
    }
  }).ok, false);
});

test("bridge rejects arbitrary protected-action approval and workflow fields", () => {
  assert.equal(validateBridgePayload(CHANNELS.PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {}).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind: "local_authorization_execution",
    target: "0x1234"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: "approval_1",
    callData: "0xdeadbeef"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: "workflow_1",
    decision: "approve",
    presentationDigest: "0x" + "11".repeat(32),
    freshAuthenticationEvidenceId: "fresh_1",
    signature: "0x1234"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    workflowId: "workflow_1",
    terminalStatus: "timed_out",
    reason: "user_presence_timeout"
  }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT, {
    workflowId: "sepolia_workflow",
    approvalArtifactId: "approval_artifact",
    presentationDigest: `0x${"11".repeat(32)}`,
    freshAuthenticationEvidenceId: "fresh_auth_evidence",
    proofTimeoutMs: 120000
  }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT, {
    workflowId: "sepolia_workflow",
    privateKey: `0x${"11".repeat(32)}`
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    workflowId: "workflow_1",
    terminalStatus: "completed"
  }).ok, false);
});

test("bridge detects secret-shaped keys", () => {
  assert.equal(containsForbiddenKey({ safe: "ok" }), false);
  assert.equal(containsForbiddenKey({ privateKey: "nope" }), true);
  assert.equal(containsForbiddenKey({ nested: { vaultKey: "nope" } }), true);
});

test("recovery transport bridge is exact and rejects Role 2 IPC", () => {
  const {
    RECOVERY_TRANSPORT_CHANNELS
  } = require("../src/shared/bridge-contract.cjs");
  assert.ok(RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_BEGIN));
  assert.ok(RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_STATUS));
  assert.ok(RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_CANCEL));
  assert.ok(
    RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_BEGIN_ROLE0_ASSERTION)
  );
  assert.ok(
    RECOVERY_TRANSPORT_CHANNELS.includes(CHANNELS.RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION)
  );
  assert.equal(
    RECOVERY_TRANSPORT_CHANNELS.some((channel) => /role2|offline|secret/i.test(channel)),
    false
  );
  assert.equal(isAllowedChannel("philcore:recoveryTransport:contributeRole2"), false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap: 3 }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap: 5 }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap: 6 }).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap: 4 }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, {
    bitmap: 3,
    digest: `0x${"11".repeat(32)}`
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_BEGIN, {
    bitmap: 3,
    account: "0x0000000000000000000000000000000000004400"
  }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_STATUS, {}).ok, true);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_STATUS, { x: 1 }).ok, false);
  assert.equal(validateBridgePayload(CHANNELS.RECOVERY_TRANSPORT_CANCEL, {}).ok, true);
  const preload = fs.readFileSync(
    path.join(__dirname, "../src/preload/preload.cjs"),
    "utf8"
  );
  assert.match(preload, /RECOVERY_TRANSPORT_BEGIN/);
  assert.match(preload, /transport:\s*Object\.freeze/);
  assert.doesNotMatch(preload, /contributeRole2|role2Factor/);
});

test("retired assertion oracle is fully removed from the bridge", () => {
  assert.equal(CHANNELS.RECOVERY_ENROLLMENT_REQUEST_ASSERTION, undefined);
  assert.equal(
    ALLOWED_CHANNELS.includes("philcore:recoveryEnrollment:requestAssertion"),
    false
  );
  assert.equal(
    isAllowedChannel("philcore:recoveryEnrollment:requestAssertion"),
    false
  );
  assert.throws(() => {
    validateBridgePayload("philcore:recoveryEnrollment:requestAssertion", {});
  });
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC),
    true
  );
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION),
    true
  );
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION),
    true
  );
  assert.equal(
    ALLOWED_CHANNELS.includes(CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC),
    true
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC, {}).ok,
    true
  );
  assert.equal(
    validateBridgePayload(CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC, {}).ok,
    true
  );
});
