"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { CHANNELS } = require("../src/shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createFixturePlatformKeyAdapter
} = require("../src/main/runtime-host.cjs");
const {
  PHIL_NOIR_ROOT_PROOF_TYPE,
  createNoirRootProofStack,
  proveNoirRootProofV1,
  resolveNoirRootProofPaths,
  verifyNoirRootProofV1
} = require("../src/main/noir-root-proof-stack.cjs");

const repositoryRoot = path.resolve(__dirname, "../../..");
const vector = JSON.parse(fs.readFileSync(
  path.join(repositoryRoot, "proofs/phil-v1-step3-noir/fixtures/canonical-vector.json"),
  "utf8"
));

function approve(host, kind) {
  const presentation = host.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, {
    kind,
    confirmationTarget: ""
  });
  assert.equal(presentation.status, "presentation_created");
  const approved = host.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: presentation.presentation.presentationId,
    decision: "approve",
    typedConfirmation: ""
  });
  assert.equal(approved.status, "approved");
  return approved;
}

async function testLowLevelProof() {
  const paths = resolveNoirRootProofPaths(repositoryRoot);
  const generated = await proveNoirRootProofV1({
    paths,
    philSecret: vector.privateWitness.philSecret,
    nullifierSeed: vector.privateWitness.nullifierSeed,
    publicInputs: vector.logicalPublicInputs,
    timeoutMs: 120_000
  });
  const verified = verifyNoirRootProofV1({
    paths,
    proof: generated.proof,
    publicInputBytes: generated.publicInputBytes,
    publicInputs: vector.logicalPublicInputs,
    timeoutMs: 120_000
  });
  assert.equal(verified.verified, true);
  assert.equal(generated.proofByteLength, 9_408);
  assert.equal(generated.publicInputByteLength, 416);
  assert.equal(generated.witnessFileUsed, false);
  assert.equal(generated.proverInputFileUsed, false);

  const tampered = Buffer.from(generated.proof.slice(2), "hex");
  tampered[Math.floor(tampered.length / 2)] ^= 1;
  assert.throws(() => verifyNoirRootProofV1({
    paths,
    proof: `0x${tampered.toString("hex")}`,
    publicInputBytes: generated.publicInputBytes,
    publicInputs: vector.logicalPublicInputs,
    timeoutMs: 120_000
  }), /Barretenberg verification failed/u);
}

async function testProductFlow() {
  const storageRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-noir-product-test-"));
  try {
    const host = createDesktopRuntimeHost({
      preferencesPath: path.join(storageRoot, "prefs.json"),
      identityStorageRoot: path.join(storageRoot, "identities"),
      platformKeyAdapter: createFixturePlatformKeyAdapter(),
      rootProofStack: createNoirRootProofStack({ repositoryRoot }),
      sessionTtlMs: 600_000
    });
    const passphrase = "Noir-product-alpha-test!123";
    const created = host.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
      label: "Noir Alpha Test",
      passphrase,
      createRecoveryAuthority: true
    });
    assert.match(created.identity?.identityId || "", /^identity_/u);
    host.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase });
    host.invoke(CHANNELS.UNLOCK_VAULT, {});
    const enrollment = approve(host, "platform_unlock_enrollment");
    const enrolled = host.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
      passphrase,
      approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
    });
    assert.equal(enrolled.status, "enrolled");

    const execution = approve(host, "local_authorization_execution");
    const started = await host.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
      approvalArtifactId: execution.approvalArtifact.approvalArtifactId,
      proofTimeoutMs: 120_000
    });
    assert.equal(started.status, "signing_approval_required", started.workflow?.error);
    assert.equal(
      started.workflow.evidenceLabels.starkProofGeneration,
      "real_local_noir_ultra_keccak_zk_honk_alpha"
    );
    assert.equal(started.workflow.proof.proofType, PHIL_NOIR_ROOT_PROOF_TYPE);
    assert.equal(started.workflow.proof.proofByteLength, 9_408);
    assert.match(started.workflow.proof.rootProofNullifier, /^0x[0-9a-f]{64}$/u);

    const fresh = host.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
      workflowId: started.workflow.workflowId
    });
    assert.equal(fresh.status, "authenticated");
    const completed = await host.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
      workflowId: started.workflow.workflowId,
      decision: "approve",
      presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
      freshAuthenticationEvidenceId: fresh.evidence.evidenceId
    });
    assert.equal(completed.status, "completed", completed.workflow?.error);
    assert.equal(completed.workflow.execution.nullifierConsumed, true);
    assert.equal(completed.workflow.execution.consumerExecuted, true);
    assert.equal(completed.workflow.publicNetworkMutation, false);
    assert.equal(completed.workflow.proofWitnessExposed, false);
    const serialized = JSON.stringify(completed);
    assert.equal(serialized.includes(vector.privateWitness.philSecret.slice(2)), false);
    assert.equal(serialized.includes("phil_secret"), false);
    assert.equal(serialized.includes("nullifier_seed"), false);
    assert.equal(serialized.includes("privateKey\""), false);
  } finally {
    fs.rmSync(storageRoot, { recursive: true, force: true });
  }
}

(async () => {
  await testLowLevelProof();
  console.log("ok - pinned Noir root proof verifies and tampering fails");
  await testProductFlow();
  console.log("ok - protected Desktop product completes behind a real Noir root proof");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
