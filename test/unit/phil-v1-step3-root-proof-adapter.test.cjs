const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { keccak256, toUtf8Bytes } = require("ethers");

const {
  PHIL_ZERO_BYTES32,
  createPhilAuthorizationEnvelopeV1,
  derivePhilAuthorizationEnvelopeDigestV1
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const {
  PHIL_PROOF_DESCRIPTOR_V1_HASH,
  PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_ID,
  PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_ID,
  derivePhilVerifierBindingHashV1,
  derivePhilProofDescriptorHashV1,
  createPhilRootProofPublicInputsV1,
  assertPhilRootProofPublicInputsBindingV1,
  packPhilRootProofPublicInputsV1
} = require("../../apps/phil-device-sdk/src/rootProofV1.ts");
const {
  derivePhilScopedOwnerCommitmentV1
} = require("../../apps/phil-device-sdk/src/secureIdentityV1.ts");
const { derivePhilIdentityRoot } = require("../../apps/phil-device-sdk/src/identity.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");

function hash(label) {
  return keccak256(toUtf8Bytes(label));
}

function syntheticDescriptor() {
  const descriptor = {
    descriptorVersionHash: PHIL_PROOF_DESCRIPTOR_V1_HASH,
    proofSuiteId: hash("PHIL_NOIR_ULTRA_KECCAK_ZK_HONK_GARAGA_V1"),
    proofSystemVersionHash: hash(
      "nargo-1.0.0-beta.16|bb-3.0.0-nightly.20251104|garaga-1.0.1|cairo-2.14.0"
    ),
    circuitOrProgramId: hash("synthetic-circuit-id"),
    publicInputSchemaId: PHIL_ROOT_PROOF_PUBLIC_INPUTS_U128X2_V1_ID,
    verificationKeyHash: hash("synthetic-verification-key"),
    verifierCodeHash: hash("synthetic-verifier-code"),
    codecId: PHIL_GARAGA_ULTRA_KECCAK_ZK_HONK_CALLDATA_V1_ID
  };
  return {
    ...descriptor,
    verifierBindingHash: derivePhilVerifierBindingHashV1(descriptor)
  };
}

function exceptionalFixture() {
  const philSecret = `0x${(0x1234567890n).toString(16).padStart(64, "0")}`;
  const nullifierSeed = hash("phil-v1-step3-synthetic-nullifier-seed");
  const scopeId = hash("phil-v1-step3-synthetic-scope-id");
  const scopeInstance = hash("phil-v1-step3-synthetic-scope-instance");
  const scopeEpoch = "7";
  const scopedOwnerCommitment = derivePhilScopedOwnerCommitmentV1({
    identityRoot: derivePhilIdentityRoot(philSecret),
    scopeId,
    scopeInstance,
    scopeEpoch
  });
  const proofDescriptorHash = derivePhilProofDescriptorHashV1(syntheticDescriptor());
  const pendingEnvelope = {
    operationClass: 2,
    scopedOwnerCommitment,
    scopeId,
    scopeInstance,
    scopeEpoch,
    principalIdHash: hash("synthetic-principal"),
    capabilityId: PHIL_ZERO_BYTES32,
    capabilityEpoch: "3",
    networkIdHash: hash("SN_SEPOLIA_REFERENCE_ONLY"),
    accountBindingHash: hash("synthetic-starknet-account-binding"),
    adapterId: hash("PHIL_STARKNET_REFERENCE_ADAPTER_V1"),
    actionTypeHash: hash("synthetic-exceptional-rotation"),
    parametersHash: hash("synthetic-parameters"),
    intentDigest: hash("synthetic-intent"),
    policyHash: hash("synthetic-policy-v3"),
    nonceDomain: hash("synthetic-nullifier-nonce-domain"),
    nonce: "11",
    rootProofNullifier: PHIL_ZERO_BYTES32,
    validAfter: "1800000000",
    validUntil: "1800000300",
    valueLimit: "0",
    feeLimit: "1000000000000000",
    deviceEpoch: "4",
    recoveryEpoch: "5",
    validatorEpoch: "6",
    deviceSignatureSuiteId: hash("PHIL_SECURE_ENCLAVE_P256_DEVICE_APPROVAL_V1"),
    proofDescriptorHash,
    humanPresentationHash: hash("synthetic-human-presentation")
  };
  const authorizationEnvelopeDigest = derivePhilAuthorizationEnvelopeDigestV1(
    pendingEnvelope
  );
  const publicInputs = createPhilRootProofPublicInputsV1({
    philSecret,
    nullifierSeed,
    scopeId,
    scopeInstance,
    scopeEpoch,
    authorizationEnvelopeDigest,
    proofDescriptorHash
  });
  const envelope = createPhilAuthorizationEnvelopeV1({
    ...pendingEnvelope,
    rootProofNullifier: publicInputs.rootProofNullifier
  });
  return {
    philSecret,
    nullifierSeed,
    proofDescriptorHash,
    pendingEnvelope,
    authorizationEnvelopeDigest,
    publicInputs,
    envelope
  };
}

function errorCode(code) {
  return (error) => error?.code === code;
}

describe("Phil V1 Step 3 root-proof reference adapter", function () {
  it("removes the nullifier fixed-point cycle without weakening action binding", function () {
    const fixture = exceptionalFixture();
    assert.equal(
      derivePhilAuthorizationEnvelopeDigestV1(fixture.envelope),
      fixture.authorizationEnvelopeDigest
    );

    const alternateNullifier = {
      ...fixture.envelope,
      rootProofNullifier: hash("another-derived-nullifier")
    };
    assert.equal(
      derivePhilAuthorizationEnvelopeDigestV1(alternateNullifier),
      fixture.authorizationEnvelopeDigest
    );

    for (const [field, value] of [
      ["networkIdHash", hash("another-network")],
      ["accountBindingHash", hash("another-account")],
      ["actionTypeHash", hash("another-action")],
      ["parametersHash", hash("another-parameter-set")],
      ["intentDigest", hash("another-intent")],
      ["policyHash", hash("another-policy")],
      ["nonce", "12"],
      ["validUntil", "1800000301"],
      ["valueLimit", "1"],
      ["feeLimit", "1000000000000001"],
      ["deviceEpoch", "8"],
      ["recoveryEpoch", "9"],
      ["validatorEpoch", "10"],
      ["proofDescriptorHash", hash("another-proof-descriptor")],
      ["humanPresentationHash", hash("another-presentation")]
    ]) {
      assert.notEqual(
        derivePhilAuthorizationEnvelopeDigestV1({
          ...fixture.pendingEnvelope,
          [field]: value
        }),
        fixture.authorizationEnvelopeDigest,
        `${field} was not bound`
      );
    }
  });

  it("derives the scoped commitment and nullifier and packs exactly 13 public values", function () {
    const fixture = exceptionalFixture();
    assert.equal(
      fixture.publicInputs.scopedOwnerCommitment,
      fixture.envelope.scopedOwnerCommitment
    );
    assert.equal(
      fixture.publicInputs.rootProofNullifier,
      fixture.envelope.rootProofNullifier
    );
    assert.equal(
      fixture.publicInputs.authorizationEnvelopeDigest,
      fixture.authorizationEnvelopeDigest
    );
    assert.equal(
      fixture.publicInputs.proofDescriptorHash,
      fixture.proofDescriptorHash
    );
    assert.deepEqual(
      assertPhilRootProofPublicInputsBindingV1({
        publicInputs: fixture.publicInputs,
        expected: {
          ...fixture.publicInputs,
          proofDescriptorHash: fixture.envelope.proofDescriptorHash
        }
      }),
      fixture.publicInputs
    );

    for (const field of [
      "scopedOwnerCommitment",
      "scopeId",
      "scopeInstance",
      "authorizationEnvelopeDigest",
      "rootProofNullifier",
      "proofDescriptorHash"
    ]) {
      assert.throws(
        () => assertPhilRootProofPublicInputsBindingV1({
          publicInputs: { ...fixture.publicInputs, [field]: hash(`wrong-${field}`) },
          expected: fixture.publicInputs
        }),
        errorCode("PHIL_ROOT_PROOF_PUBLIC_INPUT_BINDING_MISMATCH")
      );
    }
    assert.throws(
      () => assertPhilRootProofPublicInputsBindingV1({
        publicInputs: { ...fixture.publicInputs, scopeEpoch: "8" },
        expected: fixture.publicInputs
      }),
      errorCode("PHIL_ROOT_PROOF_PUBLIC_INPUT_BINDING_MISMATCH")
    );

    const packed = packPhilRootProofPublicInputsV1(fixture.publicInputs);
    assert.equal(packed.codec, "phil-root-proof-public-inputs-u128x2-v1");
    assert.equal(packed.felts.length, 13);
    for (const felt of packed.felts) {
      assert.match(felt, /^(0|[1-9][0-9]*)$/);
      assert(BigInt(felt) < (1n << 128n));
    }
  });

  it("fails closed across operation classes and required proof fields", function () {
    const fixture = exceptionalFixture();
    assert.throws(
      () => createPhilAuthorizationEnvelopeV1(fixture.pendingEnvelope),
      errorCode("PHIL_AUTHORIZATION_ENVELOPE_EXCEPTIONAL_PROOF_REQUIRED")
    );
    assert.throws(
      () => createPhilAuthorizationEnvelopeV1({
        ...fixture.envelope,
        capabilityId: hash("forbidden-exceptional-capability")
      }),
      errorCode("PHIL_AUTHORIZATION_ENVELOPE_CAPABILITY_FORBIDDEN")
    );
    assert.throws(
      () => createPhilAuthorizationEnvelopeV1({
        ...fixture.envelope,
        operationClass: 1,
        capabilityId: hash("routine-capability")
      }),
      errorCode("PHIL_AUTHORIZATION_ENVELOPE_ROUTINE_PROOF_FORBIDDEN")
    );
    assert.throws(
      () => derivePhilProofDescriptorHashV1({
        ...syntheticDescriptor(),
        verificationKeyHash: PHIL_ZERO_BYTES32
      }),
      (error) => error?.code === "PHIL_SECURE_IDENTITY_ZERO_BYTES32"
    );
    assert.throws(
      () => derivePhilProofDescriptorHashV1({
        ...syntheticDescriptor(),
        verifierBindingHash: hash("wrong-verifier-binding")
      }),
      errorCode("PHIL_ROOT_PROOF_VERIFIER_BINDING_MISMATCH")
    );
  });

  it("limits the selected Step 3 route to the protected Desktop main-process proof stack", function () {
    const adapterSources = [
      "apps/phil-device-sdk/src/authorizationEnvelopeV1.ts",
      "apps/phil-device-sdk/src/rootProofV1.ts"
    ].map((relative) => fs.readFileSync(path.join(REPO_ROOT, relative), "utf8")).join("\n");
    assert.doesNotMatch(
      adapterSources,
      /from\s+["'][^"']*(?:proof\/stwo|runtime\/)|DeviceVault|\bsubmit\b|\bdeploy\b/i
    );

    for (const root of [
      "apps/philcore-desktop/src",
      "apps/phil-device-sdk/src/runtime",
      "plugins"
    ]) {
      const absolute = path.join(REPO_ROOT, root);
      if (!fs.existsSync(absolute)) continue;
      const stack = [absolute];
      while (stack.length > 0) {
        const entry = stack.pop();
        for (const child of fs.readdirSync(entry, { withFileTypes: true })) {
          const childPath = path.join(entry, child.name);
          if (child.isDirectory()) stack.push(childPath);
          else if (/\.(?:c?js|mjs|ts|tsx)$/.test(child.name)) {
            const source = fs.readFileSync(childPath, "utf8");
            const relative = path.relative(REPO_ROOT, childPath);
            if (relative === "apps/philcore-desktop/src/main/noir-root-proof-stack.cjs") {
              assert.match(source, /PHIL_NOIR_ULTRA_KECCAK_ZK_HONK_LOCAL_ALPHA_V1/);
              assert.doesNotMatch(source, /proof\/stwo|publicNetworkMutation:\s*true|\bsubmit\b|\bdeploy\b/i);
              continue;
            }
            if (relative === "apps/philcore-desktop/src/main/sepolia-mint-composed-workflow.cjs") {
              assert.match(source, /noir-root-proof-stack\.cjs/);
              assert.match(source, /createPhilRootProofPublicInputsV1/);
              assert.match(source, /ethereumVerifiesNoirProof:false/);
              assert.doesNotMatch(source, /proof\/stwo|publicNetworkMutation:\s*true|eth_sendUserOperation|\bsubmit\b|\bdeploy\b/i);
              continue;
            }
            assert.doesNotMatch(source, /authorizationEnvelopeV1|rootProofV1/);
          }
        }
      }
    }

    const cairoTest = fs.readFileSync(
      path.join(
        REPO_ROOT,
        "starknet/phil-v1-step3-verifier/tests/test_phil_v1_step3_verifier.cairo"
      ),
      "utf8"
    );
    assert.doesNotMatch(cairoTest, /#\[fork|https?:\/\/|rpc/i);
  });
});
