const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { p256 } = require("@noble/curves/p256");
const { getBytes, keccak256, toBeHex, toUtf8Bytes } = require("ethers");
const {
  PHIL_AUTHORIZATION_ENVELOPE_V1_HASH
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const {
  PHIL_DEVICE_APPROVAL_V1_HASH,
  derivePhilDeviceApprovalDigestV1
} = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");
const {
  derivePhilStep4ReferenceReceiptDigestV1
} = require("../../apps/phil-device-sdk/src/composedAccountAuthorizationV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const PROJECT = path.join(REPO_ROOT, "starknet/phil-v1-step4-account-gate");
const STEP3_VECTOR_PATH = path.join(
  REPO_ROOT,
  "proofs/phil-v1-step3-noir/fixtures/canonical-vector.json"
);
const STEP3_CALLDATA_PATH = path.join(
  REPO_ROOT,
  "starknet/phil-v1-step3-verifier/tests/proof_calldata.txt"
);
const WRITE = process.argv.includes("--write");

function hashLabel(label) {
  return keccak256(toUtf8Bytes(label));
}

function bigintHex(value) {
  return toBeHex(value, 32).toLowerCase();
}

function cairoU256(value) {
  return BigInt(value).toString();
}

function cairoU64(value) {
  return BigInt(value).toString();
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

const step3 = JSON.parse(fs.readFileSync(STEP3_VECTOR_PATH, "utf8"));
const envelope = {
  formatVersionHash: PHIL_AUTHORIZATION_ENVELOPE_V1_HASH,
  ...step3.finalizedAuthorizationEnvelope
};

const privateSeed = hashLabel("phil-v1-step4-disclosed-synthetic-p256-private-key");
const privateScalar = (BigInt(privateSeed) % (p256.CURVE.n - 1n)) + 1n;
const privateKey = getBytes(bigintHex(privateScalar));
const publicKey = p256.getPublicKey(privateKey, false);
if (publicKey.length !== 65 || publicKey[0] !== 4) {
  throw new Error("unexpected uncompressed P-256 public key encoding");
}
const publicKeyX = bigintHex(BigInt(`0x${Buffer.from(publicKey.slice(1, 33)).toString("hex")}`));
const publicKeyY = bigintHex(BigInt(`0x${Buffer.from(publicKey.slice(33, 65)).toString("hex")}`));

const approval = {
  formatVersionHash: PHIL_DEVICE_APPROVAL_V1_HASH,
  authorizationEnvelopeDigest: step3.authorizationEnvelopeDigest,
  deviceId: hashLabel("phil-v1-step4-synthetic-device-id"),
  deviceKeyId: hashLabel("phil-v1-step4-synthetic-device-key-id"),
  deviceEpoch: envelope.deviceEpoch,
  approvalNonce: hashLabel("phil-v1-step4-synthetic-approval-nonce"),
  approvedAt: "1800000100",
  approvalExpiresAt: "1800000200",
  humanPresentationHash: envelope.humanPresentationHash,
  signatureSuiteId: envelope.deviceSignatureSuiteId
};
const deviceApprovalDigest = derivePhilDeviceApprovalDigestV1(approval);
const signature = p256.sign(getBytes(deviceApprovalDigest), privateKey, { lowS: true });
if (!p256.verify(signature, getBytes(deviceApprovalDigest), publicKey, { lowS: true })) {
  throw new Error("synthetic P-256 signature failed native reference verification");
}
approval.signatureR = bigintHex(signature.r);
approval.signatureS = bigintHex(signature.s);
const wrongPrivateScalar = (privateScalar % (p256.CURVE.n - 1n)) + 1n;
const wrongKeySignature = p256.sign(
  getBytes(deviceApprovalDigest),
  getBytes(bigintHex(wrongPrivateScalar)),
  { lowS: true }
);

const accountNonce = envelope.nonce;
const receiptSequence = "1";
const referenceActionValue = "0";
const referenceActionFee = "999999999999999";
const policyMaxValue = "0";
const policyMaxFee = envelope.feeLimit;
const expectedReceiptDigest = derivePhilStep4ReferenceReceiptDigestV1({
  authorizationEnvelopeDigest: step3.authorizationEnvelopeDigest,
  rootProofNullifier: envelope.rootProofNullifier,
  deviceApprovalDigest,
  accountNonce,
  receiptSequence
});

const vector = {
  format: "phil-v1-step4-composed-account-gate-vector-v1",
  classification: "disclosed-synthetic-private-fixture",
  productionAuthority: false,
  networkActivity: false,
  physicalDeviceUsed: false,
  inheritedStep3VectorSha256: sha256(fs.readFileSync(STEP3_VECTOR_PATH)),
  inheritedStep3CalldataSha256: sha256(fs.readFileSync(STEP3_CALLDATA_PATH)),
  disclosedSyntheticDevicePrivateScalar: bigintHex(privateScalar),
  disclosedSyntheticWrongDevicePrivateScalar: bigintHex(wrongPrivateScalar),
  devicePublicKey: {
    encoding: "uncompressed-sec1-p256",
    bytes: `0x${Buffer.from(publicKey).toString("hex")}`,
    x: publicKeyX,
    y: publicKeyY
  },
  blockTimestamp: "1800000150",
  envelope,
  authorizationEnvelopeDigest: step3.authorizationEnvelopeDigest,
  approval,
  deviceApprovalDigest,
  accountConfiguration: {
    nextNonce: accountNonce,
    referenceActionValue,
    referenceActionFee,
    policyMaxValue,
    policyMaxFee,
    scopeActive: true,
    policyActive: true,
    proofDescriptorActive: true,
    deviceActive: true,
    emergencyStopped: false
  },
  expectedAuthorizationState: {
    nextNonce: (BigInt(accountNonce) + 1n).toString(),
    receiptCount: receiptSequence,
    lastReceiptDigest: expectedReceiptDigest
  },
  expectedReceiptDigest
};

const fixtureSource = `// Generated by scripts/security/generate-phil-v1-step4-artifacts.cjs.
// Every key, signature, proof, identifier, and timestamp is disclosed synthetic test material.

use phil_v1_step4_account_gate::composed_account_gate::{
    PhilAuthorizationEnvelopeV1, PhilDeviceApprovalV1, PhilStep4AccountConfigurationV1,
};

pub const BLOCK_TIMESTAMP: u64 = ${cairoU64(vector.blockTimestamp)};
pub const AUTHORIZATION_ENVELOPE_DIGEST: u256 = ${cairoU256(vector.authorizationEnvelopeDigest)};
pub const DEVICE_APPROVAL_DIGEST: u256 = ${cairoU256(vector.deviceApprovalDigest)};
pub const EXPECTED_RECEIPT_DIGEST: u256 = ${cairoU256(vector.expectedReceiptDigest)};
pub const ROOT_PROOF_NULLIFIER: u256 = ${cairoU256(envelope.rootProofNullifier)};
pub const APPROVAL_NONCE: u256 = ${cairoU256(approval.approvalNonce)};
pub const WRONG_KEY_SIGNATURE_R: u256 = ${cairoU256(wrongKeySignature.r)};
pub const WRONG_KEY_SIGNATURE_S: u256 = ${cairoU256(wrongKeySignature.s)};
pub const ACCEPTED_STEP3_VERIFIER_CLASS_HASH: felt252 =
    0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd;

pub fn canonical_config() -> PhilStep4AccountConfigurationV1 {
    PhilStep4AccountConfigurationV1 {
        scoped_owner_commitment: ${cairoU256(envelope.scopedOwnerCommitment)},
        scope_id: ${cairoU256(envelope.scopeId)},
        scope_instance: ${cairoU256(envelope.scopeInstance)},
        scope_epoch: ${cairoU64(envelope.scopeEpoch)},
        principal_id_hash: ${cairoU256(envelope.principalIdHash)},
        capability_epoch: ${cairoU64(envelope.capabilityEpoch)},
        network_id_hash: ${cairoU256(envelope.networkIdHash)},
        account_binding_hash: ${cairoU256(envelope.accountBindingHash)},
        adapter_id: ${cairoU256(envelope.adapterId)},
        action_type_hash: ${cairoU256(envelope.actionTypeHash)},
        parameters_hash: ${cairoU256(envelope.parametersHash)},
        intent_digest: ${cairoU256(envelope.intentDigest)},
        policy_hash: ${cairoU256(envelope.policyHash)},
        nonce_domain: ${cairoU256(envelope.nonceDomain)},
        next_nonce: ${cairoU64(accountNonce)},
        device_epoch: ${cairoU64(envelope.deviceEpoch)},
        recovery_epoch: ${cairoU64(envelope.recoveryEpoch)},
        validator_epoch: ${cairoU64(envelope.validatorEpoch)},
        device_signature_suite_id: ${cairoU256(envelope.deviceSignatureSuiteId)},
        proof_descriptor_hash: ${cairoU256(envelope.proofDescriptorHash)},
        human_presentation_hash: ${cairoU256(envelope.humanPresentationHash)},
        device_id: ${cairoU256(approval.deviceId)},
        device_key_id: ${cairoU256(approval.deviceKeyId)},
        device_public_key_x: ${cairoU256(publicKeyX)},
        device_public_key_y: ${cairoU256(publicKeyY)},
        reference_action_value: ${cairoU256(referenceActionValue)},
        reference_action_fee: ${cairoU256(referenceActionFee)},
        policy_max_value: ${cairoU256(policyMaxValue)},
        policy_max_fee: ${cairoU256(policyMaxFee)},
        scope_active: true,
        policy_active: true,
        proof_descriptor_active: true,
        device_active: true,
        emergency_stopped: false,
    }
}

pub fn canonical_envelope() -> PhilAuthorizationEnvelopeV1 {
    PhilAuthorizationEnvelopeV1 {
        format_version_hash: ${cairoU256(envelope.formatVersionHash)},
        operation_class: ${envelope.operationClass},
        scoped_owner_commitment: ${cairoU256(envelope.scopedOwnerCommitment)},
        scope_id: ${cairoU256(envelope.scopeId)},
        scope_instance: ${cairoU256(envelope.scopeInstance)},
        scope_epoch: ${cairoU64(envelope.scopeEpoch)},
        principal_id_hash: ${cairoU256(envelope.principalIdHash)},
        capability_id: ${cairoU256(envelope.capabilityId)},
        capability_epoch: ${cairoU64(envelope.capabilityEpoch)},
        network_id_hash: ${cairoU256(envelope.networkIdHash)},
        account_binding_hash: ${cairoU256(envelope.accountBindingHash)},
        adapter_id: ${cairoU256(envelope.adapterId)},
        action_type_hash: ${cairoU256(envelope.actionTypeHash)},
        parameters_hash: ${cairoU256(envelope.parametersHash)},
        intent_digest: ${cairoU256(envelope.intentDigest)},
        policy_hash: ${cairoU256(envelope.policyHash)},
        nonce_domain: ${cairoU256(envelope.nonceDomain)},
        nonce: ${cairoU256(envelope.nonce)},
        root_proof_nullifier: ${cairoU256(envelope.rootProofNullifier)},
        valid_after: ${cairoU64(envelope.validAfter)},
        valid_until: ${cairoU64(envelope.validUntil)},
        value_limit: ${cairoU256(envelope.valueLimit)},
        fee_limit: ${cairoU256(envelope.feeLimit)},
        device_epoch: ${cairoU64(envelope.deviceEpoch)},
        recovery_epoch: ${cairoU64(envelope.recoveryEpoch)},
        validator_epoch: ${cairoU64(envelope.validatorEpoch)},
        device_signature_suite_id: ${cairoU256(envelope.deviceSignatureSuiteId)},
        proof_descriptor_hash: ${cairoU256(envelope.proofDescriptorHash)},
        human_presentation_hash: ${cairoU256(envelope.humanPresentationHash)},
    }
}

pub fn canonical_approval() -> PhilDeviceApprovalV1 {
    PhilDeviceApprovalV1 {
        format_version_hash: ${cairoU256(approval.formatVersionHash)},
        authorization_envelope_digest: ${cairoU256(approval.authorizationEnvelopeDigest)},
        device_id: ${cairoU256(approval.deviceId)},
        device_key_id: ${cairoU256(approval.deviceKeyId)},
        device_epoch: ${cairoU64(approval.deviceEpoch)},
        approval_nonce: ${cairoU256(approval.approvalNonce)},
        approved_at: ${cairoU64(approval.approvedAt)},
        approval_expires_at: ${cairoU64(approval.approvalExpiresAt)},
        human_presentation_hash: ${cairoU256(approval.humanPresentationHash)},
        signature_suite_id: ${cairoU256(approval.signatureSuiteId)},
        signature_r: ${cairoU256(approval.signatureR)},
        signature_s: ${cairoU256(approval.signatureS)},
    }
}
`;

const generatedOutputs = [
  {
    path: path.join(PROJECT, "fixtures/canonical-vector.json"),
    bytes: Buffer.from(`${JSON.stringify(vector, null, 2)}\n`)
  },
  {
    path: path.join(PROJECT, "tests/canonical_fixture.cairo"),
    bytes: Buffer.from(fixtureSource)
  },
  {
    path: path.join(PROJECT, "tests/proof_calldata.txt"),
    bytes: fs.readFileSync(STEP3_CALLDATA_PATH)
  }
];

function artifactFromBytes(relative, bytes) {
  return { path: relative, bytes: bytes.length, sha256: sha256(bytes) };
}

function artifactFromFile(relative) {
  return artifactFromBytes(relative, fs.readFileSync(path.join(REPO_ROOT, relative)));
}

const generatedByRelative = new Map(
  generatedOutputs.map((output) => [path.relative(REPO_ROOT, output.path), output.bytes])
);
const sourcePaths = [
  "apps/phil-device-sdk/src/composedAccountAuthorizationV1.ts",
  "docs/CANONICAL_DOCS.md",
  "docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md",
  "docs/reference/PHIL_V1_STEP4_COMPOSED_ACCOUNT_AUTHORIZATION_GATE.md",
  "docs/reference/PHIL_V1_STEP4_INDEPENDENT_REVIEW_895320F.md",
  "docs/security/PHIL_V1_STEP4_CORRECTIVE_IMPLEMENTATION_REPORT.md",
  "docs/security/PHIL_V1_STEP4_COMPOSED_ACCOUNT_THREAT_MODEL.md",
  "docs/security/PHIL_V1_STEP4_COMPOSED_ACCOUNT_IMPLEMENTATION_EVIDENCE.md",
  "scripts/security/generate-phil-v1-step4-artifacts.cjs",
  "package.json",
  "starknet/phil-v1-step4-account-gate/.tool-versions",
  "starknet/phil-v1-step4-account-gate/README.md",
  "starknet/phil-v1-step4-account-gate/Scarb.lock",
  "starknet/phil-v1-step4-account-gate/Scarb.toml",
  "starknet/phil-v1-step4-account-gate/src/composed_account_gate.cairo",
  "starknet/phil-v1-step4-account-gate/src/lib.cairo",
  "starknet/phil-v1-step4-account-gate/tests/lib.cairo",
  "starknet/phil-v1-step4-account-gate/tests/composed_account_gate_test.cairo",
  "test/unit/phil-v1-step4-composed-account-authorization.test.cjs",
  ...fs
    .readdirSync(path.join(PROJECT, "vendor/phil-v1-step3-verifier/src"))
    .filter((name) => name.endsWith(".cairo"))
    .sort()
    .map((name) => `starknet/phil-v1-step4-account-gate/vendor/phil-v1-step3-verifier/src/${name}`),
  "starknet/phil-v1-step4-account-gate/vendor/phil-v1-step3-verifier/Scarb.toml",
  ...generatedByRelative.keys()
];

const manifest = {
  format: "phil-v1-step4-composed-account-artifact-manifest-v1",
  status: "accepted-exact-candidate-3377606d404312ef7f7dcfec37a11c046f2c907e",
  acceptedStep3Candidate: "11234ea623a6b8883eed0036f3d95174cef90627",
  productionBackendSelected: false,
  productionAuthority: false,
  networkActivity: false,
  physicalDeviceUsed: false,
  toolchain: {
    cairo: "2.14.0",
    starknet: "2.14.0",
    scarb: {
      version: "2.14.0",
      executableSha256: "2e20da95b4cd51c030c54c0e5977a3a398ca18c8b68eefe6dc6e000d91467488"
    },
    starknetFoundry: {
      version: "0.53.0",
      snforgeExecutableSha256: "fb2d19e2c4befbdf2ffd9937351b6a6d9363421c50aafe86d252a92d19442d72"
    },
    universalSierraCompiler: {
      version: "2.10.0",
      executableSha256: "de6d1d4e03b8398cd895238ff2205d848b73488b0c2e8b8c7fec427a0281c4f1"
    },
    garaga: {
      version: "1.0.1",
      sourceCommit: "aa91b6504c86995789edb4e78f9f9ba20571625c"
    }
  },
  compiledClasses: {
    acceptedStep3Verifier: {
      sierraClassHash: "0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd",
      compiledClassHash: "0x154b6afe8acf0e963177e9e80f46b7c760d2b554245f41aec3d2d78710d8911",
      sierraJsonBytes: 1691441,
      casmJsonBytes: 1221983
    },
    step4ComposedAccountGate: {
      sierraClassHash: "0x0453ab1f858031f49d19dc3cb431af0d80e81d0bb958372dfe88666173360669",
      compiledClassHash: "0x36a5bb9774da5922be5d06473ff0c0e5915ab6404c277619c635563718c1a90",
      sierraJsonBytes: 629434,
      casmJsonBytes: 279456
    }
  },
  measurements: {
    cairoTests: 60,
    typescriptTests: 3,
    validCompositionApproximateL2Gas: 314221414,
    validCompositionSierraGas: 314139494,
    validCompositionApproximateL1DataGas: 5472,
    note: "local Starknet Foundry evidence, not a network fee quote"
  },
  artifacts: sourcePaths.map((relative) =>
    generatedByRelative.has(relative)
      ? artifactFromBytes(relative, generatedByRelative.get(relative))
      : artifactFromFile(relative)
  )
};
const outputs = [
  ...generatedOutputs,
  {
    path: path.join(PROJECT, "artifacts/reference-manifest.json"),
    bytes: Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)
  }
];

for (const output of outputs) {
  const relative = path.relative(REPO_ROOT, output.path);
  if (WRITE) {
    fs.mkdirSync(path.dirname(output.path), { recursive: true });
    fs.writeFileSync(output.path, output.bytes);
    console.log(`wrote ${relative} sha256=${sha256(output.bytes)}`);
  } else {
    if (!fs.existsSync(output.path)) {
      throw new Error(`missing generated artifact: ${relative}`);
    }
    const current = fs.readFileSync(output.path);
    if (!current.equals(output.bytes)) {
      throw new Error(`generated artifact drift: ${relative}`);
    }
    console.log(`verified ${relative} sha256=${sha256(output.bytes)}`);
  }
}
