const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { keccak256, toUtf8Bytes } = require("ethers");
const {
  createPhilAuthorizationEnvelopeV1,
  derivePhilAuthorizationEnvelopeDigestV1,
  PHIL_ZERO_BYTES32
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const { PHIL_CRYPTO_SCHEME_IDS_V1 } = require(
  "../../apps/phil-device-sdk/src/postQuantumMigrationV1.ts"
);
const {
  PHIL_ADAPTER_GUARANTEE_V1,
  PHIL_ADAPTER_PQ_CAPABILITY_V1,
  PHIL_BASE_MAINNET_CHAIN_ID,
  PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS,
  PHIL_EVM_SINGLE_CALL_V1_HASH,
  createPhilBaseMainnetAdapterAuthorizationV1,
  createPhilBaseMainnetAdapterManifestV1,
  createPhilEvmSingleCallV1,
  derivePhilEvmAccountBindingHashV1,
  derivePhilEvmIntentDigestV1,
  derivePhilEvmNonceDomainV1
} = require("../../apps/phil-device-sdk/src/networkAdapterV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const SOURCE_RELATIVE = "apps/phil-device-sdk/src/networkAdapterV1.ts";
const FIXTURE_RELATIVE = "config/adapters/PHIL_V1_STEP6A_BASE_ADAPTER_FIXTURE.json";
const MANIFEST_RELATIVE = "docs/reference/PHIL_V1_STEP6A_ARTIFACT_MANIFEST.json";
const SOURCE_PATH = path.join(REPO_ROOT, SOURCE_RELATIVE);
const FIXTURE_PATH = path.join(REPO_ROOT, FIXTURE_RELATIVE);
const MANIFEST_PATH = path.join(REPO_ROOT, MANIFEST_RELATIVE);
const WRITE = process.argv.includes("--write");

function hashLabel(label) {
  return keccak256(toUtf8Bytes(label));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const sourceBytes = fs.readFileSync(SOURCE_PATH);
const implementationSha256 = sha256(sourceBytes);
const manifest = createPhilBaseMainnetAdapterManifestV1({
  implementationHash: `0x${implementationSha256}`,
  auditStatusHash: hashLabel("phil-v1-step6a-independent-review-required")
});

const action = createPhilEvmSingleCallV1({
  chainId: PHIL_BASE_MAINNET_CHAIN_ID,
  account: "0x1111111111111111111111111111111111111111",
  entryPoint: PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS,
  target: "0x2222222222222222222222222222222222222222",
  targetCalldataHash: hashLabel("phil-v1-step6a-disclosed-synthetic-target-calldata"),
  valueWei: 1000,
  nonceKey: 7,
  nonceSequence: 3,
  callGasLimit: 100000,
  verificationGasLimit: 200000,
  preVerificationGas: 50000,
  maxFeePerGas: 1000000000,
  maxPriorityFeePerGas: 100000000,
  validAfter: 1800000000,
  validUntil: 1800003600
});

const accountBindingHash = derivePhilEvmAccountBindingHashV1(manifest, action);
const nonceDomain = derivePhilEvmNonceDomainV1(manifest, action);
const intentDigest = derivePhilEvmIntentDigestV1(manifest, action);
const envelope = createPhilAuthorizationEnvelopeV1({
  operationClass: 1,
  scopedOwnerCommitment: hashLabel("phil-v1-step6a-disclosed-synthetic-scoped-owner"),
  scopeId: hashLabel("phil-v1-step6a-base-mainnet-account-scope"),
  scopeInstance: hashLabel("phil-v1-step6a-disclosed-synthetic-scope-instance"),
  scopeEpoch: 1,
  principalIdHash: hashLabel("phil-v1-step6a-disclosed-synthetic-principal"),
  capabilityId: hashLabel("phil-v1-step6a-disclosed-synthetic-routine-capability"),
  capabilityEpoch: 1,
  networkIdHash: manifest.networkIdHash,
  accountBindingHash,
  adapterId: manifest.adapterId,
  actionTypeHash: PHIL_EVM_SINGLE_CALL_V1_HASH,
  parametersHash: action.actionHash,
  intentDigest,
  policyHash: hashLabel("phil-v1-step6a-disclosed-synthetic-policy"),
  nonceDomain,
  nonce: action.userOpNonce,
  rootProofNullifier: PHIL_ZERO_BYTES32,
  validAfter: action.validAfter,
  validUntil: action.validUntil,
  valueLimit: 2000,
  feeLimit: action.maxTotalFeeWei,
  deviceEpoch: 1,
  recoveryEpoch: 1,
  validatorEpoch: 1,
  deviceSignatureSuiteId: PHIL_CRYPTO_SCHEME_IDS_V1.P256_SHA256_SIGNATURE,
  proofDescriptorHash: PHIL_ZERO_BYTES32,
  humanPresentationHash: hashLabel("phil-v1-step6a-disclosed-synthetic-human-presentation")
});

const deviceApproval = Object.freeze({
  deviceId: hashLabel("phil-v1-step6a-disclosed-synthetic-device"),
  deviceKeyId: hashLabel("phil-v1-step6a-disclosed-synthetic-device-key"),
  deviceEpoch: 1,
  approvalNonce: hashLabel("phil-v1-step6a-disclosed-synthetic-approval-nonce"),
  approvedAt: 1800000001,
  approvalExpiresAt: 1800000300
});
const authorization = createPhilBaseMainnetAdapterAuthorizationV1({
  manifest,
  trustedManifestHash: manifest.manifestHash,
  envelope,
  action,
  deviceApproval
});

const fixture = {
  format: "phil-v1-step6a-base-network-adapter-fixture-v1",
  classification: "architecture-only-disclosed-synthetic-local-binding",
  network: "Base mainnet",
  chainId: PHIL_BASE_MAINNET_CHAIN_ID.toString(10),
  entryPointVersion: "0.7.0",
  guarantee: "local_policy_only",
  guaranteeCode: PHIL_ADAPTER_GUARANTEE_V1.LOCAL_POLICY_ONLY,
  postQuantumCapability: PHIL_ADAPTER_PQ_CAPABILITY_V1.NONE,
  productionAuthority: false,
  networkAuthorizationPathAvailable: false,
  networkActivity: false,
  rpcUsed: false,
  transactionCreated: false,
  userOperationCreated: false,
  signatureCreatedOrVerified: false,
  physicalDeviceUsed: false,
  secretUsed: false,
  proofBackendSelected: false,
  existingEvmArtifactsCompatibilityOnly: true,
  manifest,
  action,
  envelope,
  authorizationEnvelopeDigest: derivePhilAuthorizationEnvelopeDigestV1(envelope),
  deviceApproval,
  authorization
};
const fixtureJson = canonicalJson(fixture);

const artifactManifest = {
  format: "phil-v1-step6a-artifact-manifest-v1",
  source: SOURCE_RELATIVE,
  sourceSha256: implementationSha256,
  fixture: FIXTURE_RELATIVE,
  fixtureSha256: sha256(fixtureJson),
  adapterManifestHash: manifest.manifestHash,
  actionHash: action.actionHash,
  authorizationEnvelopeDigest: fixture.authorizationEnvelopeDigest,
  deviceApprovalDigest: authorization.deviceApprovalDigest,
  authorizationHash: authorization.authorizationHash,
  standardsSnapshot: {
    asOf: "2026-08-22",
    erc4337: "https://eips.ethereum.org/EIPS/eip-4337",
    baseAccountOverview: "https://docs.base.org/base-account/overview/what-is-base-account",
    basePreinstalls: "https://docs.base.org/base-chain/specs/protocol/execution/evm/preinstalls"
  }
};
const artifactManifestJson = canonicalJson(artifactManifest);

function writeOrCheck(filePath, expected) {
  if (WRITE) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, expected);
    return;
  }
  if (!fs.existsSync(filePath) || fs.readFileSync(filePath, "utf8") !== expected) {
    throw new Error(`${path.relative(REPO_ROOT, filePath)} is missing or stale`);
  }
}

writeOrCheck(FIXTURE_PATH, fixtureJson);
writeOrCheck(MANIFEST_PATH, artifactManifestJson);
console.log(WRITE ? "wrote Step 6A artifacts" : "verified Step 6A artifacts");
