const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { keccak256, toUtf8Bytes } = require("ethers");
const {
  createPhilAuthorizationEnvelopeV1,
  PHIL_ZERO_BYTES32
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const { PHIL_CRYPTO_SCHEME_IDS_V1 } = require(
  "../../apps/phil-device-sdk/src/postQuantumMigrationV1.ts"
);
const {
  PHIL_ADAPTER_GUARANTEE_V1,
  PHIL_ADAPTER_PQ_CAPABILITY_V1,
  PHIL_ADAPTER_TYPE_V1,
  PHIL_BASE_MAINNET_ADAPTER_ID,
  PHIL_BASE_MAINNET_CHAIN_ID,
  PHIL_BASE_MAINNET_NETWORK_ID_HASH,
  PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS,
  PHIL_EVM_SINGLE_CALL_V1_HASH,
  createPhilAdapterManifestV1,
  createPhilBaseMainnetAdapterAuthorizationV1,
  createPhilEvmSingleCallV1,
  derivePhilEvmAccountBindingHashV1,
  derivePhilEvmIntentDigestV1,
  derivePhilEvmNonceDomainV1,
  validatePhilBaseMainnetAdapterManifestV1,
  validatePhilEvmSingleCallV1
} = require("../../apps/phil-device-sdk/src/networkAdapterV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const fixture = JSON.parse(fs.readFileSync(
  path.join(REPO_ROOT, "config/adapters/PHIL_V1_STEP6A_BASE_ADAPTER_FIXTURE.json"),
  "utf8"
));

function h(label) {
  return keccak256(toUtf8Bytes(label));
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function action(overrides = {}) {
  return createPhilEvmSingleCallV1({
    chainId: PHIL_BASE_MAINNET_CHAIN_ID,
    account: fixture.action.account,
    entryPoint: PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS,
    target: fixture.action.target,
    targetCalldataHash: fixture.action.targetCalldataHash,
    valueWei: fixture.action.valueWei,
    nonceKey: fixture.action.nonceKey,
    nonceSequence: fixture.action.nonceSequence,
    callGasLimit: fixture.action.callGasLimit,
    verificationGasLimit: fixture.action.verificationGasLimit,
    preVerificationGas: fixture.action.preVerificationGas,
    maxFeePerGas: fixture.action.maxFeePerGas,
    maxPriorityFeePerGas: fixture.action.maxPriorityFeePerGas,
    validAfter: fixture.action.validAfter,
    validUntil: fixture.action.validUntil,
    ...overrides
  });
}

function envelopeFor(manifest = fixture.manifest, evmAction = fixture.action, overrides = {}) {
  const base = {
    ...fixture.envelope,
    networkIdHash: manifest.networkIdHash,
    adapterId: manifest.adapterId,
    accountBindingHash: derivePhilEvmAccountBindingHashV1(manifest, evmAction),
    parametersHash: evmAction.actionHash,
    intentDigest: derivePhilEvmIntentDigestV1(manifest, evmAction),
    nonceDomain: derivePhilEvmNonceDomainV1(manifest, evmAction),
    nonce: evmAction.userOpNonce,
    validAfter: evmAction.validAfter,
    validUntil: evmAction.validUntil,
    feeLimit: evmAction.maxTotalFeeWei,
    ...overrides
  };
  return createPhilAuthorizationEnvelopeV1(base);
}

function authorize(overrides = {}) {
  return createPhilBaseMainnetAdapterAuthorizationV1({
    manifest: fixture.manifest,
    trustedManifestHash: fixture.manifest.manifestHash,
    envelope: fixture.envelope,
    action: fixture.action,
    deviceApproval: fixture.deviceApproval,
    ...overrides
  });
}

function rebuiltManifest(overrides = {}) {
  const { manifestHash: _ignored, ...base } = fixture.manifest;
  return createPhilAdapterManifestV1({ ...base, ...overrides });
}

describe("Phil V1 Step 6A Base network adapter", function () {
  it("freezes the exact Base ERC-4337 v0.7 local-only manifest", function () {
    const manifest = validatePhilBaseMainnetAdapterManifestV1(fixture.manifest);
    assert.equal(manifest.adapterId, PHIL_BASE_MAINNET_ADAPTER_ID);
    assert.equal(manifest.networkIdHash, PHIL_BASE_MAINNET_NETWORK_ID_HASH);
    assert.equal(manifest.adapterType, PHIL_ADAPTER_TYPE_V1.NETWORK_ACCOUNT);
    assert.equal(manifest.postQuantumCapability, PHIL_ADAPTER_PQ_CAPABILITY_V1.NONE);
    assert.deepEqual(
      manifest.supportedDeviceSignatureSuiteIds,
      [PHIL_CRYPTO_SCHEME_IDS_V1.P256_SHA256_SIGNATURE]
    );
    assert.deepEqual(manifest.supportedProofSuiteIds, []);
    assert.equal(fixture.action.entryPoint, PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS);
  });

  it("canonically binds one call, keyed nonce, validity window, and disclosed fee ceiling", function () {
    const evmAction = validatePhilEvmSingleCallV1(fixture.action);
    assert.equal(
      evmAction.userOpNonce,
      ((BigInt(evmAction.nonceKey) << 64n) | BigInt(evmAction.nonceSequence)).toString(10)
    );
    assert.equal(
      evmAction.maxTotalFeeWei,
      ((BigInt(evmAction.callGasLimit) + BigInt(evmAction.verificationGasLimit)
        + BigInt(evmAction.preVerificationGas)) * BigInt(evmAction.maxFeePerGas)).toString(10)
    );
    assert.equal(evmAction.initCodeHash, PHIL_ZERO_BYTES32);
    assert.equal(evmAction.paymasterAndDataHash, PHIL_ZERO_BYTES32);
  });

  it("reproduces the synthetic authorization while granting no authority", function () {
    const result = authorize();
    assert.deepEqual(result, fixture.authorization);
    assert.equal(result.guarantee, PHIL_ADAPTER_GUARANTEE_V1.LOCAL_POLICY_ONLY);
    assert.equal(result.deviceSignatureVerified, false);
    assert.equal(result.networkAuthorizationPathAvailable, false);
    assert.equal(result.productionAuthority, false);
    assert.equal(result.networkActivity, false);
    assert.equal(fixture.signatureCreatedOrVerified, false);
    assert.equal(fixture.userOperationCreated, false);
  });

  it("rejects manifest substitution and every Base profile overclaim", function () {
    expectCode(
      () => authorize({ trustedManifestHash: h("untrusted-manifest") }),
      "PHIL_ADAPTER_MANIFEST_UNTRUSTED"
    );
    expectCode(
      () => authorize({ manifest: { ...fixture.manifest, manifestHash: h("tampered-manifest") } }),
      "PHIL_ADAPTER_MANIFEST_HASH_MISMATCH"
    );
    expectCode(
      () => authorize({ manifest: rebuiltManifest({ networkIdHash: h("eip155:1") }) }),
      "PHIL_ADAPTER_BASE_MANIFEST_MISMATCH"
    );
    expectCode(
      () => authorize({ manifest: rebuiltManifest({ postQuantumCapability: 1 }) }),
      "PHIL_ADAPTER_BASE_MANIFEST_MISMATCH"
    );
    expectCode(
      () => authorize({ manifest: rebuiltManifest({ supportedProofSuiteIds: [h("fake-proof")] }) }),
      "PHIL_ADAPTER_BASE_MANIFEST_MISMATCH"
    );
    expectCode(
      () => authorize({ manifest: rebuiltManifest({ accountModelId: h("other-account-model") }) }),
      "PHIL_ADAPTER_BASE_MANIFEST_MISMATCH"
    );
    for (const [field, value] of [
      ["adapterId", h("other-adapter")],
      ["adapterVersionHash", h("other-adapter-version")],
      ["scopeCanonicalizationId", h("other-scope-codec")],
      ["actionCodecId", h("other-action-codec")],
      ["replayModelId", h("other-replay-model")],
      ["feeModelId", h("other-fee-model")],
      ["supportedDeviceSignatureSuiteIds", [h("other-device-suite")]]
    ]) {
      expectCode(
        () => authorize({ manifest: rebuiltManifest({ [field]: value }) }),
        "PHIL_ADAPTER_BASE_MANIFEST_MISMATCH"
      );
    }
    for (const [field, value] of [
      ["implementationHash", h("substituted-implementation")],
      ["auditStatusHash", h("substituted-audit-status")]
    ]) {
      expectCode(
        () => authorize({ manifest: rebuiltManifest({ [field]: value }) }),
        "PHIL_ADAPTER_MANIFEST_UNTRUSTED"
      );
    }
    expectCode(
      () => rebuiltManifest({ adapterType: PHIL_ADAPTER_TYPE_V1.CREDENTIAL }),
      "PHIL_ADAPTER_TYPE_UNSUPPORTED"
    );
    expectCode(
      () => rebuiltManifest({ supportedDeviceSignatureSuiteIds: [] }),
      "PHIL_ADAPTER_SCHEME_SET_EMPTY"
    );
    expectCode(
      () => rebuiltManifest({
        supportedDeviceSignatureSuiteIds: [
          PHIL_CRYPTO_SCHEME_IDS_V1.P256_SHA256_SIGNATURE,
          PHIL_CRYPTO_SCHEME_IDS_V1.P256_SHA256_SIGNATURE
        ]
      }),
      "PHIL_ADAPTER_SCHEME_SET_DUPLICATE"
    );
    expectCode(
      () => rebuiltManifest({ implementationHash: PHIL_ZERO_BYTES32 }),
      "PHIL_ADAPTER_ZERO_BYTES32"
    );
    expectCode(
      () => rebuiltManifest({ auditStatusHash: PHIL_ZERO_BYTES32 }),
      "PHIL_ADAPTER_ZERO_BYTES32"
    );
  });

  it("rejects chain, EntryPoint, account, action, intent, and nonce substitution", function () {
    expectCode(
      () => authorize({ action: { ...fixture.action, actionHash: h("tampered-action") } }),
      "PHIL_ADAPTER_ACTION_HASH_MISMATCH"
    );
    const wrongChain = action({ chainId: 1 });
    expectCode(
      () => authorize({ action: wrongChain, envelope: envelopeFor(fixture.manifest, wrongChain) }),
      "PHIL_ADAPTER_CHAIN_MISMATCH"
    );
    const wrongEntryPoint = action({ entryPoint: "0x3333333333333333333333333333333333333333" });
    expectCode(
      () => authorize({ action: wrongEntryPoint, envelope: envelopeFor(fixture.manifest, wrongEntryPoint) }),
      "PHIL_ADAPTER_ENTRYPOINT_MISMATCH"
    );
    for (const [overrides, code] of [
      [{ account: "0x4444444444444444444444444444444444444444" }, "PHIL_ADAPTER_ACCOUNT_BINDING_MISMATCH"],
      [{ target: "0x5555555555555555555555555555555555555555" }, "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"],
      [{ targetCalldataHash: h("substituted-target-calldata") }, "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"],
      [{ nonceKey: "8" }, "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"],
      [{ nonceSequence: "4" }, "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"]
    ]) {
      expectCode(() => authorize({ action: action(overrides) }), code);
    }
    for (const [field, value, code] of [
      ["adapterId", h("wrong-adapter"), "PHIL_ADAPTER_ENVELOPE_MANIFEST_MISMATCH"],
      ["networkIdHash", h("wrong-network"), "PHIL_ADAPTER_ENVELOPE_MANIFEST_MISMATCH"],
      ["accountBindingHash", h("wrong-account"), "PHIL_ADAPTER_ACCOUNT_BINDING_MISMATCH"],
      ["actionTypeHash", h("wrong-action-type"), "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"],
      ["parametersHash", h("wrong-action"), "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"],
      ["intentDigest", h("wrong-intent"), "PHIL_ADAPTER_ACTION_BINDING_MISMATCH"],
      ["nonceDomain", h("wrong-nonce-domain"), "PHIL_ADAPTER_NONCE_MISMATCH"],
      ["nonce", "4", "PHIL_ADAPTER_NONCE_MISMATCH"]
    ]) {
      expectCode(() => authorize({ envelope: envelopeFor(fixture.manifest, fixture.action, { [field]: value }) }), code);
    }
  });

  it("rejects value, fee, validity, device-suite, epoch, and approval-window mismatch", function () {
    expectCode(
      () => authorize({ envelope: envelopeFor(fixture.manifest, fixture.action, { valueLimit: "999" }) }),
      "PHIL_ADAPTER_VALUE_LIMIT_EXCEEDED"
    );
    expectCode(
      () => authorize({ envelope: envelopeFor(fixture.manifest, fixture.action, { feeLimit: "1" }) }),
      "PHIL_ADAPTER_FEE_LIMIT_EXCEEDED"
    );
    expectCode(
      () => authorize({ envelope: envelopeFor(fixture.manifest, fixture.action, { validUntil: "1800003599" }) }),
      "PHIL_ADAPTER_VALIDITY_MISMATCH"
    );
    expectCode(
      () => authorize({ envelope: envelopeFor(fixture.manifest, fixture.action, { deviceSignatureSuiteId: h("wrong-suite") }) }),
      "PHIL_ADAPTER_DEVICE_SUITE_UNSUPPORTED"
    );
    expectCode(
      () => authorize({ deviceApproval: { ...fixture.deviceApproval, deviceEpoch: 2 } }),
      "PHIL_ADAPTER_DEVICE_EPOCH_MISMATCH"
    );
    expectCode(
      () => authorize({ deviceApproval: { ...fixture.deviceApproval, approvalExpiresAt: "1800003601" } }),
      "PHIL_ADAPTER_DEVICE_APPROVAL_WINDOW_INVALID"
    );
  });

  it("rejects exceptional/root-proof authority, deployment, sponsorship, and ambiguous call targets", function () {
    const exceptionalEnvelope = envelopeFor(fixture.manifest, fixture.action, {
      operationClass: 2,
      capabilityId: PHIL_ZERO_BYTES32,
      rootProofNullifier: h("exceptional-nullifier"),
      proofDescriptorHash: h("exceptional-proof")
    });
    expectCode(
      () => authorize({ envelope: exceptionalEnvelope }),
      "PHIL_ADAPTER_OPERATION_UNSUPPORTED"
    );
    const recoveryEnvelope = envelopeFor(fixture.manifest, fixture.action, {
      operationClass: 3,
      capabilityId: PHIL_ZERO_BYTES32
    });
    expectCode(
      () => authorize({ envelope: recoveryEnvelope }),
      "PHIL_ADAPTER_OPERATION_UNSUPPORTED"
    );
    expectCode(
      () => action({ initCodeHash: h("init-code") }),
      "PHIL_ADAPTER_DYNAMIC_AUTHORITY_FORBIDDEN"
    );
    expectCode(
      () => action({ paymasterAndDataHash: h("paymaster") }),
      "PHIL_ADAPTER_DYNAMIC_AUTHORITY_FORBIDDEN"
    );
    expectCode(() => action({ target: fixture.action.account }), "PHIL_ADAPTER_TARGET_FORBIDDEN");
    expectCode(() => action({ target: PHIL_ERC4337_ENTRYPOINT_V07_ADDRESS }), "PHIL_ADAPTER_TARGET_FORBIDDEN");
    expectCode(
      () => action({ maxPriorityFeePerGas: "1000000001" }),
      "PHIL_ADAPTER_FEE_RELATION_INVALID"
    );
    expectCode(
      () => action({
        preVerificationGas: (1n << 256n) - 1n,
        maxFeePerGas: 1,
        maxPriorityFeePerGas: 0
      }),
      "PHIL_ADAPTER_FEE_OVERFLOW"
    );
    for (const overrides of [
      { chainId: "01" },
      { valueWei: "-1" },
      { nonceKey: 1n << 192n },
      { nonceSequence: 1n << 64n },
      { callGasLimit: 0 },
      { maxFeePerGas: 1n << 128n },
      { validUntil: 0 }
    ]) {
      expectCode(() => action(overrides), "PHIL_ADAPTER_INVALID_UNSIGNED");
    }
    expectCode(
      () => action({ chainId: Number.MAX_SAFE_INTEGER + 1 }),
      "PHIL_ADAPTER_INVALID_UNSIGNED"
    );
    expectCode(
      () => action({ account: "not-an-address" }),
      "PHIL_ADAPTER_INVALID_ADDRESS"
    );
    expectCode(
      () => action({ targetCalldataHash: "0x12" }),
      "PHIL_ADAPTER_INVALID_BYTES32"
    );
    expectCode(
      () => action({ validAfter: 1800003601, validUntil: 1800003600 }),
      "PHIL_ADAPTER_VALIDITY_INVALID"
    );
    expectCode(
      () => authorize({
        action: { ...fixture.action, formatVersionHash: h("other-action-format") }
      }),
      "PHIL_ADAPTER_ACTION_FORMAT_MISMATCH"
    );
    for (const [field, value] of [
      ["accountCallCommitment", h("tampered-account-call-commitment")],
      ["userOpNonce", "4"],
      ["maxTotalFeeWei", "1"]
    ]) {
      expectCode(
        () => authorize({ action: { ...fixture.action, [field]: value } }),
        "PHIL_ADAPTER_ACTION_HASH_MISMATCH"
      );
    }
    for (const field of ["deviceId", "deviceKeyId", "approvalNonce"]) {
      expectCode(
        () => authorize({
          deviceApproval: { ...fixture.deviceApproval, [field]: PHIL_ZERO_BYTES32 }
        }),
        "PHIL_ADAPTER_ZERO_BYTES32"
      );
    }
    expectCode(
      () => authorize({ deviceApproval: { ...fixture.deviceApproval, approvedAt: 0 } }),
      "PHIL_ADAPTER_INVALID_UNSIGNED"
    );
    expectCode(
      () => authorize({
        deviceApproval: {
          ...fixture.deviceApproval,
          approvedAt: 1800000200,
          approvalExpiresAt: 1800000100
        }
      }),
      "PHIL_DEVICE_APPROVAL_TIME_INVALID"
    );
  });

  it("keeps Step 6A isolated from secrets, signing, RPC, UserOperation creation, and compatibility runtimes", function () {
    const source = fs.readFileSync(
      path.join(REPO_ROOT, "apps/phil-device-sdk/src/networkAdapterV1.ts"),
      "utf8"
    );
    const generator = fs.readFileSync(
      path.join(REPO_ROOT, "scripts/security/generate-phil-v1-step6a-artifacts.cjs"),
      "utf8"
    );
    const candidateSource = `${source}\n${generator}`;
    assert.doesNotMatch(source, /from\s+["']\.\/runtime\//);
    assert.doesNotMatch(
      candidateSource,
      /fetch\s*\(|XMLHttpRequest|WebSocket|JsonRpcProvider|ethers\.Wallet|PrivateKey|signTransaction|sendTransaction|sendUserOperation|eth_sendUserOperation|deploy\s*\(|stwo|STWO/
    );
    assert.doesNotMatch(
      source,
      /identityRoot|rootOwnerCommitment|K_data_root|K_backup|recovery share|vault key|phil_secret/
    );
    assert.equal(fixture.existingEvmArtifactsCompatibilityOnly, true);
    assert.equal(fixture.rpcUsed, false);
    assert.equal(fixture.transactionCreated, false);
    assert.equal(fixture.secretUsed, false);
  });
});
