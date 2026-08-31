require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {
  keccak256,
  toUtf8Bytes
} = require("ethers");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  ETHEREUM_SEPOLIA_NETWORK_PROFILE,
  PHILCORE_SEPOLIA_AUTHORIZATION_VERSION,
  classifyEthereumSepoliaRpcMethod,
  computeEthereumSepoliaAuthorizationDigest,
  createEthereumSepoliaBundlerConfiguration,
  createEthereumSepoliaDryRunReport,
  evaluateEthereumSepoliaMutationGuard,
  validateEthereumSepoliaAuthorizationComposition,
  validateEthereumSepoliaAuthorizationEnvelope,
  validateEthereumSepoliaManifestStatus
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees
} = require("../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts");

const ROOT = path.resolve(__dirname, "../..");
const MANIFEST_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/ETHEREUM_SEPOLIA_DEPLOYMENT_MANIFEST_PROPOSED.json"
);

const ACCOUNT = "0x1000000000000000000000000000000000000001";
const FACTORY = "0x2000000000000000000000000000000000000002";
const TARGET = "0x3000000000000000000000000000000000000003";
const OTHER_TARGET = "0x4000000000000000000000000000000000000004";
const H = (label) => keccak256(toUtf8Bytes(label));

function fixture() {
  const terminalCalldata = "0x12345678";
  const userOperation = {
    sender: ACCOUNT,
    nonce: "7",
    initCode: "0x",
    callData: "0xb61d27f600000000",
    accountGasLimits: packPhilCore4337AccountGasLimits({
      verificationGasLimit: 500000n,
      callGasLimit: 300000n
    }),
    preVerificationGas: "80000",
    gasFees: packPhilCore4337GasFees({
      maxPriorityFeePerGas: 1000000000n,
      maxFeePerGas: 2000000000n
    }),
    paymasterAndData: "0x",
    signature: "0x"
  };
  const userOperationHash = computePhilCore4337UserOperationHash({
    userOperation,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID
  });
  const envelope = {
    authorizationVersion: PHILCORE_SEPOLIA_AUTHORIZATION_VERSION,
    identityReference: H("identity"),
    ownerCommitment: H("owner"),
    actionId: H("action"),
    canonicalActionDigest: H("canonical-action"),
    policyId: "sepolia-first-action-v1",
    policyCommitment: H("policy"),
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    smartAccountAddress: ACCOUNT,
    factoryAddress: FACTORY,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    nonce: "7",
    targetContract: TARGET,
    valueWei: "0",
    calldataHash: keccak256(terminalCalldata),
    userOperationCallDataHash: keccak256(userOperation.callData),
    callType: "single",
    verificationGasLimit: "500000",
    callGasLimit: "300000",
    preVerificationGas: "80000",
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "1000000000",
    totalFeeCeilingWei: "1760000000000000",
    validAfter: "2000000000",
    expiresAt: "2000000300",
    nullifier: H("nullifier"),
    proofInputHash: H("proof-input"),
    proofType: "stwo-unlock-keccak-v1",
    runtimeAuthorizationVersion: "runtime-authorization-v1",
    accountDeploymentIncluded: true,
    userOperationHash,
    approvalPresentationDigest: H("approval"),
    userPresenceEvidenceDigest: H("presence"),
    auditCorrelationId: "audit-o17-fixture"
  };
  const executionBinding = {
    targetContract: TARGET,
    valueWei: "0",
    terminalCalldataHash: envelope.calldataHash,
    userOperationCallDataHash: envelope.userOperationCallDataHash
  };
  return { envelope, executionBinding, terminalCalldata, userOperation };
}

function validate({ envelope, executionBinding, userOperation }) {
  return validateEthereumSepoliaAuthorizationEnvelope({
    envelope,
    executionBinding,
    userOperation,
    allowlistedTargetAddress: TARGET,
    nowSeconds: 1999999999
  });
}

function artifactFixture(envelope) {
  return [
    "request",
    "policy",
    "approval",
    "user_presence",
    "stwo_proof",
    "runtime_authorization",
    "user_operation",
    "signing_request"
  ].map((artifactKind) => ({
    artifactKind,
    actionId: envelope.actionId,
    canonicalActionDigest: envelope.canonicalActionDigest,
    identityReference: envelope.identityReference,
    ownerCommitment: envelope.ownerCommitment,
    chainId: envelope.chainId,
    smartAccountAddress: envelope.smartAccountAddress,
    auditCorrelationId: envelope.auditCorrelationId,
    userOperationHash: envelope.userOperationHash,
    proofInputHash: envelope.proofInputHash,
    approvalPresentationDigest: envelope.approvalPresentationDigest,
    userPresenceEvidenceDigest: envelope.userPresenceEvidenceDigest
  }));
}

describe("Ethereum Sepolia readiness boundary", function () {
  it("defines a clean Ethereum Sepolia v0.7 profile without inheriting Base", function () {
    assert.equal(ETHEREUM_SEPOLIA_NETWORK_PROFILE.chainId, 11155111);
    assert.equal(ETHEREUM_SEPOLIA_NETWORK_PROFILE.networkName, "Ethereum Sepolia");
    assert.equal(ETHEREUM_SEPOLIA_NETWORK_PROFILE.entryPointVersion, "0.7");
    assert.equal(
      ETHEREUM_SEPOLIA_NETWORK_PROFILE.entryPointAddress,
      "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
    );
    assert.equal(ETHEREUM_SEPOLIA_NETWORK_PROFILE.baseConfigurationInherited, false);
    assert.equal(ETHEREUM_SEPOLIA_NETWORK_PROFILE.paymasterAllowed, false);
    const bundler = createEthereumSepoliaBundlerConfiguration({
      bundlerId: "unapproved-provider-neutral-reference",
      endpointReference: "external-secret-reference"
    });
    assert.equal(bundler.profile, "ethereum_sepolia");
    assert.equal(bundler.status, "unapproved");
    assert.equal(bundler.chainId, 11155111);
    assert.equal(bundler.policy.paymasterAllowed, false);
    assert.equal(bundler.reference.productionApproved, false);
  });

  it("uses canonical typed encoding and validates every final UserOperation binding", function () {
    const f = fixture();
    const result = validate(f);
    assert.equal(result.valid, true, result.errors.join(", "));
    assert.equal(result.authorizationDigest, computeEthereumSepoliaAuthorizationDigest(f.envelope));
  });

  it("rejects chain, EntryPoint, account, target, calldata, value, nonce, fee, expiry, and paymaster substitution", function () {
    const base = fixture();
    const cases = [
      { name: "chain", envelope: { ...base.envelope, chainId: 84532 }, issue: "chain_id_mismatch" },
      {
        name: "EntryPoint",
        envelope: { ...base.envelope, entryPointAddress: FACTORY },
        issue: "entry_point_mismatch"
      },
      {
        name: "account",
        envelope: { ...base.envelope, smartAccountAddress: FACTORY },
        issue: "smart_account_mismatch"
      },
      {
        name: "target",
        envelope: { ...base.envelope, targetContract: OTHER_TARGET },
        issue: "target_not_allowlisted"
      },
      {
        name: "terminal calldata",
        envelope: { ...base.envelope, calldataHash: H("changed-calldata") },
        issue: "terminal_calldata_hash_mismatch"
      },
      {
        name: "UserOperation calldata",
        envelope: { ...base.envelope, userOperationCallDataHash: H("changed-userop-calldata") },
        issue: "user_operation_calldata_binding_mismatch"
      },
      { name: "value", envelope: { ...base.envelope, valueWei: "1" }, issue: "value_must_be_zero" },
      { name: "nonce", envelope: { ...base.envelope, nonce: "8" }, issue: "nonce_mismatch" },
      {
        name: "fee",
        envelope: { ...base.envelope, maxFeePerGas: "3000000000" },
        issue: "max_fee_per_gas_mismatch"
      },
      {
        name: "expiry",
        envelope: { ...base.envelope, expiresAt: "1999999998" },
        issue: "authorization_expired"
      }
    ];
    for (const testCase of cases) {
      const result = validate({ ...base, envelope: testCase.envelope });
      assert.equal(result.valid, false, `${testCase.name} unexpectedly valid`);
      assert.ok(result.errors.includes(testCase.issue), `${testCase.name}: ${result.errors.join(", ")}`);
    }

    const withPaymaster = {
      ...base,
      userOperation: { ...base.userOperation, paymasterAndData: "0x1234" }
    };
    assert.ok(validate(withPaymaster).errors.includes("paymaster_not_allowed"));
  });

  it("rejects cross-action proof, approval, presence, and UserOperation substitution", function () {
    const { envelope } = fixture();
    const artifacts = artifactFixture(envelope);
    const valid = validateEthereumSepoliaAuthorizationComposition({ envelope, artifacts });
    assert.equal(valid.valid, true, valid.errors.join(", "));

    for (const artifactKind of ["approval", "user_presence", "stwo_proof", "user_operation"]) {
      const mutated = artifacts.map((artifact) => artifact.artifactKind === artifactKind
        ? { ...artifact, actionId: H(`other-${artifactKind}`), canonicalActionDigest: H("other-action") }
        : artifact);
      const result = validateEthereumSepoliaAuthorizationComposition({ envelope, artifacts: mutated });
      assert.equal(result.valid, false);
      assert.ok(result.errors.includes(`${artifactKind}_action_id_mismatch`));
      assert.ok(result.errors.includes(`${artifactKind}_canonical_digest_mismatch`));
    }
  });

  it("returns validation issues rather than throwing on malformed numeric input", function () {
    const base = fixture();
    const result = validate({
      ...base,
      envelope: {
        ...base.envelope,
        nonce: "not-a-number",
        maxFeePerGas: "also-not-a-number"
      }
    });
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("nonce_invalid"));
    assert.ok(result.errors.includes("max_fee_per_gas_invalid"));
  });

  it("keeps proposed deployment evidence distinct from deployed or accepted evidence", function () {
    const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
    const summary = {
      status: manifest.status,
      chainId: manifest.network.chainId,
      entryPointAddress: manifest.entryPoint.address,
      deploymentApproved: manifest.approval.deploymentApproved,
      userOperationSubmissionApproved: manifest.approval.userOperationSubmissionApproved,
      productionApproved: manifest.approval.productionApproved,
      acceptedAddressesPresent: manifest.approval.acceptedAddressesPresent
    };
    assert.equal(validateEthereumSepoliaManifestStatus(summary).valid, true);
    assert.equal(summary.status, "proposed");

    const falsePromotion = {
      ...summary,
      deploymentApproved: true,
      acceptedAddressesPresent: true
    };
    const result = validateEthereumSepoliaManifestStatus(falsePromotion);
    assert.equal(result.valid, false);
    assert.ok(result.errors.includes("proposed_manifest_cannot_approve_deployment"));
    assert.ok(result.errors.includes("proposed_manifest_cannot_claim_accepted_addresses"));
  });

  it("classifies RPC methods and fails closed with all mutation gates absent", function () {
    assert.equal(classifyEthereumSepoliaRpcMethod("eth_chainId"), "READ_ONLY");
    assert.equal(classifyEthereumSepoliaRpcMethod("eth_getUserOperationReceipt"), "READ_ONLY");
    assert.equal(classifyEthereumSepoliaRpcMethod("eth_sendRawTransaction"), "PUBLIC_MUTATION");
    assert.equal(classifyEthereumSepoliaRpcMethod("eth_sendUserOperation"), "PUBLIC_MUTATION");

    const guard = evaluateEthereumSepoliaMutationGuard({
      operation: "submit_first_user_operation",
      manifest: {
        status: "proposed",
        chainId: 11155111,
        entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
        deploymentApproved: false,
        userOperationSubmissionApproved: false,
        productionApproved: false,
        acceptedAddressesPresent: false
      },
      environment: {},
      chainId: 11155111,
      entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
      targetAddress: TARGET,
      allowlistedTargetAddress: TARGET,
      valueWei: "0",
      paymasterAndData: "0x",
      maxFeePerGas: "2",
      approvedMaxFeePerGas: "2",
      expiresAt: "2099-01-01T00:00:00.000Z",
      repositoryClean: true
    });
    assert.equal(guard.allowed, false);
    assert.equal(guard.mode, "mutation_blocked");
    assert.ok(guard.errors.includes("public_network_approval_missing"));
    assert.ok(guard.errors.includes("ethereum_sepolia_approval_missing"));
    assert.ok(guard.errors.includes("user_operation_submission_approval_missing"));
    assert.ok(guard.errors.includes("accepted_manifest_required"));
  });

  it("reports current fact-route and no-mutation limitations honestly", function () {
    const report = createEthereumSepoliaDryRunReport();
    assert.equal(report.localProofOnlyPublicExecutionSupported, false);
    assert.equal(report.factAvailabilityModel, "l1_anchored_fact_required_by_current_action_gate");
    assert.equal(report.mutationPerformed, false);
    assert.equal(report.paymasterEnabled, false);
  });

  it("runs local readiness scripts without RPC contact or public mutation", function () {
    const { spawnSync } = require("node:child_process");
    const inspect = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/run-readiness.cjs", "--stage", "inspect-config"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(inspect.status, 0, inspect.stderr);
    const inspectResult = JSON.parse(inspect.stdout);
    assert.equal(inspectResult.rpcContacted, false);
    assert.equal(inspectResult.publicMutationPerformed, false);

    const submit = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/run-readiness.cjs", "--stage", "submit-first-userop"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(submit.status, 2, submit.stderr);
    const submitResult = JSON.parse(submit.stdout);
    assert.equal(submitResult.transportImplemented, false);
    assert.equal(submitResult.rpcContacted, false);
    assert.equal(submitResult.publicMutationPerformed, false);
    assert.equal(submitResult.guard.allowed, false);

    const verifyManifest = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/verify-proposed-manifest.cjs"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(verifyManifest.status, 0, verifyManifest.stderr);
    const manifestResult = JSON.parse(verifyManifest.stdout);
    assert.equal(manifestResult.valid, true, manifestResult.errors.join(", "));
    assert.equal(manifestResult.publicMutationPerformed, false);
  });
});
