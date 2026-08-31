require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  Wallet,
  keccak256,
  toUtf8Bytes
} = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID,
  PHILCORE_SEPOLIA_AUTHORIZATION_VERSION
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  computePhilCore4337UserOperationHash,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees
} = require("../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts");
const {
  LOCAL_PROOF_GATED_SECURITY_MODEL,
  computeLocalProofGatedAccountSignatureDigest,
  encodeLocalProofGatedExecutionCall,
  runLocalProofGatedSepoliaReadOnlyPreflight,
  signLocalProofGatedUserOperation,
  validateLocalProofGatedSigningAuthorization
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedAccount.ts");

const H = (value) => keccak256(toUtf8Bytes(value));
const ACCOUNT = "0x1000000000000000000000000000000000000001";
const FACTORY = "0x2000000000000000000000000000000000000002";
const TARGET = "0x3000000000000000000000000000000000000003";
const VALIDATOR_KEY_ID = H("validator-key-id");
const RUNTIME_AUTHORIZATION_DIGEST = H("runtime-authorization-digest");
const ROOT = path.resolve(__dirname, "../..");

function artifactFixture(envelope) {
  return [
    "request", "policy", "approval", "user_presence", "stwo_proof",
    "runtime_authorization", "user_operation", "signing_request"
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

function fixture() {
  const nowSeconds = 2_000_000_000;
  const expiresAt = String(nowSeconds + 300);
  const actionId = H("action");
  const canonicalActionDigest = H("canonical-action");
  const callData = encodeLocalProofGatedExecutionCall({
    actionId,
    authorizationDigest: RUNTIME_AUTHORIZATION_DIGEST,
    expiry: expiresAt
  });
  const userOperation = {
    sender: ACCOUNT,
    nonce: "7",
    initCode: "0x",
    callData,
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
  const terminalCalldata = "0x12345678";
  const envelope = {
    authorizationVersion: PHILCORE_SEPOLIA_AUTHORIZATION_VERSION,
    identityReference: H("identity"),
    ownerCommitment: H("owner"),
    actionId,
    canonicalActionDigest,
    policyId: "local-proof-first-action-v1",
    policyCommitment: H("policy"),
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    smartAccountAddress: ACCOUNT,
    factoryAddress: FACTORY,
    entryPointAddress: ERC4337_V07_CANONICAL_ENTRYPOINT,
    nonce: "7",
    targetContract: TARGET,
    valueWei: "0",
    calldataHash: keccak256(terminalCalldata),
    userOperationCallDataHash: keccak256(callData),
    callType: "single",
    verificationGasLimit: "500000",
    callGasLimit: "300000",
    preVerificationGas: "80000",
    maxFeePerGas: "2000000000",
    maxPriorityFeePerGas: "1000000000",
    totalFeeCeilingWei: "1760000000000000",
    validAfter: String(nowSeconds - 5),
    expiresAt,
    nullifier: H("local-runtime-nullifier"),
    proofInputHash: H("proof-input"),
    proofType: "stwo-unlock-keccak-v1",
    runtimeAuthorizationVersion: "runtime-authorization-v1",
    accountDeploymentIncluded: true,
    userOperationHash,
    approvalPresentationDigest: H("approval"),
    userPresenceEvidenceDigest: H("presence"),
    auditCorrelationId: "audit-local-proof-v1"
  };
  const proof = {
    status: "generated",
    proofType: "stwo-unlock-keccak-v1",
    proofArtifactDigest: H("proof-artifact"),
    proofInputHash: envelope.proofInputHash,
    actionId,
    canonicalActionDigest,
    generatedAt: new Date((nowSeconds - 2) * 1000).toISOString()
  };
  const verification = {
    status: "verified",
    valid: true,
    proofType: "stwo-unlock-keccak-v1",
    proofArtifactDigest: proof.proofArtifactDigest,
    proofInputHash: envelope.proofInputHash,
    actionId,
    canonicalActionDigest,
    verifiedAt: new Date((nowSeconds - 1) * 1000).toISOString()
  };
  const approval = {
    status: "approved",
    actionId,
    canonicalActionDigest,
    presentationDigest: envelope.approvalPresentationDigest,
    approvedAt: new Date((nowSeconds - 5) * 1000).toISOString(),
    expiresAt: new Date((nowSeconds + 120) * 1000).toISOString(),
    oneTime: true,
    consumed: false
  };
  const userPresence = {
    status: "verified",
    actionId,
    canonicalActionDigest,
    evidenceDigest: envelope.userPresenceEvidenceDigest,
    verifiedAt: new Date((nowSeconds - 4) * 1000).toISOString(),
    expiresAt: new Date((nowSeconds + 60) * 1000).toISOString()
  };
  return {
    envelope,
    artifacts: artifactFixture(envelope),
    proof,
    verification,
    approval,
    userPresence,
    userOperation,
    executionBinding: {
      targetContract: TARGET,
      valueWei: "0",
      terminalCalldataHash: envelope.calldataHash,
      userOperationCallDataHash: envelope.userOperationCallDataHash
    },
    allowlistedTargetAddress: TARGET,
    expectedFactoryAddress: FACTORY,
    expectedOwnerAddress: Wallet.createRandom().address,
    validatorKeyId: VALIDATOR_KEY_ID,
    runtimeAuthorizationDigest: RUNTIME_AUTHORIZATION_DIGEST,
    nullifierStatus: "available",
    signingPolicy: {
      maxVerificationGasLimit: "500000",
      maxCallGasLimit: "300000",
      maxPreVerificationGas: "80000",
      maxFeePerGas: "2000000000",
      maxPriorityFeePerGas: "1000000000",
      maxTotalFeeWei: "1760000000000000"
    },
    nowSeconds
  };
}

function createSigner(wallet, calls) {
  const descriptor = {
    signerId: "device-vault-fixture",
    mode: "device_vault_beta_ecdsa",
    ownerAddress: wallet.address,
    keyReference: {
      keyReferenceId: "fixture-key",
      mode: "device_vault_beta_ecdsa",
      custody: "device_vault_encrypted",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    },
    available: true,
    productionApproved: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  };
  return {
    async describeSigner() { return descriptor; },
    async checkAvailability() { return descriptor; },
    async getOwnerAddress() { return wallet.address; },
    async signUserOperationHash(request) {
      calls.push(request);
      return {
        status: "signed",
        signature: await wallet.signMessage(Buffer.from(request.signingDigest.slice(2), "hex")),
        signerDescriptor: descriptor,
        signedAt: new Date().toISOString()
      };
    }
  };
}

describe("Runtime local-proof-gated account boundary", function () {
  it("authorizes and signs only after all proof, approval, presence, and UserOperation bindings match", async function () {
    const request = fixture();
    const validation = validateLocalProofGatedSigningAuthorization(request);
    assert.equal(validation.valid, true, validation.errors.join(", "));
    assert.equal(validation.authorization.securityModel, LOCAL_PROOF_GATED_SECURITY_MODEL);
    assert.equal(validation.authorization.localProofVerified, true);
    assert.equal(validation.authorization.factEnforcedOnchain, false);
    assert.equal(
      validation.authorization.accountSignatureDigest,
      computeLocalProofGatedAccountSignatureDigest({
        chainId: request.envelope.chainId,
        entryPointAddress: request.envelope.entryPointAddress,
        smartAccountAddress: request.envelope.smartAccountAddress,
        userOperationHash: request.envelope.userOperationHash,
        actionId: request.envelope.actionId,
        authorizationDigest: request.runtimeAuthorizationDigest,
        expiry: request.envelope.expiresAt,
        validatorKeyId: request.validatorKeyId
      })
    );

    const calls = [];
    const wallet = Wallet.createRandom();
    const result = await signLocalProofGatedUserOperation({
      request: { ...request, expectedOwnerAddress: wallet.address },
      signer: createSigner(wallet, calls)
    });
    assert.equal(result.status, "signed");
    assert.equal(calls.length, 1);
    assert.equal(calls[0].userOperationHash, request.envelope.userOperationHash);
    assert.equal(calls[0].signingDigest, validation.authorization.accountSignatureDigest);
    assert.notEqual(result.value.userOperation.signature, "0x");
    assert.equal(result.value.userOperationSubmitted, false);
    assert.equal(result.value.starkVerifiedOnchain, false);
    const serialized = JSON.stringify(result.value);
    for (const forbidden of [
      "privateKey",
      "phil_secret",
      "nullifierSeed",
      "witness",
      "vaultKey",
      "wrappingKey"
    ]) {
      assert.equal(serialized.includes(forbidden), false, forbidden);
    }
  });

  it("rejects the wrong validator owner before requesting a signature", async function () {
    const request = fixture();
    const calls = [];
    const signerWallet = Wallet.createRandom();
    const result = await signLocalProofGatedUserOperation({
      request: {
        ...request,
        expectedOwnerAddress: Wallet.createRandom().address
      },
      signer: createSigner(signerWallet, calls)
    });
    assert.equal(result.status, "rejected");
    assert.ok(result.errors.includes("device_vault_owner_binding_mismatch"));
    assert.equal(calls.length, 0);
  });

  it("never calls the Device Vault signer when a required local artifact is absent or invalid", async function () {
    const base = fixture();
    const cases = [
      { name: "no proof", mutate: (f) => ({ ...f, proof: undefined }), issue: "proof_missing" },
      {
        name: "unverified proof",
        mutate: (f) => ({ ...f, verification: { ...f.verification, valid: false, status: "failed" } }),
        issue: "proof_not_verified"
      },
      {
        name: "forged proof result",
        mutate: (f) => ({ ...f, verification: { ...f.verification, proofArtifactDigest: H("forged") } }),
        issue: "proof_artifact_digest_mismatch"
      },
      {
        name: "stale approval",
        mutate: (f) => ({ ...f, approval: { ...f.approval, expiresAt: "2000-01-01T00:00:00.000Z" } }),
        issue: "approval_expired"
      },
      {
        name: "stale presence",
        mutate: (f) => ({ ...f, userPresence: { ...f.userPresence, expiresAt: "2000-01-01T00:00:00.000Z" } }),
        issue: "user_presence_expired"
      },
      {
        name: "wrong factory",
        mutate: (f) => ({ ...f, expectedFactoryAddress: TARGET }),
        issue: "factory_address_mismatch"
      },
      {
        name: "higher fee cap",
        mutate: (f) => ({ ...f, signingPolicy: { ...f.signingPolicy, maxFeePerGas: "1" } }),
        issue: "max_fee_per_gas_exceeded"
      },
      {
        name: "duplicate nullifier",
        mutate: (f) => ({ ...f, nullifierStatus: "consumed" }),
        issue: "nullifier_unavailable"
      },
      {
        name: "changed calldata",
        mutate: (f) => ({ ...f, userOperation: { ...f.userOperation, callData: `${f.userOperation.callData}00` } }),
        issue: "account_calldata_mismatch"
      }
    ];
    for (const testCase of cases) {
      const calls = [];
      const result = await signLocalProofGatedUserOperation({
        request: testCase.mutate(base),
        signer: createSigner(Wallet.createRandom(), calls)
      });
      assert.equal(result.status, "rejected", testCase.name);
      assert.ok(result.errors.includes(testCase.issue), `${testCase.name}: ${result.errors.join(", ")}`);
      assert.equal(calls.length, 0, `${testCase.name} reached signer`);
    }
  });

  it("rejects cross-action, identity, chain, account, EntryPoint, nonce, target, value, gas, and paymaster substitution", function () {
    const base = fixture();
    const mutations = [
      (f) => ({ ...f, proof: { ...f.proof, actionId: H("other-action") } }),
      (f) => ({ ...f, artifacts: f.artifacts.map((a, i) => i === 0 ? { ...a, identityReference: H("other") } : a) }),
      (f) => ({ ...f, envelope: { ...f.envelope, chainId: 84532 } }),
      (f) => ({ ...f, envelope: { ...f.envelope, smartAccountAddress: FACTORY } }),
      (f) => ({ ...f, envelope: { ...f.envelope, entryPointAddress: FACTORY } }),
      (f) => ({ ...f, envelope: { ...f.envelope, nonce: "8" } }),
      (f) => ({ ...f, allowlistedTargetAddress: FACTORY }),
      (f) => ({ ...f, envelope: { ...f.envelope, valueWei: "1" } }),
      (f) => ({ ...f, signingPolicy: { ...f.signingPolicy, maxCallGasLimit: "1" } }),
      (f) => ({ ...f, userOperation: { ...f.userOperation, paymasterAndData: "0x1234" } })
    ];
    for (const mutate of mutations) {
      const result = validateLocalProofGatedSigningAuthorization(mutate(base));
      assert.equal(result.valid, false);
    }
  });

  it("fails closed without an explicitly supplied read-only Sepolia client", async function () {
    const absent = await runLocalProofGatedSepoliaReadOnlyPreflight({});
    assert.equal(absent.status, "READ_ONLY_RPC_NOT_CONFIGURED");
    assert.equal(absent.rpcMutationMethodsCalled, false);

    const calls = [];
    const passed = await runLocalProofGatedSepoliaReadOnlyPreflight({
      client: {
        async request(method, params) {
          calls.push({ method, params });
          if (method === "eth_chainId") return "0xaa36a7";
          return params[0] === ERC4337_V07_CANONICAL_ENTRYPOINT ? "0x6000" : "0x";
        }
      },
      proposedAddresses: { target: TARGET, factory: FACTORY }
    });
    assert.equal(passed.status, "READ_ONLY_PREFLIGHT_PASSED", passed.errors.join(", "));
    assert.deepEqual([...new Set(calls.map((call) => call.method))].sort(), ["eth_chainId", "eth_getCode"]);
    assert.equal(passed.proposedAddresses.target, "empty");
    assert.equal(passed.rpcMutationMethodsCalled, false);
  });

  it("keeps the proposed manifest unapproved and all mutation scripts blocked", function () {
    const manifest = JSON.parse(fs.readFileSync(path.join(
      ROOT,
      "config/ethereum-sepolia/LOCAL_PROOF_GATED_DEPLOYMENT_MANIFEST_PROPOSED.json"
    )));
    assert.equal(manifest.status, "proposed");
    assert.equal(manifest.decisionStatus, "Proposed — Human Approval Required");
    assert.equal(manifest.security.securityModel, "local-proof-gated-v1");
    assert.equal(manifest.security.factEnforcedOnchain, false);
    assert.equal(manifest.security.starkVerifiedOnchain, false);
    assert.equal(manifest.security.productionApproved, false);
    assert.equal(manifest.approval.acp0002Status, "Proposed");
    assert.equal(manifest.approval.deploymentApproved, false);
    assert.equal(manifest.approval.userOperationSubmissionApproved, false);
    assert.deepEqual(
      manifest.contracts.map((contract) => contract.contract).sort(),
      [
        "PhilCore4337LocalProofAccountFactoryV1",
        "PhilCore4337LocalProofAccountV1",
        "PhilCoreLocalProofConfirmationTargetV1"
      ]
    );

    const inspect = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/run-local-proof-account.cjs", "--stage", "verify-bytecode"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(inspect.status, 0, inspect.stderr);
    const inspected = JSON.parse(inspect.stdout);
    assert.equal(inspected.bytecode.valid, true);
    assert.equal(inspected.sourceBinding.sourceCommitExists, true);
    assert.equal(typeof inspected.sourceBinding.implementationPathsMatch, "boolean");
    assert.equal(typeof inspected.sourceBinding.repositoryClean, "boolean");
    assert.equal(inspected.publicMutationPerformed, false);

    const preflight = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/run-local-proof-account.cjs", "--stage", "read-only-preflight"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(preflight.status, 0, preflight.stderr);
    assert.equal(JSON.parse(preflight.stdout).preflight.status, "READ_ONLY_RPC_NOT_CONFIGURED");

    const mutation = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/run-local-proof-account.cjs", "--stage", "submit-first-userop"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(mutation.status, 2, mutation.stderr);
    const blocked = JSON.parse(mutation.stdout);
    assert.equal(blocked.allowed, false);
    assert.equal(blocked.transportImplemented, false);
    assert.equal(blocked.publicMutationPerformed, false);
    assert.ok(blocked.errors.includes("accepted_manifest_required"));
  });
});
