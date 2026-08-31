const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");

const hre = require("hardhat");
const { ethers } = hre;
const { describe, it } = require("mocha");

const { deployContract, expectRevert } = require("../helpers/context.cjs");
const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseMirroredFactEvidence,
  createFixtureBaseActionGateDeploymentReader,
  createFixtureBaseAuthorizationExecutionSimulator,
  createFixtureBaseExecutionFeeDataReader,
  createFixtureBaseExecutionGasEstimator,
  createFixtureBaseExecutionNonceReader,
  createFixtureBaseNullifierStateReader,
  encodeBaseVerifyAndConsumeCalldata,
  prepareBaseAuthorizationExecutionTransaction,
  requestBaseAuthorizationExecutionPreparation,
  validateBaseAuthorizationExecutionTransactionDraft
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const {
  UNLOCK_PROOF_SCHEMA_VERSION,
  UNLOCK_PROOF_TYPE,
  dataHash,
  unlockActionHash
} = require("../../apps/phil-device-sdk/src/hashes.ts");
const {
  buildUnlockProofPackageFromAuthorization
} = require("../../apps/phil-device-sdk/src/proof/publicInputs.ts");

const abiCoder = ethers.AbiCoder.defaultAbiCoder();
const POLICY_HASH = `0x${"22".repeat(32)}`;
const OWNER_COMMITMENT = `0x${"11".repeat(32)}`;
const NULLIFIER = `0x${"33".repeat(32)}`;

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function hexPairFromProofInputHash(proofInputHash) {
  const raw = proofInputHash.slice(2).padStart(64, "0");
  return {
    factHigh: `0x${raw.slice(0, 32)}`,
    factLow: `0x${raw.slice(32)}`
  };
}

function encodeUnlockRequest(request) {
  return abiCoder.encode(
    ["tuple(address account,address target,uint256 value,bytes callData)"],
    [request]
  );
}

function proofBlobForFact(factHigh, factLow) {
  return abiCoder.encode(["uint256", "uint256"], [BigInt(factHigh), BigInt(factLow)]);
}

async function deployBaseExecutionContracts() {
  const [deployer, account, target, sender] = await ethers.getSigners();
  const baseMessenger = await deployContract(deployer, "MockBaseCrossDomainMessenger");
  const adapter = await deployContract(deployer, "PhilBaseCrossDomainMessengerAdapter", [
    await baseMessenger.getAddress(),
    200000
  ]);
  const baseMirror = await deployContract(deployer, "PhilBaseProofInputHashMirror", [
    await baseMessenger.getAddress(),
    await adapter.getAddress()
  ]);
  const verifier = await deployContract(deployer, "PhilBaseMirroredFactUnlockProofVerifier", [
    await baseMirror.getAddress()
  ]);
  const gate = await deployContract(deployer, "PhilBaseActionGate", [await verifier.getAddress()]);
  const unlockConsumer = await deployContract(deployer, "PhilUnlockConsumer", [await gate.getAddress()]);
  return { deployer, account, target, sender, baseMessenger, adapter, baseMirror, verifier, gate, unlockConsumer };
}

async function buildPreparedFixture(overrides = {}) {
  const contracts = await deployBaseExecutionContracts();
  const issuedAt = now();
  const expiresAt = futureDate();
  const expiry = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const consumerAddress = await contracts.unlockConsumer.getAddress();
  const unlockRequest = {
    account: overrides.account ?? await contracts.account.getAddress(),
    target: overrides.target ?? await contracts.target.getAddress(),
    value: overrides.value ?? 0n,
    callData: overrides.callData ?? ethers.hexlify(ethers.toUtf8Bytes("philcore-m7"))
  };
  const consumerData = overrides.consumerData ?? encodeUnlockRequest(unlockRequest);
  const actionHash = unlockActionHash({
    chainId: 31337,
    consumer: consumerAddress,
    account: unlockRequest.account,
    target: unlockRequest.target,
    value: unlockRequest.value,
    callDataHash: dataHash(unlockRequest.callData)
  });
  const authorization = {
    consumer: consumerAddress,
    ownerCommitment: OWNER_COMMITMENT,
    actionHash,
    policyHash: POLICY_HASH,
    nullifier: overrides.nullifier ?? NULLIFIER,
    consumerDataHash: dataHash(consumerData),
    expiry
  };
  const initialPackage = buildUnlockProofPackageFromAuthorization(authorization, { proofBlob: "0x1234" });
  const fact = hexPairFromProofInputHash(initialPackage.proofInputHash);
  const proofPackage = buildUnlockProofPackageFromAuthorization(authorization, {
    proofBlob: proofBlobForFact(fact.factHigh, fact.factLow)
  });
  const proofDigest = dataHash(proofPackage.proofBlob);
  const finalizedPackage = {
    finalizedAuthorizationPackageId: "m7-finalized-package",
    status: "authorization_package_finalized",
    outcome: "authorization_package_finalized",
    binding: {
      authorizationPackageDraftId: "m7-package-draft",
      proofGenerationArtifactId: "m7-proof-generation",
      proofVerificationResultId: "m7-proof-verification",
      sessionId: "m7-session",
      applicationId: "ethereum-net",
      intentId: "m7-intent",
      capabilityName: "request_contract_call",
      ownerCommitment: OWNER_COMMITMENT,
      proofInputHash: proofPackage.proofInputHash,
      auditCorrelationId: "m7-audit"
    },
    actionUnlockAuthorization: {
      version: UNLOCK_PROOF_SCHEMA_VERSION,
      proofType: UNLOCK_PROOF_TYPE,
      ownerCommitment: authorization.ownerCommitment,
      actionHash: authorization.actionHash,
      policyHash: authorization.policyHash,
      nullifier: authorization.nullifier,
      consumerDataHash: authorization.consumerDataHash,
      expiry: expiry.toString(),
      proofInputHash: proofPackage.proofInputHash,
      factShapeReference: "[fact_high, fact_low]"
    },
    proofArtifact: {
      proofArtifactId: "m7-proof-artifact",
      proofGenerationArtifactId: "m7-proof-generation",
      proofVerificationResultId: "m7-proof-verification",
      proofType: UNLOCK_PROOF_TYPE,
      proofDigest,
      proofByteLength: (proofPackage.proofBlob.length - 2) / 2,
      proofInputHash: proofPackage.proofInputHash,
      proofBlobIncluded: false,
      proofBytesLogged: false,
      nonSecretProofArtifact: true,
      containsWitnessOpenings: false,
      safeForExternalVerifierTransmission: true,
      executableByAdapters: false
    },
    evidence: {
      proofGenerated: true,
      proofVerifiedLocally: true,
      proofTypeMatched: true,
      publicInputsMatched: true,
      proofInputHashMatched: true,
      factShapeValidated: true,
      localVerificationResultId: "m7-proof-verification",
      verifiedProofReferenceId: "m7-proof-artifact"
    },
    factShapePreview: {
      factShapeReference: "[fact_high, fact_low]",
      factHigh: fact.factHigh,
      factLow: fact.factLow,
      sourceProofInputHash: proofPackage.proofInputHash,
      ordering: "fact_high_then_fact_low",
      factPublished: false,
      onChainRegistered: false
    },
    validity: {
      issuedAt,
      expiresAt,
      expired: false
    },
    limitations: [
      "local_finalization_only",
      "non_executing_authorization_package",
      "no_verified_fact_publication",
      "no_on_chain_verification",
      "no_nullifier_consumption",
      "no_adapter_execution",
      "no_contract_execution",
      "no_transaction_submission",
      "process_local_package_store_only"
    ],
    authorizationPackageFinalized: true,
    proofGenerated: true,
    proofVerifiedLocally: true,
    verifiedFactPublished: false,
    onChainVerificationPerformed: false,
    nullifierConsumed: false,
    adapterExecutionAllowed: false,
    contractExecutionAllowed: false,
    transactionSubmitted: false,
    executableByApplications: false,
    witnessMaterialExposed: false,
    persisted: false
  };
  const capabilityGrant = {
    authoritativeCapabilityGrantId: "m7-capability-grant",
    requestId: "m7-capability-request",
    status: "active",
    outcome: "capability_granted",
    scope: {
      capabilityName: "request_contract_call",
      allowedTargets: [consumerAddress],
      actionTypes: ["base_authorization_execution"],
      chainId: 31337,
      network: "hardhat"
    },
    binding: {
      authoritativeTrustDecisionId: "m7-trust",
      authoritativePolicyDecisionId: "m7-policy",
      platformUserApprovalDecisionId: "m7-approval",
      sessionLifecycleId: "m7-lifecycle",
      sessionLifecycleState: "unlocked",
      ownerCommitment: OWNER_COMMITMENT,
      sessionId: "m7-session",
      applicationId: "ethereum-net",
      capabilityName: "request_contract_call",
      auditCorrelationId: "m7-audit",
      validityWindowId: "m7-window",
      reusableAcrossOwners: false,
      reusableAcrossSessions: false,
      reusableAcrossApplications: false,
      reusableAcrossCapabilities: false,
      reusableAcrossScopes: false,
      reusableAcrossTimeWindows: false
    },
    constraints: [],
    requirements: [],
    limitations: ["authorization_still_required"],
    reasons: ["trust_policy_and_user_approval_satisfied"],
    validity: {
      issuedAt,
      expiresAt,
      expired: false,
      invalidatedBySessionLock: true,
      invalidatedBySessionClose: true,
      invalidatedByExplicitRevocation: true,
      invalidatedByTrustDecisionExpiry: true,
      invalidatedByPolicyDecisionExpiry: true,
      invalidatedByApprovalDecisionExpiry: true
    },
    revocation: {
      revoked: false,
      durableRevocationImplemented: false,
      processLocalOnly: true
    },
    usagePolicy: {
      mayRequestFutureActions: true,
      actionAuthorizationStillRequired: true,
      authorizationEngineRequired: true,
      proofMayBeRequiredLater: true,
      adapterExecutionAllowed: false,
      unrestrictedWalletAuthority: false,
      usageCountConsumed: 0
    },
    capabilityGranted: true,
    activeCapabilityCreated: true,
    actionAuthorized: false,
    authorizationCreated: false,
    authorizationPackageCreated: false,
    sessionKeyCreated: false,
    executionAllowed: false,
    proofExecuted: false,
    adapterExecuted: false,
    transactionSubmitted: false,
    vaultAccessed: false,
    worldIdVerified: false,
    rawTrustEvidenceIncluded: false,
    rawApprovalArtifactIncluded: false,
    credentialRecordIncluded: false,
    privateMaterialIncluded: false,
    persisted: false,
    persistedAsAuthority: false
  };
  const sessionLifecycleSnapshot = {
    lifecycleId: "m7-lifecycle",
    sessionId: "m7-session",
    state: "unlocked",
    sequence: 7,
    version: 7,
    createdAt: issuedAt,
    updatedAt: issuedAt,
    metadata: { deviceVaultUnlocked: true },
    limitations: ["ephemeral_only"],
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: true,
    grantsAuthority: false
  };
  const configuration = {
    configurationId: "m7-base-action-gate",
    approvalStatus: "accepted",
    activeProfile: {
      profileId: "hardhat-base-local",
      network: "hardhat",
      chainId: 31337,
      enabled: true
    },
    actionGateAddress: await contracts.gate.getAddress(),
    verifier: {
      address: await contracts.verifier.getAddress(),
      expectedProofType: UNLOCK_PROOF_TYPE,
      baseMirrorAddress: await contracts.baseMirror.getAddress(),
      approved: true
    },
    mirror: {
      address: await contracts.baseMirror.getAddress(),
      messengerAddress: await contracts.baseMessenger.getAddress(),
      authorizedL1RemoteSender: await contracts.adapter.getAddress(),
      approved: true
    },
    consumer: {
      address: consumerAddress,
      consumerKind: "PhilUnlockConsumer",
      actionGateAddress: await contracts.gate.getAddress(),
      approved: true,
      payable: true
    },
    methodSelector: BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
    abiVersion: "phil-base-action-gate-v1",
    supportedProofType: UNLOCK_PROOF_TYPE,
    valuePolicy: "exact_authorized_value",
    mainnetAllowed: false
  };
  const mirroredFactEvidence = createBaseMirroredFactEvidence({
    source: "local_hardhat_receipt",
    binding: {
      baseChainId: 31337,
      baseMirrorAddress: await contracts.baseMirror.getAddress(),
      baseMessengerAddress: await contracts.baseMessenger.getAddress(),
      authorizedL1RemoteSender: await contracts.adapter.getAddress(),
      mirrorTransactionHash: `0x${"ab".repeat(32)}`,
      factHigh: fact.factHigh,
      factLow: fact.factLow,
      proofInputHash: proofPackage.proofInputHash,
      auditCorrelationId: "m7-audit"
    }
  });
  const deploymentReader = createFixtureBaseActionGateDeploymentReader({
    chainId: 31337,
    actionGateAddress: await contracts.gate.getAddress(),
    verifierAddress: await contracts.verifier.getAddress(),
    mirrorAddress: await contracts.baseMirror.getAddress(),
    consumerAddress,
    baseMessengerAddress: await contracts.baseMessenger.getAddress(),
    authorizedL1RemoteSender: await contracts.adapter.getAddress()
  });
  const request = {
    requestId: "m7-base-execution-preparation",
    finalizedAuthorizationPackage: finalizedPackage,
    baseActionAuthorization: authorization,
    proofPackage,
    consumerData,
    mirroredFactEvidence,
    activeCapabilityGrant: capabilityGrant,
    sessionLifecycleSnapshot,
    configuration,
    deploymentReader,
    nullifierStateReader: createFixtureBaseNullifierStateReader("nullifier_available"),
    senderAccount: await contracts.sender.getAddress(),
    simulator: createFixtureBaseAuthorizationExecutionSimulator("simulation_succeeded"),
    gasEstimator: createFixtureBaseExecutionGasEstimator("500000"),
    nonceReader: createFixtureBaseExecutionNonceReader("9"),
    feeDataReader: createFixtureBaseExecutionFeeDataReader(),
    issuedAt,
    expiresAt,
    auditCorrelationId: "m7-audit"
  };
  return { ...contracts, request, authorization, proofPackage, consumerData, fact };
}

describe("Base authorization execution preparation boundary", function () {
  it("rejects a secret-bearing proof package before execution preparation", async function () {
    const fixture = await buildPreparedFixture();
    const unsafePackage = {
      ...fixture.request.finalizedAuthorizationPackage,
      proofArtifact: {
        ...fixture.request.finalizedAuthorizationPackage.proofArtifact,
        nonSecretProofArtifact: false,
        containsWitnessOpenings: true,
        safeForExternalVerifierTransmission: false
      }
    };
    const result = await requestBaseAuthorizationExecutionPreparation({
      ...fixture.request,
      finalizedAuthorizationPackage: unsafePackage
    });
    assert.equal(result.status, "denied");
    assert.match(result.error.details.errors.join("\n"), /witness-hiding proof reference/);
  });

  it("creates an unsigned verifyAndConsume transaction draft without execution authority", async function () {
    const fixture = await buildPreparedFixture();
    const result = await prepareBaseAuthorizationExecutionTransaction(fixture.request);

    assert.equal(result.status, "approved");
    const draft = result.value;
    assert.equal(draft.methodSelector, BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR);
    assert.equal(
      draft.calldata,
      encodeBaseVerifyAndConsumeCalldata({
        authorization: fixture.authorization,
        proofPackage: fixture.proofPackage,
        consumerData: fixture.consumerData
      })
    );
    assert.equal(draft.transactionPrepared, true);
    assert.equal(draft.transactionSigned, false);
    assert.equal(draft.transactionSubmitted, false);
    assert.equal(draft.userOperationCreated, false);
    assert.equal(draft.nullifierConsumed, false);
    assert.equal(draft.consumerExecuted, false);
    assert.equal(draft.baseStateMutated, false);
    assert.equal(draft.applicationCanSubmitDirectly, false);
    assert.equal(draft.productionSignable, false);
    assert.deepEqual(validateBaseAuthorizationExecutionTransactionDraft(draft), { valid: true, errors: [] });
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), false);
  });

  it("rejects mismatched mirrored facts and proof input hashes", async function () {
    const fixture = await buildPreparedFixture();
    const request = {
      ...fixture.request,
      mirroredFactEvidence: createBaseMirroredFactEvidence({
        source: "local_hardhat_receipt",
        binding: {
          ...fixture.request.mirroredFactEvidence.binding,
          factHigh: fixture.fact.factLow,
          factLow: fixture.fact.factHigh
        }
      })
    };
    const result = await requestBaseAuthorizationExecutionPreparation(request);
    assert.equal(result.status, "denied");
    assert.equal(result.error.details.outcome, "mirrored_fact_mismatch");
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), false);
  });

  it("rejects inactive capabilities, locked sessions, consumed nullifiers, and failed simulations", async function () {
    const fixture = await buildPreparedFixture();
    const inactive = await prepareBaseAuthorizationExecutionTransaction({
      ...fixture.request,
      activeCapabilityGrant: { ...fixture.request.activeCapabilityGrant, status: "expired" }
    });
    assert.equal(inactive.status, "denied");
    assert.equal(inactive.error.details.outcome, "capability_ineligible");

    const locked = await prepareBaseAuthorizationExecutionTransaction({
      ...fixture.request,
      sessionLifecycleSnapshot: { ...fixture.request.sessionLifecycleSnapshot, state: "locked" }
    });
    assert.equal(locked.status, "denied");
    assert.equal(locked.error.details.outcome, "session_ineligible");

    const consumed = await prepareBaseAuthorizationExecutionTransaction({
      ...fixture.request,
      nullifierStateReader: createFixtureBaseNullifierStateReader("nullifier_consumed")
    });
    assert.equal(consumed.status, "denied");
    assert.equal(consumed.error.details.outcome, "nullifier_consumed");

    const simulatedRevert = await prepareBaseAuthorizationExecutionTransaction({
      ...fixture.request,
      simulator: createFixtureBaseAuthorizationExecutionSimulator("consumer_reverted")
    });
    assert.equal(simulatedRevert.status, "denied");
    assert.equal(simulatedRevert.error.details.outcome, "simulation_failed");
  });

  it("rejects deployment/configuration mismatches and unresolved nonce", async function () {
    const fixture = await buildPreparedFixture();
    const badDeployment = await prepareBaseAuthorizationExecutionTransaction({
      ...fixture.request,
      deploymentReader: createFixtureBaseActionGateDeploymentReader({
        chainId: 31337,
        actionGateAddress: await fixture.gate.getAddress(),
        verifierAddress: "0x9999999999999999999999999999999999999999",
        mirrorAddress: await fixture.baseMirror.getAddress(),
        consumerAddress: await fixture.unlockConsumer.getAddress(),
        baseMessengerAddress: await fixture.baseMessenger.getAddress(),
        authorizedL1RemoteSender: await fixture.adapter.getAddress()
      })
    });
    assert.equal(badDeployment.status, "denied");
    assert.equal(badDeployment.error.details.outcome, "verifier_configuration_invalid");

    const nonceUnresolved = await prepareBaseAuthorizationExecutionTransaction({
      ...fixture.request,
      nonceReader: undefined
    });
    assert.equal(nonceUnresolved.status, "denied");
    assert.equal(nonceUnresolved.error.details.outcome, "nonce_unresolved");
  });

  it("executes only when the actual ActionGate transaction is sent, consumes nullifier once, and blocks replay", async function () {
    const fixture = await buildPreparedFixture();
    await fixture.adapter.sendMessage(
      await fixture.baseMirror.getAddress(),
      fixture.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
        BigInt(fixture.fact.factHigh),
        BigInt(fixture.fact.factLow)
      ])
    );

    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), false);
    const tx = await fixture.gate.verifyAndConsume(
      fixture.authorization,
      fixture.proofPackage,
      fixture.consumerData,
      { value: fixture.request.baseActionAuthorization.value ?? 0 }
    );
    await tx.wait();
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), true);

    await expectRevert(
      () => fixture.gate.verifyAndConsume(fixture.authorization, fixture.proofPackage, fixture.consumerData),
      "expected replayed nullifier to revert"
    );
  });

  it("does not consume nullifiers for missing mirrored facts or wrong consumer data", async function () {
    const missingFact = await buildPreparedFixture();
    await expectRevert(
      () => missingFact.gate.verifyAndConsume(
        missingFact.authorization,
        missingFact.proofPackage,
        missingFact.consumerData
      ),
      "expected missing mirrored fact to revert"
    );
    assert.equal(await missingFact.gate.consumedNullifier(missingFact.authorization.nullifier), false);

    const wrongData = await buildPreparedFixture();
    await wrongData.adapter.sendMessage(
      await wrongData.baseMirror.getAddress(),
      wrongData.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
        BigInt(wrongData.fact.factHigh),
        BigInt(wrongData.fact.factLow)
      ])
    );
    await expectRevert(
      () => wrongData.gate.verifyAndConsume(wrongData.authorization, wrongData.proofPackage, "0x1234"),
      "expected wrong consumer data to revert"
    );
    assert.equal(await wrongData.gate.consumedNullifier(wrongData.authorization.nullifier), false);
  });

  it("rolls back nullifier consumption when PhilUnlockConsumer downstream execution fails", async function () {
    const fixture = await buildPreparedFixture({ target: ethers.ZeroAddress });
    await fixture.adapter.sendMessage(
      await fixture.baseMirror.getAddress(),
      fixture.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
        BigInt(fixture.fact.factHigh),
        BigInt(fixture.fact.factLow)
      ])
    );

    await expectRevert(
      () => fixture.gate.verifyAndConsume(fixture.authorization, fixture.proofPackage, fixture.consumerData),
      "expected invalid downstream target to revert"
    );
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), false);
  });

  it("enforces gate-only consumer access and forwards only the approved value", async function () {
    const fixture = await buildPreparedFixture({ value: 1n });
    await fixture.adapter.sendMessage(
      await fixture.baseMirror.getAddress(),
      fixture.baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
        BigInt(fixture.fact.factHigh),
        BigInt(fixture.fact.factLow)
      ])
    );

    await expectRevert(
      () => fixture.unlockConsumer.consumePhilAuthorization(fixture.authorization, fixture.consumerData),
      "expected direct consumer call to revert"
    );

    const targetAddress = await fixture.target.getAddress();
    const before = await ethers.provider.getBalance(targetAddress);
    await (
      await fixture.gate.verifyAndConsume(
        fixture.authorization,
        fixture.proofPackage,
        fixture.consumerData,
        { value: 1n }
      )
    ).wait();
    const after = await ethers.provider.getBalance(targetAddress);
    assert.equal(after - before, 1n);
    assert.equal(await fixture.gate.consumedNullifier(fixture.authorization.nullifier), true);
  });

  it("keeps diagnostics non-mutating", function () {
    const diagnostic = spawnSync(
      "npm",
      ["run", "diagnose:base-authorization-execution-preparation", "--", "--json"],
      { encoding: "utf8" }
    );
    assert.equal(diagnostic.status, 0, diagnostic.stderr);
    const output = JSON.parse(diagnostic.stdout.slice(diagnostic.stdout.indexOf("{")));
    assert.equal(output.phase, "M.7");
    assert.equal(output.executionPrepared, true);
    assert.equal(output.transactionSigned, false);
    assert.equal(output.transactionSubmitted, false);
    assert.equal(output.nullifierConsumed, false);
    assert.equal(output.consumerExecuted, false);
    assert.equal(output.baseStateMutated, false);
  });
});
