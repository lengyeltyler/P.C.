const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  PHILCORE_4337_EXECUTE_SELECTOR_FORBIDDEN_TO_RECOVERY,
  PHILCORE_4337_REQUEST_RECOVERY_SELECTOR,
  bindPhilCoreRecoveryAuthorityAccountReference,
  createInMemoryPhilCoreRecoveryApprovalStore,
  createPhilCore4337RecoveryCandidate,
  createPhilCoreRecoveryActionApprovalArtifact,
  createPhilCoreRecoveryActionPresentation,
  createPhilCoreRecoveryAuthoritySigningSession,
  createUserSessionLifecycleSnapshot,
  generateDeviceVaultEcdsaValidator,
  generatePhilCoreRecoveryAuthority,
  preparePhilCoreRecoveryUserOperation,
  revokeDeviceVaultEcdsaValidator,
  signPhilCoreRecoveryUserOperation
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const {
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");

const OWNER_COMMITMENT = ethers.id("philcore-n5-owner-commitment");

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function lifecycle(sessionId = "n5-session") {
  return createUserSessionLifecycleSnapshot({
    sessionId,
    state: "unlocked",
    metadata: {
      deviceVaultUnlocked: true,
      protectedStateAvailable: true
    }
  });
}

function vaultHandle(snapshot = lifecycle()) {
  return {
    handleId: `n5-vault:${snapshot.sessionId}`,
    sessionId: snapshot.sessionId,
    ownerCommitment: OWNER_COMMITMENT,
    envelopeId: "n5-envelope",
    unlockResultId: "n5-unlock",
    unlockedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    processLocal: true,
    serializable: false,
    exportable: false,
    containsPlaintext: false,
    containsRawVaultKey: false,
    containsPhilSecret: false,
    applicationAccessible: false
  };
}

function custodyEnv(name = "primary") {
  const snapshot = lifecycle(`n5-${name}`);
  return {
    lifecycleSnapshot: snapshot,
    unlockedVaultHandle: vaultHandle(snapshot),
    storageBackend: createInMemoryDeviceIdentityRegistryStorageBackend(),
    keyProvider: createLocalDevPassphraseKeyProvider({
      passphrase: `n5-${name}-passphrase`,
      scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
    })
  };
}

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  return new ethers.ContractFactory(EntryPointArtifact.abi, EntryPointArtifact.bytecode, deployer).deploy();
}

async function generateExecutionValidator(env, label, accountAddress) {
  const result = await generateDeviceVaultEcdsaValidator({
    requestId: `n5-${label}`,
    lifecycleSnapshot: env.lifecycleSnapshot,
    unlockedVaultHandle: env.unlockedVaultHandle,
    storageBackend: env.storageBackend,
    keyProvider: env.keyProvider,
    ownerCommitment: OWNER_COMMITMENT,
    purpose: "erc4337_owner_validator_local_alpha",
    accountAddress,
    chainId: 31337,
    expiresAt: futureDate()
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

async function generateRecoveryAuthority(env, executionOwnerAddress) {
  const result = await generatePhilCoreRecoveryAuthority({
    requestId: "n5-recovery-authority",
    lifecycleSnapshot: env.lifecycleSnapshot,
    unlockedVaultHandle: env.unlockedVaultHandle,
    storageBackend: env.storageBackend,
    keyProvider: env.keyProvider,
    ownerCommitment: OWNER_COMMITMENT,
    chainId: 31337,
    networkProfile: "local-hardhat",
    purpose: "local_alpha_recovery_authority",
    executionOwnerAddress,
    expiresAt: futureDate()
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value.record;
}

async function bindRecoveryAuthority(env, record, accountAddress) {
  const result = await bindPhilCoreRecoveryAuthorityAccountReference({
    requestId: "n5-bind-recovery",
    recoveryRecord: record,
    storageBackend: env.storageBackend,
    keyProvider: env.keyProvider,
    accountAddress,
    chainId: 31337
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value.record;
}

async function deployAccountWithRecovery({ entryPoint, actionGate, ownerAddress, recoveryAddress }) {
  const [deployer] = await ethers.getSigners();
  const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
  const factory = await AccountFactory.deploy(
    await entryPoint.getAddress(),
    await actionGate.getAddress(),
    recoveryAddress,
    60,
    3600
  );
  const predicted = await factory.getFunction("getAddress").staticCall(ownerAddress, OWNER_COMMITMENT, 1n);
  await (await factory.createAccount(ownerAddress, OWNER_COMMITMENT, 1n)).wait();
  await deployer.sendTransaction({ to: predicted, value: ethers.parseEther("1") });
  return {
    factory,
    account: await ethers.getContractAt("PhilCore4337Account", predicted),
    accountAddress: predicted
  };
}

function recoveryCandidate({ action, accountAddress, recoveryAuthority, currentOwner, pendingOwner, recoveryRequestId }) {
  const result = createPhilCore4337RecoveryCandidate({
    requestId: `n5-${action}-${Math.random()}`,
    action,
    accountAddress,
    recoveryAuthority,
    currentOwner,
    pendingOwner,
    recoveryRequestId,
    ownerCommitment: OWNER_COMMITMENT,
    chainId: 31337,
    expiresAt: futureDate()
  });
  assert.equal(result.status, "approved", result.error?.details?.errors?.join("\n"));
  return result.value;
}

async function signRecoveryUserOperation({
  env,
  recoveryRecord,
  candidate,
  entryPoint,
  approvalId = "n5-approval"
}) {
  const nonce = await entryPoint.getNonce(candidate.accountAddress, 0);
  const draft = preparePhilCoreRecoveryUserOperation({
    requestId: `n5-prepare-${candidate.action}`,
    candidate,
    entryPointAddress: await entryPoint.getAddress(),
    nonce,
    chainId: 31337,
    expiresAt: futureDate()
  });
  assert.equal(draft.status, "approved", draft.error?.details?.errors?.join("\n"));
  const presentation = createPhilCoreRecoveryActionPresentation(draft.value);
  const approval = createPhilCoreRecoveryActionApprovalArtifact({
    approvalId,
    presentationDigest: presentation.presentationDigest,
    source: "developer_fixture",
    approved: true,
    approvedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    oneTime: true,
    publicNetworkAllowed: false
  });
  const session = await createPhilCoreRecoveryAuthoritySigningSession({
    requestId: `n5-session-${candidate.action}`,
    lifecycleSnapshot: env.lifecycleSnapshot,
    unlockedVaultHandle: env.unlockedVaultHandle,
    storageBackend: env.storageBackend,
    keyProvider: env.keyProvider,
    recoveryRecord,
    draft: draft.value,
    presentationDigest: presentation.presentationDigest,
    expiresAt: futureDate()
  });
  assert.equal(session.status, "approved", session.error?.details?.errors?.join("\n"));
  const signed = await signPhilCoreRecoveryUserOperation({
    requestId: `n5-sign-${candidate.action}`,
    draft: draft.value,
    presentation: presentation.presentation,
    presentationDigest: presentation.presentationDigest,
    approval,
    signer: session.value.signingSession,
    approvalStore: createInMemoryPhilCoreRecoveryApprovalStore()
  });
  assert.equal(signed.status, "approved", signed.error?.details?.errors?.join("\n"));
  return signed.value;
}

async function handleOp(entryPoint, beneficiary, signed) {
  return entryPoint.handleOps([signed.userOperation], beneficiary.address, { gasLimit: 8_000_000 });
}

async function increase(seconds) {
  await ethers.provider.send("evm_increaseTime", [seconds]);
  await ethers.provider.send("evm_mine", []);
}

async function baseFixture() {
  const [deployer, beneficiary] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const actionGate = await ActionGate.deploy(ethers.ZeroAddress);
  return { deployer, beneficiary, entryPoint, actionGate };
}

describe("PhilCore recovery authority custody and workflow", function () {
  it("creates a separate encrypted recovery authority record without exposing private keys", async function () {
    const currentEnv = custodyEnv("current");
    const current = await generateExecutionValidator(currentEnv, "current");
    const recoveryEnv = custodyEnv("recovery");
    const recoveryRecord = await generateRecoveryAuthority(recoveryEnv, current.ownerAddress);

    assert.notEqual(recoveryRecord.metadata.publicRecoveryAddress, current.ownerAddress);
    assert.equal(recoveryRecord.metadata.privateKeyReturned, false);
    assert.equal(recoveryRecord.metadata.storedEncrypted, true);
    assert.equal(recoveryRecord.metadata.separateFromExecutionKey, true);
    assert.equal(recoveryRecord.metadata.ordinaryExecutionAuthority, false);
    assert.equal(recoveryRecord.metadata.publicSubmissionEnabled, false);
    assert.doesNotMatch(JSON.stringify(recoveryRecord), /"privateKey":"0x[0-9a-fA-F]{64}"/);
    assert.doesNotMatch(JSON.stringify(recoveryRecord), /phil_secret|nullifierSeed|rawVaultKey|mnemonic/);
  });

  it("rejects wrong vault/key binding and secret-shaped metadata", async function () {
    const currentEnv = custodyEnv("current");
    const current = await generateExecutionValidator(currentEnv, "current");
    const recoveryEnv = custodyEnv("recovery");
    const rejected = await generatePhilCoreRecoveryAuthority({
      requestId: "n5-secret-metadata",
      lifecycleSnapshot: recoveryEnv.lifecycleSnapshot,
      unlockedVaultHandle: recoveryEnv.unlockedVaultHandle,
      storageBackend: recoveryEnv.storageBackend,
      keyProvider: recoveryEnv.keyProvider,
      ownerCommitment: OWNER_COMMITMENT,
      chainId: 31337,
      networkProfile: "local-hardhat",
      purpose: "local_alpha_recovery_authority",
      executionOwnerAddress: current.ownerAddress,
      metadata: { phil_secret: "nope" }
    });
    assert.equal(rejected.status, "denied");

    const record = await generateRecoveryAuthority(recoveryEnv, current.ownerAddress);
    const fixture = await baseFixture();
    const { accountAddress } = await deployAccountWithRecovery({
      entryPoint: fixture.entryPoint,
      actionGate: fixture.actionGate,
      ownerAddress: current.ownerAddress,
      recoveryAddress: record.metadata.publicRecoveryAddress
    });
    const bound = await bindRecoveryAuthority(recoveryEnv, record, accountAddress);
    const candidate = recoveryCandidate({
      action: "request_recovery",
      accountAddress,
      recoveryAuthority: bound.metadata.publicRecoveryAddress,
      currentOwner: current.ownerAddress,
      pendingOwner: ethers.Wallet.createRandom().address
    });
    const draft = preparePhilCoreRecoveryUserOperation({
      requestId: "n5-wrong-vault-draft",
      candidate,
      entryPointAddress: await fixture.entryPoint.getAddress(),
      nonce: 0,
      chainId: 31337,
      expiresAt: futureDate()
    }).value;
    const presentation = createPhilCoreRecoveryActionPresentation(draft);
    const wrongEnv = custodyEnv("wrong");
    const session = await createPhilCoreRecoveryAuthoritySigningSession({
      requestId: "n5-wrong-vault-session",
      lifecycleSnapshot: wrongEnv.lifecycleSnapshot,
      unlockedVaultHandle: wrongEnv.unlockedVaultHandle,
      storageBackend: recoveryEnv.storageBackend,
      keyProvider: wrongEnv.keyProvider,
      recoveryRecord: bound,
      draft,
      presentationDigest: presentation.presentationDigest,
      expiresAt: futureDate()
    });
    assert.equal(session.status, "denied");
  });

  it("blocks recovery authority signing for execute and cancellation paths", async function () {
    const currentEnv = custodyEnv("current");
    const current = await generateExecutionValidator(currentEnv, "current");
    const recoveryEnv = custodyEnv("recovery");
    const record = await generateRecoveryAuthority(recoveryEnv, current.ownerAddress);
    const fixture = await baseFixture();
    const { accountAddress } = await deployAccountWithRecovery({
      entryPoint: fixture.entryPoint,
      actionGate: fixture.actionGate,
      ownerAddress: current.ownerAddress,
      recoveryAddress: record.metadata.publicRecoveryAddress
    });
    const bound = await bindRecoveryAuthority(recoveryEnv, record, accountAddress);
    const request = recoveryCandidate({
      action: "request_recovery",
      accountAddress,
      recoveryAuthority: bound.metadata.publicRecoveryAddress,
      currentOwner: current.ownerAddress,
      pendingOwner: ethers.Wallet.createRandom().address
    });
    const signed = await signRecoveryUserOperation({
      env: recoveryEnv,
      recoveryRecord: bound,
      candidate: request,
      entryPoint: fixture.entryPoint
    });
    const executeSession = await createPhilCoreRecoveryAuthoritySigningSession({
      requestId: "n5-execute-reject-session",
      lifecycleSnapshot: recoveryEnv.lifecycleSnapshot,
      unlockedVaultHandle: recoveryEnv.unlockedVaultHandle,
      storageBackend: recoveryEnv.storageBackend,
      keyProvider: recoveryEnv.keyProvider,
      recoveryRecord: bound,
      draft: signed.draft,
      presentationDigest: signed.presentationDigest,
      expiresAt: futureDate()
    });
    assert.equal(executeSession.status, "approved", executeSession.error?.details?.errors?.join("\n"));
    const rejectedExecute = await executeSession.value.signingSession.signRecoveryUserOperationHash({
      userOperationHash: signed.draft.userOperationHash,
      presentationDigest: signed.presentationDigest,
      expectedRecoveryAuthority: bound.metadata.publicRecoveryAddress,
      entryPointAddress: signed.draft.entryPointAddress,
      accountAddress,
      chainId: 31337,
      nonce: signed.draft.nonce,
      callDataHash: signed.draft.callDataHash,
      maintenanceSelector: PHILCORE_4337_EXECUTE_SELECTOR_FORBIDDEN_TO_RECOVERY,
      auditCorrelationId: "n5-execute-reject"
    });
    assert.equal(rejectedExecute.status, "rejected");

    const cancelCandidate = recoveryCandidate({
      action: "cancel_recovery",
      accountAddress,
      recoveryAuthority: bound.metadata.publicRecoveryAddress,
      currentOwner: current.ownerAddress,
      recoveryRequestId: ethers.ZeroHash
    });
    const cancelDraft = preparePhilCoreRecoveryUserOperation({
      requestId: "n5-cancel-reject",
      candidate: cancelCandidate,
      entryPointAddress: await fixture.entryPoint.getAddress(),
      nonce: 0,
      chainId: 31337,
      expiresAt: futureDate()
    });
    assert.equal(cancelDraft.status, "denied");
  });

  it("performs complete local lost-key recovery through EntryPoint and coordinates Device Vault state", async function () {
    const currentEnv = custodyEnv("current");
    const current = await generateExecutionValidator(currentEnv, "current");
    const pendingEnv = custodyEnv("pending");
    const pending = await generateExecutionValidator(pendingEnv, "pending");
    const recoveryEnv = custodyEnv("recovery");
    const recoveryRecord = await generateRecoveryAuthority(recoveryEnv, current.ownerAddress);
    const fixture = await baseFixture();
    const deployed = await deployAccountWithRecovery({
      entryPoint: fixture.entryPoint,
      actionGate: fixture.actionGate,
      ownerAddress: current.ownerAddress,
      recoveryAddress: recoveryRecord.metadata.publicRecoveryAddress
    });
    const boundRecovery = await bindRecoveryAuthority(recoveryEnv, recoveryRecord, deployed.accountAddress);

    const requestCandidate = recoveryCandidate({
      action: "request_recovery",
      accountAddress: deployed.accountAddress,
      recoveryAuthority: boundRecovery.metadata.publicRecoveryAddress,
      currentOwner: current.ownerAddress,
      pendingOwner: pending.ownerAddress
    });
    const signedRequest = await signRecoveryUserOperation({
      env: recoveryEnv,
      recoveryRecord: boundRecovery,
      candidate: requestCandidate,
      entryPoint: fixture.entryPoint,
      approvalId: "n5-request-approval"
    });
    await (await handleOp(fixture.entryPoint, fixture.beneficiary, signedRequest)).wait();
    let pendingRequest = await deployed.account.recoveryRequest();
    assert.equal(pendingRequest.active, true);
    assert.equal(pendingRequest.pendingOwner, pending.ownerAddress);
    assert.equal(await deployed.account.frozen(), true);
    assert.equal(await deployed.account.owner(), current.ownerAddress);
    assert.equal(await deployed.account.ownerCommitment(), OWNER_COMMITMENT);
    assert.equal(await deployed.account.approvedActionGate(), await fixture.actionGate.getAddress());
    assert.equal(await deployed.account.entryPoint(), await fixture.entryPoint.getAddress());

    await increase(61);
    const completeCandidate = recoveryCandidate({
      action: "complete_recovery",
      accountAddress: deployed.accountAddress,
      recoveryAuthority: boundRecovery.metadata.publicRecoveryAddress,
      currentOwner: current.ownerAddress,
      pendingOwner: pending.ownerAddress,
      recoveryRequestId: pendingRequest.requestId
    });
    const signedComplete = await signRecoveryUserOperation({
      env: recoveryEnv,
      recoveryRecord: boundRecovery,
      candidate: completeCandidate,
      entryPoint: fixture.entryPoint,
      approvalId: "n5-complete-approval"
    });
    await (await handleOp(fixture.entryPoint, fixture.beneficiary, signedComplete)).wait();
    pendingRequest = await deployed.account.recoveryRequest();
    assert.equal(pendingRequest.active, false);
    assert.equal(await deployed.account.frozen(), false);
    assert.equal(await deployed.account.owner(), pending.ownerAddress);
    assert.equal(await deployed.account.ownerCommitment(), OWNER_COMMITMENT);
    assert.equal(await deployed.account.approvedActionGate(), await fixture.actionGate.getAddress());
    assert.equal(await deployed.account.entryPoint(), await fixture.entryPoint.getAddress());

    const revoked = await revokeDeviceVaultEcdsaValidator({
      storageBackend: currentEnv.storageBackend,
      keyProvider: currentEnv.keyProvider,
      keyReference: current.keyReference
    });
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.onChainOwnerChanged, false);
    assert.equal(signedComplete.publicUserOperationSubmitted, false);
    assert.equal(signedComplete.privateKeyExposed, false);
  });

  it("keeps cancellation current-owner controlled and rejects recovery authority cancellation", async function () {
    const [owner, newOwner, recovery] = await ethers.getSigners();
    const fixture = await baseFixture();
    const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
    const factory = await AccountFactory.deploy(
      await fixture.entryPoint.getAddress(),
      await fixture.actionGate.getAddress(),
      recovery.address,
      60,
      3600
    );
    const predicted = await factory.getFunction("getAddress").staticCall(owner.address, OWNER_COMMITMENT, 2n);
    await (await factory.createAccount(owner.address, OWNER_COMMITMENT, 2n)).wait();
    const account = await ethers.getContractAt("PhilCore4337Account", predicted);
    await (await account.connect(recovery).requestRecovery(newOwner.address)).wait();
    const pending = await account.recoveryRequest();
    await assert.rejects(account.connect(recovery).cancelRecovery(pending.requestId), /UnauthorizedMaintenanceCaller/);
    await (await account.connect(owner).cancelRecovery(pending.requestId)).wait();
    assert.equal(await account.frozen(), false);
  });
});
