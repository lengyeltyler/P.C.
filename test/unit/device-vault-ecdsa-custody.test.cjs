const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseExecutionDraftFixture,
  createDeviceVaultEcdsaSigningSession,
  createDeviceVaultEcdsaProtectedSigningSession,
  createDeviceVaultEcdsaValidatorSigner,
  bindDeviceVaultEcdsaValidatorAccountReference,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337PrefundReader,
  createPhilCore4337LocalFoundationConfiguration,
  createPhilCore4337SigningApprovalArtifact,
  createPhilCore4337SigningPresentation,
  createUserSessionLifecycleSnapshot,
  generateDeviceVaultEcdsaValidator,
  markDeviceVaultEcdsaValidatorPendingRotation,
  preparePhilCore4337UserOperation,
  revokeDeviceVaultEcdsaValidator,
  signPhilCore4337UserOperation
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const {
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");

const OWNER_COMMITMENT = ethers.id("philcore-n3-owner-commitment");
const PROOF_INPUT_HASH = ethers.id("philcore-n3-proof-input");
const NULLIFIER = ethers.id("philcore-n3-nullifier");

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function lifecycle(state = "unlocked", sessionId = "n3-session") {
  return createUserSessionLifecycleSnapshot({
    sessionId,
    state,
    metadata: {
      deviceVaultUnlocked: state === "unlocked",
      protectedStateAvailable: state === "unlocked"
    }
  });
}

function vaultHandle(snapshot = lifecycle()) {
  return {
    handleId: `vault-handle:${snapshot.sessionId}`,
    sessionId: snapshot.sessionId,
    ownerCommitment: OWNER_COMMITMENT,
    envelopeId: "n3-vault-envelope",
    unlockResultId: "n3-vault-unlock",
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

function custodyEnv(state = "unlocked") {
  const snapshot = lifecycle(state);
  return {
    lifecycleSnapshot: snapshot,
    unlockedVaultHandle: vaultHandle(snapshot),
    storageBackend: createInMemoryDeviceIdentityRegistryStorageBackend(),
    keyProvider: createLocalDevPassphraseKeyProvider({
      passphrase: "local-alpha-n3-test-passphrase",
      scrypt: { N: 1024, r: 8, p: 1, keyLength: 32 }
    })
  };
}

async function generateValidator(env = custodyEnv(), overrides = {}) {
  const result = await generateDeviceVaultEcdsaValidator({
    requestId: overrides.requestId ?? `n3-generate-${Math.random()}`,
    lifecycleSnapshot: env.lifecycleSnapshot,
    unlockedVaultHandle: overrides.unlockedVaultHandle ?? env.unlockedVaultHandle,
    storageBackend: env.storageBackend,
    keyProvider: env.keyProvider,
    ownerCommitment: overrides.ownerCommitment ?? OWNER_COMMITMENT,
    purpose: "erc4337_owner_validator_local_alpha",
    chainId: overrides.chainId,
    accountAddress: overrides.accountAddress,
    expiresAt: overrides.expiresAt ?? futureDate(),
    metadata: overrides.metadata
  });
  return result;
}

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  return new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
}

async function local4337Env() {
  const [deployer, beneficiary, recovery] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const actionGate = await ActionGate.deploy(ethers.ZeroAddress);
  const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
  const accountFactory = await AccountFactory.deploy(await entryPoint.getAddress(), await actionGate.getAddress(), recovery.address, 60, 3600);
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  return { deployer, beneficiary, entryPoint, actionGate, accountFactory, chainId };
}

async function createAccount(accountFactory, ownerAddress, salt = 1n) {
  const predicted = await accountFactory
    .getFunction("getAddress")
    .staticCall(ownerAddress, OWNER_COMMITMENT, salt);
  await (await accountFactory.createAccount(ownerAddress, OWNER_COMMITMENT, salt)).wait();
  const account = await ethers.getContractAt("PhilCore4337Account", predicted);
  return { account, predicted };
}

function baseDraftFor({ actionGateAddress, senderAccount, chainId }) {
  return createBaseExecutionDraftFixture({
    actionGateAddress,
    senderAccount,
    ownerCommitment: OWNER_COMMITMENT,
    proofInputHash: PROOF_INPUT_HASH,
    nullifier: NULLIFIER,
    chainId,
    calldata: `${BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR}01`
  });
}

function accountStateReader(account) {
  return {
    async readAccountState(request) {
      const code = await ethers.provider.getCode(request.accountAddress);
      return {
        accountAddress: request.accountAddress,
        chainId: request.expectedChainId,
        codeExists: code !== "0x",
        codeHash: ethers.keccak256(code),
        entryPoint: await account.entryPoint(),
        owner: await account.owner(),
        ownerCommitment: await account.ownerCommitment(),
        approvedActionGate: await account.approvedActionGate(),
        checkedAt: new Date().toISOString()
      };
    }
  };
}

function nonceReader(entryPoint) {
  return {
    async readNonce(request) {
      return {
        status: "resolved",
        nonce: (await entryPoint.getNonce(request.accountAddress, 0)).toString(),
        nonceKey: request.nonceKey,
        source: "entrypoint_get_nonce",
        checkedAt: new Date().toISOString()
      };
    }
  };
}

function runtimeAuthority() {
  return {
    capabilityGrantStatus: "active",
    sessionStatus: "eligible",
    platformApprovalStatus: "valid",
    baseExecutionApprovalStatus: "valid",
    finalizedPackageStatus: "valid",
    mirroredFactStatus: "present",
    nullifierStatus: "available"
  };
}

function signingRequest(env, signer) {
  const presentation = createPhilCore4337SigningPresentation(env.draft);
  const approval = createPhilCore4337SigningApprovalArtifact({
    approvalId: "n3-approval",
    presentationDigest: presentation.presentationDigest,
    source: "developer_fixture",
    approved: true,
    approvedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    oneTime: true,
    publicNetworkAllowed: false
  });
  return {
    requestId: "n3-m10-signing",
    draft: env.draft,
    foundation: env.foundation,
    runtimeAuthority: runtimeAuthority(),
    approval,
    signer,
    nonceReader: nonceReader(env.entryPoint),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    accountStateReader: accountStateReader(env.account),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "n3-m10-signing-audit"
  };
}

describe("Device Vault ECDSA validator custody", function () {
  it("creates one-time Sepolia purpose-bound sessions from protected vault authority", async function () {
    const wallet = ethers.Wallet.createRandom();
    const userOperationHash = ethers.id("o21-2-user-operation");
    const signingDigest = ethers.id("o21-2-signing-digest");
    const presentationDigest = ethers.id("o21-2-presentation");
    const callDataHash = ethers.id("o21-2-calldata");
    const sessionResult = await createDeviceVaultEcdsaProtectedSigningSession({
      requestId: "o21-2-protected-session",
      identityUnlocked: true,
      activeSession: true,
      recentUserPresence: true,
      currentApproval: true,
      keyReferenceId: "o21-2-validator-key",
      recordId: "o21-2-validator-record",
      ownerCommitment: OWNER_COMMITMENT,
      ownerAddress: wallet.address,
      sessionId: "o21-2-session",
      vaultHandleId: "o21-2-vault-handle",
      smartAccountAddress: ethers.Wallet.createRandom().address,
      entryPointAddress: ethers.Wallet.createRandom().address,
      chainId: 11155111,
      userOperationHash,
      signingDigest,
      presentationDigest,
      callDataHash,
      signingPurpose: "ethereum_sepolia_local_proof_gated_v1_signing",
      expiresAt: futureDate(),
      checkAuthorityAvailable: () => true,
      signBoundDigest: (digest) => wallet.signMessage(ethers.getBytes(digest))
    });
    assert.equal(sessionResult.status, "approved");
    assert.equal(
      sessionResult.value.snapshot.binding.purpose,
      "ethereum_sepolia_local_proof_gated_v1_signing"
    );
    const request = {
      userOperationHash,
      signingDigest,
      presentationDigest,
      expectedOwner: wallet.address,
      chainId: 11155111,
      entryPointAddress:
        sessionResult.value.snapshot.binding.entryPointAddress,
      smartAccountAddress:
        sessionResult.value.snapshot.binding.smartAccountAddress,
      nonce: "0",
      callDataHash,
      auditCorrelationId: "o21-2-audit"
    };
    const signed = await sessionResult.value.signingSession
      .signUserOperationHash(request);
    assert.equal(signed.status, "signed");
    const replay = await sessionResult.value.signingSession
      .signUserOperationHash(request);
    assert.equal(replay.status, "rejected");

    const wrongChain = await createDeviceVaultEcdsaProtectedSigningSession({
      requestId: "o21-2-wrong-chain",
      identityUnlocked: true,
      activeSession: true,
      recentUserPresence: true,
      currentApproval: true,
      keyReferenceId: "o21-2-validator-key",
      recordId: "o21-2-validator-record",
      ownerCommitment: OWNER_COMMITMENT,
      ownerAddress: wallet.address,
      sessionId: "o21-2-session",
      vaultHandleId: "o21-2-vault-handle",
      smartAccountAddress: ethers.Wallet.createRandom().address,
      entryPointAddress: ethers.Wallet.createRandom().address,
      chainId: 1,
      userOperationHash,
      signingDigest,
      presentationDigest,
      callDataHash,
      signingPurpose: "ethereum_sepolia_local_proof_gated_v1_signing",
      expiresAt: futureDate(),
      checkAuthorityAvailable: () => true,
      signBoundDigest: (digest) => wallet.signMessage(ethers.getBytes(digest))
    });
    assert.equal(wrongChain.status, "denied");

    for (const [label, override] of [
      ["locked identity", { identityUnlocked: false }],
      ["missing presence", { recentUserPresence: false }],
      ["missing approval", { currentApproval: false }]
    ]) {
      const rejected = await createDeviceVaultEcdsaProtectedSigningSession({
        requestId: `o21-2-${label.replaceAll(" ", "-")}`,
        identityUnlocked: true,
        activeSession: true,
        recentUserPresence: true,
        currentApproval: true,
        keyReferenceId: "o21-2-validator-key",
        recordId: "o21-2-validator-record",
        ownerCommitment: OWNER_COMMITMENT,
        ownerAddress: wallet.address,
        sessionId: "o21-2-session",
        vaultHandleId: "o21-2-vault-handle",
        smartAccountAddress: ethers.Wallet.createRandom().address,
        entryPointAddress: ethers.Wallet.createRandom().address,
        chainId: 11155111,
        userOperationHash,
        signingDigest,
        presentationDigest,
        callDataHash,
        signingPurpose: "ethereum_sepolia_local_proof_gated_v1_signing",
        expiresAt: futureDate(),
        checkAuthorityAvailable: () => true,
        signBoundDigest: (digest) => wallet.signMessage(ethers.getBytes(digest)),
        ...override
      });
      assert.equal(rejected.status, "denied", label);
    }
  });

  it("generates distinct encrypted validator records without returning private keys", async function () {
    const env = custodyEnv();
    const first = await generateValidator(env);
    const second = await generateValidator(env);
    assert.equal(first.status, "approved");
    assert.equal(second.status, "approved");
    assert.notEqual(first.value.ownerAddress, second.value.ownerAddress);
    assert.equal(first.value.privateKeyReturned, false);
    assert.equal(first.value.storedEncrypted, true);
    assert.equal(first.value.derivedFromPhilSecret, false);
    assert.equal(typeof first.value.record.ciphertext, "string");
    assert.equal(first.value.record.ciphertext.length > 0, true);
    const serialized = await env.storageBackend.read();
    assert.equal(/"privateKey"\s*:\s*"0x[0-9a-fA-F]{64}"/.test(serialized), false);
    assert.equal(/phil_secret|mnemonic|seedPhrase/.test(serialized), false);
  });

  it("rejects locked sessions, wrong vault handles, and secret-shaped metadata", async function () {
    const locked = custodyEnv("locked");
    const lockedResult = await generateValidator(locked);
    assert.equal(lockedResult.status, "denied");
    assert.match(lockedResult.error.code, /GENERATION_REJECTED/);

    const env = custodyEnv();
    const wrongVault = await generateValidator(env, {
      unlockedVaultHandle: {
        ...env.unlockedVaultHandle,
        ownerCommitment: ethers.id("wrong-owner")
      }
    });
    assert.equal(wrongVault.status, "denied");

    const secretMetadata = await generateValidator(env, {
      metadata: { privateKey: "never" }
    });
    assert.equal(secretMetadata.status, "denied");
  });

  it("rejects tampered storage and mismatched owner/account/chain bindings", async function () {
    const env = custodyEnv();
    const generated = await generateValidator(env, { chainId: 31337 });
    assert.equal(generated.status, "approved");
    const wrongOwner = await createDeviceVaultEcdsaSigningSession({
      requestId: "wrong-owner-session",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: generated.value.keyReference,
      ownerCommitment: ethers.id("wrong-owner"),
      smartAccountAddress: ethers.Wallet.createRandom().address,
      entryPointAddress: ethers.Wallet.createRandom().address,
      chainId: 31337,
      userOperationHash: ethers.id("uoh"),
      presentationDigest: ethers.id("presentation"),
      callDataHash: ethers.id("calldata"),
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: futureDate()
    });
    assert.equal(wrongOwner.status, "denied");

    const serialized = await env.storageBackend.read();
    await env.storageBackend.write(serialized.replace(/.$/, serialized.endsWith("}") ? "x" : "}"));
    const tampered = await createDeviceVaultEcdsaSigningSession({
      requestId: "tampered-session",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: generated.value.keyReference,
      ownerCommitment: OWNER_COMMITMENT,
      smartAccountAddress: ethers.Wallet.createRandom().address,
      entryPointAddress: ethers.Wallet.createRandom().address,
      chainId: 31337,
      userOperationHash: ethers.id("uoh"),
      presentationDigest: ethers.id("presentation"),
      callDataHash: ethers.id("calldata"),
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: futureDate()
    });
    assert.equal(tampered.status, "denied");
  });

  it("creates one-time exact-hash signing sessions and rejects arbitrary signing", async function () {
    const env = custodyEnv();
    const generated = await generateValidator(env);
    assert.equal(generated.status, "approved");
    const accountAddress = ethers.Wallet.createRandom().address;
    const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: generated.value.keyReference,
      accountAddress,
      chainId: 31337
    });
    assert.equal(bound.status, "account_reference_bound");
    const signingSession = await createDeviceVaultEcdsaSigningSession({
      requestId: "n3-signing-session",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: bound.record.keyReference,
      ownerCommitment: OWNER_COMMITMENT,
      smartAccountAddress: accountAddress,
      entryPointAddress: ethers.Wallet.createRandom().address,
      chainId: 31337,
      userOperationHash: ethers.id("uoh"),
      presentationDigest: ethers.id("presentation"),
      callDataHash: ethers.id("calldata"),
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: futureDate()
    });
    assert.equal(signingSession.status, "approved");
    assert.throws(() => JSON.stringify(signingSession.value.signingSession), /non-serializable/);
    const signer = createDeviceVaultEcdsaValidatorSigner(signingSession.value.signingSession);
    const rejected = await signer.signUserOperationHash({
      userOperationHash: ethers.id("wrong"),
      presentationDigest: ethers.id("presentation"),
      expectedOwner: generated.value.ownerAddress,
      chainId: 31337,
      entryPointAddress: signingSession.value.snapshot.binding.entryPointAddress,
      smartAccountAddress: accountAddress,
      nonce: "0",
      callDataHash: ethers.id("calldata"),
      auditCorrelationId: "n3-sign"
    });
    assert.equal(rejected.status, "rejected");

    const signed = await signer.signUserOperationHash({
      userOperationHash: ethers.id("uoh"),
      presentationDigest: ethers.id("presentation"),
      expectedOwner: generated.value.ownerAddress,
      chainId: 31337,
      entryPointAddress: signingSession.value.snapshot.binding.entryPointAddress,
      smartAccountAddress: accountAddress,
      nonce: "0",
      callDataHash: ethers.id("calldata"),
      auditCorrelationId: "n3-sign"
    });
    assert.equal(signed.status, "signed");
    const replay = await signer.signUserOperationHash({
      userOperationHash: ethers.id("uoh"),
      presentationDigest: ethers.id("presentation"),
      expectedOwner: generated.value.ownerAddress,
      chainId: 31337,
      entryPointAddress: signingSession.value.snapshot.binding.entryPointAddress,
      smartAccountAddress: accountAddress,
      nonce: "0",
      callDataHash: ethers.id("calldata"),
      auditCorrelationId: "n3-sign"
    });
    assert.equal(replay.status, "rejected");
  });

  it("signs a purpose-bound local-proof digest only when the canonical UserOperation hash also matches", async function () {
    const env = custodyEnv();
    const generated = await generateValidator(env);
    const accountAddress = ethers.Wallet.createRandom().address;
    const entryPointAddress = ethers.Wallet.createRandom().address;
    const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: generated.value.keyReference,
      accountAddress,
      chainId: 31337
    });
    const session = await createDeviceVaultEcdsaSigningSession({
      requestId: "n3-local-proof-purpose-bound-session",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: bound.record.keyReference,
      ownerCommitment: OWNER_COMMITMENT,
      smartAccountAddress: accountAddress,
      entryPointAddress,
      chainId: 31337,
      userOperationHash: ethers.id("canonical-user-operation"),
      signingDigest: ethers.id("local-proof-account-signature-digest"),
      presentationDigest: ethers.id("local-proof-presentation"),
      callDataHash: ethers.id("local-proof-calldata"),
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: futureDate()
    });
    assert.equal(session.status, "approved");
    const signer = createDeviceVaultEcdsaValidatorSigner(session.value.signingSession);
    const rejected = await signer.signUserOperationHash({
      userOperationHash: ethers.id("canonical-user-operation"),
      signingDigest: ethers.id("substituted-digest"),
      presentationDigest: ethers.id("local-proof-presentation"),
      expectedOwner: generated.value.ownerAddress,
      chainId: 31337,
      entryPointAddress,
      smartAccountAddress: accountAddress,
      nonce: "0",
      callDataHash: ethers.id("local-proof-calldata"),
      auditCorrelationId: "local-proof-purpose-bound"
    });
    assert.equal(rejected.status, "rejected");
    assert.ok(rejected.errors.includes("purpose-bound signing digest mismatch"));

    const signed = await signer.signUserOperationHash({
      userOperationHash: ethers.id("canonical-user-operation"),
      signingDigest: ethers.id("local-proof-account-signature-digest"),
      presentationDigest: ethers.id("local-proof-presentation"),
      expectedOwner: generated.value.ownerAddress,
      chainId: 31337,
      entryPointAddress,
      smartAccountAddress: accountAddress,
      nonce: "0",
      callDataHash: ethers.id("local-proof-calldata"),
      auditCorrelationId: "local-proof-purpose-bound"
    });
    assert.equal(signed.status, "signed");
    assert.equal(
      ethers.verifyMessage(
        ethers.getBytes(ethers.id("local-proof-account-signature-digest")),
        signed.signature
      ),
      generated.value.ownerAddress
    );
  });

  it("rejects a previously created signing session after local validator revocation", async function () {
    const env = custodyEnv();
    const generated = await generateValidator(env);
    assert.equal(generated.status, "approved");
    const accountAddress = ethers.Wallet.createRandom().address;
    const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: generated.value.keyReference,
      accountAddress,
      chainId: 31337
    });
    const session = await createDeviceVaultEcdsaSigningSession({
      requestId: "n3-revoke-session",
      lifecycleSnapshot: env.lifecycleSnapshot,
      unlockedVaultHandle: env.unlockedVaultHandle,
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: bound.record.keyReference,
      ownerCommitment: OWNER_COMMITMENT,
      smartAccountAddress: accountAddress,
      entryPointAddress: ethers.Wallet.createRandom().address,
      chainId: 31337,
      userOperationHash: ethers.id("uoh-revoked"),
      presentationDigest: ethers.id("presentation-revoked"),
      callDataHash: ethers.id("calldata-revoked"),
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: futureDate()
    });
    assert.equal(session.status, "approved");
    const signer = createDeviceVaultEcdsaValidatorSigner(session.value.signingSession);
    const revoked = await revokeDeviceVaultEcdsaValidator({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: bound.record.keyReference
    });
    assert.equal(revoked.status, "revoked");
    const signed = await signer.signUserOperationHash({
      userOperationHash: ethers.id("uoh-revoked"),
      presentationDigest: ethers.id("presentation-revoked"),
      expectedOwner: generated.value.ownerAddress,
      chainId: 31337,
      entryPointAddress: session.value.snapshot.binding.entryPointAddress,
      smartAccountAddress: accountAddress,
      nonce: "0",
      callDataHash: ethers.id("calldata-revoked"),
      auditCorrelationId: "n3-revoked-sign"
    });
    assert.equal(signed.status, "rejected");
    assert.match(signed.errors.join(" "), /revoked/);
  });

  it("signs an M.10 UserOperation hash through Device Vault custody and then invalidates the session", async function () {
    const custody = custodyEnv();
    const generated = await generateValidator(custody);
    assert.equal(generated.status, "approved");

    const env = await local4337Env();
    const { account, predicted } = await createAccount(env.accountFactory, generated.value.ownerAddress);
    const bound = await bindDeviceVaultEcdsaValidatorAccountReference({
      storageBackend: custody.storageBackend,
      keyProvider: custody.keyProvider,
      keyReference: generated.value.keyReference,
      accountAddress: predicted,
      chainId: env.chainId
    });
    assert.equal(bound.status, "account_reference_bound");
    const foundation = createPhilCore4337LocalFoundationConfiguration({
      chainId: env.chainId,
      entryPointAddress: await env.entryPoint.getAddress(),
      factoryAddress: await env.accountFactory.getAddress(),
      approvedActionGateAddress: await env.actionGate.getAddress(),
      owner: generated.value.ownerAddress,
      ownerCommitment: OWNER_COMMITMENT
    });
    const prep = await preparePhilCore4337UserOperation({
      requestId: "n3-prepare",
      baseExecutionDraft: baseDraftFor({
        actionGateAddress: await env.actionGate.getAddress(),
        senderAccount: predicted,
        chainId: env.chainId
      }),
      foundation,
      accountMode: "deployed",
      accountAddress: predicted,
      accountStateReader: accountStateReader(account),
      nonceReader: nonceReader(env.entryPoint),
      gasEstimator: createFixturePhilCore4337GasEstimator(),
      prefundReader: createFixturePhilCore4337PrefundReader(),
      issuedAt: new Date().toISOString(),
      expiresAt: futureDate(),
      auditCorrelationId: "n3-prepare-audit"
    });
    assert.equal(prep.status, "approved");
    const presentation = createPhilCore4337SigningPresentation(prep.value);
    const session = await createDeviceVaultEcdsaSigningSession({
      requestId: "n3-m10-device-vault-session",
      lifecycleSnapshot: custody.lifecycleSnapshot,
      unlockedVaultHandle: custody.unlockedVaultHandle,
      storageBackend: custody.storageBackend,
      keyProvider: custody.keyProvider,
      keyReference: bound.record.keyReference,
      ownerCommitment: OWNER_COMMITMENT,
      smartAccountAddress: predicted,
      entryPointAddress: await env.entryPoint.getAddress(),
      chainId: env.chainId,
      userOperationHash: prep.value.binding.userOperationHash,
      presentationDigest: presentation.presentationDigest,
      callDataHash: ethers.keccak256(prep.value.userOperation.callData),
      purpose: "erc4337_owner_validator_local_alpha",
      expiresAt: futureDate()
    });
    assert.equal(session.status, "approved");
    const signer = createDeviceVaultEcdsaValidatorSigner(session.value.signingSession);
    const signed = await signPhilCore4337UserOperation(signingRequest({
      ...env,
      account,
      draft: prep.value,
      foundation
    }, signer));
    assert.equal(signed.status, "approved");
    assert.equal(signed.value.signatureArtifact.recoveredOwner, generated.value.ownerAddress);
    assert.equal(signed.value.limitations.includes("device_vault_custody_not_implemented"), false);
    await env.deployer.sendTransaction({ to: predicted, value: ethers.parseEther("1") });
    await (await env.entryPoint.handleOps([signed.value.userOperation], env.beneficiary.address, { gasLimit: 6_000_000 })).wait();

    const replay = await signPhilCore4337UserOperation(signingRequest({
      ...env,
      account,
      draft: prep.value,
      foundation
    }, signer));
    assert.equal(replay.status, "denied");
  });

  it("marks local rotation as incomplete without on-chain owner rotation and revokes future signing", async function () {
    const env = custodyEnv();
    const generated = await generateValidator(env);
    assert.equal(generated.status, "approved");
    const rotation = await markDeviceVaultEcdsaValidatorPendingRotation({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: generated.value.keyReference
    });
    assert.equal(rotation.status, "rotation_marked_pending");
    assert.equal(rotation.onChainOwnerChanged, false);
    assert.equal(rotation.futureAccountOwnerRotationRequired, true);

    const revoked = await revokeDeviceVaultEcdsaValidator({
      storageBackend: env.storageBackend,
      keyProvider: env.keyProvider,
      keyReference: rotation.oldRecord.keyReference
    });
    assert.equal(revoked.status, "revoked");
    assert.equal(revoked.onChainOwnerChanged, false);
  });

  it("runs non-mutating custody diagnostics", function () {
    const diagnose = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-device-vault-ecdsa-custody-diagnostic.cjs",
      "--json"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(diagnose.status, 0, diagnose.stderr);
    const parsed = JSON.parse(diagnose.stdout);
    assert.equal(parsed.validatorGenerated, true);
    assert.equal(parsed.storedEncrypted, true);
    assert.equal(parsed.privateKeyReturned, false);
    assert.equal(parsed.transactionSubmitted, false);

    const inspect = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-device-vault-ecdsa-custody-diagnostic.cjs",
      "--inspect"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(inspect.status, 0, inspect.stderr);
    assert.match(inspect.stdout, /Device Vault ECDSA validator custody diagnostic/);
    assert.match(inspect.stdout, /private key not returned/);
  });
});
