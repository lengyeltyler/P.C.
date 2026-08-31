const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  PHILCORE_4337_EMPTY_BYTES,
  createBaseExecutionDraftFixture,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337PrefundReader,
  createInMemoryAuditDraftCollector,
  createInMemoryPhilCore4337SigningApprovalStore,
  createInMemorySignedPhilCore4337UserOperationStore,
  createPhilCore4337LocalFoundationConfiguration,
  createPhilCore4337SigningApprovalArtifact,
  createPhilCore4337SigningPresentation,
  createFixturePhilCore4337AccountStateReader,
  inspectSignedPhilCore4337UserOperation,
  preparePhilCore4337UserOperation,
  requestPhilCore4337SigningAuthorization,
  signPhilCore4337UserOperation,
  validatePhilCore4337SignatureArtifact,
  verifyPhilCore4337SignerBinding
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const OWNER_COMMITMENT = ethers.id("philcore-m10-owner-commitment");
const PROOF_INPUT_HASH = ethers.id("philcore-m10-proof-input");
const NULLIFIER = ethers.id("philcore-m10-nullifier");
const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  return new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
}

async function fixture() {
  const [deployer, owner, other, beneficiary, harmlessTarget, recovery] = await ethers.getSigners();
  const entryPoint = await deployEntryPoint();
  const ActionGate = await ethers.getContractFactory("PhilBaseActionGate");
  const actionGate = await ActionGate.deploy(ethers.ZeroAddress);
  const AccountFactory = await ethers.getContractFactory("PhilCore4337AccountFactory");
  const accountFactory = await AccountFactory.deploy(await entryPoint.getAddress(), await actionGate.getAddress(), recovery.address, 60, 3600);
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const foundation = createPhilCore4337LocalFoundationConfiguration({
    chainId,
    entryPointAddress: await entryPoint.getAddress(),
    factoryAddress: await accountFactory.getAddress(),
    approvedActionGateAddress: await actionGate.getAddress(),
    owner: owner.address,
    ownerCommitment: OWNER_COMMITMENT
  });
  return { deployer, owner, other, beneficiary, harmlessTarget, actionGate, entryPoint, accountFactory, chainId, foundation };
}

async function createAccount({ accountFactory, owner, salt = 1n }) {
  const predicted = await accountFactory
    .getFunction("getAddress")
    .staticCall(owner.address, OWNER_COMMITMENT, salt);
  await (await accountFactory.createAccount(owner.address, OWNER_COMMITMENT, salt)).wait();
  const account = await ethers.getContractAt("PhilCore4337Account", predicted);
  return { account, predicted };
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

function runtimeAuthority(overrides = {}) {
  return {
    capabilityGrantStatus: "active",
    sessionStatus: "eligible",
    platformApprovalStatus: "valid",
    baseExecutionApprovalStatus: "valid",
    finalizedPackageStatus: "valid",
    mirroredFactStatus: "present",
    nullifierStatus: "available",
    ...overrides
  };
}

function baseDraftFor({ actionGateAddress, senderAccount, chainId, calldataSuffix = "01" }) {
  return createBaseExecutionDraftFixture({
    actionGateAddress,
    senderAccount,
    ownerCommitment: OWNER_COMMITMENT,
    proofInputHash: PROOF_INPUT_HASH,
    nullifier: NULLIFIER,
    chainId,
    calldata: `${BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR}${calldataSuffix}`
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

function nonceReader(entryPoint, overrideNonce) {
  return {
    async readNonce(request) {
      return {
        status: "resolved",
        nonce: overrideNonce ?? (await entryPoint.getNonce(request.accountAddress, 0)).toString(),
        nonceKey: request.nonceKey,
        source: "entrypoint_get_nonce",
        checkedAt: new Date().toISOString()
      };
    }
  };
}

function counterfactualResolver(accountFactory) {
  return {
    async resolveCounterfactualAccount(request) {
      const predictedAddress = await accountFactory
        .getFunction("getAddress")
        .staticCall(request.owner, request.ownerCommitment, BigInt(request.salt));
      const createAccountCalldata = accountFactory.interface.encodeFunctionData("createAccount", [
        request.owner,
        request.ownerCommitment,
        BigInt(request.salt)
      ]);
      return {
        outcome: "counterfactual_resolved",
        binding: {
          factoryAddress: request.factoryAddress,
          owner: request.owner,
          ownerCommitment: request.ownerCommitment,
          salt: BigInt(request.salt).toString(),
          predictedAddress,
          chainId: request.expectedChainId,
          factoryData: {
            factoryAddress: request.factoryAddress,
            createAccountCalldata,
            initCode: ethers.concat([request.factoryAddress, createAccountCalldata]),
            createAccountSelector: accountFactory.interface.getFunction("createAccount").selector
          },
          accountDeploymentPerformed: false
        },
        errors: []
      };
    }
  };
}

function validatorSigner(signer, { mode = "developer_fixture", available = true } = {}) {
  const descriptor = {
    signerId: `fixture-signer:${signer.address}`,
    mode,
    ownerAddress: signer.address,
    keyReference: {
      keyReferenceId: `fixture-key:${signer.address}`,
      mode,
      custody: mode === "developer_fixture" ? "developer_fixture" : "external",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    },
    available,
    productionApproved: false,
    arbitraryMessageSigning: false,
    arbitraryTransactionSigning: false
  };
  return {
    async describeSigner() {
      return descriptor;
    },
    async checkAvailability() {
      return descriptor;
    },
    async getOwnerAddress() {
      return signer.address;
    },
    async signUserOperationHash(request) {
      if (!available) {
        return {
          status: "signer_unavailable",
          signerDescriptor: descriptor,
          signedAt: new Date().toISOString(),
          errors: ["signer unavailable"]
        };
      }
      if (request.expectedOwner.toLowerCase() !== signer.address.toLowerCase()) {
        return {
          status: "rejected",
          signerDescriptor: descriptor,
          signedAt: new Date().toISOString(),
          errors: ["expected owner mismatch"]
        };
      }
      return {
        status: "signed",
        signature: await signer.signMessage(ethers.getBytes(request.userOperationHash)),
        signerDescriptor: descriptor,
        signedAt: new Date().toISOString()
      };
    }
  };
}

async function prepareDeployed() {
  const env = await fixture();
  const { account } = await createAccount({ accountFactory: env.accountFactory, owner: env.owner });
  const accountAddress = await account.getAddress();
  const baseExecutionDraft = baseDraftFor({
    actionGateAddress: await env.actionGate.getAddress(),
    senderAccount: accountAddress,
    chainId: env.chainId
  });
  const result = await preparePhilCore4337UserOperation({
    requestId: "m10-prepare",
    baseExecutionDraft,
    foundation: env.foundation,
    accountMode: "deployed",
    accountAddress,
    accountStateReader: accountStateReader(account),
    nonceReader: nonceReader(env.entryPoint),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "m10-prepare-audit"
  });
  assert.equal(result.status, "approved");
  return { ...env, account, accountAddress, baseExecutionDraft, draft: result.value };
}

async function prepareCounterfactual() {
  const env = await fixture();
  const salt = 42n;
  const predicted = await env.accountFactory
    .getFunction("getAddress")
    .staticCall(env.owner.address, OWNER_COMMITMENT, salt);
  const result = await preparePhilCore4337UserOperation({
    requestId: "m10-counterfactual-prepare",
    baseExecutionDraft: baseDraftFor({
      actionGateAddress: await env.actionGate.getAddress(),
      senderAccount: predicted,
      chainId: env.chainId
    }),
    foundation: env.foundation,
    accountMode: "counterfactual",
    counterfactual: {
      factoryAddress: await env.accountFactory.getAddress(),
      owner: env.owner.address,
      ownerCommitment: OWNER_COMMITMENT,
      salt,
      expectedChainId: env.chainId,
      predictedAddress: predicted
    },
    counterfactualResolver: counterfactualResolver(env.accountFactory),
    nonceReader: nonceReader(env.entryPoint, "0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "m10-counterfactual-prepare-audit"
  });
  assert.equal(result.status, "approved");
  return { ...env, predicted, draft: result.value };
}

function signingRequest(env, overrides = {}) {
  const presentation = createPhilCore4337SigningPresentation(env.draft);
  const approval = createPhilCore4337SigningApprovalArtifact({
    approvalId: overrides.approvalId ?? "m10-approval",
    presentationDigest: overrides.presentationDigest ?? presentation.presentationDigest,
    source: overrides.source ?? "developer_fixture",
    approved: overrides.approved ?? true,
    approvedAt: new Date().toISOString(),
    expiresAt: overrides.approvalExpiresAt ?? futureDate(),
    oneTime: true,
    publicNetworkAllowed: false,
    consumed: overrides.consumed
  });
  return {
    requestId: overrides.requestId ?? "m10-signing",
    draft: env.draft,
    foundation: overrides.foundation ?? env.foundation,
    runtimeAuthority: overrides.runtimeAuthority ?? runtimeAuthority(),
    approval,
    signer: overrides.signer ?? validatorSigner(env.owner),
    nonceReader: overrides.nonceReader ?? nonceReader(env.entryPoint),
    gasEstimator: overrides.gasEstimator ?? createFixturePhilCore4337GasEstimator(),
    prefundReader: overrides.prefundReader ?? createFixturePhilCore4337PrefundReader(),
    accountStateReader: overrides.accountStateReader ?? (env.account ? accountStateReader(env.account) : undefined),
    approvalStore: overrides.approvalStore,
    issuedAt: new Date().toISOString(),
    expiresAt: overrides.expiresAt ?? futureDate(),
    auditCorrelationId: overrides.auditCorrelationId ?? "m10-signing-audit",
    auditDraftCollector: overrides.auditDraftCollector,
    signedOperationStore: overrides.signedOperationStore
  };
}

describe("PhilCore ERC-4337 UserOperation signing boundary", function () {
  it("authorizes signing with an immutable presentation and one exact owner signer", async function () {
    const env = await prepareDeployed();
    const request = signingRequest(env);
    const authorization = await requestPhilCore4337SigningAuthorization(request);
    assert.equal(authorization.status, "approved");
    assert.equal(authorization.value.status, "signing_authorized");
    assert.equal(authorization.value.binding.userOperationHash, env.draft.binding.userOperationHash);
    assert.equal(authorization.value.signerDescriptor.ownerAddress, env.owner.address);
    assert.equal(authorization.value.presentation.paymasterDisabled, true);
    assert.equal(authorization.value.limitations.includes("acp_0002_proposed"), true);
  });

  it("signs a deployed-account UserOperation and keeps the artifact unsubmitted", async function () {
    const env = await prepareDeployed();
    const store = createInMemorySignedPhilCore4337UserOperationStore({ maxSignedOperationCount: 2 });
    const collector = createInMemoryAuditDraftCollector();
    const result = await signPhilCore4337UserOperation(signingRequest(env, {
      auditDraftCollector: collector,
      signedOperationStore: store
    }));
    assert.equal(result.status, "approved");
    const signed = result.value;
    assert.equal(signed.userOperation.signature !== PHILCORE_4337_EMPTY_BYTES, true);
    assert.equal(signed.userOperationSigned, true);
    assert.equal(signed.userOperationSubmitted, false);
    assert.equal(signed.bundlerSubmissionPerformed, false);
    assert.equal(signed.paymasterInvoked, false);
    assert.equal(signed.nullifierConsumed, false);
    assert.equal(signed.consumerExecuted, false);
    assert.equal(signed.baseStateMutated, false);
    assert.equal(signed.applicationCanSubmitDirectly, false);
    assert.equal(signed.signatureArtifact.recoveredOwner, env.owner.address);
    assert.equal(validatePhilCore4337SignatureArtifact(signed.signatureArtifact).valid, true);
    assert.equal(store.count(), 1);
    assert.equal(collector.count() >= 1, true);

    const inspection = inspectSignedPhilCore4337UserOperation(signed);
    assert.equal(inspection.signaturePresent, true);
    assert.equal(inspection.userOperationSubmitted, false);
  });

  it("passes the signed operation through actual local EntryPoint handleOps while Runtime exposes no submitter", async function () {
    const env = await prepareDeployed();
    await env.owner.sendTransaction({ to: env.accountAddress, value: ethers.parseEther("1") });
    const result = await signPhilCore4337UserOperation(signingRequest(env));
    assert.equal(result.status, "approved");
    await (await env.entryPoint.handleOps([result.value.userOperation], env.beneficiary.address, { gasLimit: 6_000_000 })).wait();
    assert.equal(result.value.userOperationSubmitted, false);
    assert.equal(result.value.bundlerSubmissionPerformed, false);
    assert.equal(result.value.nullifierConsumed, false);
  });

  it("signs a counterfactual UserOperation without deploying the account", async function () {
    const env = await prepareCounterfactual();
    assert.equal(await ethers.provider.getCode(env.predicted), "0x");
    const result = await signPhilCore4337UserOperation(signingRequest(env, {
      accountStateReader: undefined
    }));
    assert.equal(result.status, "approved");
    assert.equal(result.value.userOperation.sender, env.predicted);
    assert.equal(result.value.userOperation.initCode !== "0x", true);
    assert.equal(result.value.smartAccountDeploymentPerformed, false);
    assert.equal(await ethers.provider.getCode(env.predicted), "0x");
  });

  it("rejects ineligible runtime authority, consumed nullifiers, and expired packages", async function () {
    const env = await prepareDeployed();
    for (const [runtimeAuthorityOverride, expected] of [
      [{ capabilityGrantStatus: "revoked" }, /CAPABILITY_INELIGIBLE/],
      [{ sessionStatus: "locked" }, /SESSION_INELIGIBLE/],
      [{ finalizedPackageStatus: "expired" }, /PACKAGE_INELIGIBLE/],
      [{ mirroredFactStatus: "missing" }, /MIRRORED_FACT_INELIGIBLE/],
      [{ nullifierStatus: "consumed" }, /NULLIFIER_UNAVAILABLE/]
    ]) {
      const result = await signPhilCore4337UserOperation(signingRequest(env, {
        runtimeAuthority: runtimeAuthority(runtimeAuthorityOverride)
      }));
      assert.equal(result.status, "denied");
      assert.match(result.error.code, expected);
    }
  });

  it("rejects owner, ownerCommitment, EntryPoint, nonce, gas, fee, prefund, and presentation mutations", async function () {
    const env = await prepareDeployed();
    const wrongOwner = await signPhilCore4337UserOperation(signingRequest(env, {
      foundation: {
        ...env.foundation,
        validator: { ...env.foundation.validator, owner: env.other.address }
      }
    }));
    assert.equal(wrongOwner.status, "denied");
    assert.match(wrongOwner.error.code, /OWNER_MISMATCH/);

    const wrongCommitment = await signPhilCore4337UserOperation(signingRequest(env, {
      foundation: {
        ...env.foundation,
        validator: { ...env.foundation.validator, ownerCommitment: ethers.id("wrong") }
      }
    }));
    assert.equal(wrongCommitment.status, "denied");
    assert.match(wrongCommitment.error.code, /OWNER_COMMITMENT_MISMATCH/);

    const wrongEntryPoint = await signPhilCore4337UserOperation(signingRequest(env, {
      foundation: {
        ...env.foundation,
        entryPoint: { ...env.foundation.entryPoint, address: env.other.address }
      }
    }));
    assert.equal(wrongEntryPoint.status, "denied");
    assert.match(wrongEntryPoint.error.code, /ENTRY_POINT_MISMATCH/);

    const nonceChanged = await signPhilCore4337UserOperation(signingRequest(env, {
      nonceReader: nonceReader(env.entryPoint, "99")
    }));
    assert.equal(nonceChanged.status, "denied");
    assert.match(nonceChanged.error.code, /NONCE_CHANGED/);

    const gasChanged = await signPhilCore4337UserOperation(signingRequest(env, {
      gasEstimator: createFixturePhilCore4337GasEstimator({ callGasLimit: "1" })
    }));
    assert.equal(gasChanged.status, "denied");
    assert.match(gasChanged.error.code, /GAS_CHANGED/);

    const feeChanged = await signPhilCore4337UserOperation(signingRequest(env, {
      gasEstimator: createFixturePhilCore4337GasEstimator({ maxFeePerGas: "1" })
    }));
    assert.equal(feeChanged.status, "denied");
    assert.match(feeChanged.error.code, /FEE_CHANGED/);

    const prefund = await signPhilCore4337UserOperation(signingRequest(env, {
      prefundReader: createFixturePhilCore4337PrefundReader({
        status: "prefund_insufficient",
        requiredPrefund: "100",
        missingPrefund: "100"
      })
    }));
    assert.equal(prefund.status, "denied");
    assert.match(prefund.error.code, /PREFUND_INSUFFICIENT/);

    const presentationMismatch = await signPhilCore4337UserOperation(signingRequest(env, {
      presentationDigest: ethers.id("wrong-presentation")
    }));
    assert.equal(presentationMismatch.status, "denied");
    assert.match(presentationMismatch.error.code, /PRESENTATION_APPROVAL_REJECTED/);
  });

  it("rejects missing approval, approval replay, unavailable signer, wrong signer, and malformed signatures", async function () {
    const env = await prepareDeployed();
    const rejected = await signPhilCore4337UserOperation(signingRequest(env, { approved: false }));
    assert.equal(rejected.status, "denied");
    assert.match(rejected.error.code, /PRESENTATION_APPROVAL_REQUIRED/);

    const approvalStore = createInMemoryPhilCore4337SigningApprovalStore();
    const first = await signPhilCore4337UserOperation(signingRequest(env, { approvalStore, approvalId: "one-time" }));
    assert.equal(first.status, "approved");
    const replay = await signPhilCore4337UserOperation(signingRequest(env, { approvalStore, approvalId: "one-time" }));
    assert.equal(replay.status, "denied");
    assert.match(replay.error.code, /PRESENTATION_APPROVAL_REJECTED/);

    const unavailable = await signPhilCore4337UserOperation(signingRequest(env, {
      signer: validatorSigner(env.owner, { available: false })
    }));
    assert.equal(unavailable.status, "denied");
    assert.match(unavailable.error.code, /SIGNER_UNAVAILABLE/);

    const wrongSigner = await signPhilCore4337UserOperation(signingRequest(env, {
      signer: validatorSigner(env.other)
    }));
    assert.equal(wrongSigner.status, "denied");
    assert.match(wrongSigner.error.code, /OWNER_MISMATCH|SIGNING_REJECTED/);

    assert.throws(() => verifyPhilCore4337SignerBinding({
      signature: "0x1234",
      userOperationHash: env.draft.binding.userOperationHash,
      expectedOwner: env.owner.address
    }));
  });

  it("rejects mutated UserOperation hash, calldata, and factory data", async function () {
    const env = await prepareCounterfactual();
    const mutatedHash = {
      ...env.draft,
      binding: {
        ...env.draft.binding,
        userOperationHash: ethers.id("wrong-hash")
      }
    };
    const hashResult = await signPhilCore4337UserOperation(signingRequest({ ...env, draft: mutatedHash }, {
      accountStateReader: undefined
    }));
    assert.equal(hashResult.status, "denied");

    const mutatedCallData = {
      ...env.draft,
      userOperation: {
        ...env.draft.userOperation,
        callData: `${env.draft.userOperation.callData}00`
      }
    };
    const callDataResult = await signPhilCore4337UserOperation(signingRequest({ ...env, draft: mutatedCallData }, {
      accountStateReader: undefined
    }));
    assert.equal(callDataResult.status, "denied");

    const mutatedFactory = {
      ...env.draft,
      userOperation: {
        ...env.draft.userOperation,
        initCode: `${env.draft.userOperation.initCode}00`
      }
    };
    const factoryResult = await signPhilCore4337UserOperation(signingRequest({ ...env, draft: mutatedFactory }, {
      accountStateReader: undefined
    }));
    assert.equal(factoryResult.status, "denied");
  });

  it("blocks invalid local signatures through actual EntryPoint and preserves account security properties", async function () {
    const env = await prepareDeployed();
    await env.owner.sendTransaction({ to: env.accountAddress, value: ethers.parseEther("1") });
    const wrongSignature = await env.other.signMessage(ethers.getBytes(env.draft.binding.userOperationHash));
    const wrongUserOp = { ...env.draft.userOperation, signature: wrongSignature };
    await assert.rejects(
      env.entryPoint.handleOps([wrongUserOp], env.beneficiary.address, { gasLimit: 6_000_000 }),
      /AA24 signature error|unrecognized custom error/
    );

    const account = await ethers.getContractAt("PhilCore4337Account", env.accountAddress);
    await assert.rejects(
      account.connect(env.owner).execute(env.harmlessTarget.address, 0, env.draft.executionCall.innerCalldata),
      /UnauthorizedExecuteCaller/
    );
    await assert.rejects(
      env.accountFactory.createAccount(ethers.ZeroAddress, OWNER_COMMITMENT, 1n),
      /InvalidOwner/
    );
  });

  it("runs non-submitting M.10 diagnostics", function () {
    const diagnose = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-philcore-4337-user-operation-signing-diagnostic.cjs",
      "--json"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(diagnose.status, 0, diagnose.stderr);
    const parsed = JSON.parse(diagnose.stdout);
    assert.equal(parsed.entryPointVersion, "0.7");
    assert.equal(parsed.userOperationSigned, true);
    assert.equal(parsed.userOperationSubmitted, false);
    assert.equal(parsed.bundlerSubmissionPerformed, false);
    assert.equal(parsed.nullifierConsumed, false);

    const inspect = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-philcore-4337-user-operation-signing-diagnostic.cjs",
      "--inspect"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(inspect.status, 0, inspect.stderr);
    assert.match(inspect.stdout, /Signed PhilCore ERC-4337 UserOperation diagnostic/);
    assert.match(inspect.stdout, /not submitted/);
  });

  it("classifies high-s signatures as invalid when they can be represented", async function () {
    const env = await prepareDeployed();
    const valid = await env.owner.signMessage(ethers.getBytes(env.draft.binding.userOperationHash));
    const sig = ethers.Signature.from(valid);
    const highSValue = ethers.toBeHex(SECP256K1_N - BigInt(sig.s), 32);
    const v = ethers.toBeHex(sig.v === 27 ? 28 : 27, 1).slice(2);
    const highS = `0x${sig.r.slice(2)}${highSValue.slice(2)}${v}`;
    const artifact = verifyPhilCore4337SignerBinding({
      signature: highS,
      userOperationHash: env.draft.binding.userOperationHash,
      expectedOwner: env.owner.address
    });
    assert.equal(validatePhilCore4337SignatureArtifact(artifact).valid, false);
  });
});
