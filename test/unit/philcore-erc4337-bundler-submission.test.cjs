const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  PHILCORE_4337_EMPTY_BYTES,
  computePhilCore4337UserOperationHash,
  createBaseExecutionDraftFixture,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337PrefundReader,
  createInMemoryPhilCore4337SubmittedOperationStore,
  createInMemoryPhilCore4337SubmissionApprovalStore,
  createPhilCore4337LocalFixtureBundlerConfiguration,
  createPhilCore4337LocalFoundationConfiguration,
  createPhilCore4337SigningApprovalArtifact,
  createPhilCore4337SigningPresentation,
  createPhilCore4337SubmissionApprovalArtifact,
  inspectSubmittedPhilCore4337UserOperation,
  preparePhilCore4337UserOperation,
  requestPhilCore4337BundlerCapabilityCheck,
  requestPhilCore4337SubmissionAuthorization,
  requestPhilCore4337UserOperationReceiptMonitoring,
  requestPhilCore4337UserOperationSubmission,
  serializePhilCore4337UserOperationForBundler,
  signPhilCore4337UserOperation,
  validateBundlerUserOperationSerialization
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const OWNER_COMMITMENT = ethers.id("philcore-m11-owner-commitment");
const PROOF_INPUT_HASH = ethers.id("philcore-m11-proof-input");
const NULLIFIER = ethers.id("philcore-m11-nullifier");

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  return new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  ).deploy();
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
  const { account, accountAddress } = await createAccount({ accountFactory, owner });
  const baseExecutionDraft = createBaseExecutionDraftFixture({
    actionGateAddress: await actionGate.getAddress(),
    senderAccount: accountAddress,
    ownerCommitment: OWNER_COMMITMENT,
    proofInputHash: PROOF_INPUT_HASH,
    nullifier: NULLIFIER,
    chainId,
    calldata: `${BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR}01`
  });
  const draftResult = await preparePhilCore4337UserOperation({
    requestId: "m11-prepare",
    baseExecutionDraft,
    foundation,
    accountMode: "deployed",
    accountAddress,
    accountStateReader: accountStateReader(account),
    nonceReader: nonceReader(entryPoint),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "m11-prepare-audit"
  });
  assert.equal(draftResult.status, "approved");
  const signedResult = await signPhilCore4337UserOperation(signingRequest({
    draft: draftResult.value,
    foundation,
    owner,
    entryPoint,
    account
  }));
  assert.equal(signedResult.status, "approved");
  return {
    deployer,
    owner,
    other,
    beneficiary,
    harmlessTarget,
    actionGate,
    entryPoint,
    accountFactory,
    account,
    accountAddress,
    chainId,
    foundation,
    draft: draftResult.value,
    signed: signedResult.value
  };
}

async function createAccount({ accountFactory, owner, salt = 1n }) {
  const accountAddress = await accountFactory
    .getFunction("getAddress")
    .staticCall(owner.address, OWNER_COMMITMENT, salt);
  await (await accountFactory.createAccount(owner.address, OWNER_COMMITMENT, salt)).wait();
  const account = await ethers.getContractAt("PhilCore4337Account", accountAddress);
  return { account, accountAddress };
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

function validatorSigner(signer) {
  const descriptor = {
    signerId: `fixture-signer:${signer.address}`,
    mode: "developer_fixture",
    ownerAddress: signer.address,
    keyReference: {
      keyReferenceId: `fixture-key:${signer.address}`,
      mode: "developer_fixture",
      custody: "developer_fixture",
      privateKeyExportable: false,
      derivedFromPhilSecret: false
    },
    available: true,
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
      return {
        status: "signed",
        signature: await signer.signMessage(ethers.getBytes(request.userOperationHash)),
        signerDescriptor: descriptor,
        signedAt: new Date().toISOString()
      };
    }
  };
}

function signingRequest({ draft, foundation, owner, entryPoint, account }) {
  const presentation = createPhilCore4337SigningPresentation(draft);
  const approval = createPhilCore4337SigningApprovalArtifact({
    approvalId: "m11-signing-approval",
    presentationDigest: presentation.presentationDigest,
    source: "developer_fixture",
    approved: true,
    approvedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    oneTime: true,
    publicNetworkAllowed: false
  });
  return {
    requestId: "m11-signing",
    draft,
    foundation,
    runtimeAuthority: runtimeAuthority(),
    approval,
    signer: validatorSigner(owner),
    nonceReader: nonceReader(entryPoint),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    accountStateReader: accountStateReader(account),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "m11-signing-audit"
  };
}

function submissionApproval(signed, bundlerConfig, overrides = {}) {
  return createPhilCore4337SubmissionApprovalArtifact({
    approvalId: overrides.approvalId ?? "m11-submission-approval",
    userOperationHash: overrides.userOperationHash ?? signed.binding.userOperationHash,
    bundlerId: overrides.bundlerId ?? bundlerConfig.reference.bundlerId,
    chainId: overrides.chainId ?? signed.binding.chainId,
    entryPointAddress: overrides.entryPointAddress ?? signed.binding.entryPointAddress,
    approved: overrides.approved ?? true,
    approvedAt: new Date().toISOString(),
    expiresAt: overrides.expiresAt ?? futureDate(),
    source: overrides.source ?? "developer_fixture",
    oneTime: true,
    publicNetworkAllowed: overrides.publicNetworkAllowed ?? false,
    consumed: overrides.consumed
  });
}

function submissionRequest(env, overrides = {}) {
  const bundlerConfiguration = overrides.bundlerConfiguration
    ?? createPhilCore4337LocalFixtureBundlerConfiguration({
      chainId: env.chainId,
      entryPointAddress: awaitableAddress(env.entryPoint),
      bundlerId: "m11-local-bundler"
    });
  const signedOperation = overrides.signedOperation ?? env.signed;
  return {
    requestId: overrides.requestId ?? "m11-submit",
    signedOperation,
    foundation: overrides.foundation ?? env.foundation,
    bundlerConfiguration,
    bundlerClient: overrides.bundlerClient ?? fixtureBundlerClient({ env, bundlerConfiguration }),
    runtimeAuthority: overrides.runtimeAuthority ?? runtimeAuthority(),
    approval: overrides.approval ?? submissionApproval(signedOperation, bundlerConfiguration),
    nonceReader: overrides.nonceReader ?? nonceReader(env.entryPoint),
    gasEstimator: overrides.gasEstimator ?? createFixturePhilCore4337GasEstimator(),
    prefundReader: overrides.prefundReader ?? createFixturePhilCore4337PrefundReader(),
    accountStateReader: overrides.accountStateReader ?? accountStateReader(env.account),
    approvalStore: overrides.approvalStore,
    issuedAt: new Date().toISOString(),
    expiresAt: overrides.expiresAt ?? futureDate(),
    auditCorrelationId: overrides.auditCorrelationId ?? "m11-submit-audit",
    submittedOperationStore: overrides.submittedOperationStore
  };
}

function awaitableAddress(contract) {
  return contract.target ?? contract.address;
}

function fixtureBundlerClient({ env, bundlerConfiguration, mode = "record_only" }) {
  const receipts = new Map();
  return {
    receipts,
    async verifyCapabilities(request) {
      const required = request.requiredMethods ?? [
        "eth_supportedEntryPoints",
        "eth_chainId",
        "eth_sendUserOperation",
        "eth_getUserOperationReceipt"
      ];
      const errors = [];
      if (request.configuration.chainId !== request.expectedChainId) errors.push("wrong chain");
      if (request.configuration.entryPointAddress.toLowerCase() !== request.expectedEntryPointAddress.toLowerCase()) {
        errors.push("EntryPoint unsupported");
      }
      for (const method of required) {
        if (!request.configuration.supportedMethods.includes(method)) errors.push(`required method missing: ${method}`);
      }
      return {
        status: errors.length ? "bundler_incompatible" : "bundler_compatible",
        outcome: errors.length ? (errors.join(" ").includes("chain") ? "wrong_chain" : "required_method_missing") : "bundler_compatible",
        bundler: request.configuration.reference,
        chainId: request.configuration.chainId,
        supportedEntryPoints: [request.configuration.entryPointAddress],
        supportedMethods: request.configuration.supportedMethods,
        checkedAt: new Date().toISOString(),
        errors
      };
    },
    async sendUserOperation(request) {
      if (mode === "hash_mismatch") {
        return {
          status: "submitted",
          outcome: "user_operation_submitted",
          returnedUserOperationHash: ethers.id("wrong-user-op-hash"),
          submittedAt: new Date().toISOString()
        };
      }
      if (mode === "entrypoint_handleops") {
        const tx = await env.entryPoint.handleOps(
          [request.signedOperation.userOperation],
          env.beneficiary.address,
          { gasLimit: 6_000_000 }
        );
        const receipt = await tx.wait();
        receipts.set(request.signedOperation.binding.userOperationHash, {
          status: receipt.status === 1 ? "included" : "included_failed",
          userOperationHash: request.signedOperation.binding.userOperationHash,
          entryPointAddress: await env.entryPoint.getAddress(),
          sender: request.signedOperation.userOperation.sender,
          nonce: request.signedOperation.userOperation.nonce,
          success: receipt.status === 1,
          actualGasCost: "0",
          actualGasUsed: receipt.gasUsed.toString(),
          transactionHash: receipt.hash,
          blockNumber: receipt.blockNumber,
          blockHash: receipt.blockHash,
          logs: receipt.logs.map((log) => ({
            address: log.address,
            topics: [...log.topics],
            data: log.data
          })),
          paymaster: ethers.ZeroAddress,
          checkedAt: new Date().toISOString()
        });
      }
      return {
        status: "submitted",
        outcome: "user_operation_submitted",
        returnedUserOperationHash: request.signedOperation.binding.userOperationHash,
        submittedAt: new Date().toISOString()
      };
    },
    async getUserOperationReceipt(request) {
      return receipts.get(request.userOperationHash) ?? {
        status: "pending",
        userOperationHash: request.userOperationHash,
        entryPointAddress: request.entryPointAddress,
        checkedAt: new Date().toISOString()
      };
    }
  };
}

describe("PhilCore ERC-4337 bundler submission boundary", function () {
  it("checks a compatible local fixture bundler without submission", async function () {
    const env = await fixture();
    const config = createPhilCore4337LocalFixtureBundlerConfiguration({
      chainId: env.chainId,
      entryPointAddress: await env.entryPoint.getAddress()
    });
    const result = await requestPhilCore4337BundlerCapabilityCheck({
      configuration: config,
      bundlerClient: fixtureBundlerClient({ env, bundlerConfiguration: config })
    });
    assert.equal(result.status, "approved");
    assert.equal(result.value.outcome, "bundler_compatible");
  });

  it("serializes the exact signed PackedUserOperation for a v0.7 bundler shape", async function () {
    const env = await fixture();
    const serialized = serializePhilCore4337UserOperationForBundler(env.signed);
    assert.equal(serialized.shape, "packed_v0_7");
    assert.equal(serialized.userOperation.sender, env.signed.userOperation.sender);
    assert.equal(BigInt(serialized.userOperation.nonce), BigInt(env.signed.userOperation.nonce));
    assert.equal(serialized.userOperation.paymasterAndData, PHILCORE_4337_EMPTY_BYTES);
    assert.equal(serialized.userOperation.signature, env.signed.userOperation.signature.toLowerCase());
    assert.deepEqual(validateBundlerUserOperationSerialization({
      signedOperation: env.signed,
      serialized
    }), { valid: true, errors: [] });
  });

  it("authorizes submission separately from signing approval", async function () {
    const env = await fixture();
    const result = await requestPhilCore4337SubmissionAuthorization(submissionRequest(env));
    assert.equal(result.status, "approved");
    assert.equal(result.value.status, "submission_authorized");
    assert.equal(result.value.binding.userOperationHash, env.signed.binding.userOperationHash);
    assert.equal(result.value.limitations.includes("paymaster_disabled"), true);
  });

  it("submits through a restricted local fixture bundler and records no execution receipt yet", async function () {
    const env = await fixture();
    const store = createInMemoryPhilCore4337SubmittedOperationStore({ maxSubmittedOperationCount: 1 });
    const result = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      submittedOperationStore: store
    }));
    assert.equal(result.status, "approved");
    assert.equal(result.value.userOperationSubmitted, true);
    assert.equal(result.value.bundlerSubmissionPerformed, true);
    assert.equal(result.value.paymasterInvoked, false);
    assert.equal(result.value.nullifierConsumed, false);
    assert.equal(result.value.consumerExecuted, false);
    assert.equal(result.value.applicationCanSubmitDirectly, false);
    assert.equal(store.count(), 1);
    assert.equal(inspectSubmittedPhilCore4337UserOperation(result.value).receiptMonitored, false);
  });

  it("rejects ineligible authority, missing approval, replayed approval, nonce changes, and hash mismatches", async function () {
    const env = await fixture();
    const consumed = createInMemoryPhilCore4337SubmissionApprovalStore();
    const first = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      approvalStore: consumed,
      approval: submissionApproval(env.signed, createPhilCore4337LocalFixtureBundlerConfiguration({
        chainId: env.chainId,
        entryPointAddress: await env.entryPoint.getAddress(),
        bundlerId: "m11-local-bundler"
      }), { approvalId: "one-time" })
    }));
    assert.equal(first.status, "approved");
    const replay = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      approvalStore: consumed,
      approval: submissionApproval(env.signed, createPhilCore4337LocalFixtureBundlerConfiguration({
        chainId: env.chainId,
        entryPointAddress: await env.entryPoint.getAddress(),
        bundlerId: "m11-local-bundler"
      }), { approvalId: "one-time" })
    }));
    assert.equal(replay.status, "denied");
    assert.match(replay.error.code, /APPROVAL_REJECTED/);

    const inactive = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      runtimeAuthority: runtimeAuthority({ capabilityGrantStatus: "inactive" })
    }));
    assert.equal(inactive.status, "denied");
    assert.match(inactive.error.code, /RUNTIME_AUTHORITY_INELIGIBLE/);

    const missingApproval = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      approval: submissionApproval(env.signed, createPhilCore4337LocalFixtureBundlerConfiguration({
        chainId: env.chainId,
        entryPointAddress: await env.entryPoint.getAddress(),
        bundlerId: "m11-local-bundler"
      }), { approved: false })
    }));
    assert.equal(missingApproval.status, "denied");
    assert.match(missingApproval.error.code, /APPROVAL_REQUIRED/);

    const nonceChanged = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      nonceReader: nonceReader(env.entryPoint, "99")
    }));
    assert.equal(nonceChanged.status, "denied");
    assert.match(nonceChanged.error.code, /NONCE_CHANGED/);

    const config = createPhilCore4337LocalFixtureBundlerConfiguration({
      chainId: env.chainId,
      entryPointAddress: await env.entryPoint.getAddress(),
      bundlerId: "m11-local-bundler"
    });
    const hashMismatch = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      bundlerConfiguration: config,
      bundlerClient: fixtureBundlerClient({ env, bundlerConfiguration: config, mode: "hash_mismatch" }),
      approval: submissionApproval(env.signed, config)
    }));
    assert.equal(hashMismatch.status, "denied");
    assert.match(hashMismatch.error.code, /USER_OPERATION_HASH_MISMATCH/);
  });

  it("monitors an actual local EntryPoint handleOps path through a fixture bundler classification", async function () {
    const env = await fixture();
    await env.owner.sendTransaction({ to: env.accountAddress, value: ethers.parseEther("1") });
    const config = createPhilCore4337LocalFixtureBundlerConfiguration({
      chainId: env.chainId,
      entryPointAddress: await env.entryPoint.getAddress(),
      bundlerId: "m11-local-entrypoint-fixture"
    });
    const client = fixtureBundlerClient({ env, bundlerConfiguration: config, mode: "entrypoint_handleops" });
    const submitted = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      bundlerConfiguration: config,
      bundlerClient: client,
      approval: submissionApproval(env.signed, config)
    }));
    assert.equal(submitted.status, "approved");

    const receipt = await requestPhilCore4337UserOperationReceiptMonitoring({
      requestId: "m11-monitor",
      submittedOperation: submitted.value,
      bundlerClient: client,
      accountStateReader: accountStateReader(env.account),
      innerExecutionVerifier: {
        async verifyInnerExecution({ submittedOperation, receipt }) {
          return {
            status: "inner_execution_verified",
            actionGateAddress: env.harmlessTarget.address,
            accountAddress: submittedOperation.binding.smartAccountAddress,
            transactionHash: receipt.transactionHash,
            nullifier: NULLIFIER,
            approvedActionMatched: true,
            checkedAt: new Date().toISOString()
          };
        }
      },
      nullifierStateVerifier: {
        async verifyNullifierConsumed() {
          return { status: "nullifier_consumed", nullifier: NULLIFIER, checkedAt: new Date().toISOString() };
        }
      },
      consumerExecutionVerifier: {
        async verifyConsumerExecuted() {
          return { status: "consumer_executed", approvedActionMatched: true, checkedAt: new Date().toISOString() };
        }
      },
      maxAttempts: 1,
      auditCorrelationId: "m11-monitor-audit"
    });
    assert.equal(receipt.status, "approved");
    assert.equal(receipt.value.userOperationIncluded, true);
    assert.equal(receipt.value.accountValidationSucceeded, true);
    assert.equal(receipt.value.nullifierConsumed, true);
    assert.equal(receipt.value.consumerExecuted, true);
    assert.equal(receipt.value.paymasterInvoked, false);

    await assert.rejects(
      env.entryPoint.handleOps([env.signed.userOperation], env.beneficiary.address, { gasLimit: 6_000_000 }),
      /reverted/
    );
  });

  it("rejects included receipts when explicit execution/nullifier/consumer verifiers are missing", async function () {
    const env = await fixture();
    await env.owner.sendTransaction({ to: env.accountAddress, value: ethers.parseEther("1") });
    const config = createPhilCore4337LocalFixtureBundlerConfiguration({
      chainId: env.chainId,
      entryPointAddress: await env.entryPoint.getAddress(),
      bundlerId: "m11-local-entrypoint-fixture"
    });
    const client = fixtureBundlerClient({ env, bundlerConfiguration: config, mode: "entrypoint_handleops" });
    const submitted = await requestPhilCore4337UserOperationSubmission(submissionRequest(env, {
      bundlerConfiguration: config,
      bundlerClient: client,
      approval: submissionApproval(env.signed, config)
    }));
    assert.equal(submitted.status, "approved");

    const receipt = await requestPhilCore4337UserOperationReceiptMonitoring({
      requestId: "m11-monitor-missing-verifiers",
      submittedOperation: submitted.value,
      bundlerClient: client,
      accountStateReader: accountStateReader(env.account),
      maxAttempts: 1
    });
    assert.equal(receipt.status, "denied");
    assert.match(receipt.error.code, /EXECUTION_VERIFIERS_REQUIRED/);
  });

  it("classifies failed receipts and pending monitoring without claiming authority", async function () {
    const env = await fixture();
    const submitted = await requestPhilCore4337UserOperationSubmission(submissionRequest(env));
    assert.equal(submitted.status, "approved");
    const pending = await requestPhilCore4337UserOperationReceiptMonitoring({
      requestId: "m11-pending",
      submittedOperation: submitted.value,
      bundlerClient: fixtureBundlerClient({
        env,
        bundlerConfiguration: createPhilCore4337LocalFixtureBundlerConfiguration({
          chainId: env.chainId,
          entryPointAddress: await env.entryPoint.getAddress()
        })
      }),
      maxAttempts: 1
    });
    assert.equal(pending.status, "denied");
    assert.match(pending.error.code, /MONITORING_TIMEOUT/);
  });

  it("runs safe non-public M.11 diagnostics", function () {
    const diagnose = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-philcore-4337-bundler-submission-diagnostic.cjs",
      "--json"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(diagnose.status, 0, diagnose.stderr);
    const parsed = JSON.parse(diagnose.stdout);
    assert.equal(parsed.entryPointVersion, "0.7");
    assert.equal(parsed.userOperationSubmitted, true);
    assert.equal(parsed.paymasterInvoked, false);
    assert.equal(parsed.live_user_operation_submission_performed, false);

    const monitor = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-philcore-4337-bundler-submission-diagnostic.cjs",
      "--monitor"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(monitor.status, 0, monitor.stderr);
    assert.match(monitor.stdout, /PhilCore ERC-4337 bundler submission diagnostic/);
    assert.match(monitor.stdout, /public submission performed: false/);
  });
});
