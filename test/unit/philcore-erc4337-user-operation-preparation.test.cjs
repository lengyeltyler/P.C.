const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { ethers } = require("hardhat");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  PHILCORE_4337_EMPTY_BYTES,
  PHILCORE_4337_ENTRYPOINT_VERSION,
  PHILCORE_4337_EXECUTE_SELECTOR,
  computePhilCore4337UserOperationHash,
  createBaseExecutionDraftFixture,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337PrefundReader,
  createInMemoryAuditDraftCollector,
  createInMemoryPhilCore4337UserOperationDraftStore,
  createPhilCore4337LocalFoundationConfiguration,
  packPhilCore4337AccountGasLimits,
  packPhilCore4337GasFees,
  packPhilCore4337Uints,
  preparePhilCore4337UserOperation,
  summarizePhilCore4337UserOperationDraft,
  unpackPhilCore4337Uints,
  validatePhilCore4337UserOperationDraft,
  validatePhilCore4337UserOperationHashBinding,
  verifyPhilCore4337Foundation
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const OWNER_COMMITMENT = ethers.id("philcore-m9-owner-commitment");
const PROOF_INPUT_HASH = ethers.id("philcore-m9-proof-input");
const NULLIFIER = ethers.id("philcore-m9-nullifier");

async function deployEntryPoint() {
  const [deployer] = await ethers.getSigners();
  const factory = new ethers.ContractFactory(
    EntryPointArtifact.abi,
    EntryPointArtifact.bytecode,
    deployer
  );
  return factory.deploy();
}

async function fixture() {
  const [deployer, owner, beneficiary, harmlessTarget, recovery] = await ethers.getSigners();
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
  return { deployer, owner, beneficiary, harmlessTarget, actionGate, entryPoint, accountFactory, chainId, foundation };
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

function baseDraftFor({ actionGateAddress, senderAccount, chainId, value = 0n, calldataSuffix = "01" }) {
  return createBaseExecutionDraftFixture({
    actionGateAddress,
    senderAccount,
    ownerCommitment: OWNER_COMMITMENT,
    proofInputHash: PROOF_INPUT_HASH,
    nullifier: NULLIFIER,
    chainId,
    value,
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

function counterfactualResolver(accountFactory) {
  return {
    async resolveCounterfactualAccount(request) {
      const predictedAddress = await accountFactory
        .getFunction("getAddress")
        .staticCall(request.owner, request.ownerCommitment, BigInt(request.salt));
      const createCalldata = accountFactory.interface.encodeFunctionData("createAccount", [
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
            createAccountCalldata: createCalldata,
            initCode: ethers.concat([request.factoryAddress, createCalldata]),
            createAccountSelector: accountFactory.interface.getFunction("createAccount").selector
          },
          accountDeploymentPerformed: false
        },
        errors: []
      };
    }
  };
}

async function prepareDeployed({ simulate = false } = {}) {
  const env = await fixture();
  const { account } = await createAccount({ accountFactory: env.accountFactory, owner: env.owner });
  const accountAddress = await account.getAddress();
  const baseExecutionDraft = baseDraftFor({
    actionGateAddress: await env.actionGate.getAddress(),
    senderAccount: accountAddress,
    chainId: env.chainId
  });
  const request = {
    requestId: "m9-request",
    baseExecutionDraft,
    foundation: env.foundation,
    accountMode: "deployed",
    accountAddress,
    accountStateReader: accountStateReader(account),
    nonceReader: nonceReader(env.entryPoint),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    simulator: simulate
      ? {
        async simulateUserOperation() {
          return {
            status: "signature_required",
            fixtureOnly: true,
            simulationOnlySignatureUsed: false,
            checkedAt: new Date().toISOString()
          };
        }
      }
      : undefined,
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "m9-audit"
  };
  const result = await preparePhilCore4337UserOperation(request);
  return { ...env, account, accountAddress, baseExecutionDraft, request, result };
}

async function signPreparedUserOp({ entryPoint, userOperation, owner }) {
  const userOpHash = await entryPoint.getUserOpHash(userOperation);
  return {
    ...userOperation,
    signature: await owner.signMessage(ethers.getBytes(userOpHash))
  };
}

describe("PhilCore ERC-4337 UserOperation preparation boundary", function () {
  it("validates the proposed local foundation and keeps ACP-0002 proposed", async function () {
    const { foundation } = await fixture();
    const validation = verifyPhilCore4337Foundation(foundation);
    assert.equal(validation.valid, true);
    assert.equal(foundation.acpStatus, "Proposed");
    assert.equal(foundation.entryPoint.version, PHILCORE_4337_ENTRYPOINT_VERSION);
    assert.equal(foundation.validator.paymaster, "disabled");
  });

  it("prepares an unsigned v0.7 PackedUserOperation for a deployed account", async function () {
    const { entryPoint, chainId, result } = await prepareDeployed({ simulate: true });
    assert.equal(result.status, "approved");
    const draft = result.value;
    assert.equal(draft.entryPointVersion, "0.7");
    assert.equal(draft.accountState, "deployed");
    assert.equal(draft.userOperation.signature, PHILCORE_4337_EMPTY_BYTES);
    assert.equal(draft.userOperation.paymasterAndData, PHILCORE_4337_EMPTY_BYTES);
    assert.equal(draft.userOperation.callData.startsWith(PHILCORE_4337_EXECUTE_SELECTOR), true);
    assert.equal(draft.userOperationPrepared, true);
    assert.equal(draft.userOperationSigned, false);
    assert.equal(draft.userOperationSubmitted, false);
    assert.equal(draft.bundlerSubmissionPerformed, false);
    assert.equal(draft.paymasterInvoked, false);
    assert.equal(draft.nullifierConsumed, false);
    assert.equal(draft.consumerExecuted, false);
    assert.deepEqual(validatePhilCore4337UserOperationDraft(draft), { valid: true, errors: [] });

    const localHash = computePhilCore4337UserOperationHash({
      userOperation: draft.userOperation,
      entryPointAddress: await entryPoint.getAddress(),
      chainId
    });
    assert.equal(localHash, await entryPoint.getUserOpHash(draft.userOperation));
    assert.equal(draft.binding.userOperationHash, localHash);
    assert.equal(validatePhilCore4337UserOperationHashBinding({
      userOperation: draft.userOperation,
      entryPointAddress: await entryPoint.getAddress(),
      chainId,
      expectedUserOperationHash: localHash
    }).valid, true);
  });

  it("resolves counterfactual accounts without deploying them", async function () {
    const env = await fixture();
    const salt = 99n;
    const predicted = await env.accountFactory
      .getFunction("getAddress")
      .staticCall(env.owner.address, OWNER_COMMITMENT, salt);
    const baseExecutionDraft = baseDraftFor({
      actionGateAddress: await env.actionGate.getAddress(),
      senderAccount: predicted,
      chainId: env.chainId
    });
    assert.equal(await ethers.provider.getCode(predicted), "0x");

    const result = await preparePhilCore4337UserOperation({
      requestId: "m9-counterfactual",
      baseExecutionDraft,
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
      nonceReader: { async readNonce(request) {
        assert.equal(request.accountAddress, predicted);
        return {
          status: "resolved",
          nonce: "0",
          nonceKey: request.nonceKey,
          source: "fixture",
          checkedAt: new Date().toISOString()
        };
      } },
      gasEstimator: createFixturePhilCore4337GasEstimator(),
      prefundReader: createFixturePhilCore4337PrefundReader(),
      issuedAt: new Date().toISOString(),
      expiresAt: futureDate(),
      auditCorrelationId: "m9-counterfactual-audit"
    });

    assert.equal(result.status, "approved");
    const draft = result.value;
    assert.equal(draft.accountState, "counterfactual");
    assert.equal(draft.binding.smartAccountAddress, predicted);
    assert.equal(draft.counterfactual.predictedAddress, predicted);
    assert.equal(draft.userOperation.sender, predicted);
    assert.equal(draft.userOperation.initCode, ethers.concat([
      await env.accountFactory.getAddress(),
      env.accountFactory.interface.encodeFunctionData("createAccount", [
        env.owner.address,
        OWNER_COMMITMENT,
        salt
      ])
    ]));
    assert.equal(draft.smartAccountDeploymentPerformed, false);
    assert.equal(await ethers.provider.getCode(predicted), "0x");
  });

  it("rejects wrong EntryPoint version, nonempty signature, paymaster data, and prefund failures", async function () {
    const env = await prepareDeployed();
    const badFoundation = {
      ...env.foundation,
      entryPoint: { ...env.foundation.entryPoint, version: "0.6" }
    };
    const badVersion = await preparePhilCore4337UserOperation({
      ...env.request,
      foundation: badFoundation
    });
    assert.equal(badVersion.status, "denied");

    const nonemptySignature = await preparePhilCore4337UserOperation({
      ...env.request,
      signature: "0x1234"
    });
    assert.equal(nonemptySignature.status, "denied");
    assert.match(nonemptySignature.error.code, /SIGNATURE_MUST_BE_EMPTY/);

    const paymaster = await preparePhilCore4337UserOperation({
      ...env.request,
      paymasterAndData: "0x1234"
    });
    assert.equal(paymaster.status, "denied");
    assert.match(paymaster.error.code, /PAYMASTER_NOT_ALLOWED/);

    const prefund = await preparePhilCore4337UserOperation({
      ...env.request,
      prefundReader: createFixturePhilCore4337PrefundReader({
        status: "prefund_insufficient",
        requiredPrefund: "100",
        missingPrefund: "100"
      })
    });
    assert.equal(prefund.status, "denied");
    assert.match(prefund.error.code, /PREFUND_INSUFFICIENT/);
  });

  it("detects owner and ownerCommitment mismatches through account verification", async function () {
    const env = await prepareDeployed();
    const wrongOwner = await preparePhilCore4337UserOperation({
      ...env.request,
      foundation: {
        ...env.foundation,
        validator: {
          ...env.foundation.validator,
          owner: env.beneficiary.address
        }
      }
    });
    assert.equal(wrongOwner.status, "denied");
    assert.match(wrongOwner.error.code, /ACCOUNT_VERIFICATION_FAILED/);

    const wrongCommitment = await preparePhilCore4337UserOperation({
      ...env.request,
      foundation: {
        ...env.foundation,
        validator: {
          ...env.foundation.validator,
          ownerCommitment: ethers.id("wrong-commitment")
        }
      }
    });
    assert.equal(wrongCommitment.status, "denied");
    assert.match(wrongCommitment.error.code, /ACCOUNT_VERIFICATION_FAILED/);
  });

  it("preserves exact inner execution call binding and rejects mutated Base execution calldata", async function () {
    const env = await prepareDeployed();
    const draft = env.result.value;
    assert.equal(draft.executionCall.target, env.baseExecutionDraft.to);
    assert.equal(draft.executionCall.value, env.baseExecutionDraft.value);
    assert.equal(draft.executionCall.innerCalldata, env.baseExecutionDraft.calldata);
    assert.equal(draft.executionCall.innerCalldataHash, env.baseExecutionDraft.calldataHash);

    const mutated = {
      ...env.baseExecutionDraft,
      calldata: `${BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR}ff`
    };
    const result = await preparePhilCore4337UserOperation({
      ...env.request,
      baseExecutionDraft: mutated
    });
    assert.equal(result.status, "denied");
    assert.match(result.error.code, /EXECUTION_CALL_MISMATCH/);
  });

  it("uses v0.7 gas packing rules and rejects overflow", function () {
    const packed = packPhilCore4337Uints(123n, 456n);
    assert.deepEqual(unpackPhilCore4337Uints(packed), {
      high128: "123",
      low128: "456"
    });
    assert.equal(packPhilCore4337AccountGasLimits({
      verificationGasLimit: 900_000n,
      callGasLimit: 800_000n
    }), ethers.toBeHex((900_000n << 128n) + 800_000n, 32));
    assert.equal(packPhilCore4337GasFees({
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 2n
    }), ethers.toBeHex((1n << 128n) + 2n, 32));
    assert.throws(() => packPhilCore4337Uints(1n << 128n, 0n), /overflow/);
  });

  it("runs a signed local EntryPoint fixture separately while Runtime preparation remains unsigned", async function () {
    const { entryPoint, owner, beneficiary, accountAddress, result } = await prepareDeployed();
    const account = await ethers.getContractAt("PhilCore4337Account", accountAddress);
    await owner.sendTransaction({ to: accountAddress, value: ethers.parseEther("1") });
    const signedUserOp = await signPreparedUserOp({
      entryPoint,
      userOperation: result.value.userOperation,
      owner
    });
    assert.equal(result.value.userOperation.signature, PHILCORE_4337_EMPTY_BYTES);

    await (await entryPoint.handleOps([signedUserOp], beneficiary.address, { gasLimit: 6_000_000 })).wait();
    assert.equal(await account.owner(), owner.address);
    assert.equal(result.value.nullifierConsumed, false);
    assert.equal(result.value.consumerExecuted, false);
    assert.equal(result.value.baseStateMutated, false);
  });

  it("stores drafts ephemerally and keeps summaries non-authoritative", async function () {
    const env = await fixture();
    const { account } = await createAccount({ accountFactory: env.accountFactory, owner: env.owner });
    const accountAddress = await account.getAddress();
    const store = createInMemoryPhilCore4337UserOperationDraftStore({ maxDraftCount: 1 });
    const collector = createInMemoryAuditDraftCollector();
    const request = {
      requestId: "m9-store",
      baseExecutionDraft: baseDraftFor({
        actionGateAddress: await env.actionGate.getAddress(),
        senderAccount: accountAddress,
        chainId: env.chainId
      }),
      foundation: env.foundation,
      accountMode: "deployed",
      accountAddress,
      accountStateReader: accountStateReader(account),
      nonceReader: nonceReader(env.entryPoint),
      gasEstimator: createFixturePhilCore4337GasEstimator(),
      prefundReader: createFixturePhilCore4337PrefundReader(),
      issuedAt: new Date().toISOString(),
      expiresAt: futureDate(),
      auditCorrelationId: "m9-store-audit",
      auditDraftCollector: collector,
      draftStore: store
    };

    const result = await preparePhilCore4337UserOperation(request);
    assert.equal(result.status, "approved");
    assert.equal(store.count(), 1);
    assert.equal(result.value.collectionResult.status, "collected");
    assert.equal(collector.count(), 1);
    const summary = summarizePhilCore4337UserOperationDraft(result.value);
    assert.equal(summary.userOperationSigned, false);
    assert.equal(summary.userOperationSubmitted, false);
    assert.equal(summary.nullifierConsumed, false);
    assert.equal(summary.consumerExecuted, false);
    assert.equal(summary.baseStateMutated, false);
  });

  it("runs non-submitting M.9 diagnostics", function () {
    const inspect = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-philcore-4337-user-operation-preparation-diagnostic.cjs",
      "--inspect-account"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(inspect.status, 0, inspect.stderr);
    assert.match(inspect.stdout, /EntryPoint v0.7/);
    assert.match(inspect.stdout, /UserOperation not signed/);

    const diagnose = spawnSync(process.execPath, [
      "--import",
      "tsx",
      "./scripts/base/run-philcore-4337-user-operation-preparation-diagnostic.cjs",
      "--json"
    ], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(diagnose.status, 0, diagnose.stderr);
    const parsed = JSON.parse(diagnose.stdout);
    assert.equal(parsed.entryPointVersion, "0.7");
    assert.equal(parsed.userOperationPrepared, true);
    assert.equal(parsed.userOperationSigned, false);
    assert.equal(parsed.userOperationSubmitted, false);
    assert.equal(parsed.bundlerSubmissionPerformed, false);
    assert.equal(parsed.nullifierConsumed, false);
  });
});
