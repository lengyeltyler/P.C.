const { Wallet, keccak256 } = require("ethers");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseExecutionDraftFixture,
  createFixturePhilCore4337AccountStateReader,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337NonceReader,
  createFixturePhilCore4337PrefundReader,
  createPhilCore4337LocalFixtureBundlerConfiguration,
  createPhilCore4337LocalFoundationConfiguration,
  createPhilCore4337SigningApprovalArtifact,
  createPhilCore4337SigningPresentation,
  createPhilCore4337SubmissionApprovalArtifact,
  inspectSubmittedPhilCore4337UserOperation,
  preparePhilCore4337UserOperation,
  requestPhilCore4337BundlerCapabilityCheck,
  requestPhilCore4337UserOperationReceiptMonitoring,
  requestPhilCore4337UserOperationSubmission,
  signPhilCore4337UserOperation
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const FACTORY = "0x1000000000000000000000000000000000004337";
const ACCOUNT = "0x1000000000000000000000000000000000000002";
const ACTION_GATE = "0x1000000000000000000000000000000000000003";
const OWNER_COMMITMENT = `0x${"11".repeat(32)}`;
const PROOF_INPUT_HASH = `0x${"22".repeat(32)}`;
const NULLIFIER = `0x${"33".repeat(32)}`;
const DEV_FIXTURE_KEY = "0x59c6995e998f97a5a0044966f094538d9f2d74d8234bd60be5675760fc354f0f";

function hasArg(name) {
  return process.argv.includes(name);
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
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

function fixtureSigner(wallet) {
  const descriptor = {
    signerId: `developer-fixture:${wallet.address}`,
    mode: "developer_fixture",
    ownerAddress: wallet.address,
    keyReference: {
      keyReferenceId: "developer-fixture-key",
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
      return wallet.address;
    },
    async signUserOperationHash(request) {
      return {
        status: "signed",
        signature: await wallet.signMessage(Buffer.from(request.userOperationHash.slice(2), "hex")),
        signerDescriptor: descriptor,
        signedAt: new Date().toISOString()
      };
    }
  };
}

function fixtureBundlerClient(configuration) {
  return {
    async verifyCapabilities(request) {
      return {
        status: "bundler_compatible",
        outcome: "bundler_compatible",
        bundler: request.configuration.reference,
        chainId: request.configuration.chainId,
        supportedEntryPoints: [request.configuration.entryPointAddress],
        supportedMethods: request.configuration.supportedMethods,
        checkedAt: new Date().toISOString(),
        errors: []
      };
    },
    async sendUserOperation(request) {
      return {
        status: "submitted",
        outcome: "user_operation_submitted",
        returnedUserOperationHash: request.signedOperation.binding.userOperationHash,
        submittedAt: new Date().toISOString()
      };
    },
    async getUserOperationReceipt(request) {
      if (!hasArg("--monitor")) {
        return {
          status: "pending",
          userOperationHash: request.userOperationHash,
          entryPointAddress: request.entryPointAddress,
          checkedAt: new Date().toISOString()
        };
      }
      return {
        status: "included",
        userOperationHash: request.userOperationHash,
        entryPointAddress: request.entryPointAddress,
        sender: ACCOUNT,
        nonce: "0",
        success: true,
        actualGasCost: "0",
        actualGasUsed: "0",
        transactionHash: `0x${"44".repeat(32)}`,
        blockNumber: 1,
        blockHash: `0x${"55".repeat(32)}`,
        logs: [],
        paymaster: "0x0000000000000000000000000000000000000000",
        checkedAt: new Date().toISOString()
      };
    }
  };
}

async function buildDiagnostic() {
  const wallet = new Wallet(DEV_FIXTURE_KEY);
  const foundation = createPhilCore4337LocalFoundationConfiguration({
    chainId: 31337,
    entryPointAddress: ENTRY_POINT,
    factoryAddress: FACTORY,
    approvedActionGateAddress: ACTION_GATE,
    owner: wallet.address,
    ownerCommitment: OWNER_COMMITMENT
  });
  const baseExecutionDraft = createBaseExecutionDraftFixture({
    actionGateAddress: ACTION_GATE,
    senderAccount: ACCOUNT,
    ownerCommitment: OWNER_COMMITMENT,
    proofInputHash: PROOF_INPUT_HASH,
    nullifier: NULLIFIER,
    chainId: 31337,
    calldata: `${BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR}01`
  });
  const accountStateReader = createFixturePhilCore4337AccountStateReader({
    accountAddress: ACCOUNT,
    chainId: 31337,
    codeExists: true,
    codeHash: keccak256("0x4337"),
    entryPoint: ENTRY_POINT,
    owner: wallet.address,
    ownerCommitment: OWNER_COMMITMENT,
    approvedActionGate: ACTION_GATE
  });
  const prepared = await preparePhilCore4337UserOperation({
    requestId: "diagnostic-m11-prepare",
    baseExecutionDraft,
    foundation,
    accountMode: "deployed",
    accountAddress: ACCOUNT,
    accountStateReader,
    nonceReader: createFixturePhilCore4337NonceReader("0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m11-prepare-audit"
  });
  if (prepared.status !== "approved") return { status: prepared.status, error: prepared.error };

  const presentation = createPhilCore4337SigningPresentation(prepared.value);
  const signingApproval = createPhilCore4337SigningApprovalArtifact({
    approvalId: "diagnostic-m11-signing-approval",
    presentationDigest: presentation.presentationDigest,
    source: "developer_fixture",
    approved: true,
    approvedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    oneTime: true,
    publicNetworkAllowed: false
  });
  const signed = await signPhilCore4337UserOperation({
    requestId: "diagnostic-m11-signing",
    draft: prepared.value,
    foundation,
    runtimeAuthority: runtimeAuthority(),
    approval: signingApproval,
    signer: fixtureSigner(wallet),
    nonceReader: createFixturePhilCore4337NonceReader("0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    accountStateReader,
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m11-signing-audit"
  });
  if (signed.status !== "approved") return { status: signed.status, error: signed.error };

  const bundlerConfiguration = createPhilCore4337LocalFixtureBundlerConfiguration({
    chainId: 31337,
    entryPointAddress: ENTRY_POINT,
    bundlerId: "diagnostic-local-fixture-bundler"
  });
  const bundlerClient = fixtureBundlerClient(bundlerConfiguration);
  const capability = await requestPhilCore4337BundlerCapabilityCheck({
    configuration: bundlerConfiguration,
    bundlerClient
  });
  const submissionApproval = createPhilCore4337SubmissionApprovalArtifact({
    approvalId: "diagnostic-m11-submission-approval",
    userOperationHash: signed.value.binding.userOperationHash,
    bundlerId: bundlerConfiguration.reference.bundlerId,
    chainId: 31337,
    entryPointAddress: ENTRY_POINT,
    approved: true,
    approvedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    source: "developer_fixture",
    oneTime: true,
    publicNetworkAllowed: false
  });
  const submitted = await requestPhilCore4337UserOperationSubmission({
    requestId: "diagnostic-m11-submit",
    signedOperation: signed.value,
    foundation,
    bundlerConfiguration,
    bundlerClient,
    runtimeAuthority: runtimeAuthority(),
    approval: submissionApproval,
    nonceReader: createFixturePhilCore4337NonceReader("0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    accountStateReader,
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m11-submit-audit"
  });
  if (submitted.status !== "approved") return { status: submitted.status, error: submitted.error };

  const monitoring = await requestPhilCore4337UserOperationReceiptMonitoring({
    requestId: "diagnostic-m11-monitor",
    submittedOperation: submitted.value,
    bundlerClient,
    innerExecutionVerifier: {
      async verifyInnerExecution({ submittedOperation, receipt }) {
        return {
          status: "inner_execution_verified",
          actionGateAddress: ACTION_GATE,
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
    auditCorrelationId: "diagnostic-m11-monitor-audit"
  });

  return {
    ...inspectSubmittedPhilCore4337UserOperation(submitted.value),
    entryPointVersion: "0.7",
    bundlerCapability: capability.status,
    receiptMonitoringStatus: monitoring.status,
    receiptIncluded: monitoring.status === "approved",
    paymaster: "disabled",
    publicBundler: false,
    localFixtureBundler: true,
    live_user_operation_submission_performed: false,
    reason: "Base Sepolia deployments, custody, funding, bundler, live mirrored fact, and explicit approval are unresolved."
  };
}

buildDiagnostic()
  .then((diagnostic) => {
    if (hasArg("--json")) {
      process.stdout.write(`${JSON.stringify(diagnostic, null, 2)}\n`);
      return;
    }
    process.stdout.write([
      "PhilCore ERC-4337 bundler submission diagnostic",
      `EntryPoint v${diagnostic.entryPointVersion}`,
      `Account: ${diagnostic.sender}`,
      `UserOperation hash: ${diagnostic.userOperationHash}`,
      `Bundler: ${diagnostic.bundlerId}`,
      `Bundler capability: ${diagnostic.bundlerCapability}`,
      `Submitted: ${diagnostic.userOperationSubmitted}`,
      `Receipt included: ${diagnostic.receiptIncluded}`,
      `Paymaster invoked: ${diagnostic.paymasterInvoked}`,
      `Public submission performed: ${diagnostic.live_user_operation_submission_performed}`,
      `public submission performed: ${diagnostic.live_user_operation_submission_performed}`,
      `Reason: ${diagnostic.reason}`
    ].join("\n"));
    process.stdout.write("\n");
  })
  .catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
