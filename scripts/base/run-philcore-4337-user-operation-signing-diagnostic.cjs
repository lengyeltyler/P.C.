const { Wallet, keccak256 } = require("ethers");

const {
  BASE_ACTION_GATE_VERIFY_AND_CONSUME_SELECTOR,
  createBaseExecutionDraftFixture,
  createFixturePhilCore4337AccountStateReader,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337NonceReader,
  createFixturePhilCore4337PrefundReader,
  createPhilCore4337LocalFoundationConfiguration,
  createPhilCore4337SigningApprovalArtifact,
  createPhilCore4337SigningPresentation,
  inspectSignedPhilCore4337UserOperation,
  preparePhilCore4337UserOperation,
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
  const prepared = await preparePhilCore4337UserOperation({
    requestId: "diagnostic-m10-prepare",
    baseExecutionDraft,
    foundation,
    accountMode: "deployed",
    accountAddress: ACCOUNT,
    accountStateReader: createFixturePhilCore4337AccountStateReader({
      accountAddress: ACCOUNT,
      chainId: 31337,
      codeExists: true,
      codeHash: keccak256("0x4337"),
      entryPoint: ENTRY_POINT,
      owner: wallet.address,
      ownerCommitment: OWNER_COMMITMENT,
      approvedActionGate: ACTION_GATE
    }),
    nonceReader: createFixturePhilCore4337NonceReader("0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m10-prepare-audit"
  });
  if (prepared.status !== "approved") {
    return { status: prepared.status, error: prepared.error };
  }
  const presentation = createPhilCore4337SigningPresentation(prepared.value);
  const approval = createPhilCore4337SigningApprovalArtifact({
    approvalId: "diagnostic-m10-approval",
    presentationDigest: presentation.presentationDigest,
    source: "developer_fixture",
    approved: true,
    approvedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    oneTime: true,
    publicNetworkAllowed: false
  });
  const signed = await signPhilCore4337UserOperation({
    requestId: "diagnostic-m10-sign",
    draft: prepared.value,
    foundation,
    runtimeAuthority: runtimeAuthority(),
    approval,
    signer: fixtureSigner(wallet),
    nonceReader: createFixturePhilCore4337NonceReader("0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    accountStateReader: createFixturePhilCore4337AccountStateReader({
      accountAddress: ACCOUNT,
      chainId: 31337,
      codeExists: true,
      codeHash: keccak256("0x4337"),
      entryPoint: ENTRY_POINT,
      owner: wallet.address,
      ownerCommitment: OWNER_COMMITMENT
    }),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m10-sign-audit"
  });
  if (signed.status !== "approved") return { status: signed.status, error: signed.error };
  return {
    ...inspectSignedPhilCore4337UserOperation(signed.value),
    entryPointVersion: "0.7",
    owner: wallet.address,
    ownerCommitment: OWNER_COMMITMENT,
    presentationDigest: presentation.presentationDigest,
    approvalSource: approval.source,
    signaturePresent: true,
    signed: true,
    submitted: false,
    paymaster: "disabled"
  };
}

buildDiagnostic()
  .then((diagnostic) => {
    if (hasArg("--json")) {
      process.stdout.write(`${JSON.stringify(diagnostic, null, 2)}\n`);
      return;
    }
    process.stdout.write([
      "Signed PhilCore ERC-4337 UserOperation diagnostic",
      `EntryPoint v${diagnostic.entryPointVersion}`,
      `Account: ${diagnostic.sender}`,
      `Owner: ${diagnostic.owner}`,
      `ownerCommitment: ${diagnostic.ownerCommitment}`,
      `UserOperation hash: ${diagnostic.userOperationHash}`,
      `Presentation digest: ${diagnostic.presentationDigest}`,
      `Approval source: ${diagnostic.approvalSource}`,
      `Signature present: ${diagnostic.signaturePresent}`,
      "Signed: true",
      "UserOperation not submitted",
      `Bundler submission performed: ${diagnostic.bundlerSubmissionPerformed}`,
      `Paymaster: ${diagnostic.paymaster}`,
      `Nullifier consumed: ${diagnostic.nullifierConsumed}`,
      `Consumer executed: ${diagnostic.consumerExecuted}`,
      `Base state mutated: ${diagnostic.baseStateMutated}`
    ].join("\n"));
    process.stdout.write("\n");
  })
  .catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
    process.exitCode = 1;
  });
