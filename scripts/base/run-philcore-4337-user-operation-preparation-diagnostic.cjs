const {
  PHILCORE_4337_EMPTY_BYTES,
  PHILCORE_4337_ENTRYPOINT_VERSION,
  createBaseExecutionDraftFixture,
  createFixturePhilCore4337GasEstimator,
  createFixturePhilCore4337PrefundReader,
  createFixturePhilCore4337AccountStateReader,
  createFixturePhilCore4337NonceReader,
  createPhilCore4337LocalFoundationConfiguration,
  preparePhilCore4337UserOperation,
  summarizePhilCore4337UserOperationDraft,
  verifyPhilCore4337Foundation
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");
const { keccak256 } = require("ethers");

const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const FACTORY = "0x1000000000000000000000000000000000004337";
const OWNER = "0x1000000000000000000000000000000000000001";
const ACCOUNT = "0x1000000000000000000000000000000000000002";
const ACTION_GATE = "0x1000000000000000000000000000000000000003";
const OWNER_COMMITMENT = `0x${"11".repeat(32)}`;
const PROOF_INPUT_HASH = `0x${"22".repeat(32)}`;
const NULLIFIER = `0x${"33".repeat(32)}`;

function hasArg(name) {
  return process.argv.includes(name);
}

function futureDate(ms = 300_000) {
  return new Date(Date.now() + ms).toISOString();
}

async function buildDiagnostic() {
  const foundation = createPhilCore4337LocalFoundationConfiguration({
    chainId: 31337,
    entryPointAddress: ENTRY_POINT,
    factoryAddress: FACTORY,
    approvedActionGateAddress: ACTION_GATE,
    owner: OWNER,
    ownerCommitment: OWNER_COMMITMENT
  });
  const foundationValidation = verifyPhilCore4337Foundation(foundation);
  const baseExecutionDraft = createBaseExecutionDraftFixture({
    actionGateAddress: ACTION_GATE,
    senderAccount: ACCOUNT,
    ownerCommitment: OWNER_COMMITMENT,
    proofInputHash: PROOF_INPUT_HASH,
    nullifier: NULLIFIER,
    chainId: 31337,
    calldata: "0xb195206101"
  });
  const result = await preparePhilCore4337UserOperation({
    requestId: "diagnostic-m9-userop-preparation",
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
      owner: OWNER,
      ownerCommitment: OWNER_COMMITMENT,
      approvedActionGate: ACTION_GATE
    }),
    nonceReader: createFixturePhilCore4337NonceReader("0"),
    gasEstimator: createFixturePhilCore4337GasEstimator(),
    prefundReader: createFixturePhilCore4337PrefundReader(),
    issuedAt: new Date().toISOString(),
    expiresAt: futureDate(),
    auditCorrelationId: "diagnostic-m9-userop-audit"
  });

  if (result.status !== "approved") {
    return {
      status: result.status,
      error: result.error,
      foundationValid: foundationValidation.valid,
      userOperationPrepared: false,
      userOperationSigned: false,
      userOperationSubmitted: false
    };
  }
  return {
    ...summarizePhilCore4337UserOperationDraft(result.value),
    status: result.status,
    entryPointVersion: PHILCORE_4337_ENTRYPOINT_VERSION,
    foundationValid: foundationValidation.valid,
    acpStatus: foundation.acpStatus,
    account: ACCOUNT,
    factory: FACTORY,
    actionGate: ACTION_GATE,
    signature: result.value.userOperation.signature === PHILCORE_4337_EMPTY_BYTES
      ? "unresolved"
      : "unexpected",
    paymaster: "disabled",
    noBundlerSubmission: !result.value.bundlerSubmissionPerformed,
    noBaseMutation: !result.value.baseStateMutated
  };
}

buildDiagnostic()
  .then((diagnostic) => {
    if (hasArg("--json")) {
      process.stdout.write(`${JSON.stringify(diagnostic, null, 2)}\n`);
      return;
    }
    process.stdout.write([
      "PhilCore ERC-4337 UserOperation preparation diagnostic",
      `EntryPoint v${diagnostic.entryPointVersion}`,
      `ACP status: ${diagnostic.acpStatus}`,
      `Account: ${diagnostic.account}`,
      `Factory: ${diagnostic.factory}`,
      `ActionGate target: ${diagnostic.actionGate}`,
      `UserOperation hash: ${diagnostic.userOperationHash}`,
      `UserOperation prepared: ${diagnostic.userOperationPrepared}`,
      "UserOperation not signed",
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
