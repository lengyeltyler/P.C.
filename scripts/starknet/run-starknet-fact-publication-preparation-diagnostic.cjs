const fs = require("node:fs");
const path = require("node:path");

const {
  createFixtureStarknetNonceReader,
  createFixtureStarknetTransactionFeeEstimator,
  prepareStarknetFactPublicationTransaction
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const PUBLICATION_CONTRACT = "0x5048494c";
const L1_RECIPIENT = "0x4c315f54525553545f414e43484f52";
const PUBLISHER_ACCOUNT = "0x12345";

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(REPO_ROOT, relativePath), "utf8"));
}

function now() {
  return new Date().toISOString();
}

function futureDate(ms = 60_000) {
  return new Date(Date.now() + ms).toISOString();
}

function finalizedPackage() {
  return {
    finalizedAuthorizationPackageId: "alpha0-starknet-finalized-package",
    status: "authorization_package_finalized",
    outcome: "authorization_package_finalized",
    binding: {
      authorizationPackageDraftId: "alpha0-starknet-package-draft",
      proofGenerationArtifactId: "alpha0-starknet-proof-generation",
      proofVerificationResultId: "alpha0-starknet-proof-verification",
      sessionId: "alpha0-starknet-session",
      applicationId: "ethereum-net",
      intentId: "alpha0-starknet-intent",
      capabilityName: "request_transaction_submission",
      ownerCommitment: "0xeabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6",
      proofInputHash: PROOF_INPUT_HASH,
      auditCorrelationId: "alpha0-starknet-audit"
    },
    actionUnlockAuthorization: {
      version: "v1",
      proofType: "stwo-unlock-keccak-v1",
      ownerCommitment: "0xeabc46426af38005e06573556996c697727a37a4dee2facade7ee6b21f34f7f6",
      actionHash: "0xd5d0b728949459873e285251af92184e4697ce9fef42838314e021c76837981c",
      policyHash: "0xc427bdc4dc8a7e133577265d90328a2a3678cd85d354d9f49acf2ec72d893476",
      nullifier: "0x98babeb39173de519d32e7f5c9f9212cc992b4ce34c28f85978ba0af093a4f06",
      consumerDataHash: "0x2083576b1bd13af43e74b048befa382eb9b540dcc1bb952b4c0b3133aebd10e1",
      expiry: "1900000000",
      proofInputHash: PROOF_INPUT_HASH,
      factShapeReference: "[fact_high, fact_low]"
    },
    proofArtifact: {
      proofArtifactId: "alpha0-starknet-proof-artifact",
      proofGenerationArtifactId: "alpha0-starknet-proof-generation",
      proofVerificationResultId: "alpha0-starknet-proof-verification",
      proofType: "stwo-unlock-keccak-v1",
      proofDigest: "0x1111111111111111111111111111111111111111111111111111111111111111",
      proofByteLength: 482389,
      proofInputHash: PROOF_INPUT_HASH,
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
      factShapeValidated: true
    },
    factShapePreview: {
      proofInputHash: PROOF_INPUT_HASH,
      factHigh: FACT_HIGH,
      factLow: FACT_LOW,
      factShapeReference: "[fact_high, fact_low]"
    },
    validity: {
      issuedAt: now(),
      expiresAt: futureDate(),
      expired: false
    },
    limitations: ["diagnostic_only"],
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
}

function config(fixtureResolved) {
  const configValue = readJson("config/starknet-publication-config.local.json");
  if (!fixtureResolved) return configValue;
  configValue.artifactBinding.starknetClassHash = "0x123456789abcdef";
  configValue.artifactBinding.compiledClassHash = "0xabcdef123456789";
  configValue.l1RecipientBinding.configuredL1RecipientAddress = L1_RECIPIENT;
  configValue.expectedL2SenderBinding.status = "resolved";
  configValue.expectedL2SenderBinding.publicationContractAddress = PUBLICATION_CONTRACT;
  configValue.expectedL2SenderBinding.expectedL1AnchorSenderReference = PUBLICATION_CONTRACT;
  configValue.accountCallerModel.status = "resolved";
  configValue.accountCallerModel.accountAddress = PUBLISHER_ACCOUNT;
  configValue.networkProfiles.local_devnet.usableForTransactionPreparation = true;
  configValue.networkProfiles.local_devnet.publicationContractDeploymentStatus = "deployed";
  configValue.networkProfiles.local_devnet.l1AnchorAddressStatus = "configured";
  return configValue;
}

function summarize(result) {
  if (result.status !== "approved") {
    return {
      status: result.status,
      outcome: result.error?.details?.outcome,
      errorCode: result.error?.code,
      transactionPrepared: false,
      transactionSigned: false,
      transactionSubmitted: false,
      messageEmitted: false,
      l1AnchorCalled: false,
      baseCalled: false
    };
  }
  const draft = result.value;
  return {
    status: result.status,
    outcome: draft.outcome,
    networkProfile: draft.binding.configProfileId,
    publicationContract: draft.call.contractAddress,
    entrypoint: draft.call.entrypoint,
    selector: draft.call.selector,
    calldataHash: draft.call.calldataHash,
    proofInputHash: draft.binding.proofInputHash,
    factHigh: draft.binding.factHigh,
    factLow: draft.binding.factLow,
    l1Recipient: draft.messagePreview.destinationL1Address,
    accountModel: draft.account.accountModel,
    nonceStatus: draft.unsignedInvokeTransaction.nonce.status,
    feeStatus: draft.unsignedInvokeTransaction.fee.status,
    resourceBoundsStatus: draft.unsignedInvokeTransaction.resourceBounds.status,
    transactionPrepared: draft.transactionPrepared,
    transactionSigned: draft.transactionSigned,
    transactionSubmitted: draft.transactionSubmitted,
    messageEmitted: draft.l2ToL1MessageEmitted,
    l1AnchorCalled: false,
    baseCalled: false,
    chainStateMutated: draft.chainStateMutated
  };
}

function main() {
  const json = process.argv.includes("--json");
  const fixtureResolved = process.argv.includes("--fixture-resolved");
  const result = prepareStarknetFactPublicationTransaction({
    requestId: "alpha0-starknet-publication-preparation",
    finalizedAuthorizationPackage: finalizedPackage(),
    publicationConfig: config(fixtureResolved),
    readinessManifest: readJson("config/starknet-publication-readiness.json"),
    proofInputHashSliceArgs: readJson("proving/out/cairo_air_adapter_spike/proof_input_hash_slice_verify_args.json"),
    proofInputHashSliceSummary: readJson("proving/out/cairo_air_adapter_spike/summary.json"),
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "alpha0-starknet-preparation",
    feeEstimator: fixtureResolved ? createFixtureStarknetTransactionFeeEstimator({
      feeToken: "STRK",
      estimatedFee: "0x100",
      l1Gas: "0x1",
      l1DataGas: "0x2",
      l2Gas: "0x3",
      freshUntil: futureDate()
    }) : undefined,
    nonceReader: fixtureResolved ? createFixtureStarknetNonceReader("0x7", futureDate()) : undefined
  }, REPO_ROOT);
  const summary = summarize(result);
  if (json) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("PhilCore Alpha 0 Starknet fact-publication preparation diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`- ${key}: ${value}`);
  }
}

main();
