const fs = require("node:fs");
const path = require("node:path");

const {
  createFixtureStarknetNonceReader,
  createFixtureStarknetPublisherSigner,
  createFixtureStarknetTransactionFeeEstimator,
  createStarknetPublicationSigningPresentation,
  prepareStarknetFactPublicationTransaction,
  requestStarknetFactPublicationTransactionSigning,
  validateSigningFeeFreshness
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const PROOF_INPUT_HASH = "0x8d5607b595200f66c7d24010dc79d646b0c7469cdaca5eecbbabb83d326413d2";
const FACT_HIGH = "0x8d5607b595200f66c7d24010dc79d646";
const FACT_LOW = "0xb0c7469cdaca5eecbbabb83d326413d2";
const PUBLICATION_CONTRACT = "0x5048494c";
const L1_RECIPIENT = "0x4c315f54525553545f414e43484f52";
const PUBLISHER_ACCOUNT = "0x12345";
const PRIVATE_KEY = "0x1";

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

function resourceBounds() {
  return {
    l1_gas: { max_amount: "0x1", max_price_per_unit: "0x2" },
    l2_gas: { max_amount: "0x3", max_price_per_unit: "0x4" },
    l1_data_gas: { max_amount: "0x2", max_price_per_unit: "0x1" }
  };
}

function policy(draft) {
  return {
    allowedModes: ["developer_fixture", "infrastructure_operator"],
    allowedNetworkProfileIds: ["local_devnet"],
    allowedPublicationContractAddresses: [draft.call.contractAddress],
    allowedFeeToken: "STRK",
    maxOverallFee: "0x100",
    maxResourceBounds: {
      l1_gas: { max_amount: "0x10", max_price_per_unit: "0x10" },
      l2_gas: { max_amount: "0x10", max_price_per_unit: "0x10" },
      l1_data_gas: { max_amount: "0x10", max_price_per_unit: "0x10" }
    },
    allowMainnet: false,
    allowedApprovalSources: ["developer_fixture_approval"],
    requireFreshNonce: true,
    requireFreshFee: true
  };
}

function summarize(result) {
  if (result.status !== "approved") {
    return {
      status: result.status,
      outcome: result.error?.details?.outcome,
      errorCode: result.error?.code,
      transactionSigned: false,
      transactionSubmitted: false,
      messageEmitted: false,
      chainStateMutated: false
    };
  }
  const artifact = result.value;
  return {
    status: result.status,
    outcome: artifact.outcome,
    networkProfile: artifact.binding.networkProfileId,
    publisherModel: "developer_fixture",
    senderAccount: artifact.binding.accountAddress,
    publicationContract: artifact.binding.publicationContractAddress,
    entrypoint: artifact.binding.entrypoint,
    transactionHash: artifact.transactionHash,
    calldataHash: artifact.binding.calldataHash,
    nonce: artifact.binding.nonce,
    feeStatus: "fresh",
    resourceBoundsStatus: "fresh",
    approvalSource: "developer_fixture_approval",
    transactionSigned: artifact.transactionSigned,
    transactionSubmitted: artifact.transactionSubmitted,
    messageEmitted: artifact.l2ToL1MessageEmitted,
    chainStateMutated: artifact.chainStateMutated
  };
}

async function main() {
  const json = process.argv.includes("--json");
  const fixtureResolved = process.argv.includes("--fixture-resolved");
  const prep = prepareStarknetFactPublicationTransaction({
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
      estimatedFee: "0x20",
      l1Gas: "0x1",
      l1DataGas: "0x2",
      l2Gas: "0x3",
      freshUntil: futureDate()
    }) : undefined,
    nonceReader: fixtureResolved ? createFixtureStarknetNonceReader("0x7", futureDate()) : undefined
  }, REPO_ROOT);
  if (prep.status !== "approved") {
    const summary = summarize(prep);
    if (json) {
      console.log(JSON.stringify(summary, null, 2));
      return;
    }
    console.log("PhilCore Alpha 0 Starknet fact-publication signing diagnostic");
    for (const [key, value] of Object.entries(summary)) {
      console.log(`- ${key}: ${value}`);
    }
    return;
  }
  const draft = prep.value;
  const signer = createFixtureStarknetPublisherSigner({
    privateKey: PRIVATE_KEY,
    accountAddress: PUBLISHER_ACCOUNT
  });
  const accountBinding = {
    accountAddress: PUBLISHER_ACCOUNT,
    networkProfileId: "local_devnet",
    chainId: "SN_LOCAL",
    publicationContractAddress: draft.call.contractAddress,
    entrypoint: "verify_proof_input_hash_slice_and_send_to_l1",
    calldataHash: draft.call.calldataHash
  };
  const policyValue = policy(draft);
  const feeValidation = {
    feeToken: "STRK",
    estimatedFee: "0x20",
    freshUntil: futureDate(),
    resourceBounds: resourceBounds()
  };
  const feeResult = validateSigningFeeFreshness({
    draft,
    policy: policyValue,
    feeToken: feeValidation.feeToken,
    estimatedFee: feeValidation.estimatedFee,
    freshUntil: feeValidation.freshUntil,
    resourceBounds: feeValidation.resourceBounds
  });
  const presentation = createStarknetPublicationSigningPresentation({
    transactionDraft: draft,
    accountBinding,
    feeValidation: feeResult,
    auditCorrelationId: "alpha0-starknet-signing"
  });
  const result = await requestStarknetFactPublicationTransactionSigning({
    requestId: "alpha0-starknet-publication-signing",
    transactionDraft: draft,
    publisherIdentity: {
      publisherId: "fixture-publisher",
      mode: "developer_fixture",
      displayName: "Fixture Publisher",
      expectedSignerPublicKey: signer.describeSigner().publicKey,
      productionSuitable: false
    },
    accountBinding,
    policy: policyValue,
    approval: {
      source: "developer_fixture_approval",
      presentationDigest: presentation.digest,
      approved: true,
      approvedAt: now(),
      expiresAt: futureDate(),
      approvalId: "fixture-approval-1"
    },
    signer,
    nonceReader: createFixtureStarknetNonceReader("0x7", futureDate()),
    feeValidation,
    issueTime: now(),
    expiresAt: futureDate(),
    auditCorrelationId: "alpha0-starknet-signing"
  });
  const summary = summarize(result);
  if (json) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }
  console.log("PhilCore Alpha 0 Starknet fact-publication signing diagnostic");
  for (const [key, value] of Object.entries(summary)) {
    console.log(`- ${key}: ${value}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
