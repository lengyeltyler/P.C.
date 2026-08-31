const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");
const { ethers } = hre;

const { deployContract } = require("../../test/helpers/context.cjs");
const {
  buildMintClaimIndex
} = require("./export-mint-claim-index.cjs");
const {
  buildMintClaimIndexConsumption
} = require("./consume-mint-claim-index.cjs");
const {
  buildMintClaimStatus
} = require("./build-mint-claim-status.cjs");
const {
  resolveMintClaimStatusByNullifier
} = require("./lookup-mint-claim-status.cjs");
const {
  resolveMintClaimStatusOrNotFound
} = require("./lookup-mint-claim-status-miss.cjs");
const {
  resolveMintClaimStatusesByRecipient
} = require("./lookup-mint-claim-status-by-recipient.cjs");
const {
  buildMintRecipientOnboarding
} = require("./build-mint-recipient-onboarding.cjs");
const {
  buildMintOnboardingBundle
} = require("./build-mint-onboarding-bundle.cjs");
const {
  consumeMintOnboardingBundle
} = require("./consume-mint-onboarding-bundle.cjs");
const {
  buildMintOnboardingReadiness
} = require("./build-mint-onboarding-readiness.cjs");
const { buildMintIntent } = require("./build-mint-intent.cjs");
const {
  buildMintIntentConsumption
} = require("./consume-mint-intent.cjs");
const {
  buildMintIntentStatus
} = require("./build-mint-intent-status.cjs");
const { buildWalletInput } = require("./build-wallet-input.cjs");
const {
  buildWalletInputConsumption
} = require("./consume-wallet-input.cjs");
const { buildWalletArtifact } = require("./build-wallet-artifact.cjs");
const {
  buildSmartAccountTarget
} = require("./build-smart-account-target.cjs");
const { buildSmartAccountInit } = require("./build-smart-account-init.cjs");
const {
  buildSmartAccountDeployPlan
} = require("./build-smart-account-deploy-plan.cjs");
const {
  buildSmartAccountDeployRequest
} = require("./build-smart-account-deploy-request.cjs");
const {
  buildSmartAccountDeployEnvelope
} = require("./build-smart-account-deploy-envelope.cjs");
const {
  buildSmartAccountDeployPayload
} = require("./build-smart-account-deploy-payload.cjs");
const {
  buildSmartAccountDeployTransport
} = require("./build-smart-account-deploy-transport.cjs");
const {
  buildSmartAccountDeploySubmit
} = require("./build-smart-account-deploy-submit.cjs");
const {
  buildSmartAccountDeployUserOp
} = require("./build-smart-account-deploy-userop.cjs");
const {
  buildSmartAccountDeployUserOpHash
} = require("./build-smart-account-deploy-userop-hash.cjs");
const {
  buildSmartAccountDeploySignatureRequest
} = require("./build-smart-account-deploy-signature-request.cjs");
const {
  buildSmartAccountDeploySignedUserOp
} = require("./build-smart-account-deploy-signed-userop.cjs");
const {
  buildSmartAccountDeployBundlerSubmission
} = require("./build-smart-account-deploy-bundler-submission.cjs");
const {
  buildSmartAccountDeployEndpointSubmission
} = require("./build-smart-account-deploy-endpoint-submission.cjs");
const {
  buildSmartAccountDeployClientSession
} = require("./build-smart-account-deploy-client-session.cjs");
const {
  buildSmartAccountDeployDispatchIntent
} = require("./build-smart-account-deploy-dispatch-intent.cjs");
const {
  buildSmartAccountDeployDispatchCommand
} = require("./build-smart-account-deploy-dispatch-command.cjs");
const {
  buildSmartAccountDeployDispatchAttempt
} = require("./build-smart-account-deploy-dispatch-attempt.cjs");
const {
  runSmartAccountDeployAttemptRunner
} = require("./run-smart-account-deploy-attempt-runner.cjs");
const {
  runLocalBaseMirrorDeployment
} = require("./run-local-base-mirror-deployment.cjs");
const {
  runLocalSmartAccountDeploySigning
} = require("./run-local-smart-account-deploy-signing.cjs");

const REPO_ROOT = path.resolve(__dirname, "../..");
const OUT_ROOT = path.join(REPO_ROOT, "proving/out");
const UNLOCK_VECTOR_PATH = path.join(
  REPO_ROOT,
  "proving/fixtures/unlock_keccak_vector.json"
);
const LOCAL_DEV_EXTERNAL_SIGNATURE = `0x${"11".repeat(64)}1b`;
const L1_TRUST_ANCHOR_BOUNDARY = "0x4c315f54525553545f414e43484f52";
const STARKNET_CONTRACT_ADDRESS = "0x5048494c";
const CONSUMER_DATA = ethers.hexlify(
  ethers.toUtf8Bytes("phase3.4-consumer-data")
);

function outPath(...segments) {
  return path.join(OUT_ROOT, ...segments);
}

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function writeJson(jsonPath, value) {
  fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(value, null, 2)}\n`);
}

function copyJson(sourcePath, destinationPath) {
  writeJson(destinationPath, loadJson(sourcePath));
}

function hexUint(value) {
  return `0x${value.toString(16)}`;
}

function splitProofInputHash(proofInputHash) {
  const normalized = BigInt(proofInputHash);
  return {
    factHigh: hexUint(normalized >> 128n),
    factLow: hexUint(normalized & ((1n << 128n) - 1n))
  };
}

function buildSummaryAndRelayFixtures() {
  const vector = loadJson(UNLOCK_VECTOR_PATH);
  const { factHigh, factLow } = splitProofInputHash(vector.proofInputHashValue);
  const summary = {
    version: vector.version,
    proofType: vector.proofType,
    publicInputs: vector.publicInputs,
    proofInputHashPreimage: vector.proofInputHashPreimage,
    proofInputHash: vector.proofInputHashValue,
    expectedFactPayload: [factHigh, factLow],
    proofInputHashSliceProof: {
      source: "proving/fixtures/unlock_keccak_vector.json",
      localFixtureOnly: true
    }
  };
  const relayOutput = {
    function:
      "phil_starknet_integration::run_verify_proof_input_hash_slice_and_send_to_l1_via_contract_syscalls",
    contract_address: STARKNET_CONTRACT_ADDRESS,
    l1_recipient: L1_TRUST_ANCHOR_BOUNDARY,
    returned_fact_high: factHigh,
    returned_fact_low: factLow,
    emitted_fact_high: factHigh,
    emitted_fact_low: factLow,
    relayed_fact_high: factHigh,
    relayed_fact_low: factLow,
    relayed_to_address: L1_TRUST_ANCHOR_BOUNDARY,
    expected_fact_high: factHigh,
    expected_fact_low: factLow,
    syscalls: {
      SendMessageToL1: 1
    }
  };

  writeJson(outPath("cairo_air_adapter_spike/summary.json"), summary);
  writeJson(outPath("starknet_l1_relay/harness_output.json"), relayOutput);

  return { summary, relayOutput };
}

function proofBlobForFact(factHigh, factLow) {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "uint256"],
    [BigInt(factHigh), BigInt(factLow)]
  );
}

function canonicalAuthorization({ summary, consumerAddress }) {
  return {
    consumer: consumerAddress,
    ownerCommitment: summary.publicInputs.ownerCommitment,
    actionHash: summary.publicInputs.actionHash,
    policyHash: summary.publicInputs.policyHash,
    nullifier: summary.publicInputs.nullifier,
    consumerDataHash: summary.publicInputs.consumerDataHash,
    expiry: BigInt(summary.publicInputs.expiry)
  };
}

function canonicalProofPackage({ summary, factHigh, factLow }) {
  return {
    version: summary.version,
    proofType: summary.proofType,
    publicInputs: {
      ownerCommitment: summary.publicInputs.ownerCommitment,
      actionHash: summary.publicInputs.actionHash,
      policyHash: summary.publicInputs.policyHash,
      nullifier: summary.publicInputs.nullifier,
      consumerDataHash: summary.publicInputs.consumerDataHash,
      expiry: BigInt(summary.publicInputs.expiry)
    },
    proofInputHash: summary.proofInputHash,
    proofBlob: proofBlobForFact(factHigh, factLow)
  };
}

async function setupMirroredFactPath({ deployer, relayOutput }) {
  const messaging = await deployContract(deployer, "MockStarknetMessaging");
  const trustAnchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
    await messaging.getAddress(),
    BigInt(relayOutput.contract_address)
  ]);
  const factHigh = BigInt(relayOutput.relayed_fact_high);
  const factLow = BigInt(relayOutput.relayed_fact_low);

  await (
    await messaging.registerMessageFromL2(
      BigInt(relayOutput.contract_address),
      await trustAnchor.getAddress(),
      [factHigh, factLow]
    )
  ).wait();
  await (await trustAnchor.consumeProofInputHashFactFromL2(factHigh, factLow)).wait();

  const { crossDomainMessengerAdapter, baseMirror } =
    await runLocalBaseMirrorDeployment({
      signer: deployer,
      networkName: "hardhat"
    });
  const l1Messenger = await deployContract(deployer, "PhilL1ToBaseProofInputHashMessenger", [
    await trustAnchor.getAddress(),
    await crossDomainMessengerAdapter.getAddress()
  ]);
  await (
    await l1Messenger.relayProofInputHashFactToBase(
      await baseMirror.getAddress(),
      factHigh,
      factLow
    )
  ).wait();

  const verifier = await deployContract(deployer, "PhilBaseMirroredFactUnlockProofVerifier", [
    await baseMirror.getAddress()
  ]);
  const gate = await deployContract(deployer, "PhilBaseActionGate", [
    await verifier.getAddress()
  ]);

  return { factHigh, factLow, gate };
}

async function buildLocalRegressionArtifacts({ summary, relayOutput }) {
  const [deployer] = await ethers.getSigners();
  const { factHigh, factLow, gate } = await setupMirroredFactPath({
    deployer,
    relayOutput
  });
  const mintConsumer = await deployContract(deployer, "PhilMintPassConsumer", [
    await gate.getAddress()
  ]);
  const authorization = canonicalAuthorization({
    summary,
    consumerAddress: await mintConsumer.getAddress()
  });
  const onboardingRecipient = buildMintRecipientOnboarding({
    ownerCommitment: summary.publicInputs.ownerCommitment,
    consumerData: CONSUMER_DATA,
    expectedBaseRecipient: await mintConsumer.previewBoundMintRecipient(
      authorization,
      CONSUMER_DATA
    )
  });
  const proofPackage = canonicalProofPackage({
    summary,
    factHigh,
    factLow
  });
  const [previewRecipient, previewTokenId] = await mintConsumer.previewMintClaim(
    authorization,
    CONSUMER_DATA
  );

  await (await gate.verifyAndConsume(authorization, proofPackage, CONSUMER_DATA)).wait();
  const [minted, claimedRecipient, claimedTokenId] =
    await mintConsumer.getMintClaim(summary.publicInputs.nullifier);
  const mintClaimSource = {
    version: 1,
    path: "phil-mint-claim-source",
    networkName: "hardhat",
    proofType: summary.proofType,
    payloadShape: "[fact_high, fact_low]",
    authorization: {
      ownerCommitment: summary.publicInputs.ownerCommitment,
      actionHash: summary.publicInputs.actionHash,
      policyHash: summary.publicInputs.policyHash,
      nullifier: summary.publicInputs.nullifier,
      consumerDataHash: summary.publicInputs.consumerDataHash,
      expiry: Number(summary.publicInputs.expiry)
    },
    factPayload: {
      factHigh: relayOutput.relayed_fact_high,
      factLow: relayOutput.relayed_fact_low
    },
    claimPreview: {
      recipient: previewRecipient,
      tokenId: Number(previewTokenId)
    },
    claimRecord: {
      minted,
      recipient: claimedRecipient,
      tokenId: Number(claimedTokenId)
    }
  };

  const mintClaimIndex = buildMintClaimIndex({ mintClaimSource });
  const mintIndexConsumption = buildMintClaimIndexConsumption({ mintClaimIndex });
  const mintIndexStatus = buildMintClaimStatus({
    mintClaimConsumption: mintIndexConsumption
  });
  const mintIndexLookup = resolveMintClaimStatusByNullifier({
    mintClaimStatus: mintIndexStatus,
    nullifier: summary.publicInputs.nullifier
  });
  const mintIndexLookupMiss = resolveMintClaimStatusOrNotFound({
    mintClaimStatus: mintIndexStatus,
    nullifier: `0x${"ff".repeat(32)}`
  });
  const mintIndexRecipientLookup = resolveMintClaimStatusesByRecipient({
    mintClaimStatus: mintIndexStatus,
    recipient: onboardingRecipient.derivedRecipient
  });
  const onboardingBundle = buildMintOnboardingBundle({ onboardingRecipient });
  const onboardingBundleConsumption = consumeMintOnboardingBundle({
    onboardingBundle
  });
  const onboardingReadiness = buildMintOnboardingReadiness({
    onboardingBundleConsumption
  });
  const mintIntent = buildMintIntent({ onboardingReadiness });
  const mintIntentConsumption = buildMintIntentConsumption({ mintIntent });
  const mintIntentStatus = buildMintIntentStatus({ mintIntentConsumption });
  const walletInput = buildWalletInput({ mintIntentStatus });
  const walletInputConsumption = buildWalletInputConsumption({ walletInput });
  const walletArtifact = buildWalletArtifact({ walletInputConsumption });
  const smartAccountTarget = buildSmartAccountTarget({ walletArtifact });
  const smartAccountInit = buildSmartAccountInit({ smartAccountTarget });
  const smartAccountDeployPlan = buildSmartAccountDeployPlan({
    smartAccountInit
  });
  const smartAccountDeployRequest = buildSmartAccountDeployRequest({
    smartAccountDeployPlan
  });
  const smartAccountDeployEnvelope = buildSmartAccountDeployEnvelope({
    smartAccountDeployRequest
  });
  const smartAccountDeployPayload = buildSmartAccountDeployPayload({
    smartAccountDeployEnvelope
  });
  const smartAccountDeployTransport = buildSmartAccountDeployTransport({
    smartAccountDeployPayload
  });
  const smartAccountDeploySubmit = buildSmartAccountDeploySubmit({
    smartAccountDeployTransport
  });
  const smartAccountDeployUserOp = buildSmartAccountDeployUserOp({
    smartAccountDeploySubmit
  });
  const smartAccountDeployUserOpHash = buildSmartAccountDeployUserOpHash({
    smartAccountDeployUserOp
  });
  const smartAccountDeploySignatureRequest =
    buildSmartAccountDeploySignatureRequest({
      smartAccountDeployUserOpHash
    });
  const smartAccountDeploySignedUserOp = buildSmartAccountDeploySignedUserOp({
    smartAccountDeploySignatureRequest,
    externalSignature: LOCAL_DEV_EXTERNAL_SIGNATURE
  });
  const smartAccountDeployBundlerSubmission =
    buildSmartAccountDeployBundlerSubmission({
      smartAccountDeploySignedUserOp
    });
  const smartAccountDeployEndpointSubmission =
    buildSmartAccountDeployEndpointSubmission({
      smartAccountDeployBundlerSubmission
    });
  const smartAccountDeployClientSession = buildSmartAccountDeployClientSession({
    smartAccountDeployEndpointSubmission
  });
  const smartAccountDeployDispatchIntent =
    buildSmartAccountDeployDispatchIntent({
      smartAccountDeployClientSession
    });
  const smartAccountDeployDispatchCommand =
    buildSmartAccountDeployDispatchCommand({
      smartAccountDeployDispatchIntent
    });
  const smartAccountDeployDispatchAttempt =
    buildSmartAccountDeployDispatchAttempt({
      smartAccountDeployDispatchCommand
    });
  const smartAccountDeployAttemptRunner = runSmartAccountDeployAttemptRunner({
    smartAccountDeployDispatchAttempt
  });

  const artifacts = [
    ["mint_claim_source/local_regression_claim_source.json", mintClaimSource],
    ["mint_index_export/local_regression_mint_index.json", mintClaimIndex],
    [
      "mint_index_consume/local_regression_mint_index_consumption.json",
      mintIndexConsumption
    ],
    ["mint_index_status/local_regression_mint_index_status.json", mintIndexStatus],
    ["mint_index_lookup/local_regression_mint_index_lookup.json", mintIndexLookup],
    [
      "mint_index_lookup_miss/local_regression_mint_index_lookup_miss.json",
      mintIndexLookupMiss
    ],
    [
      "mint_index_recipient_lookup/local_regression_mint_index_recipient_lookup.json",
      mintIndexRecipientLookup
    ],
    [
      "onboarding_recipient/local_regression_mint_recipient_onboarding.json",
      onboardingRecipient
    ],
    [
      "onboarding_bundle/local_regression_mint_onboarding_bundle.json",
      onboardingBundle
    ],
    [
      "onboarding_bundle_consume/local_regression_mint_onboarding_bundle_consumption.json",
      onboardingBundleConsumption
    ],
    [
      "onboarding_readiness/local_regression_mint_onboarding_readiness.json",
      onboardingReadiness
    ],
    ["mint_intent/local_regression_mint_intent.json", mintIntent],
    [
      "mint_intent_consume/local_regression_mint_intent_consumption.json",
      mintIntentConsumption
    ],
    ["mint_intent_status/local_regression_mint_intent_status.json", mintIntentStatus],
    ["wallet_input/local_regression_wallet_input.json", walletInput],
    [
      "wallet_input_consume/local_regression_wallet_input_consumption.json",
      walletInputConsumption
    ],
    ["wallet_artifact/local_regression_wallet_artifact.json", walletArtifact],
    ["smart_account_target/local_regression_smart_account_target.json", smartAccountTarget],
    ["smart_account_init/local_regression_smart_account_init.json", smartAccountInit],
    [
      "smart_account_deploy_plan/local_regression_smart_account_deploy_plan.json",
      smartAccountDeployPlan
    ],
    [
      "smart_account_deploy_request/local_regression_smart_account_deploy_request.json",
      smartAccountDeployRequest
    ],
    [
      "smart_account_deploy_envelope/local_regression_smart_account_deploy_envelope.json",
      smartAccountDeployEnvelope
    ],
    [
      "smart_account_deploy_payload/local_regression_smart_account_deploy_payload.json",
      smartAccountDeployPayload
    ],
    [
      "smart_account_deploy_transport/local_regression_smart_account_deploy_transport.json",
      smartAccountDeployTransport
    ],
    [
      "smart_account_deploy_submit/local_regression_smart_account_deploy_submit.json",
      smartAccountDeploySubmit
    ],
    [
      "smart_account_deploy_userop/local_regression_smart_account_deploy_userop.json",
      smartAccountDeployUserOp
    ],
    [
      "smart_account_deploy_userop_hash/local_regression_smart_account_deploy_userop_hash.json",
      smartAccountDeployUserOpHash
    ],
    [
      "smart_account_deploy_signature_request/local_regression_smart_account_deploy_signature_request.json",
      smartAccountDeploySignatureRequest
    ],
    [
      "smart_account_deploy_signed_userop/local_regression_smart_account_deploy_signed_userop.json",
      smartAccountDeploySignedUserOp
    ],
    [
      "smart_account_deploy_bundler_submission/local_regression_smart_account_deploy_bundler_submission.json",
      smartAccountDeployBundlerSubmission
    ],
    [
      "smart_account_deploy_endpoint_submission/local_regression_smart_account_deploy_endpoint_submission.json",
      smartAccountDeployEndpointSubmission
    ],
    [
      "smart_account_deploy_client_session/local_regression_smart_account_deploy_client_session.json",
      smartAccountDeployClientSession
    ],
    [
      "smart_account_deploy_dispatch_intent/local_regression_smart_account_deploy_dispatch_intent.json",
      smartAccountDeployDispatchIntent
    ],
    [
      "smart_account_deploy_dispatch_command/local_regression_smart_account_deploy_dispatch_command.json",
      smartAccountDeployDispatchCommand
    ],
    [
      "smart_account_deploy_dispatch_attempt/local_regression_smart_account_deploy_dispatch_attempt.json",
      smartAccountDeployDispatchAttempt
    ],
    [
      "smart_account_deploy_attempt_runner/local_regression_smart_account_deploy_attempt_runner.json",
      smartAccountDeployAttemptRunner
    ]
  ];

  for (const [relativePath, artifact] of artifacts) {
    writeJson(outPath(relativePath), artifact);
  }

  writeJson(
    outPath("smart_account_deploy_signature_request/smart_account_deploy_signature_request.json"),
    smartAccountDeploySignatureRequest
  );
  writeJson(
    outPath("smart_account_deploy_attempt_runner/smart_account_deploy_attempt_runner.json"),
    smartAccountDeployAttemptRunner
  );

  return smartAccountDeploySignatureRequest;
}

function buildLocalDeviceSigningArtifact(smartAccountDeploySignatureRequest) {
  const localDeviceSigning = runLocalSmartAccountDeploySigning({
    smartAccountDeploySignatureRequest,
    now: () => "2026-04-24T00:00:00.000Z"
  });
  writeJson(
    outPath("local_device_signing/local_device_signing_result.json"),
    localDeviceSigning
  );
  return localDeviceSigning;
}

async function generateLocalFixtures() {
  const { summary, relayOutput } = buildSummaryAndRelayFixtures();
  const smartAccountDeploySignatureRequest =
    await buildLocalRegressionArtifacts({ summary, relayOutput });
  const localDeviceSigning = buildLocalDeviceSigningArtifact(
    smartAccountDeploySignatureRequest
  );

  copyJson(
    outPath("smart_account_deploy_signature_request/smart_account_deploy_signature_request.json"),
    outPath("smart_account_deploy_signature_request/local_regression_smart_account_deploy_signature_request.json")
  );

  return {
    version: 1,
    path: "phil-local-fixture-generation",
    generatedRoot: OUT_ROOT,
    generatedArtifacts: {
      summary: outPath("cairo_air_adapter_spike/summary.json"),
      relay: outPath("starknet_l1_relay/harness_output.json"),
      signatureRequest: outPath(
        "smart_account_deploy_signature_request/smart_account_deploy_signature_request.json"
      ),
      attemptRunner: outPath(
        "smart_account_deploy_attempt_runner/smart_account_deploy_attempt_runner.json"
      ),
      localDeviceSigning: outPath(
        "local_device_signing/local_device_signing_result.json"
      )
    },
    signatureRequestId:
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestId,
    localDeviceSigningId:
      localDeviceSigning.localDeviceSigning.localDeviceSigningId
  };
}

if (require.main === module) {
  generateLocalFixtures()
    .then((result) => {
      console.log(JSON.stringify(result, null, 2));
    })
    .catch((error) => {
      console.error(String(error && error.message ? error.message : error));
      process.exit(1);
    });
}

module.exports = {
  generateLocalFixtures
};
