const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");
const { ethers } = hre;

const { deployContract, expectRevert } = require("../helpers/context.cjs");
const {
  runLocalBaseMirrorDeployment
} = require("../../scripts/base/run-local-base-mirror-deployment.cjs");
const {
  buildMintClaimIndex
} = require("../../scripts/base/export-mint-claim-index.cjs");
const {
  buildMintClaimIndexConsumption
} = require("../../scripts/base/consume-mint-claim-index.cjs");
const {
  buildMintClaimStatus
} = require("../../scripts/base/build-mint-claim-status.cjs");
const {
  resolveMintClaimStatusByNullifier
} = require("../../scripts/base/lookup-mint-claim-status.cjs");
const {
  resolveMintClaimStatusOrNotFound
} = require("../../scripts/base/lookup-mint-claim-status-miss.cjs");
const {
  resolveMintClaimStatusesByRecipient
} = require("../../scripts/base/lookup-mint-claim-status-by-recipient.cjs");
const {
  buildMintRecipientOnboarding
} = require("../../scripts/base/build-mint-recipient-onboarding.cjs");
const {
  buildMintOnboardingBundle
} = require("../../scripts/base/build-mint-onboarding-bundle.cjs");
const {
  consumeMintOnboardingBundle
} = require("../../scripts/base/consume-mint-onboarding-bundle.cjs");
const {
  buildMintOnboardingReadiness
} = require("../../scripts/base/build-mint-onboarding-readiness.cjs");
const {
  buildMintIntent
} = require("../../scripts/base/build-mint-intent.cjs");
const {
  buildMintIntentConsumption
} = require("../../scripts/base/consume-mint-intent.cjs");
const {
  buildMintIntentStatus
} = require("../../scripts/base/build-mint-intent-status.cjs");
const {
  buildWalletInput
} = require("../../scripts/base/build-wallet-input.cjs");
const {
  buildWalletInputConsumption
} = require("../../scripts/base/consume-wallet-input.cjs");
const {
  WALLET_ARTIFACT_DOMAIN_LABEL,
  WALLET_ARTIFACT_DOMAIN_HASH,
  buildWalletArtifact
} = require("../../scripts/base/build-wallet-artifact.cjs");
const {
  SMART_ACCOUNT_TARGET_DOMAIN_LABEL,
  SMART_ACCOUNT_TARGET_DOMAIN_HASH,
  buildSmartAccountTarget
} = require("../../scripts/base/build-smart-account-target.cjs");
const {
  SMART_ACCOUNT_INIT_DOMAIN_LABEL,
  SMART_ACCOUNT_INIT_DOMAIN_HASH,
  buildSmartAccountInit
} = require("../../scripts/base/build-smart-account-init.cjs");
const {
  SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH,
  buildSmartAccountDeployPlan
} = require("../../scripts/base/build-smart-account-deploy-plan.cjs");
const {
  SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH,
  buildSmartAccountDeployRequest
} = require("../../scripts/base/build-smart-account-deploy-request.cjs");
const {
  SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH,
  buildSmartAccountDeployEnvelope
} = require("../../scripts/base/build-smart-account-deploy-envelope.cjs");
const {
  SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING,
  SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE,
  buildSmartAccountDeployPayload
} = require("../../scripts/base/build-smart-account-deploy-payload.cjs");
const {
  SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD,
  SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH,
  buildSmartAccountDeployTransport
} = require("../../scripts/base/build-smart-account-deploy-transport.cjs");
const {
  SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_SUBMIT_KIND,
  SMART_ACCOUNT_DEPLOY_SUBMIT_ACCEPT,
  buildSmartAccountDeploySubmit
} = require("../../scripts/base/build-smart-account-deploy-submit.cjs");
const {
  SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_USEROP_KIND,
  SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
  SMART_ACCOUNT_DEPLOY_USEROP_NONCE,
  SMART_ACCOUNT_DEPLOY_USEROP_CALL_DATA,
  SMART_ACCOUNT_DEPLOY_USEROP_MAX_FEE_PER_GAS,
  SMART_ACCOUNT_DEPLOY_USEROP_MAX_PRIORITY_FEE_PER_GAS,
  SMART_ACCOUNT_DEPLOY_USEROP_PAYMASTER_AND_DATA,
  SMART_ACCOUNT_DEPLOY_USEROP_SIGNATURE,
  buildSmartAccountDeployUserOp
} = require("../../scripts/base/build-smart-account-deploy-userop.cjs");
const {
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_FIELD,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_PLACEHOLDER,
  buildSmartAccountDeployUserOpHash
} = require("../../scripts/base/build-smart-account-deploy-userop-hash.cjs");
const {
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
  buildSmartAccountDeploySignatureRequest
} = require("../../scripts/base/build-smart-account-deploy-signature-request.cjs");
const {
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND,
  buildSmartAccountDeploySignedUserOp
} = require("../../scripts/base/build-smart-account-deploy-signed-userop.cjs");
const {
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT,
  buildSmartAccountDeployBundlerSubmission
} = require("../../scripts/base/build-smart-account-deploy-bundler-submission.cjs");
const {
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
  SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
  buildSmartAccountDeployEndpointSubmission
} = require("../../scripts/base/build-smart-account-deploy-endpoint-submission.cjs");
const {
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_LABEL,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_CHANNEL,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DISPATCH_MODE,
  SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_ATTEMPT_COUNT,
  buildSmartAccountDeployClientSession
} = require("../../scripts/base/build-smart-account-deploy-client-session.cjs");
const {
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_CHANNEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DISPATCH_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY,
  buildSmartAccountDeployDispatchIntent
} = require("../../scripts/base/build-smart-account-deploy-dispatch-intent.cjs");
const {
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_CHANNEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
  buildSmartAccountDeployDispatchCommand
} = require("../../scripts/base/build-smart-account-deploy-dispatch-command.cjs");
const {
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_LABEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_CHANNEL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STAGE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_EXECUTION_MODE,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY,
  buildSmartAccountDeployDispatchAttempt
} = require("../../scripts/base/build-smart-account-deploy-dispatch-attempt.cjs");
const {
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_KIND,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_LABEL,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CHANNEL,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STAGE,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_ACTION,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_MODE,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STEP,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CLIENT_API,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_TRANSPORT,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NEXT_ACTION,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD,
  SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD,
  runSmartAccountDeployAttemptRunner
} = require("../../scripts/base/run-smart-account-deploy-attempt-runner.cjs");
const {
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
} = require("../../scripts/base/run-local-bundler-stub.cjs");
const {
  LOCAL_DEPLOY_SESSION_KIND,
  runLocalSmartAccountDeploySession
} = require("../../scripts/base/run-local-smart-account-deploy-session.cjs");

const RELAY_OUTPUT_PATH = path.join(
  __dirname,
  "../../proving/out/starknet_l1_relay/harness_output.json"
);
const SUMMARY_PATH = path.join(
  __dirname,
  "../../proving/out/cairo_air_adapter_spike/summary.json"
);
const LOCAL_MINT_CLAIM_SOURCE_PATH = path.join(
  __dirname,
  "../../proving/out/mint_claim_source/local_regression_claim_source.json"
);
const LOCAL_MINT_INDEX_PATH = path.join(
  __dirname,
  "../../proving/out/mint_index_export/local_regression_mint_index.json"
);
const LOCAL_MINT_INDEX_CONSUME_PATH = path.join(
  __dirname,
  "../../proving/out/mint_index_consume/local_regression_mint_index_consumption.json"
);
const LOCAL_MINT_INDEX_STATUS_PATH = path.join(
  __dirname,
  "../../proving/out/mint_index_status/local_regression_mint_index_status.json"
);
const LOCAL_MINT_INDEX_LOOKUP_PATH = path.join(
  __dirname,
  "../../proving/out/mint_index_lookup/local_regression_mint_index_lookup.json"
);
const LOCAL_MINT_INDEX_LOOKUP_MISS_PATH = path.join(
  __dirname,
  "../../proving/out/mint_index_lookup_miss/local_regression_mint_index_lookup_miss.json"
);
const LOCAL_MINT_INDEX_RECIPIENT_LOOKUP_PATH = path.join(
  __dirname,
  "../../proving/out/mint_index_recipient_lookup/local_regression_mint_index_recipient_lookup.json"
);
const LOCAL_ONBOARDING_RECIPIENT_PATH = path.join(
  __dirname,
  "../../proving/out/onboarding_recipient/local_regression_mint_recipient_onboarding.json"
);
const LOCAL_ONBOARDING_BUNDLE_PATH = path.join(
  __dirname,
  "../../proving/out/onboarding_bundle/local_regression_mint_onboarding_bundle.json"
);
const LOCAL_ONBOARDING_BUNDLE_CONSUME_PATH = path.join(
  __dirname,
  "../../proving/out/onboarding_bundle_consume/local_regression_mint_onboarding_bundle_consumption.json"
);
const LOCAL_ONBOARDING_READINESS_PATH = path.join(
  __dirname,
  "../../proving/out/onboarding_readiness/local_regression_mint_onboarding_readiness.json"
);
const LOCAL_MINT_INTENT_PATH = path.join(
  __dirname,
  "../../proving/out/mint_intent/local_regression_mint_intent.json"
);
const LOCAL_MINT_INTENT_CONSUME_PATH = path.join(
  __dirname,
  "../../proving/out/mint_intent_consume/local_regression_mint_intent_consumption.json"
);
const LOCAL_MINT_INTENT_STATUS_PATH = path.join(
  __dirname,
  "../../proving/out/mint_intent_status/local_regression_mint_intent_status.json"
);
const LOCAL_WALLET_INPUT_PATH = path.join(
  __dirname,
  "../../proving/out/wallet_input/local_regression_wallet_input.json"
);
const LOCAL_WALLET_INPUT_CONSUME_PATH = path.join(
  __dirname,
  "../../proving/out/wallet_input_consume/local_regression_wallet_input_consumption.json"
);
const LOCAL_WALLET_ARTIFACT_PATH = path.join(
  __dirname,
  "../../proving/out/wallet_artifact/local_regression_wallet_artifact.json"
);
const LOCAL_SMART_ACCOUNT_TARGET_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_target/local_regression_smart_account_target.json"
);
const LOCAL_SMART_ACCOUNT_INIT_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_init/local_regression_smart_account_init.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_PLAN_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_plan/local_regression_smart_account_deploy_plan.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_REQUEST_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_request/local_regression_smart_account_deploy_request.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_ENVELOPE_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_envelope/local_regression_smart_account_deploy_envelope.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_PAYLOAD_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_payload/local_regression_smart_account_deploy_payload.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_transport/local_regression_smart_account_deploy_transport.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_SUBMIT_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_submit/local_regression_smart_account_deploy_submit.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_USEROP_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_userop/local_regression_smart_account_deploy_userop.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_USEROP_HASH_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_userop_hash/local_regression_smart_account_deploy_userop_hash.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_signature_request/local_regression_smart_account_deploy_signature_request.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_signed_userop/local_regression_smart_account_deploy_signed_userop.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_bundler_submission/local_regression_smart_account_deploy_bundler_submission.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_endpoint_submission/local_regression_smart_account_deploy_endpoint_submission.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_client_session/local_regression_smart_account_deploy_client_session.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_dispatch_intent/local_regression_smart_account_deploy_dispatch_intent.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_dispatch_command/local_regression_smart_account_deploy_dispatch_command.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_dispatch_attempt/local_regression_smart_account_deploy_dispatch_attempt.json"
);
const LOCAL_SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_PATH = path.join(
  __dirname,
  "../../proving/out/smart_account_deploy_attempt_runner/local_regression_smart_account_deploy_attempt_runner.json"
);
const LOCAL_DEPLOY_SESSION_REGRESSION_ROOT = path.join(
  __dirname,
  "../../proving/out/local_deploy_session_regression"
);
const LOCAL_DEPLOY_SESSION_MATRIX_REGRESSION_PATH = path.join(
  LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
  "local_regression_local_deploy_session_matrix.json"
);
const LOCAL_DEPLOY_SESSION_ACCEPTED_REGRESSION_PATH = path.join(
  LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
  "local_regression_local_deploy_session_accepted.json"
);
const LOCAL_DEPLOY_SESSION_REJECTED_REGRESSION_PATH = path.join(
  LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
  "local_regression_local_deploy_session_rejected.json"
);
const LOCAL_DEPLOY_SESSION_TRANSPORT_REGRESSION_PATH = path.join(
  LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
  "local_regression_local_deploy_session_transport.json"
);
const SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_EXTERNAL_SIGNATURE = `0x${"11".repeat(64)}1b`;

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function asBigInt(value) {
  return BigInt(value);
}

function proofBlobForFact(factHigh, factLow) {
  return ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [factHigh, factLow]);
}

async function setupMirroredFactPath({ deployer, relayOutput, relayFactToBase = true }) {
  const messaging = await deployContract(deployer, "MockStarknetMessaging");
  const trustAnchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
    await messaging.getAddress(),
    asBigInt(relayOutput.contract_address)
  ]);

  const factHigh = asBigInt(relayOutput.relayed_fact_high);
  const factLow = asBigInt(relayOutput.relayed_fact_low);

  await (
    await messaging.registerMessageFromL2(
      asBigInt(relayOutput.contract_address),
      await trustAnchor.getAddress(),
      [factHigh, factLow]
    )
  ).wait();
  await (await trustAnchor.consumeProofInputHashFactFromL2(factHigh, factLow)).wait();

  const { crossDomainMessengerAdapter, baseMirror } = await runLocalBaseMirrorDeployment({
    signer: deployer,
    networkName: "hardhat"
  });
  const l1Messenger = await deployContract(deployer, "PhilL1ToBaseProofInputHashMessenger", [
    await trustAnchor.getAddress(),
    await crossDomainMessengerAdapter.getAddress()
  ]);

  if (relayFactToBase) {
    await (
      await l1Messenger.relayProofInputHashFactToBase(
        await baseMirror.getAddress(),
        factHigh,
        factLow
      )
    ).wait();
  }

  const verifier = await deployContract(deployer, "PhilBaseMirroredFactUnlockProofVerifier", [
    await baseMirror.getAddress()
  ]);
  const gate = await deployContract(deployer, "PhilBaseActionGate", [await verifier.getAddress()]);

  return {
    factHigh,
    factLow,
    baseMirror,
    gate
  };
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

describe("Phil mint-path integration via mirrored Base fact state", function () {
  it("uses the canonical mirrored fact to unlock a bounded mint gate", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer] = await ethers.getSigners();

    const { factHigh, factLow, gate } = await setupMirroredFactPath({
      deployer,
      relayOutput
    });
    const mintConsumer = await deployContract(deployer, "PhilMintPassConsumer", [await gate.getAddress()]);

    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"));
    assert.equal(ethers.keccak256(consumerData), summary.publicInputs.consumerDataHash);

    const authorization = canonicalAuthorization({
      summary,
      consumerAddress: await mintConsumer.getAddress()
    });
    const onboardingRecipient = buildMintRecipientOnboarding({
      ownerCommitment: summary.publicInputs.ownerCommitment,
      consumerData,
      expectedBaseRecipient: await mintConsumer.previewBoundMintRecipient(
        authorization,
        consumerData
      )
    });
    const proofPackage = canonicalProofPackage({
      summary,
      factHigh,
      factLow
    });
    const boundRecipient = onboardingRecipient.derivedRecipient;
    const [previewRecipient, previewTokenId] = await mintConsumer.previewMintClaim(
      authorization,
      consumerData
    );
    assert.equal(previewRecipient, boundRecipient);
    assert.equal(previewTokenId, 1n);

    const tx = await gate.verifyAndConsume(authorization, proofPackage, consumerData);
    await tx.wait();
    const [minted, claimedRecipient, claimedTokenId] = await mintConsumer.getMintClaim(
      summary.publicInputs.nullifier
    );
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
    const mintClaimIndex = buildMintClaimIndex({
      mintClaimSource
    });
    const mintIndexConsumption = buildMintClaimIndexConsumption({
      mintClaimIndex
    });
    const mintIndexStatus = buildMintClaimStatus({
      mintClaimConsumption: mintIndexConsumption
    });
    const mintIndexLookup = resolveMintClaimStatusByNullifier({
      mintClaimStatus: mintIndexStatus,
      nullifier: summary.publicInputs.nullifier
    });
    const mintIndexLookupMissFound = resolveMintClaimStatusOrNotFound({
      mintClaimStatus: mintIndexStatus,
      nullifier: summary.publicInputs.nullifier
    });
    const mintIndexLookupMiss = resolveMintClaimStatusOrNotFound({
      mintClaimStatus: mintIndexStatus,
      nullifier:
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    });
    const mintIndexRecipientLookup = resolveMintClaimStatusesByRecipient({
      mintClaimStatus: mintIndexStatus,
      recipient: boundRecipient
    });
    const onboardingBundle = buildMintOnboardingBundle({
      onboardingRecipient
    });
    const onboardingBundleConsumption = consumeMintOnboardingBundle({
      onboardingBundle
    });
    const onboardingReadiness = buildMintOnboardingReadiness({
      onboardingBundleConsumption
    });
    const mintIntent = buildMintIntent({
      onboardingReadiness
    });
    const mintIntentConsumption = buildMintIntentConsumption({
      mintIntent
    });
    const mintIntentStatus = buildMintIntentStatus({
      mintIntentConsumption
    });
    const walletInput = buildWalletInput({
      mintIntentStatus
    });
    const walletInputConsumption = buildWalletInputConsumption({
      walletInput
    });
    const walletArtifact = buildWalletArtifact({
      walletInputConsumption
    });
    const smartAccountTarget = buildSmartAccountTarget({
      walletArtifact
    });
    const smartAccountInit = buildSmartAccountInit({
      smartAccountTarget
    });
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
    const smartAccountDeploySignatureRequest = buildSmartAccountDeploySignatureRequest({
      smartAccountDeployUserOpHash
    });
    const smartAccountDeploySignedUserOp = buildSmartAccountDeploySignedUserOp({
      smartAccountDeploySignatureRequest,
      externalSignature: SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_EXTERNAL_SIGNATURE
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

    fs.mkdirSync(path.dirname(LOCAL_MINT_CLAIM_SOURCE_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_CLAIM_SOURCE_PATH,
      JSON.stringify(mintClaimSource, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INDEX_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_MINT_INDEX_PATH, JSON.stringify(mintClaimIndex, null, 2));
    fs.mkdirSync(path.dirname(LOCAL_MINT_INDEX_CONSUME_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INDEX_CONSUME_PATH,
      JSON.stringify(mintIndexConsumption, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INDEX_STATUS_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INDEX_STATUS_PATH,
      JSON.stringify(mintIndexStatus, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INDEX_LOOKUP_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INDEX_LOOKUP_PATH,
      JSON.stringify(mintIndexLookup, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INDEX_LOOKUP_MISS_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INDEX_LOOKUP_MISS_PATH,
      JSON.stringify(mintIndexLookupMiss, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INDEX_RECIPIENT_LOOKUP_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INDEX_RECIPIENT_LOOKUP_PATH,
      JSON.stringify(mintIndexRecipientLookup, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_ONBOARDING_RECIPIENT_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_ONBOARDING_RECIPIENT_PATH,
      JSON.stringify(onboardingRecipient, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_ONBOARDING_BUNDLE_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_ONBOARDING_BUNDLE_PATH,
      JSON.stringify(onboardingBundle, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_ONBOARDING_BUNDLE_CONSUME_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_ONBOARDING_BUNDLE_CONSUME_PATH,
      JSON.stringify(onboardingBundleConsumption, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_ONBOARDING_READINESS_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_ONBOARDING_READINESS_PATH,
      JSON.stringify(onboardingReadiness, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INTENT_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_MINT_INTENT_PATH, JSON.stringify(mintIntent, null, 2));
    fs.mkdirSync(path.dirname(LOCAL_MINT_INTENT_CONSUME_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INTENT_CONSUME_PATH,
      JSON.stringify(mintIntentConsumption, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_MINT_INTENT_STATUS_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_MINT_INTENT_STATUS_PATH,
      JSON.stringify(mintIntentStatus, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_WALLET_INPUT_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_WALLET_INPUT_PATH, JSON.stringify(walletInput, null, 2));
    fs.mkdirSync(path.dirname(LOCAL_WALLET_INPUT_CONSUME_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_WALLET_INPUT_CONSUME_PATH,
      JSON.stringify(walletInputConsumption, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_WALLET_ARTIFACT_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_WALLET_ARTIFACT_PATH,
      JSON.stringify(walletArtifact, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_TARGET_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_TARGET_PATH,
      JSON.stringify(smartAccountTarget, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_INIT_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_INIT_PATH,
      JSON.stringify(smartAccountInit, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_PLAN_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_PLAN_PATH,
      JSON.stringify(smartAccountDeployPlan, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_REQUEST_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_REQUEST_PATH,
      JSON.stringify(smartAccountDeployRequest, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_ENVELOPE_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_ENVELOPE_PATH,
      JSON.stringify(smartAccountDeployEnvelope, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_PAYLOAD_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_PAYLOAD_PATH,
      JSON.stringify(smartAccountDeployPayload, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH,
      JSON.stringify(smartAccountDeployTransport, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_SUBMIT_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_SUBMIT_PATH,
      JSON.stringify(smartAccountDeploySubmit, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_USEROP_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_USEROP_PATH,
      JSON.stringify(smartAccountDeployUserOp, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_USEROP_HASH_PATH), { recursive: true });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_USEROP_HASH_PATH,
      JSON.stringify(smartAccountDeployUserOpHash, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH,
      JSON.stringify(smartAccountDeploySignatureRequest, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_PATH,
      JSON.stringify(smartAccountDeploySignedUserOp, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_PATH,
      JSON.stringify(smartAccountDeployBundlerSubmission, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_PATH,
      JSON.stringify(smartAccountDeployEndpointSubmission, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_PATH,
      JSON.stringify(smartAccountDeployClientSession, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_PATH,
      JSON.stringify(smartAccountDeployDispatchIntent, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_PATH,
      JSON.stringify(smartAccountDeployDispatchCommand, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_PATH,
      JSON.stringify(smartAccountDeployDispatchAttempt, null, 2)
    );
    fs.mkdirSync(path.dirname(LOCAL_SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_PATH,
      JSON.stringify(smartAccountDeployAttemptRunner, null, 2)
    );

    assert.equal(await gate.consumedNullifier(summary.publicInputs.nullifier), true);
    assert.equal(await mintConsumer.mintedNullifier(summary.publicInputs.nullifier), true);
    assert.equal(await mintConsumer.lastMintedNullifier(), summary.publicInputs.nullifier);
    assert.equal(await mintConsumer.lastMintedTokenId(), 1n);
    assert.equal(await mintConsumer.lastMintRecipient(), boundRecipient);
    assert.equal(minted, true);
    assert.equal(claimedRecipient, boundRecipient);
    assert.equal(claimedTokenId, 1n);
    assert.equal(await mintConsumer.ownerOf(1n), boundRecipient);
    assert.equal(await mintConsumer.balanceOf(boundRecipient), 1n);
    assert.equal(await mintConsumer.lastConsumerData(), consumerData);
    assert.equal(onboardingRecipient.path, "phil-mint-recipient-onboarding");
    assert.equal(
      onboardingRecipient.deviceMintInputs.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(onboardingRecipient.deviceMintInputs.consumerData, consumerData);
    assert.equal(
      onboardingRecipient.deviceMintInputs.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(onboardingRecipient.derivedRecipient, boundRecipient);
    assert.equal(onboardingRecipient.parityCheck.expectedBaseRecipient, boundRecipient);
    assert.equal(onboardingRecipient.parityCheck.matchesBaseRecipient, true);
    assert.equal(onboardingRecipient.appReadModel.derivedRecipient, boundRecipient);
    assert.equal(onboardingRecipient.appReadModel.consumerDataHash, summary.publicInputs.consumerDataHash);
    assert.equal(onboardingRecipient.appReadModel.parityProven, true);
    assert.equal(onboardingBundle.path, "phil-mint-onboarding-bundle");
    assert.equal(
      onboardingBundle.mintInputPreimage.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(onboardingBundle.mintInputPreimage.consumerData, consumerData);
    assert.equal(
      onboardingBundle.mintInputPreimage.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(onboardingBundle.recipientBinding.derivedRecipient, boundRecipient);
    assert.equal(onboardingBundle.recipientBinding.expectedBaseRecipient, boundRecipient);
    assert.equal(onboardingBundle.recipientBinding.parityProven, true);
    assert.equal(onboardingBundle.appBundle.derivedRecipient, boundRecipient);
    assert.equal(onboardingBundle.appBundle.consumerDataHash, summary.publicInputs.consumerDataHash);
    assert.equal(onboardingBundle.appBundle.parityProven, true);
    assert.equal(
      onboardingBundleConsumption.path,
      "phil-mint-onboarding-bundle-consumption"
    );
    assert.equal(onboardingBundleConsumption.validationChecks.bundlePathValid, true);
    assert.equal(onboardingBundleConsumption.validationChecks.payloadShapeValid, true);
    assert.equal(onboardingBundleConsumption.validationChecks.bindingDomainValid, true);
    assert.equal(onboardingBundleConsumption.validationChecks.preimageValid, true);
    assert.equal(onboardingBundleConsumption.validationChecks.recipientDerivationValid, true);
    assert.equal(onboardingBundleConsumption.validationChecks.parityValid, true);
    assert.equal(
      onboardingBundleConsumption.appReadModel.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(onboardingBundleConsumption.appReadModel.consumerData, consumerData);
    assert.equal(
      onboardingBundleConsumption.appReadModel.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(onboardingBundleConsumption.appReadModel.derivedRecipient, boundRecipient);
    assert.equal(
      onboardingBundleConsumption.appReadModel.expectedBaseRecipient,
      boundRecipient
    );
    assert.equal(onboardingBundleConsumption.appReadModel.parityProven, true);
    assert.equal(onboardingReadiness.path, "phil-mint-onboarding-readiness");
    assert.equal(onboardingReadiness.validationChecks.consumptionPathValid, true);
    assert.equal(onboardingReadiness.validationChecks.payloadShapeValid, true);
    assert.equal(onboardingReadiness.validationChecks.onboardingFieldsValid, true);
    assert.equal(onboardingReadiness.validationChecks.recipientParityValid, true);
    assert.equal(onboardingReadiness.readinessSummary.ready, true);
    assert.equal(onboardingReadiness.readinessSummary.status, "ready");
    assert.equal(
      onboardingReadiness.readinessSummary.reason,
      "validated-onboarding-bundle-consumption"
    );
    assert.equal(onboardingReadiness.readinessSummary.parityProven, true);
    assert.equal(
      onboardingReadiness.appReadiness.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      onboardingReadiness.appReadiness.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(onboardingReadiness.appReadiness.derivedRecipient, boundRecipient);
    assert.equal(
      onboardingReadiness.appReadiness.expectedBaseRecipient,
      boundRecipient
    );
    assert.equal(onboardingReadiness.appReadiness.parityProven, true);
    assert.equal(mintIntent.path, "phil-mint-intent");
    assert.equal(mintIntent.validationChecks.readinessPathValid, true);
    assert.equal(mintIntent.validationChecks.payloadShapeValid, true);
    assert.equal(mintIntent.validationChecks.readinessValid, true);
    assert.equal(mintIntent.validationChecks.recipientBindingValid, true);
    assert.equal(mintIntent.intentSummary.ready, true);
    assert.equal(mintIntent.intentSummary.status, "ready-to-mint");
    assert.equal(
      mintIntent.intentSummary.reason,
      "validated-onboarding-readiness"
    );
    assert.equal(mintIntent.intentSummary.parityProven, true);
    assert.equal(
      mintIntent.deviceMintIntent.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      mintIntent.deviceMintIntent.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(mintIntent.deviceMintIntent.canonicalRecipient, boundRecipient);
    assert.equal(mintIntent.appIntent.recipient, boundRecipient);
    assert.equal(mintIntent.appIntent.ready, true);
    assert.equal(mintIntent.appIntent.status, "ready-to-mint");
    assert.equal(mintIntent.appIntent.parityProven, true);
    assert.equal(mintIntentConsumption.path, "phil-mint-intent-consumption");
    assert.equal(mintIntentConsumption.validationChecks.intentPathValid, true);
    assert.equal(mintIntentConsumption.validationChecks.payloadShapeValid, true);
    assert.equal(mintIntentConsumption.validationChecks.intentFieldsValid, true);
    assert.equal(mintIntentConsumption.validationChecks.recipientConsistencyValid, true);
    assert.equal(
      mintIntentConsumption.appReadModel.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      mintIntentConsumption.appReadModel.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      mintIntentConsumption.appReadModel.canonicalRecipient,
      boundRecipient
    );
    assert.equal(mintIntentConsumption.appReadModel.ready, true);
    assert.equal(mintIntentConsumption.appReadModel.status, "ready-to-mint");
    assert.equal(mintIntentConsumption.appReadModel.parityProven, true);
    assert.equal(mintIntentStatus.path, "phil-mint-intent-status");
    assert.equal(mintIntentStatus.validationChecks.consumptionPathValid, true);
    assert.equal(mintIntentStatus.validationChecks.payloadShapeValid, true);
    assert.equal(mintIntentStatus.validationChecks.upstreamValidationPassed, true);
    assert.equal(mintIntentStatus.validationChecks.intentFieldConsistencyValid, true);
    assert.equal(mintIntentStatus.readinessSummary.ready, true);
    assert.equal(mintIntentStatus.readinessSummary.status, "ready");
    assert.equal(
      mintIntentStatus.readinessSummary.reason,
      "validated-mint-intent-consumption"
    );
    assert.equal(mintIntentStatus.readinessSummary.parityProven, true);
    assert.equal(
      mintIntentStatus.appReadiness.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      mintIntentStatus.appReadiness.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(mintIntentStatus.appReadiness.canonicalRecipient, boundRecipient);
    assert.equal(mintIntentStatus.appReadiness.ready, true);
    assert.equal(mintIntentStatus.appReadiness.status, "ready");
    assert.equal(mintIntentStatus.appReadiness.parityProven, true);
    assert.equal(walletInput.path, "phil-wallet-input");
    assert.equal(walletInput.validationChecks.statusPathValid, true);
    assert.equal(walletInput.validationChecks.payloadShapeValid, true);
    assert.equal(walletInput.validationChecks.upstreamStatusValid, true);
    assert.equal(walletInput.validationChecks.walletInputFieldsValid, true);
    assert.equal(walletInput.walletInputSummary.ready, true);
    assert.equal(walletInput.walletInputSummary.status, "wallet-input-ready");
    assert.equal(
      walletInput.walletInputSummary.reason,
      "validated-mint-intent-status"
    );
    assert.equal(walletInput.walletInputSummary.parityProven, true);
    assert.equal(
      walletInput.deviceWalletInput.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      walletInput.deviceWalletInput.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(walletInput.deviceWalletInput.canonicalRecipient, boundRecipient);
    assert.equal(walletInput.appWalletInput.recipient, boundRecipient);
    assert.equal(walletInput.appWalletInput.ready, true);
    assert.equal(walletInput.appWalletInput.status, "wallet-input-ready");
    assert.equal(walletInput.appWalletInput.parityProven, true);
    assert.equal(walletInputConsumption.path, "phil-wallet-input-consumption");
    assert.equal(walletInputConsumption.validationChecks.walletInputPathValid, true);
    assert.equal(walletInputConsumption.validationChecks.payloadShapeValid, true);
    assert.equal(walletInputConsumption.validationChecks.walletInputFieldsValid, true);
    assert.equal(walletInputConsumption.validationChecks.recipientConsistencyValid, true);
    assert.equal(
      walletInputConsumption.appReadModel.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      walletInputConsumption.appReadModel.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      walletInputConsumption.appReadModel.canonicalRecipient,
      boundRecipient
    );
    assert.equal(walletInputConsumption.appReadModel.ready, true);
    assert.equal(walletInputConsumption.appReadModel.status, "wallet-input-ready");
    assert.equal(walletInputConsumption.appReadModel.parityProven, true);
    assert.equal(walletArtifact.path, "phil-wallet-artifact");
    assert.equal(walletArtifact.walletGenerationDomain.label, WALLET_ARTIFACT_DOMAIN_LABEL);
    assert.equal(walletArtifact.walletGenerationDomain.hash, WALLET_ARTIFACT_DOMAIN_HASH);
    assert.equal(walletArtifact.validationChecks.walletInputConsumptionPathValid, true);
    assert.equal(walletArtifact.validationChecks.payloadShapeValid, true);
    assert.equal(walletArtifact.validationChecks.upstreamWalletInputValid, true);
    assert.equal(walletArtifact.validationChecks.deterministicWalletDerived, true);
    assert.equal(walletArtifact.deterministicWalletSummary.ready, true);
    assert.equal(walletArtifact.deterministicWalletSummary.status, "wallet-artifact-ready");
    assert.equal(
      walletArtifact.deterministicWalletSummary.reason,
      "validated-wallet-input-consumption"
    );
    assert.equal(walletArtifact.deterministicWalletSummary.parityProven, true);
    assert.equal(
      walletArtifact.deterministicWallet.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      walletArtifact.deterministicWallet.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(walletArtifact.deterministicWallet.canonicalRecipient, boundRecipient);
    assert.match(walletArtifact.deterministicWallet.walletId, /^0x[0-9a-f]{64}$/);
    assert.match(walletArtifact.deterministicWallet.walletSalt, /^0x[0-9a-f]{64}$/);
    assert.equal(walletArtifact.appWalletArtifact.recipient, boundRecipient);
    assert.equal(
      walletArtifact.appWalletArtifact.walletId,
      walletArtifact.deterministicWallet.walletId
    );
    assert.equal(
      walletArtifact.appWalletArtifact.walletSalt,
      walletArtifact.deterministicWallet.walletSalt
    );
    assert.equal(walletArtifact.appWalletArtifact.ready, true);
    assert.equal(walletArtifact.appWalletArtifact.status, "wallet-artifact-ready");
    assert.equal(walletArtifact.appWalletArtifact.parityProven, true);
    assert.equal(smartAccountTarget.path, "phil-smart-account-target");
    assert.equal(
      smartAccountTarget.smartAccountTargetDomain.label,
      SMART_ACCOUNT_TARGET_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountTarget.smartAccountTargetDomain.hash,
      SMART_ACCOUNT_TARGET_DOMAIN_HASH
    );
    assert.equal(smartAccountTarget.validationChecks.walletArtifactPathValid, true);
    assert.equal(smartAccountTarget.validationChecks.payloadShapeValid, true);
    assert.equal(smartAccountTarget.validationChecks.upstreamWalletArtifactValid, true);
    assert.equal(
      smartAccountTarget.validationChecks.deterministicSmartAccountTargetDerived,
      true
    );
    assert.equal(smartAccountTarget.smartAccountTargetSummary.ready, true);
    assert.equal(
      smartAccountTarget.smartAccountTargetSummary.status,
      "smart-account-target-ready"
    );
    assert.equal(
      smartAccountTarget.smartAccountTargetSummary.reason,
      "validated-wallet-artifact"
    );
    assert.equal(smartAccountTarget.smartAccountTargetSummary.parityProven, true);
    assert.equal(
      smartAccountTarget.smartAccountTarget.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountTarget.smartAccountTarget.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountTarget.smartAccountTarget.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountTarget.smartAccountTarget.walletId,
      walletArtifact.deterministicWallet.walletId
    );
    assert.match(smartAccountTarget.smartAccountTarget.targetId, /^0x[0-9a-f]{64}$/);
    assert.match(smartAccountTarget.smartAccountTarget.targetSalt, /^0x[0-9a-f]{64}$/);
    assert.match(
      smartAccountTarget.smartAccountTarget.targetAddress,
      /^0x[0-9A-Fa-f]{40}$/
    );
    assert.equal(smartAccountTarget.appSmartAccountTarget.recipient, boundRecipient);
    assert.equal(
      smartAccountTarget.appSmartAccountTarget.targetId,
      smartAccountTarget.smartAccountTarget.targetId
    );
    assert.equal(
      smartAccountTarget.appSmartAccountTarget.targetAddress,
      smartAccountTarget.smartAccountTarget.targetAddress
    );
    assert.equal(smartAccountTarget.appSmartAccountTarget.ready, true);
    assert.equal(
      smartAccountTarget.appSmartAccountTarget.status,
      "smart-account-target-ready"
    );
    assert.equal(smartAccountTarget.appSmartAccountTarget.parityProven, true);
    assert.equal(smartAccountInit.path, "phil-smart-account-init");
    assert.equal(
      smartAccountInit.smartAccountInitDomain.label,
      SMART_ACCOUNT_INIT_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountInit.smartAccountInitDomain.hash,
      SMART_ACCOUNT_INIT_DOMAIN_HASH
    );
    assert.equal(smartAccountInit.validationChecks.smartAccountTargetPathValid, true);
    assert.equal(smartAccountInit.validationChecks.payloadShapeValid, true);
    assert.equal(smartAccountInit.validationChecks.upstreamSmartAccountTargetValid, true);
    assert.equal(
      smartAccountInit.validationChecks.deterministicSmartAccountInitDerived,
      true
    );
    assert.equal(smartAccountInit.smartAccountInitSummary.ready, true);
    assert.equal(
      smartAccountInit.smartAccountInitSummary.status,
      "smart-account-init-ready"
    );
    assert.equal(
      smartAccountInit.smartAccountInitSummary.reason,
      "validated-smart-account-target"
    );
    assert.equal(smartAccountInit.smartAccountInitSummary.parityProven, true);
    assert.equal(
      smartAccountInit.smartAccountInit.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountInit.smartAccountInit.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(smartAccountInit.smartAccountInit.canonicalRecipient, boundRecipient);
    assert.equal(
      smartAccountInit.smartAccountInit.walletId,
      smartAccountTarget.smartAccountTarget.walletId
    );
    assert.equal(
      smartAccountInit.smartAccountInit.targetId,
      smartAccountTarget.smartAccountTarget.targetId
    );
    assert.equal(
      smartAccountInit.smartAccountInit.targetSalt,
      smartAccountTarget.smartAccountTarget.targetSalt
    );
    assert.equal(
      smartAccountInit.smartAccountInit.targetAddress,
      smartAccountTarget.smartAccountTarget.targetAddress
    );
    assert.match(smartAccountInit.smartAccountInit.initPayloadHash, /^0x[0-9a-f]{64}$/);
    assert.match(smartAccountInit.smartAccountInit.initCommitment, /^0x[0-9a-f]{64}$/);
    assert.equal(smartAccountInit.appSmartAccountInit.recipient, boundRecipient);
    assert.equal(
      smartAccountInit.appSmartAccountInit.targetId,
      smartAccountInit.smartAccountInit.targetId
    );
    assert.equal(
      smartAccountInit.appSmartAccountInit.targetAddress,
      smartAccountInit.smartAccountInit.targetAddress
    );
    assert.equal(
      smartAccountInit.appSmartAccountInit.initPayloadHash,
      smartAccountInit.smartAccountInit.initPayloadHash
    );
    assert.equal(
      smartAccountInit.appSmartAccountInit.initCommitment,
      smartAccountInit.smartAccountInit.initCommitment
    );
    assert.equal(smartAccountInit.appSmartAccountInit.ready, true);
    assert.equal(
      smartAccountInit.appSmartAccountInit.status,
      "smart-account-init-ready"
    );
    assert.equal(smartAccountInit.appSmartAccountInit.parityProven, true);
    assert.equal(smartAccountDeployPlan.path, "phil-smart-account-deploy-plan");
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlanDomain.label,
      SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlanDomain.hash,
      SMART_ACCOUNT_DEPLOY_PLAN_DOMAIN_HASH
    );
    assert.equal(smartAccountDeployPlan.validationChecks.smartAccountInitPathValid, true);
    assert.equal(smartAccountDeployPlan.validationChecks.payloadShapeValid, true);
    assert.equal(smartAccountDeployPlan.validationChecks.upstreamSmartAccountInitValid, true);
    assert.equal(
      smartAccountDeployPlan.validationChecks.deterministicSmartAccountDeployPlanDerived,
      true
    );
    assert.equal(smartAccountDeployPlan.smartAccountDeployPlanSummary.ready, true);
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlanSummary.status,
      "smart-account-deploy-plan-ready"
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlanSummary.reason,
      "validated-smart-account-init"
    );
    assert.equal(smartAccountDeployPlan.smartAccountDeployPlanSummary.parityProven, true);
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.walletId,
      smartAccountInit.smartAccountInit.walletId
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.targetId,
      smartAccountInit.smartAccountInit.targetId
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.targetSalt,
      smartAccountInit.smartAccountInit.targetSalt
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.targetAddress,
      smartAccountInit.smartAccountInit.targetAddress
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.initPayloadHash,
      smartAccountInit.smartAccountInit.initPayloadHash
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.initCommitment,
      smartAccountInit.smartAccountInit.initCommitment
    );
    assert.equal(
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentMode,
      "deterministic-smart-account-init"
    );
    assert.match(
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentEnvelopeHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentPlanId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(smartAccountDeployPlan.appSmartAccountDeployPlan.recipient, boundRecipient);
    assert.equal(
      smartAccountDeployPlan.appSmartAccountDeployPlan.targetAddress,
      smartAccountDeployPlan.smartAccountDeployPlan.targetAddress
    );
    assert.equal(
      smartAccountDeployPlan.appSmartAccountDeployPlan.deploymentMode,
      "deterministic-smart-account-init"
    );
    assert.equal(
      smartAccountDeployPlan.appSmartAccountDeployPlan.deploymentEnvelopeHash,
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentEnvelopeHash
    );
    assert.equal(
      smartAccountDeployPlan.appSmartAccountDeployPlan.deploymentPlanId,
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentPlanId
    );
    assert.equal(smartAccountDeployPlan.appSmartAccountDeployPlan.ready, true);
    assert.equal(
      smartAccountDeployPlan.appSmartAccountDeployPlan.status,
      "smart-account-deploy-plan-ready"
    );
    assert.equal(smartAccountDeployPlan.appSmartAccountDeployPlan.parityProven, true);
    assert.equal(smartAccountDeployRequest.path, "phil-smart-account-deploy-request");
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequestDomain.label,
      SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequestDomain.hash,
      SMART_ACCOUNT_DEPLOY_REQUEST_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployRequest.validationChecks.smartAccountDeployPlanPathValid,
      true
    );
    assert.equal(smartAccountDeployRequest.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeployRequest.validationChecks.upstreamSmartAccountDeployPlanValid,
      true
    );
    assert.equal(
      smartAccountDeployRequest.validationChecks.deterministicSmartAccountDeployRequestDerived,
      true
    );
    assert.equal(smartAccountDeployRequest.smartAccountDeployRequestSummary.ready, true);
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequestSummary.status,
      "smart-account-deploy-request-ready"
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequestSummary.reason,
      "validated-smart-account-deploy-plan"
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequestSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.walletId,
      smartAccountDeployPlan.smartAccountDeployPlan.walletId
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.targetId,
      smartAccountDeployPlan.smartAccountDeployPlan.targetId
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.targetAddress,
      smartAccountDeployPlan.smartAccountDeployPlan.targetAddress
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.deploymentMode,
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentMode
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.deploymentEnvelopeHash,
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentEnvelopeHash
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.deploymentPlanId,
      smartAccountDeployPlan.smartAccountDeployPlan.deploymentPlanId
    );
    assert.equal(
      smartAccountDeployRequest.smartAccountDeployRequest.requestKind,
      "smart-account-deploy"
    );
    assert.match(
      smartAccountDeployRequest.smartAccountDeployRequest.requestPayloadHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployRequest.smartAccountDeployRequest.requestId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(smartAccountDeployRequest.appSmartAccountDeployRequest.recipient, boundRecipient);
    assert.equal(
      smartAccountDeployRequest.appSmartAccountDeployRequest.targetAddress,
      smartAccountDeployRequest.smartAccountDeployRequest.targetAddress
    );
    assert.equal(
      smartAccountDeployRequest.appSmartAccountDeployRequest.requestKind,
      "smart-account-deploy"
    );
    assert.equal(
      smartAccountDeployRequest.appSmartAccountDeployRequest.requestPayloadHash,
      smartAccountDeployRequest.smartAccountDeployRequest.requestPayloadHash
    );
    assert.equal(
      smartAccountDeployRequest.appSmartAccountDeployRequest.requestId,
      smartAccountDeployRequest.smartAccountDeployRequest.requestId
    );
    assert.equal(smartAccountDeployRequest.appSmartAccountDeployRequest.ready, true);
    assert.equal(
      smartAccountDeployRequest.appSmartAccountDeployRequest.status,
      "smart-account-deploy-request-ready"
    );
    assert.equal(smartAccountDeployRequest.appSmartAccountDeployRequest.parityProven, true);
    assert.equal(smartAccountDeployEnvelope.path, "phil-smart-account-deploy-envelope");
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelopeDomain.label,
      SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelopeDomain.hash,
      SMART_ACCOUNT_DEPLOY_ENVELOPE_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployEnvelope.validationChecks.smartAccountDeployRequestPathValid,
      true
    );
    assert.equal(smartAccountDeployEnvelope.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeployEnvelope.validationChecks.upstreamSmartAccountDeployRequestValid,
      true
    );
    assert.equal(
      smartAccountDeployEnvelope.validationChecks.deterministicSmartAccountDeployEnvelopeDerived,
      true
    );
    assert.equal(smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.ready, true);
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.status,
      "smart-account-deploy-envelope-ready"
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.reason,
      "validated-smart-account-deploy-request"
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelopeSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.walletId,
      smartAccountDeployRequest.smartAccountDeployRequest.walletId
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetId,
      smartAccountDeployRequest.smartAccountDeployRequest.targetId
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetAddress,
      smartAccountDeployRequest.smartAccountDeployRequest.targetAddress
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestKind,
      "smart-account-deploy"
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestPayloadHash,
      smartAccountDeployRequest.smartAccountDeployRequest.requestPayloadHash
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestId,
      smartAccountDeployRequest.smartAccountDeployRequest.requestId
    );
    assert.equal(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopeKind,
      "smart-account-deploy-envelope"
    );
    assert.match(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopePayloadHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopeId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.targetAddress,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetAddress
    );
    assert.equal(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.envelopeKind,
      "smart-account-deploy-envelope"
    );
    assert.equal(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.envelopePayloadHash,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopePayloadHash
    );
    assert.equal(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.envelopeId,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopeId
    );
    assert.equal(smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.ready, true);
    assert.equal(
      smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.status,
      "smart-account-deploy-envelope-ready"
    );
    assert.equal(smartAccountDeployEnvelope.appSmartAccountDeployEnvelope.parityProven, true);
    assert.equal(smartAccountDeployPayload.path, "phil-smart-account-deploy-payload");
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayloadDomain.label,
      SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayloadDomain.hash,
      SMART_ACCOUNT_DEPLOY_PAYLOAD_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployPayload.validationChecks.smartAccountDeployEnvelopePathValid,
      true
    );
    assert.equal(smartAccountDeployPayload.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeployPayload.validationChecks.upstreamSmartAccountDeployEnvelopeValid,
      true
    );
    assert.equal(
      smartAccountDeployPayload.validationChecks.executionReadySmartAccountDeployPayloadDerived,
      true
    );
    assert.equal(smartAccountDeployPayload.smartAccountDeployPayloadSummary.ready, true);
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayloadSummary.status,
      "smart-account-deploy-payload-ready"
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayloadSummary.reason,
      "validated-smart-account-deploy-envelope"
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayloadSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.walletId,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.walletId
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.targetId,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetId
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.targetAddress,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.targetAddress
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.requestKind,
      "smart-account-deploy"
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.requestPayloadHash,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestPayloadHash
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.requestId,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.requestId
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.envelopeKind,
      "smart-account-deploy-envelope"
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.envelopePayloadHash,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopePayloadHash
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.envelopeId,
      smartAccountDeployEnvelope.smartAccountDeployEnvelope.envelopeId
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.executionValue,
      SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE
    );
    assert.equal(
      smartAccountDeployPayload.smartAccountDeployPayload.payloadEncoding,
      SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING
    );
    assert.match(
      smartAccountDeployPayload.smartAccountDeployPayload.deployCalldata,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployPayload.smartAccountDeployPayload.deployCalldataHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployPayload.smartAccountDeployPayload.deployPayloadHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.expectedDeployedAddress,
      smartAccountDeployPayload.smartAccountDeployPayload.targetAddress
    );
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.executionValue,
      SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE
    );
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.payloadEncoding,
      SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING
    );
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.deployCalldata,
      smartAccountDeployPayload.smartAccountDeployPayload.deployCalldata
    );
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.deployPayloadHash,
      smartAccountDeployPayload.smartAccountDeployPayload.deployPayloadHash
    );
    assert.equal(smartAccountDeployPayload.appSmartAccountDeployPayload.ready, true);
    assert.equal(
      smartAccountDeployPayload.appSmartAccountDeployPayload.status,
      "smart-account-deploy-payload-ready"
    );
    assert.equal(smartAccountDeployPayload.appSmartAccountDeployPayload.parityProven, true);
    assert.equal(smartAccountDeployTransport.path, "phil-smart-account-deploy-transport");
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransportDomain.label,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransportDomain.hash,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployTransport.validationChecks.smartAccountDeployPayloadPathValid,
      true
    );
    assert.equal(smartAccountDeployTransport.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeployTransport.validationChecks.upstreamSmartAccountDeployPayloadValid,
      true
    );
    assert.equal(
      smartAccountDeployTransport.validationChecks.deterministicSmartAccountDeployTransportDerived,
      true
    );
    assert.equal(smartAccountDeployTransport.smartAccountDeployTransportSummary.ready, true);
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransportSummary.status,
      "smart-account-deploy-transport-ready"
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransportSummary.reason,
      "validated-smart-account-deploy-payload"
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransportSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.walletId,
      smartAccountDeployPayload.smartAccountDeployPayload.walletId
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.targetId,
      smartAccountDeployPayload.smartAccountDeployPayload.targetId
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.targetAddress,
      smartAccountDeployPayload.smartAccountDeployPayload.targetAddress
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.executionValue,
      SMART_ACCOUNT_DEPLOY_EXECUTION_VALUE
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.payloadEncoding,
      SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.deployCalldata,
      smartAccountDeployPayload.smartAccountDeployPayload.deployCalldata
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.deployPayloadHash,
      smartAccountDeployPayload.smartAccountDeployPayload.deployPayloadHash
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.transportKind,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.contentType,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.method,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD
    );
    assert.equal(
      smartAccountDeployTransport.smartAccountDeployTransport.path,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH
    );
    assert.match(
      smartAccountDeployTransport.smartAccountDeployTransport.transportBody,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployTransport.smartAccountDeployTransport.transportBodyBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployTransport.smartAccountDeployTransport.transportBodyHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployTransport.smartAccountDeployTransport.transportRequestId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.expectedDeployedAddress,
      smartAccountDeployTransport.smartAccountDeployTransport.targetAddress
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.contentType,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.method,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.path,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.transportBody,
      smartAccountDeployTransport.smartAccountDeployTransport.transportBody
    );
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.transportRequestId,
      smartAccountDeployTransport.smartAccountDeployTransport.transportRequestId
    );
    assert.equal(smartAccountDeployTransport.appSmartAccountDeployTransport.ready, true);
    assert.equal(
      smartAccountDeployTransport.appSmartAccountDeployTransport.status,
      "smart-account-deploy-transport-ready"
    );
    assert.equal(smartAccountDeployTransport.appSmartAccountDeployTransport.parityProven, true);
    assert.equal(smartAccountDeploySubmit.path, "phil-smart-account-deploy-submit");
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmitDomain.label,
      SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmitDomain.hash,
      SMART_ACCOUNT_DEPLOY_SUBMIT_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeploySubmit.validationChecks.smartAccountDeployTransportPathValid,
      true
    );
    assert.equal(smartAccountDeploySubmit.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeploySubmit.validationChecks.upstreamSmartAccountDeployTransportValid,
      true
    );
    assert.equal(
      smartAccountDeploySubmit.validationChecks.deterministicSmartAccountDeploySubmitDerived,
      true
    );
    assert.equal(smartAccountDeploySubmit.smartAccountDeploySubmitSummary.ready, true);
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmitSummary.status,
      "smart-account-deploy-submit-ready"
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmitSummary.reason,
      "validated-smart-account-deploy-transport"
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmitSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.walletId,
      smartAccountDeployTransport.smartAccountDeployTransport.walletId
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetId,
      smartAccountDeployTransport.smartAccountDeployTransport.targetId
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetAddress,
      smartAccountDeployTransport.smartAccountDeployTransport.targetAddress
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.deployPayloadHash,
      smartAccountDeployTransport.smartAccountDeployTransport.deployPayloadHash
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.transportKind,
      SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.transportRequestId,
      smartAccountDeployTransport.smartAccountDeployTransport.transportRequestId
    );
    assert.equal(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submissionKind,
      SMART_ACCOUNT_DEPLOY_SUBMIT_KIND
    );
    assert.deepEqual(smartAccountDeploySubmit.smartAccountDeploySubmit.submitHeaders, {
      accept: SMART_ACCOUNT_DEPLOY_SUBMIT_ACCEPT,
      "content-type": SMART_ACCOUNT_DEPLOY_TRANSPORT_CONTENT_TYPE,
      "idempotency-key":
        smartAccountDeploySubmit.smartAccountDeploySubmit.submitIdempotencyKey,
      "x-phil-deploy-payload-hash":
        smartAccountDeployTransport.smartAccountDeployTransport.deployPayloadHash,
      "x-phil-proof-type": "stwo-unlock-keccak-v1",
      "x-phil-target-address":
        smartAccountDeployTransport.smartAccountDeployTransport.targetAddress,
      "x-phil-transport-kind": SMART_ACCOUNT_DEPLOY_TRANSPORT_KIND,
      "x-phil-transport-request-id":
        smartAccountDeployTransport.smartAccountDeployTransport.transportRequestId
    });
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitHeadersHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitIdempotencyKey,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequest, {
      method: SMART_ACCOUNT_DEPLOY_TRANSPORT_METHOD,
      path: SMART_ACCOUNT_DEPLOY_TRANSPORT_PATH,
      headers: smartAccountDeploySubmit.smartAccountDeploySubmit.submitHeaders,
      body: smartAccountDeployTransport.smartAccountDeployTransport.transportBody
    });
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestLengthBytes,
      /^[0-9]+$/
    );
    assert.match(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.expectedDeployedAddress,
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetAddress
    );
    assert.deepEqual(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.headers,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitHeaders
    );
    assert.deepEqual(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.request,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequest
    );
    assert.equal(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.idempotencyKey,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitIdempotencyKey
    );
    assert.equal(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.submitId,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitId
    );
    assert.equal(smartAccountDeploySubmit.appSmartAccountDeploySubmit.ready, true);
    assert.equal(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.status,
      "smart-account-deploy-submit-ready"
    );
    assert.equal(smartAccountDeploySubmit.appSmartAccountDeploySubmit.parityProven, true);
    assert.equal(smartAccountDeployUserOp.path, "phil-smart-account-deploy-userop");
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOpDomain.label,
      SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOpDomain.hash,
      SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployUserOp.validationChecks.smartAccountDeploySubmitPathValid,
      true
    );
    assert.equal(smartAccountDeployUserOp.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeployUserOp.validationChecks.upstreamSmartAccountDeploySubmitValid,
      true
    );
    assert.equal(
      smartAccountDeployUserOp.validationChecks.deterministicSmartAccountDeployUserOpDerived,
      true
    );
    assert.equal(smartAccountDeployUserOp.smartAccountDeployUserOpSummary.ready, true);
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOpSummary.status,
      "smart-account-deploy-userop-ready"
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOpSummary.reason,
      "validated-smart-account-deploy-submit"
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOpSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.walletId,
      smartAccountDeploySubmit.smartAccountDeploySubmit.walletId
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.targetId,
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetId
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.targetAddress,
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetAddress
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.submissionKind,
      SMART_ACCOUNT_DEPLOY_SUBMIT_KIND
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.submitId,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitId
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.submitRequestHash,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestHash
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.userOpKind,
      SMART_ACCOUNT_DEPLOY_USEROP_KIND
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.entryPointVersion,
      SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.sender,
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetAddress
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.nonce,
      SMART_ACCOUNT_DEPLOY_USEROP_NONCE
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.initCodeSource,
      "submitBody.deployCalldata"
    );
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.payloadEncoding,
      SMART_ACCOUNT_DEPLOY_PAYLOAD_ENCODING
    );
    assert.equal(smartAccountDeployUserOp.smartAccountDeployUserOp.executionValue, "0");
    assert.equal(
      smartAccountDeployUserOp.smartAccountDeployUserOp.deployPayloadHash,
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitHeaders["x-phil-deploy-payload-hash"]
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.initCodeHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.callDataHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation,
      {
        sender: smartAccountDeploySubmit.smartAccountDeploySubmit.targetAddress,
        nonce: SMART_ACCOUNT_DEPLOY_USEROP_NONCE,
        initCode: JSON.parse(
          smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequest.body
        ).deployCalldata.toLowerCase(),
        callData: SMART_ACCOUNT_DEPLOY_USEROP_CALL_DATA,
        callGasLimit: "0",
        verificationGasLimit:
          smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
            .verificationGasLimit,
        preVerificationGas:
          smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
            .preVerificationGas,
        maxFeePerGas: SMART_ACCOUNT_DEPLOY_USEROP_MAX_FEE_PER_GAS,
        maxPriorityFeePerGas: SMART_ACCOUNT_DEPLOY_USEROP_MAX_PRIORITY_FEE_PER_GAS,
        paymasterAndData: SMART_ACCOUNT_DEPLOY_USEROP_PAYMASTER_AND_DATA,
        signature: SMART_ACCOUNT_DEPLOY_USEROP_SIGNATURE
      }
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
        .verificationGasLimit,
      /^[0-9]+$/
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
        .preVerificationGas,
      /^[0-9]+$/
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOpJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOpBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOpHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployUserOp.smartAccountDeployUserOp.userOpId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.sender,
      smartAccountDeployUserOp.smartAccountDeployUserOp.sender
    );
    assert.deepEqual(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.unsignedUserOperation,
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
    );
    assert.equal(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.userOpId,
      smartAccountDeployUserOp.smartAccountDeployUserOp.userOpId
    );
    assert.equal(smartAccountDeployUserOp.appSmartAccountDeployUserOp.ready, true);
    assert.equal(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.status,
      "smart-account-deploy-userop-ready"
    );
    assert.equal(smartAccountDeployUserOp.appSmartAccountDeployUserOp.parityProven, true);
    assert.equal(smartAccountDeployUserOpHash.path, "phil-smart-account-deploy-userop-hash");
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHashDomain.label,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHashDomain.hash,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployUserOpHash.validationChecks.smartAccountDeployUserOpPathValid,
      true
    );
    assert.equal(smartAccountDeployUserOpHash.validationChecks.payloadShapeValid, true);
    assert.equal(
      smartAccountDeployUserOpHash.validationChecks.upstreamSmartAccountDeployUserOpValid,
      true
    );
    assert.equal(
      smartAccountDeployUserOpHash.validationChecks.deterministicSmartAccountDeployUserOpHashDerived,
      true
    );
    assert.equal(smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.ready, true);
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.status,
      "smart-account-deploy-userop-hash-ready"
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.reason,
      "validated-smart-account-deploy-userop"
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.walletId,
      smartAccountDeployUserOp.smartAccountDeployUserOp.walletId
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetId,
      smartAccountDeployUserOp.smartAccountDeployUserOp.targetId
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetAddress,
      smartAccountDeployUserOp.smartAccountDeployUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpKind,
      SMART_ACCOUNT_DEPLOY_USEROP_KIND
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.entryPointVersion,
      SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRpcMethod,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.erc4337PackHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContext,
      {
        networkName: SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME,
        chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
        entryPointVersion: SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
        entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
        userOpHash: smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash,
        signatureField: SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_FIELD,
        signaturePlaceholder: SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_PLACEHOLDER
      }
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplate,
      {
        jsonrpc: "2.0",
        method: SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
        params: [
          smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation,
          SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
        ]
      }
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.sender,
      smartAccountDeployUserOp.smartAccountDeployUserOp.sender
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.bundlerRpcMethod,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD
    );
    assert.equal(smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.ready, true);
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.status,
      "smart-account-deploy-userop-hash-ready"
    );
    assert.equal(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.parityProven,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.path,
      "phil-smart-account-deploy-signature-request"
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestDomain.label,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestDomain.hash,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeploySignatureRequest.validationChecks
        .smartAccountDeployUserOpHashPathValid,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.validationChecks
        .upstreamSmartAccountDeployUserOpHashValid,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.validationChecks
        .deterministicSmartAccountDeploySignatureRequestDerived,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.status,
      "smart-account-deploy-signature-request-ready"
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.reason,
      "validated-smart-account-deploy-userop-hash"
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.walletId,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.walletId
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.targetId,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetId
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.targetAddress,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetAddress
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.userOpKind,
      SMART_ACCOUNT_DEPLOY_USEROP_KIND
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.networkName,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.entryPointVersion,
      SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.bundlerRpcMethod,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signingContextHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signingContextId,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextId
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .bundlerRequestTemplateHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestKind,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signableDigest,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signableDigestBytes,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.digestEncoding,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING
    );
    assert.deepEqual(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .unsignedUserOperation,
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
    );
    assert.deepEqual(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signerPayload,
      {
        payloadKind: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND,
        signableDigest:
          smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash,
        digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
        networkName: SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME,
        chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
        sender: smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetAddress,
        entryPointVersion: SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
        entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
        signatureField: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
        signaturePlaceholder:
          SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
      }
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signerPayloadJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signerPayloadBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signerPayloadHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signatureTarget,
      {
        userOperationField: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
        bundlerRequestPath: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
        signaturePlaceholder:
          SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
      }
    );
    assert.deepEqual(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequest,
      {
        requestKind: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
        signableDigest:
          smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash,
        digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
        signerPayload:
          smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
            .signerPayload,
        signatureTarget:
          smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
            .signatureTarget,
        submissionContext: {
          bundlerRpcMethod: SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
          entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
          chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
          bundlerRequestTemplateHash:
            smartAccountDeployUserOpHash.smartAccountDeployUserOpHash
              .bundlerRequestTemplateHash
        }
      }
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.sender,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetAddress
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .signatureRequestKind,
      SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .signableDigest,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .signatureRequestId,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestId
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.ready,
      true
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.status,
      "smart-account-deploy-signature-request-ready"
    );
    assert.equal(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.path,
      "phil-smart-account-deploy-signed-userop"
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpDomain.label,
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpDomain.hash,
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeploySignedUserOp.validationChecks
        .smartAccountDeploySignatureRequestPathValid,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.validationChecks
        .upstreamSmartAccountDeploySignatureRequestValid,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.validationChecks.externalSignatureAccepted,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.validationChecks
        .deterministicSmartAccountDeploySignedUserOpDerived,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.status,
      "smart-account-deploy-signed-userop-ready"
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.reason,
      "validated-smart-account-deploy-signature-request"
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.parityProven,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.walletId,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.walletId
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetId,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.targetId
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .targetAddress
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.userOpKind,
      SMART_ACCOUNT_DEPLOY_USEROP_KIND
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.entryPointVersion,
      SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.bundlerRpcMethod,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signingContextHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextHash
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signingContextId,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextId
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signatureRequestId,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestId
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpKind,
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND
    );
    assert.equal(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.externalSignature,
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_EXTERNAL_SIGNATURE.toLowerCase()
    );
    assert.deepEqual(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOperation,
      {
        ...smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
          .unsignedUserOperation,
        signature: SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_EXTERNAL_SIGNATURE.toLowerCase()
      }
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedUserOperationJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedUserOperationBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedUserOperationHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequest,
      {
        jsonrpc: "2.0",
        method: SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
        params: [
          smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
            .signedUserOperation,
          SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
        ]
      }
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.sender,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .targetAddress
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp
        .signedUserOpKind,
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp
        .signedUserOpId,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.ready,
      true
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.status,
      "smart-account-deploy-signed-userop-ready"
    );
    assert.equal(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.path,
      "phil-smart-account-deploy-bundler-submission"
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionDomain.label,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionDomain.hash,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.validationChecks
        .smartAccountDeploySignedUserOpPathValid,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.validationChecks
        .upstreamSmartAccountDeploySignedUserOpValid,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.validationChecks
        .deterministicSmartAccountDeployBundlerSubmissionDerived,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary.status,
      "smart-account-deploy-bundler-submission-ready"
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary.reason,
      "validated-smart-account-deploy-signed-userop"
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmissionSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.walletId,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.walletId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.targetId,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .targetAddress,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.userOpKind,
      SMART_ACCOUNT_DEPLOY_USEROP_KIND
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .entryPointVersion,
      SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerRpcMethod,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signingContextHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signingContextId,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signatureRequestId,
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signedUserOpKind,
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signedUserOpId,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signedUserOperationHash,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedUserOperationHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .signedBundlerRequestHash,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionKind,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND
    );
    assert.deepEqual(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionTarget,
      {
        transportKind: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND,
        rpcMethod: SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
        entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
        chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
      }
    );
    assert.deepEqual(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBody,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequest
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBodyJson,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestJson
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBodyBytes,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestBytes
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBodyHash,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders.accept,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["content-type"],
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-proof-type"],
      "stwo-unlock-keccak-v1"
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-chain-id"],
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-entry-point-address"],
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-target-address"],
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-userop-hash"],
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-signed-userop-kind"],
      SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-signed-userop-id"],
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionHeaders["x-phil-signed-bundler-request-hash"],
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash
    );
    assert.match(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionIdempotencyKey,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequest,
      {
        method: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
        headers:
          smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
            .bundlerSubmissionHeaders,
        body:
          smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
            .bundlerSubmissionBody
      }
    );
    assert.match(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .signedUserOpId,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .bundlerSubmissionKind,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .bundlerSubmissionId,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionId
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestHash,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestHash
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .ready,
      true
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .status,
      "smart-account-deploy-bundler-submission-ready"
    );
    assert.equal(
      smartAccountDeployBundlerSubmission.appSmartAccountDeployBundlerSubmission
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.path,
      "phil-smart-account-deploy-endpoint-submission"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionDomain
        .label,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionDomain
        .hash,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.validationChecks
        .smartAccountDeployBundlerSubmissionPathValid,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.validationChecks
        .upstreamSmartAccountDeployBundlerSubmissionValid,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.validationChecks
        .deterministicSmartAccountDeployEndpointSubmissionDerived,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
        .ready,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
        .status,
      "smart-account-deploy-endpoint-submission-ready"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
        .reason,
      "validated-smart-account-deploy-bundler-submission"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmissionSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.walletId,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.walletId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.targetId,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission.targetId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .targetAddress,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .targetAddress
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .signedUserOpId,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .bundlerSubmissionKind,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .bundlerSubmissionId,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .bundlerSubmissionRequestHash,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionRequestHash
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointSubmissionKind,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND
    );
    assert.deepEqual(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointBinding,
      {
        endpointLabel: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        endpointOrigin: "https://base-8453-bundler.phil.invalid",
        endpointProtocol: "https:",
        endpointHost: "base-8453-bundler.phil.invalid",
        endpointHostname: "base-8453-bundler.phil.invalid",
        endpointPathname: "/rpc"
      }
    );
    assert.match(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointUrlHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders.accept,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["content-type"],
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders.host,
      "base-8453-bundler.phil.invalid"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders.origin,
      "https://base-8453-bundler.phil.invalid"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-endpoint-label"],
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-proof-type"],
      "stwo-unlock-keccak-v1"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-chain-id"],
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-entry-point-address"],
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-target-address"],
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-userop-hash"],
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeaders["x-phil-signed-userop-id"],
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequest.url,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequest.method,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD
    );
    assert.deepEqual(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequest.body,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionBody
    );
    assert.match(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointHeadersHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequestHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointSubmissionId,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointUrl,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .bundlerSubmissionId,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointSubmissionKind,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointSubmissionId,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointSubmissionId
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .endpointRequestHash,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequestHash
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .ready,
      true
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .status,
      "smart-account-deploy-endpoint-submission-ready"
    );
    assert.equal(
      smartAccountDeployEndpointSubmission.appSmartAccountDeployEndpointSubmission
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.path,
      "phil-smart-account-deploy-client-session"
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSessionDomain.label,
      SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSessionDomain.hash,
      SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployClientSession.validationChecks
        .smartAccountDeployEndpointSubmissionPathValid,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.validationChecks
        .upstreamSmartAccountDeployEndpointSubmissionValid,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.validationChecks
        .deterministicSmartAccountDeployClientSessionDerived,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSessionSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSessionSummary.status,
      "smart-account-deploy-client-session-ready"
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSessionSummary.reason,
      "validated-smart-account-deploy-endpoint-submission"
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSessionSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession.ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession.consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession.walletId,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .walletId
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession.targetId,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .targetId
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .targetAddress,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .targetAddress
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .bundlerSubmissionId,
      smartAccountDeployBundlerSubmission.smartAccountDeployBundlerSubmission
        .bundlerSubmissionId
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .endpointSubmissionKind,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_KIND
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .endpointSubmissionId,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointSubmissionId
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .endpointRequestHash,
      smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
        .endpointRequestHash
    );
    assert.equal(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionKind,
      SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND
    );
    assert.deepEqual(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionContext,
      {
        sessionLabel: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_LABEL,
        sessionChannel: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_CHANNEL,
        sessionStage: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE,
        dispatchMode: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_DISPATCH_MODE,
        nextAction: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_NEXT_ACTION,
        attemptCount: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_ATTEMPT_COUNT,
        networkSubmissionPerformed: false,
        responseObserved: false,
        pollingEnabled: false,
        readyToDispatch: true,
        endpointLabel: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_LABEL,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        requestMethod: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
        requestHash:
          smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
            .endpointRequestHash
      }
    );
    assert.match(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionContextJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionContextHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployClientSession.smartAccountDeployClientSession.clientSessionId,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoff,
      {
        sessionId:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionId,
        session:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionContext,
        endpointRequest:
          smartAccountDeployEndpointSubmission.smartAccountDeployEndpointSubmission
            .endpointRequest
      }
    );
    assert.match(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoffJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoffBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoffHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .endpointUrl,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionKind,
      SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionId,
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionId
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionStage,
      SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_STAGE
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .clientSessionHandoffHash,
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoffHash
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.ready,
      true
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession.status,
      "smart-account-deploy-client-session-ready"
    );
    assert.equal(
      smartAccountDeployClientSession.appSmartAccountDeployClientSession
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.path,
      "phil-smart-account-deploy-dispatch-intent"
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentDomain
        .label,
      SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentDomain
        .hash,
      SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployDispatchIntent.validationChecks
        .smartAccountDeployClientSessionPathValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.validationChecks
        .upstreamSmartAccountDeployClientSessionValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.validationChecks
        .deterministicSmartAccountDeployDispatchIntentDerived,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary.status,
      "smart-account-deploy-dispatch-intent-ready"
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary
        .reason,
      "validated-smart-account-deploy-client-session"
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntentSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.walletId,
      smartAccountDeployClientSession.smartAccountDeployClientSession.walletId
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.targetId,
      smartAccountDeployClientSession.smartAccountDeployClientSession.targetId
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .targetAddress,
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .targetAddress
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .clientSessionKind,
      SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .clientSessionId,
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionId
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .clientSessionHandoffHash,
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionHandoffHash
    );
    assert.equal(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND
    );
    assert.deepEqual(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentContext,
      {
        intentLabel: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_LABEL,
        intentChannel: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_CHANNEL,
        intentStage: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE,
        approvalMode: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE,
        approvalState: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
        approvalScope: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE,
        dispatchMode: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_DISPATCH_MODE,
        nextAction: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NEXT_ACTION,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_NO_SEND_POLICY,
        approvedForDispatch: true,
        networkSubmissionPerformed: false,
        responseObserved: false,
        pollingEnabled: false,
        clientSessionId:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionId,
        clientSessionHandoffHash:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionHandoffHash,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        requestMethod: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
        requestHash:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .endpointRequestHash
      }
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentContextJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentContextHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .userApproval,
      {
        approvalMode: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_MODE,
        approvalState: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
        approvalScope: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_SCOPE,
        approvalSubjectKind: SMART_ACCOUNT_DEPLOY_CLIENT_SESSION_KIND,
        approvalSubjectId:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionId,
        approvalSubjectHash:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionHandoffHash,
        approvedEndpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        approvedRequestHash:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .endpointRequestHash,
        approvalEffect: "dispatch-intent-recorded-no-send",
        dispatchAuthorized: true,
        networkSubmissionPerformed: false
      }
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .userApprovalJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .userApprovalHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentId,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntent,
      {
        intentId:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .dispatchIntentId,
        intent:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .dispatchIntentContext,
        userApproval:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .userApproval,
        clientSessionHandoff:
          smartAccountDeployClientSession.smartAccountDeployClientSession
            .clientSessionHandoff
      }
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .endpointUrl,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .clientSessionId,
      smartAccountDeployClientSession.smartAccountDeployClientSession
        .clientSessionId
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentId,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentId
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentStage,
      SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_STAGE
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchIntentHash,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentHash
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .approved,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .dispatchAuthorized,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .networkSubmissionPerformed,
      false
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.ready,
      true
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent.status,
      "smart-account-deploy-dispatch-intent-ready"
    );
    assert.equal(
      smartAccountDeployDispatchIntent.appSmartAccountDeployDispatchIntent
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.path,
      "phil-smart-account-deploy-dispatch-command"
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandDomain
        .label,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_LABEL
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandDomain
        .hash,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_DOMAIN_HASH
    );
    assert.equal(
      smartAccountDeployDispatchCommand.validationChecks
        .smartAccountDeployDispatchIntentPathValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.validationChecks
        .upstreamSmartAccountDeployDispatchIntentValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.validationChecks
        .deterministicSmartAccountDeployDispatchCommandDerived,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary.status,
      "smart-account-deploy-dispatch-command-ready"
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary
        .reason,
      "validated-smart-account-deploy-dispatch-intent"
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommandSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.walletId,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.walletId
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.targetId,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent.targetId
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .targetAddress,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .targetAddress
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentId,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentId
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentHash,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentHash
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND
    );
    assert.deepEqual(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandContext,
      {
        commandLabel: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_LABEL,
        commandChannel: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_CHANNEL,
        commandStage: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE,
        commandAction: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION,
        commandTransport: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_TRANSPORT,
        commandExecutionMode:
          SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_EXECUTION_MODE,
        nextAction: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NEXT_ACTION,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
        dispatchIntentId:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .dispatchIntentId,
        dispatchIntentHash:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .dispatchIntentHash,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        requestMethod: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
        requestHash:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .endpointRequestHash,
        approvedForDispatch: true,
        commandReady: true,
        networkSubmissionPerformed: false,
        responseObserved: false,
        pollingEnabled: false
      }
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandContextJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandContextHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandRequest,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntent.clientSessionHandoff.endpointRequest
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.equal(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandRequestHash,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .endpointRequestHash
    );
    assert.deepEqual(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .commandGuard,
      {
        dispatchIntentKind: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_KIND,
        dispatchIntentId:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .dispatchIntentId,
        dispatchIntentHash:
          smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
            .dispatchIntentHash,
        approvalState: SMART_ACCOUNT_DEPLOY_DISPATCH_INTENT_APPROVAL_STATE,
        dispatchAuthorized: true,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY,
        networkSubmissionPerformed: false
      }
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .commandGuardJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .commandGuardHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandId,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommand,
      {
        commandId:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandId,
        context:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandContext,
        request:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandRequest,
        guard:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .commandGuard
      }
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .endpointUrl,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .requestMethod,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchIntentId,
      smartAccountDeployDispatchIntent.smartAccountDeployDispatchIntent
        .dispatchIntentId
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandId
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandStage,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_STAGE
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandAction,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_ACTION
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .dispatchCommandHash,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandHash
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .noSendPolicy,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_NO_SEND_POLICY
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .commandReady,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .networkSubmissionPerformed,
      false
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.ready,
      true
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand.status,
      "smart-account-deploy-dispatch-command-ready"
    );
    assert.equal(
      smartAccountDeployDispatchCommand.appSmartAccountDeployDispatchCommand
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.path,
      "phil-smart-account-deploy-dispatch-attempt"
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.consumedPath,
      "phil-smart-account-deploy-dispatch-command"
    );
    assert.equal(smartAccountDeployDispatchAttempt.proofType, "stwo-unlock-keccak-v1");
    assert.equal(smartAccountDeployDispatchAttempt.payloadShape, "[fact_high, fact_low]");
    assert.deepEqual(smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptDomain, {
      label: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_DOMAIN_HASH
    });
    assert.equal(
      smartAccountDeployDispatchAttempt.validationChecks
        .smartAccountDeployDispatchCommandPathValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.validationChecks
        .upstreamSmartAccountDeployDispatchCommandValid,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.validationChecks
        .deterministicSmartAccountDeployDispatchAttemptDerived,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary
        .ready,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary
        .status,
      "smart-account-deploy-dispatch-attempt-ready"
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttemptSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.walletId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.walletId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.targetId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand.targetId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .targetAddress,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .targetAddress
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .bundlerSubmissionId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .bundlerSubmissionId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .endpointSubmissionId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .endpointSubmissionId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .endpointRequestHash,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .endpointRequestHash
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchIntentId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchIntentHash,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchIntentHash
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchCommandKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchCommandId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchCommandHash,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandHash
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND
    );
    assert.deepEqual(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptContext,
      {
        attemptLabel: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_LABEL,
        attemptChannel: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_CHANNEL,
        attemptStage: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STAGE,
        attemptAction: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ACTION,
        attemptOrdinal: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
        attemptState: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE,
        attemptExecutionMode:
          SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_EXECUTION_MODE,
        nextAction: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NEXT_ACTION,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY,
        dispatchCommandId:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandId,
        dispatchCommandHash:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandHash,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        requestMethod: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
        requestHash:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .endpointRequestHash,
        readyForNetworkBoundary: true,
        networkSubmissionPerformed: false,
        responseObserved: false,
        pollingEnabled: false
      }
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptContextJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptContextHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequest,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommand.request
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequestJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequestBytes,
      /^0x[0-9a-f]+$/
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequestHash,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .endpointRequestHash
    );
    assert.deepEqual(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .attemptGuard,
      {
        dispatchCommandKind: SMART_ACCOUNT_DEPLOY_DISPATCH_COMMAND_KIND,
        dispatchCommandId:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandId,
        dispatchCommandHash:
          smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
            .dispatchCommandHash,
        commandReady: true,
        attemptOrdinal: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
        attemptState: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STATE,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY,
        networkSubmissionPerformed: false
      }
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .attemptGuardJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .attemptGuardHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptId,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttempt,
      {
        attemptId:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptId,
        context:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptContext,
        request:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptRequest,
        guard:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .attemptGuard
      }
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .endpointUrl,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .requestMethod,
      SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchCommandId,
      smartAccountDeployDispatchCommand.smartAccountDeployDispatchCommand
        .dispatchCommandId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptId,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptId
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptStage,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_STAGE
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptAction,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ACTION
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptOrdinal,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .dispatchAttemptHash,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptHash
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .noSendPolicy,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_NO_SEND_POLICY
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .readyForNetworkBoundary,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .networkSubmissionPerformed,
      false
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt.ready,
      true
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt.status,
      "smart-account-deploy-dispatch-attempt-ready"
    );
    assert.equal(
      smartAccountDeployDispatchAttempt.appSmartAccountDeployDispatchAttempt
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.path,
      "phil-smart-account-deploy-submission-attempt-runner"
    );
    assert.equal(
      smartAccountDeployAttemptRunner.consumedPath,
      "phil-smart-account-deploy-dispatch-attempt"
    );
    assert.equal(smartAccountDeployAttemptRunner.proofType, "stwo-unlock-keccak-v1");
    assert.equal(smartAccountDeployAttemptRunner.payloadShape, "[fact_high, fact_low]");
    assert.deepEqual(smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerDomain, {
      label: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_DOMAIN_HASH
    });
    assert.equal(
      smartAccountDeployAttemptRunner.validationChecks
        .smartAccountDeployDispatchAttemptPathValid,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.validationChecks.payloadShapeValid,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.validationChecks
        .upstreamSmartAccountDeployDispatchAttemptValid,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.validationChecks.localNoSendRunnerStepExecuted,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSummary.ready,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSummary.status,
      "smart-account-deploy-attempt-runner-ready"
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSummary
        .networkSubmissionPerformed,
      false
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSummary
        .parityProven,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .ownerCommitment,
      summary.publicInputs.ownerCommitment
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .consumerDataHash,
      summary.publicInputs.consumerDataHash
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .canonicalRecipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.walletId,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.walletId
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.targetId,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt.targetId
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.targetAddress,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .targetAddress
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.userOpHash,
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .endpointRequestHash,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .endpointRequestHash
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .dispatchAttemptKind,
      SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .dispatchAttemptId,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptId
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .dispatchAttemptHash,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptHash
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.runnerKind,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_KIND
    );
    assert.deepEqual(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.runnerContext,
      {
        runnerLabel: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_LABEL,
        runnerChannel: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CHANNEL,
        runnerStage: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STAGE,
        runnerAction: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_ACTION,
        runnerMode: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_MODE,
        runnerStep: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STEP,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY,
        nextAction: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NEXT_ACTION,
        dispatchAttemptId:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptId,
        dispatchAttemptHash:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptHash,
        dispatchAttemptOrdinal: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_ORDINAL,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        requestMethod: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD,
        rpcMethod: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD,
        requestHash:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptRequestHash,
        requestBytes:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptRequestBytes,
        readyForLiveCall: true,
        liveNetworkCallPerformed: false,
        networkSubmissionPerformed: false,
        responseObserved: false,
        pollingEnabled: false
      }
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .runnerContextJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .runnerContextHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .clientCallBoundary,
      {
        transport: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_TRANSPORT,
        clientApi: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_CLIENT_API,
        endpointUrl: SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL,
        requestMethod: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD,
        rpcMethod: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD,
        entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
        chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
        sender:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .targetAddress,
        idempotencyKey:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptRequest.headers["idempotency-key"],
        requestHash:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptRequestHash,
        requestBytes:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptRequestBytes,
        liveNetworkCallPerformed: false
      }
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .clientCallBoundaryHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.runnerGuard,
      {
        dispatchAttemptKind: SMART_ACCOUNT_DEPLOY_DISPATCH_ATTEMPT_KIND,
        dispatchAttemptId:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptId,
        dispatchAttemptHash:
          smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
            .dispatchAttemptHash,
        attemptReady: true,
        readyForNetworkBoundary: true,
        readyForLiveCall: true,
        noSendPolicy: SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY,
        liveNetworkCallPerformed: false,
        networkSubmissionPerformed: false
      }
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .runnerGuardHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.runnerId,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .localPreSendExecutionRecord,
      {
        runnerId:
          smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .runnerId,
        context:
          smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .runnerContext,
        clientCallBoundary:
          smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .clientCallBoundary,
        request:
          smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.request,
        guard:
          smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
            .runnerGuard
      }
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .localPreSendExecutionRecordJson,
      /^\{.+\}$/
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .localPreSendExecutionRecordBytes,
      /^0x[0-9a-f]+$/
    );
    assert.match(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .localPreSendExecutionRecordHash,
      /^0x[0-9a-f]{64}$/
    );
    assert.deepEqual(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.request,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequest
    );
    assert.equal(
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.requestHash,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptRequestHash
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.recipient,
      boundRecipient
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.sender,
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .entryPointAddress,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.chainId,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .endpointUrl,
      SMART_ACCOUNT_DEPLOY_ENDPOINT_SUBMISSION_ENDPOINT_URL
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .requestMethod,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_REQUEST_METHOD
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.rpcMethod,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_RPC_METHOD
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .dispatchAttemptId,
      smartAccountDeployDispatchAttempt.smartAccountDeployDispatchAttempt
        .dispatchAttemptId
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.runnerKind,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_KIND
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.runnerId,
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner.runnerId
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.runnerStage,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STAGE
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.runnerAction,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_ACTION
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.runnerMode,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_MODE
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.runnerStep,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_STEP
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .localPreSendExecutionRecordHash,
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner
        .localPreSendExecutionRecordHash
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .noSendPolicy,
      SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_NO_SEND_POLICY
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .readyForLiveCall,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .liveNetworkCallPerformed,
      false
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .networkSubmissionPerformed,
      false
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.ready,
      true
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner.status,
      "smart-account-deploy-attempt-runner-ready"
    );
    assert.equal(
      smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner
        .parityProven,
      true
    );
    assert.equal(mintClaimIndex.path, "phil-mint-claim-index");
    assert.equal(mintClaimIndex.claimCount, 1);
    assert.equal(mintClaimIndex.claims[0].recipient, boundRecipient);
    assert.equal(mintClaimIndex.claims[0].tokenId, 1);
    assert.equal(mintClaimIndex.claims[0].factHigh, relayOutput.relayed_fact_high.toLowerCase());
    assert.equal(mintClaimIndex.claims[0].factLow, relayOutput.relayed_fact_low.toLowerCase());
    assert.equal(mintIndexConsumption.path, "phil-mint-claim-index-consumption");
    assert.equal(mintIndexConsumption.validationChecks.indexPathValid, true);
    assert.equal(mintIndexConsumption.validationChecks.claimCountMatches, true);
    assert.equal(mintIndexConsumption.appReadModel.claimCount, 1);
    assert.equal(mintIndexConsumption.appReadModel.claims[0].recipient, boundRecipient);
    assert.equal(mintIndexConsumption.appReadModel.claims[0].tokenId, 1);
    assert.equal(
      mintIndexConsumption.appReadModel.claims[0].factHigh,
      relayOutput.relayed_fact_high.toLowerCase()
    );
    assert.equal(
      mintIndexConsumption.appReadModel.claims[0].factLow,
      relayOutput.relayed_fact_low.toLowerCase()
    );
    assert.equal(mintIndexStatus.path, "phil-mint-claim-index-status");
    assert.equal(mintIndexStatus.readinessSummary.ready, true);
    assert.equal(mintIndexStatus.readinessSummary.status, "ready");
    assert.equal(mintIndexStatus.readinessSummary.claimCount, 1);
    assert.equal(mintIndexStatus.primaryClaim.recipient, boundRecipient);
    assert.equal(mintIndexStatus.primaryClaim.tokenId, 1);
    assert.equal(
      mintIndexStatus.primaryClaim.factHigh,
      relayOutput.relayed_fact_high.toLowerCase()
    );
    assert.equal(
      mintIndexStatus.primaryClaim.factLow,
      relayOutput.relayed_fact_low.toLowerCase()
    );
    assert.equal(mintIndexStatus.appReadiness.claimCount, 1);
    assert.equal(mintIndexStatus.appReadiness.claims[0].ready, true);
    assert.equal(mintIndexStatus.appReadiness.claims[0].status, "ready");
    assert.equal(mintIndexStatus.appReadiness.claims[0].recipient, boundRecipient);
    assert.equal(mintIndexStatus.appReadiness.claims[0].tokenId, 1);
    assert.equal(mintIndexLookup.path, "phil-mint-claim-index-lookup");
    assert.equal(mintIndexLookup.lookupQuery.nullifier, summary.publicInputs.nullifier);
    assert.equal(mintIndexLookup.validationChecks.lookupResolved, true);
    assert.equal(mintIndexLookup.claimStatus.nullifier, summary.publicInputs.nullifier);
    assert.equal(mintIndexLookup.claimStatus.recipient, boundRecipient);
    assert.equal(mintIndexLookup.claimStatus.tokenId, 1);
    assert.equal(mintIndexLookup.claimStatus.ready, true);
    assert.equal(mintIndexLookup.claimStatus.status, "ready");
    assert.equal(
      mintIndexLookup.claimStatus.factHigh,
      relayOutput.relayed_fact_high.toLowerCase()
    );
    assert.equal(
      mintIndexLookup.claimStatus.factLow,
      relayOutput.relayed_fact_low.toLowerCase()
    );
    assert.equal(mintIndexLookupMissFound.path, "phil-mint-claim-index-lookup-miss");
    assert.equal(mintIndexLookupMissFound.lookupResult.found, true);
    assert.equal(mintIndexLookupMissFound.lookupResult.status, "ready");
    assert.equal(
      mintIndexLookupMissFound.claimStatus.nullifier,
      summary.publicInputs.nullifier
    );
    assert.equal(mintIndexLookupMissFound.claimStatus.recipient, boundRecipient);
    assert.equal(mintIndexLookupMissFound.claimStatus.tokenId, 1);
    assert.equal(
      mintIndexLookupMissFound.claimStatus.factHigh,
      relayOutput.relayed_fact_high.toLowerCase()
    );
    assert.equal(
      mintIndexLookupMissFound.claimStatus.factLow,
      relayOutput.relayed_fact_low.toLowerCase()
    );
    assert.equal(mintIndexLookupMiss.path, "phil-mint-claim-index-lookup-miss");
    assert.equal(
      mintIndexLookupMiss.lookupQuery.nullifier,
      "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
    assert.equal(mintIndexLookupMiss.validationChecks.lookupCompleted, true);
    assert.equal(mintIndexLookupMiss.validationChecks.lookupFound, false);
    assert.equal(mintIndexLookupMiss.lookupResult.found, false);
    assert.equal(mintIndexLookupMiss.lookupResult.status, "not-found");
    assert.equal(mintIndexLookupMiss.lookupResult.reason, "nullifier-not-found");
    assert.equal(mintIndexLookupMiss.claimStatus, null);
    assert.equal(
      mintIndexRecipientLookup.path,
      "phil-mint-claim-index-recipient-lookup"
    );
    assert.equal(mintIndexRecipientLookup.lookupQuery.recipient, boundRecipient);
    assert.equal(mintIndexRecipientLookup.validationChecks.lookupCompleted, true);
    assert.equal(mintIndexRecipientLookup.recipientSummary.recipient, boundRecipient);
    assert.equal(mintIndexRecipientLookup.recipientSummary.matchedClaimCount, 1);
    assert.equal(mintIndexRecipientLookup.recipientSummary.readyClaimCount, 1);
    assert.equal(mintIndexRecipientLookup.claimStatuses.length, 1);
    assert.equal(
      mintIndexRecipientLookup.claimStatuses[0].nullifier,
      summary.publicInputs.nullifier
    );
    assert.equal(mintIndexRecipientLookup.claimStatuses[0].recipient, boundRecipient);
    assert.equal(mintIndexRecipientLookup.claimStatuses[0].tokenId, 1);
    assert.equal(mintIndexRecipientLookup.claimStatuses[0].ready, true);
    assert.equal(mintIndexRecipientLookup.claimStatuses[0].status, "ready");
    assert.equal(
      mintIndexRecipientLookup.claimStatuses[0].factHigh,
      relayOutput.relayed_fact_high.toLowerCase()
    );
    assert.equal(
      mintIndexRecipientLookup.claimStatuses[0].factLow,
      relayOutput.relayed_fact_low.toLowerCase()
    );
  });

  it("locks the top-level local deploy session matrix classifications and selected-mode behavior", async function () {
    const smartAccountDeployAttemptRunner = loadJson(
      LOCAL_SMART_ACCOUNT_DEPLOY_ATTEMPT_RUNNER_PATH
    );

    fs.rmSync(LOCAL_DEPLOY_SESSION_REGRESSION_ROOT, {
      recursive: true,
      force: true
    });

    const matrixOutDir = path.join(LOCAL_DEPLOY_SESSION_REGRESSION_ROOT, "matrix");
    const acceptedOutDir = path.join(
      LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
      "accepted"
    );
    const rejectedOutDir = path.join(
      LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
      "rejected"
    );
    const transportOutDir = path.join(
      LOCAL_DEPLOY_SESSION_REGRESSION_ROOT,
      "transport"
    );

    const matrixSession = await runLocalSmartAccountDeploySession({
      smartAccountDeployAttemptRunner,
      matrix: true,
      outDir: matrixOutDir
    });
    const acceptedSession = await runLocalSmartAccountDeploySession({
      smartAccountDeployAttemptRunner,
      mode: LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
      outDir: acceptedOutDir
    });
    const rejectedSession = await runLocalSmartAccountDeploySession({
      smartAccountDeployAttemptRunner,
      mode: LOCAL_BUNDLER_STUB_MODE_REJECTED,
      outDir: rejectedOutDir
    });
    const transportSession = await runLocalSmartAccountDeploySession({
      smartAccountDeployAttemptRunner,
      mode: LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR,
      outDir: transportOutDir
    });

    fs.mkdirSync(path.dirname(LOCAL_DEPLOY_SESSION_MATRIX_REGRESSION_PATH), {
      recursive: true
    });
    fs.writeFileSync(
      LOCAL_DEPLOY_SESSION_MATRIX_REGRESSION_PATH,
      JSON.stringify(matrixSession, null, 2)
    );
    fs.writeFileSync(
      LOCAL_DEPLOY_SESSION_ACCEPTED_REGRESSION_PATH,
      JSON.stringify(acceptedSession, null, 2)
    );
    fs.writeFileSync(
      LOCAL_DEPLOY_SESSION_REJECTED_REGRESSION_PATH,
      JSON.stringify(rejectedSession, null, 2)
    );
    fs.writeFileSync(
      LOCAL_DEPLOY_SESSION_TRANSPORT_REGRESSION_PATH,
      JSON.stringify(transportSession, null, 2)
    );

    assert.equal(matrixSession.version, 1);
    assert.equal(matrixSession.path, "phil-local-smart-account-deploy-session");
    assert.equal(
      matrixSession.localDeploySession.sessionKind,
      LOCAL_DEPLOY_SESSION_KIND
    );
    assert.equal(matrixSession.consumedPath, smartAccountDeployAttemptRunner.path);
    assert.equal(matrixSession.proofType, "stwo-unlock-keccak-v1");
    assert.equal(matrixSession.payloadShape, "[fact_high, fact_low]");
    assert.equal(matrixSession.validationChecks.attemptRunnerPathValid, true);
    assert.equal(matrixSession.validationChecks.payloadShapeValid, true);
    assert.equal(matrixSession.validationChecks.delegatedSeamReused, true);
    assert.equal(matrixSession.validationChecks.selectedPathExercised, true);
    assert.equal(matrixSession.validationChecks.continuityPreserved, true);
    assert.equal(matrixSession.localDeploySessionSummary.ready, true);
    assert.equal(
      matrixSession.localDeploySessionSummary.status,
      "local-deploy-session-complete"
    );
    assert.equal(matrixSession.localDeploySessionSummary.delegatedPath, "matrix");
    assert.equal(matrixSession.localDeploySessionSummary.sessionMode, "matrix");
    assert.equal(
      matrixSession.localDeploySessionSummary.sessionClassification,
      "local-deploy-session-matrix-complete"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact.path,
      "phil-local-smart-account-deploy-submission-drill-matrix"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact
        .localSubmissionDrillMatrixSummary.acceptedClassification,
      "accepted-json-rpc-response"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact
        .localSubmissionDrillMatrixSummary.rejectedClassification,
      "rejected-json-rpc-response"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact
        .localSubmissionDrillMatrixSummary.transportClassification,
      "transport-error-response"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact
        .localSubmissionDrillMatrixSummary.scenarioCount,
      3
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact.localSubmissionDrillMatrix
        .scenarios[0].localEndpoint,
      "http://127.0.0.1:45884/rpc"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact.localSubmissionDrillMatrix
        .scenarios[1].localEndpoint,
      "http://127.0.0.1:45885/rpc"
    );
    assert.equal(
      matrixSession.localDeploySession.delegatedArtifact.localSubmissionDrillMatrix
        .scenarios[2].localEndpoint,
      "http://127.0.0.1:45886/rpc"
    );

    assert.equal(acceptedSession.version, 1);
    assert.equal(acceptedSession.path, "phil-local-smart-account-deploy-session");
    assert.equal(acceptedSession.consumedPath, smartAccountDeployAttemptRunner.path);
    assert.equal(acceptedSession.proofType, "stwo-unlock-keccak-v1");
    assert.equal(acceptedSession.payloadShape, "[fact_high, fact_low]");
    assert.equal(acceptedSession.validationChecks.attemptRunnerPathValid, true);
    assert.equal(acceptedSession.validationChecks.payloadShapeValid, true);
    assert.equal(acceptedSession.validationChecks.delegatedSeamReused, true);
    assert.equal(acceptedSession.validationChecks.selectedPathExercised, true);
    assert.equal(acceptedSession.localDeploySessionSummary.ready, true);
    assert.equal(
      acceptedSession.localDeploySessionSummary.status,
      "local-deploy-session-complete"
    );
    assert.equal(
      acceptedSession.localDeploySessionSummary.delegatedPath,
      "single-mode"
    );
    assert.equal(
      acceptedSession.localDeploySessionSummary.sessionMode,
      LOCAL_BUNDLER_STUB_MODE_ACCEPTED
    );
    assert.equal(
      acceptedSession.localDeploySessionSummary.sessionClassification,
      "accepted-json-rpc-response"
    );
    assert.equal(
      acceptedSession.localDeploySession.delegatedArtifact.path,
      "phil-local-smart-account-deploy-submission-drill"
    );
    assert.equal(
      acceptedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .selectedMode,
      LOCAL_BUNDLER_STUB_MODE_ACCEPTED
    );
    assert.equal(
      acceptedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .classification,
      "accepted-json-rpc-response"
    );
    assert.equal(
      acceptedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .responseCaptured,
      true
    );
    assert.equal(
      acceptedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .localHttpExchangeOccurred,
      true
    );
    assert.equal(
      acceptedSession.localDeploySession.delegatedArtifact.localSubmissionDrill
        .localEndpoint,
      "http://127.0.0.1:45884/rpc"
    );

    assert.equal(rejectedSession.version, 1);
    assert.equal(rejectedSession.path, "phil-local-smart-account-deploy-session");
    assert.equal(rejectedSession.consumedPath, smartAccountDeployAttemptRunner.path);
    assert.equal(rejectedSession.proofType, "stwo-unlock-keccak-v1");
    assert.equal(rejectedSession.payloadShape, "[fact_high, fact_low]");
    assert.equal(rejectedSession.validationChecks.attemptRunnerPathValid, true);
    assert.equal(rejectedSession.validationChecks.payloadShapeValid, true);
    assert.equal(rejectedSession.validationChecks.delegatedSeamReused, true);
    assert.equal(rejectedSession.validationChecks.selectedPathExercised, true);
    assert.equal(rejectedSession.localDeploySessionSummary.ready, true);
    assert.equal(
      rejectedSession.localDeploySessionSummary.status,
      "local-deploy-session-complete"
    );
    assert.equal(
      rejectedSession.localDeploySessionSummary.delegatedPath,
      "single-mode"
    );
    assert.equal(
      rejectedSession.localDeploySessionSummary.sessionMode,
      LOCAL_BUNDLER_STUB_MODE_REJECTED
    );
    assert.equal(
      rejectedSession.localDeploySessionSummary.sessionClassification,
      "rejected-json-rpc-response"
    );
    assert.equal(
      rejectedSession.localDeploySession.sessionKind,
      LOCAL_DEPLOY_SESSION_KIND
    );
    assert.equal(
      rejectedSession.localDeploySession.delegatedArtifact.path,
      "phil-local-smart-account-deploy-submission-drill"
    );
    assert.equal(
      rejectedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .selectedMode,
      LOCAL_BUNDLER_STUB_MODE_REJECTED
    );
    assert.equal(
      rejectedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .classification,
      "rejected-json-rpc-response"
    );
    assert.equal(
      rejectedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .responseCaptured,
      true
    );
    assert.equal(
      rejectedSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .localHttpExchangeOccurred,
      true
    );
    assert.equal(
      rejectedSession.localDeploySession.delegatedArtifact.localSubmissionDrill
        .localEndpoint,
      "http://127.0.0.1:45885/rpc"
    );
    assert.equal(
      rejectedSession.appLocalDeploySession.delegatedPath,
      "single-mode"
    );
    assert.equal(
      rejectedSession.appLocalDeploySession.sessionMode,
      LOCAL_BUNDLER_STUB_MODE_REJECTED
    );
    assert.equal(
      rejectedSession.appLocalDeploySession.sessionClassification,
      "rejected-json-rpc-response"
    );

    assert.equal(transportSession.version, 1);
    assert.equal(transportSession.path, "phil-local-smart-account-deploy-session");
    assert.equal(transportSession.consumedPath, smartAccountDeployAttemptRunner.path);
    assert.equal(transportSession.proofType, "stwo-unlock-keccak-v1");
    assert.equal(transportSession.payloadShape, "[fact_high, fact_low]");
    assert.equal(transportSession.validationChecks.attemptRunnerPathValid, true);
    assert.equal(transportSession.validationChecks.payloadShapeValid, true);
    assert.equal(transportSession.validationChecks.delegatedSeamReused, true);
    assert.equal(transportSession.validationChecks.selectedPathExercised, true);
    assert.equal(transportSession.localDeploySessionSummary.ready, true);
    assert.equal(
      transportSession.localDeploySessionSummary.status,
      "local-deploy-session-complete"
    );
    assert.equal(
      transportSession.localDeploySessionSummary.delegatedPath,
      "single-mode"
    );
    assert.equal(
      transportSession.localDeploySessionSummary.sessionMode,
      LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
    );
    assert.equal(
      transportSession.localDeploySessionSummary.sessionClassification,
      "transport-error-response"
    );
    assert.equal(
      transportSession.localDeploySession.sessionKind,
      LOCAL_DEPLOY_SESSION_KIND
    );
    assert.equal(
      transportSession.localDeploySession.delegatedArtifact.path,
      "phil-local-smart-account-deploy-submission-drill"
    );
    assert.equal(
      transportSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .selectedMode,
      LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
    );
    assert.equal(
      transportSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .classification,
      "transport-error-response"
    );
    assert.equal(
      transportSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .responseCaptured,
      false
    );
    assert.equal(
      transportSession.localDeploySession.delegatedArtifact.localSubmissionDrillSummary
        .localHttpExchangeOccurred,
      false
    );
    assert.equal(
      transportSession.localDeploySession.delegatedArtifact.localSubmissionDrill
        .localEndpoint,
      "http://127.0.0.1:45886/rpc"
    );
    assert.equal(
      transportSession.appLocalDeploySession.delegatedPath,
      "single-mode"
    );
    assert.equal(
      transportSession.appLocalDeploySession.sessionMode,
      LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
    );
    assert.equal(
      transportSession.appLocalDeploySession.sessionClassification,
      "transport-error-response"
    );

    assert.equal(
      matrixSession.appLocalDeploySession.recipient,
      acceptedSession.appLocalDeploySession.recipient
    );
    assert.equal(
      matrixSession.appLocalDeploySession.sender,
      acceptedSession.appLocalDeploySession.sender
    );
    assert.equal(
      matrixSession.appLocalDeploySession.entryPointAddress,
      acceptedSession.appLocalDeploySession.entryPointAddress
    );
    assert.equal(
      matrixSession.appLocalDeploySession.chainId,
      acceptedSession.appLocalDeploySession.chainId
    );
    assert.equal(
      matrixSession.appLocalDeploySession.recipient,
      rejectedSession.appLocalDeploySession.recipient
    );
    assert.equal(
      matrixSession.appLocalDeploySession.sender,
      rejectedSession.appLocalDeploySession.sender
    );
    assert.equal(
      matrixSession.appLocalDeploySession.entryPointAddress,
      rejectedSession.appLocalDeploySession.entryPointAddress
    );
    assert.equal(
      matrixSession.appLocalDeploySession.chainId,
      rejectedSession.appLocalDeploySession.chainId
    );
    assert.equal(
      matrixSession.appLocalDeploySession.recipient,
      transportSession.appLocalDeploySession.recipient
    );
    assert.equal(
      matrixSession.appLocalDeploySession.sender,
      transportSession.appLocalDeploySession.sender
    );
    assert.equal(
      matrixSession.appLocalDeploySession.entryPointAddress,
      transportSession.appLocalDeploySession.entryPointAddress
    );
    assert.equal(
      matrixSession.appLocalDeploySession.chainId,
      transportSession.appLocalDeploySession.chainId
    );
  });

  it("rejects nonzero value for the mint consumer and leaves no retained ETH", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer] = await ethers.getSigners();

    const { factHigh, factLow, gate } = await setupMirroredFactPath({
      deployer,
      relayOutput
    });
    const mintConsumer = await deployContract(deployer, "PhilMintPassConsumer", [await gate.getAddress()]);
    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"));
    const authorization = canonicalAuthorization({
      summary,
      consumerAddress: await mintConsumer.getAddress()
    });
    const boundRecipient = await mintConsumer.previewBoundMintRecipient(
      authorization,
      consumerData
    );

    await expectRevert(
      () =>
        gate.verifyAndConsume(
          authorization,
          canonicalProofPackage({
            summary,
            factHigh,
            factLow
          }),
          consumerData,
          { value: 1n }
        ),
      "expected nonzero mint-pass value to revert"
    );

    const [minted, claimedRecipient, claimedTokenId] = await mintConsumer.getMintClaim(
      summary.publicInputs.nullifier
    );
    assert.equal(minted, false);
    assert.equal(claimedRecipient, ethers.ZeroAddress);
    assert.equal(claimedTokenId, 0n);
    assert.equal(await mintConsumer.balanceOf(boundRecipient), 0n);
    assert.equal(await mintConsumer.nextTokenId(), 1n);
    assert.equal(await ethers.provider.getBalance(await mintConsumer.getAddress()), 0n);
  });

  it("rejects the mint path when the canonical mirrored Base fact has not been populated", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer] = await ethers.getSigners();

    const { factHigh, factLow, gate } = await setupMirroredFactPath({
      deployer,
      relayOutput,
      relayFactToBase: false
    });
    const mintConsumer = await deployContract(deployer, "PhilMintPassConsumer", [await gate.getAddress()]);
    const mintConsumerAddress = await mintConsumer.getAddress();
    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"));
    const authorization = canonicalAuthorization({
      summary,
      consumerAddress: mintConsumerAddress
    });
    const boundRecipient = await mintConsumer.previewBoundMintRecipient(
      authorization,
      consumerData
    );
    const [previewRecipient, previewTokenId] = await mintConsumer.previewMintClaim(
      authorization,
      consumerData
    );
    assert.equal(previewRecipient, boundRecipient);
    assert.equal(previewTokenId, 1n);

    await expectRevert(
      () =>
        gate.verifyAndConsume(
          authorization,
          canonicalProofPackage({
            summary,
            factHigh,
            factLow
          }),
          consumerData
        ),
      "expected missing mirrored fact to reject mint path"
    );
    const [minted, claimedRecipient, claimedTokenId] = await mintConsumer.getMintClaim(
      summary.publicInputs.nullifier
    );

    assert.equal(minted, false);
    assert.equal(claimedRecipient, ethers.ZeroAddress);
    assert.equal(claimedTokenId, 0n);
    assert.equal(await mintConsumer.balanceOf(boundRecipient), 0n);
    assert.equal(await mintConsumer.nextTokenId(), 1n);
  });

  it("rejects mismatched recipient/preimage paths", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer, wrongRecipient] = await ethers.getSigners();

    const { factHigh, factLow, gate } = await setupMirroredFactPath({
      deployer,
      relayOutput
    });
    const mintConsumer = await deployContract(deployer, "PhilMintPassConsumer", [await gate.getAddress()]);
    const mintConsumerAddress = await mintConsumer.getAddress();
    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"));
    const authorization = canonicalAuthorization({
      summary,
      consumerAddress: mintConsumerAddress
    });
    const boundRecipient = await mintConsumer.previewBoundMintRecipient(
      authorization,
      consumerData
    );
    const [previewRecipient, previewTokenId] = await mintConsumer.previewMintClaim(
      authorization,
      consumerData
    );
    assert.equal(previewRecipient, boundRecipient);
    assert.equal(previewTokenId, 1n);

    await expectRevert(
      () =>
        mintConsumer.assertBoundMintRecipient(
          authorization,
          consumerData,
          wrongRecipient.address
        ),
      "expected mismatched recipient/preimage path to reject"
    );
    const [minted, claimedRecipient, claimedTokenId] = await mintConsumer.getMintClaim(
      summary.publicInputs.nullifier
    );

    assert.notEqual(boundRecipient, wrongRecipient.address);
    assert.equal(minted, false);
    assert.equal(claimedRecipient, ethers.ZeroAddress);
    assert.equal(claimedTokenId, 0n);
    assert.equal(await mintConsumer.balanceOf(boundRecipient), 0n);
    assert.equal(await mintConsumer.nextTokenId(), 1n);
  });

  it("rejects the mint path when the fact payload is perturbed", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer] = await ethers.getSigners();

    const { factHigh, factLow, gate } = await setupMirroredFactPath({
      deployer,
      relayOutput
    });
    const mintConsumer = await deployContract(deployer, "PhilMintPassConsumer", [await gate.getAddress()]);
    const mintConsumerAddress = await mintConsumer.getAddress();
    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"));
    const authorization = canonicalAuthorization({
      summary,
      consumerAddress: mintConsumerAddress
    });
    const boundRecipient = await mintConsumer.previewBoundMintRecipient(
      authorization,
      consumerData
    );
    const [previewRecipient, previewTokenId] = await mintConsumer.previewMintClaim(
      authorization,
      consumerData
    );
    assert.equal(previewRecipient, boundRecipient);
    assert.equal(previewTokenId, 1n);

    await expectRevert(
      () =>
        gate.verifyAndConsume(
          authorization,
          canonicalProofPackage({
            summary,
            factHigh,
            factLow: factLow + 1n
          }),
          consumerData
        ),
      "expected perturbed mirrored fact payload to reject mint path"
    );
    const [minted, claimedRecipient, claimedTokenId] = await mintConsumer.getMintClaim(
      summary.publicInputs.nullifier
    );

    assert.equal(minted, false);
    assert.equal(claimedRecipient, ethers.ZeroAddress);
    assert.equal(claimedTokenId, 0n);
    assert.equal(await mintConsumer.balanceOf(boundRecipient), 0n);
    assert.equal(await mintConsumer.nextTokenId(), 1n);
  });
});
