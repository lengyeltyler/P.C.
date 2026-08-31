const fs = require("node:fs");
const path = require("node:path");

const {
  validateStarknetPublicationPreflight
} = require("../../apps/phil-device-sdk/src/runtime/index.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const CONFIG_PATH = path.join(REPO_ROOT, "config/starknet-publication-config.local.json");
const READINESS_PATH = path.join(REPO_ROOT, "config/starknet-publication-readiness.json");

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function hasArg(name) {
  return process.argv.includes(name);
}

function mode() {
  if (hasArg("--monitor")) return "monitor";
  if (hasArg("--submit")) return "submit";
  return "diagnose";
}

function profile(config) {
  return config.networkProfiles?.[config.profileId] || {};
}

function readiness(config, manifest) {
  const selectedProfile = profile(config);
  const preflight = validateStarknetPublicationPreflight(config);
  const blockers = [...preflight.errors];
  if (config.profileId !== "starknet_sepolia") {
    blockers.push("live public submission requires starknet_sepolia profile");
  }
  if (selectedProfile.starknetChainId === "SN_MAIN" || config.profileId.includes("mainnet")) {
    blockers.push("mainnet is prohibited");
  }
  if (selectedProfile.publicationContractDeploymentStatus !== "deployed") {
    blockers.push("publication contract deployment is not accepted");
  }
  if (config.accountCallerModel?.status !== "resolved") {
    blockers.push("publisher account model unresolved");
  }
  if (config.secretsPolicy?.privateKeysAllowed !== false) {
    blockers.push("private key policy must reject repository secrets");
  }
  const artifact = manifest.artifacts?.starknet_integration_contract_class || {};
  if (!artifact.sha256 && !config.artifactBinding?.sierraSha256) {
    blockers.push("reproducible Sierra artifact hash missing");
  }
  return blockers;
}

function report() {
  const config = readJson(CONFIG_PATH);
  const manifest = readJson(READINESS_PATH);
  const selectedProfile = profile(config);
  const blockers = readiness(config, manifest);
  const requestedMode = mode();
  const mutationFlagPresent = hasArg("--submit");
  const canAttemptLiveSubmit =
    requestedMode === "submit"
    && mutationFlagPresent
    && blockers.length === 0
    && config.profileId === "starknet_sepolia";
  return {
    phase: "M.6A.5",
    command_mode: requestedMode,
    configured_profile: config.profileId,
    starknet_chain_id: selectedProfile.starknetChainId || null,
    rpc_reference: selectedProfile.rpcReference || null,
    publication_class_hash: config.artifactBinding?.starknetClassHash || null,
    compiled_class_hash: config.artifactBinding?.compiledClassHash || null,
    abi_hash: config.artifactBinding?.abiSha256 || null,
    publication_contract_address: config.expectedL2SenderBinding?.publicationContractAddress || null,
    l1_recipient_address: config.l1RecipientBinding?.configuredL1RecipientAddress || null,
    publisher_account_address: config.accountCallerModel?.accountAddress || null,
    deployment_status: selectedProfile.publicationContractDeploymentStatus || null,
    deployment_approval_status: config.configurationApprovalStatus || null,
    account_model_status: config.accountCallerModel?.status || null,
    submission_approval_status: "missing_external_approval_artifact",
    live_submission_performed: false,
    live_deployment_performed: false,
    receipt_monitoring_performed: false,
    l1_anchor_called: false,
    l1_to_base_relay_called: false,
    base_execution_called: false,
    nullifier_consumed: false,
    can_attempt_live_submission: canAttemptLiveSubmit,
    reason: blockers.length > 0
      ? blockers.join("; ")
      : "no signed approved transaction artifact or live submitter is wired in this diagnostic command",
    blockers
  };
}

function printText(summary) {
  console.log("Starknet fact-publication submission readiness");
  console.log(`phase: ${summary.phase}`);
  console.log(`commandMode: ${summary.command_mode}`);
  console.log(`configuredProfile: ${summary.configured_profile}`);
  console.log(`starknetChainId: ${summary.starknet_chain_id}`);
  console.log(`publicationContract: ${summary.publication_contract_address}`);
  console.log(`l1Recipient: ${summary.l1_recipient_address}`);
  console.log(`publisherAccount: ${summary.publisher_account_address}`);
  console.log(`deploymentStatus: ${summary.deployment_status}`);
  console.log(`submissionApprovalStatus: ${summary.submission_approval_status}`);
  console.log(`live_submission_performed: ${summary.live_submission_performed}`);
  console.log(`live_deployment_performed: ${summary.live_deployment_performed}`);
  console.log(`receipt_monitoring_performed: ${summary.receipt_monitoring_performed}`);
  console.log(`l1_anchor_called: ${summary.l1_anchor_called}`);
  console.log(`base_execution_called: ${summary.base_execution_called}`);
  console.log(`nullifier_consumed: ${summary.nullifier_consumed}`);
  console.log(`reason: ${summary.reason}`);
}

const summary = report();
if (hasArg("--json")) {
  console.log(JSON.stringify(summary, null, 2));
} else {
  printText(summary);
}
