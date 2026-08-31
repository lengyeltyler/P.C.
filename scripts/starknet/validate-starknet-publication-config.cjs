const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { keccak256, toUtf8Bytes } = require("ethers");

const REPO_ROOT = path.resolve(__dirname, "../..");
const DEFAULT_CONFIG = path.join(REPO_ROOT, "config/starknet-publication-config.local.json");
const DEFAULT_READINESS = path.join(REPO_ROOT, "config/starknet-publication-readiness.json");

const SENSITIVE_FIELD_NAMES = [
  "privateKey",
  "private_key",
  "seed",
  "seedPhrase",
  "mnemonic",
  "password",
  "passphrase",
  "secret",
  "apiKey",
  "rpcPassword",
  "rpcCredential",
  "phil_secret",
  "nullifierSeed",
  "vaultKey"
];

function readJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function sha256File(relativePath) {
  const absolutePath = path.join(REPO_ROOT, relativePath);
  if (!fs.existsSync(absolutePath)) return null;
  return crypto.createHash("sha256").update(fs.readFileSync(absolutePath)).digest("hex");
}

function sha256Json(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function starknetSelector(entrypoint) {
  const mask = (1n << 250n) - 1n;
  return `0x${(BigInt(keccak256(toUtf8Bytes(entrypoint))) & mask).toString(16)}`;
}

function addIssue(issues, code, message) {
  issues.push({ code, message });
}

function walkForSensitiveKeys(value, issues, trail = []) {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkForSensitiveKeys(item, issues, [...trail, String(index)]));
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE_FIELD_NAMES.some((sensitive) => key.toLowerCase() === sensitive.toLowerCase())) {
      addIssue(issues, "secret_field_present", `secret-shaped field is not allowed: ${[...trail, key].join(".")}`);
    }
    walkForSensitiveKeys(child, issues, [...trail, key]);
  }
}

function validateConfig(config, readiness) {
  const issues = [];
  if (config.version !== 1) addIssue(issues, "invalid_version", "version must be 1.");
  if (config.kind !== "starknet-verified-fact-publication-config") {
    addIssue(issues, "invalid_kind", "kind must be starknet-verified-fact-publication-config.");
  }
  walkForSensitiveKeys(config, issues);

  const binding = config.artifactBinding || {};
  const publication = config.publication || {};
  const messageShape = publication.messageShape || {};
  const readinessArtifacts = readiness.artifacts || {};
  const readinessMessage = readiness.messageShape || {};

  const expectedArtifacts = [
    ["sierra", "sierraPath", "sierraSha256"],
    ["casm", "compiledClassPath", "compiledClassSha256"],
    ["packageSierra", "packageSierraPath", "packageSierraSha256"],
    ["starknetArtifacts", "starknetArtifactsPath", "starknetArtifactsSha256"]
  ];
  for (const [readinessKey, pathKey, hashKey] of expectedArtifacts) {
    const artifact = readinessArtifacts[readinessKey];
    if (!artifact || !artifact.present) {
      addIssue(issues, "readiness_artifact_missing", `${readinessKey} artifact is not present in readiness manifest.`);
      continue;
    }
    if (binding[pathKey] !== artifact.path) {
      addIssue(issues, "artifact_path_mismatch", `${pathKey} does not match readiness manifest.`);
    }
    if (binding[hashKey] !== artifact.sha256) {
      addIssue(issues, "artifact_hash_mismatch", `${hashKey} does not match readiness manifest.`);
    }
    const actualHash = sha256File(binding[pathKey]);
    if (actualHash !== binding[hashKey]) {
      addIssue(issues, "artifact_file_hash_mismatch", `${pathKey} does not hash to configured ${hashKey}.`);
    }
  }

  if (binding.packageName !== readiness.package?.name) {
    addIssue(issues, "package_name_mismatch", "packageName does not match readiness manifest.");
  }
  if (binding.contractName !== readiness.package?.contractName) {
    addIssue(issues, "contract_name_mismatch", "contractName does not match readiness manifest.");
  }
  if (binding.entrypoint !== readiness.package?.entrypoint) {
    addIssue(issues, "entrypoint_mismatch", "entrypoint does not match readiness manifest.");
  }
  if (binding.entrypointSelector !== starknetSelector(binding.entrypoint)) {
    addIssue(issues, "entrypoint_selector_mismatch", "entrypointSelector does not match Starknet selector derivation.");
  }
  if (binding.scarbVersion !== readiness.toolchain?.scarbVersion) {
    addIssue(issues, "scarb_version_mismatch", "scarbVersion does not match readiness manifest.");
  }
  if (binding.cairoVersion !== readiness.toolchain?.cairoVersion) {
    addIssue(issues, "cairo_version_mismatch", "cairoVersion does not match readiness manifest.");
  }
  if (binding.rustNightlyToolchain !== readiness.toolchain?.rustNightlyToolchain) {
    addIssue(issues, "rust_version_mismatch", "rustNightlyToolchain does not match readiness manifest.");
  }

  const contractClass = binding.sierraPath ? readJson(path.join(REPO_ROOT, binding.sierraPath)) : null;
  if (contractClass) {
    const abiHash = sha256Json(contractClass.abi);
    if (binding.abiSha256 !== abiHash) {
      addIssue(issues, "abi_hash_mismatch", "abiSha256 does not match the contract class ABI.");
    }
    const entrypoint = (contractClass.abi || []).find(
      (item) => item.type === "function" && item.name === binding.entrypoint
    );
    if (!entrypoint) {
      addIssue(issues, "entrypoint_missing", "configured entrypoint is missing from ABI.");
    } else {
      const entrypointHash = sha256Json(entrypoint);
      if (binding.entrypointAbiSha256 !== entrypointHash) {
        addIssue(issues, "entrypoint_abi_hash_mismatch", "entrypointAbiSha256 does not match ABI entrypoint.");
      }
      const inputNames = entrypoint.inputs.map((input) => input.name).join(",");
      if (inputNames !== "l1_recipient,proof,claim") {
        addIssue(issues, "entrypoint_inputs_mismatch", "entrypoint inputs must be l1_recipient,proof,claim.");
      }
    }
  }

  if (publication.proofType !== readinessMessage.expectedProofType) {
    addIssue(issues, "unsupported_proof_type", "proofType does not match readiness manifest.");
  }
  if (messageShape.payload !== readinessMessage.payload) {
    addIssue(issues, "message_shape_mismatch", "payload shape does not match readiness manifest.");
  }
  if (messageShape.proofInputHash !== readinessMessage.proofInputHash) {
    addIssue(issues, "proof_input_hash_mismatch", "proofInputHash does not match readiness manifest.");
  }
  if (JSON.stringify(messageShape.expectedFactPayload) !== JSON.stringify(readinessMessage.expectedFactPayload)) {
    addIssue(issues, "fact_payload_mismatch", "expectedFactPayload does not match readiness manifest.");
  }
  if (JSON.stringify(messageShape.l2ToL1PayloadOrdering) !== JSON.stringify(["fact_high", "fact_low"])) {
    addIssue(issues, "high_low_order_mismatch", "L2-to-L1 payload ordering must be fact_high, fact_low.");
  }

  const l1 = config.l1RecipientBinding || {};
  if (l1.configuredL1RecipientAddress === "0x0" || l1.configuredL1RecipientAddress === "0x") {
    addIssue(issues, "zero_l1_recipient", "zero L1 recipient address is not allowed.");
  }
  if (l1.model === "caller_supplied_entrypoint_argument" && !l1.requiredPolicy) {
    addIssue(issues, "missing_l1_recipient_policy", "caller-supplied L1 recipient requires an explicit policy.");
  }

  const l2 = config.expectedL2SenderBinding || {};
  if (l2.status !== "unresolved_until_deployment" && !l2.publicationContractAddress) {
    addIssue(issues, "missing_publication_contract_address", "resolved L2 sender binding requires a publication contract address.");
  }

  const profiles = config.networkProfiles || {};
  for (const [profileId, profile] of Object.entries(profiles)) {
    if (!profile.starknetChainId) {
      addIssue(issues, "missing_chain_id", `${profileId} is missing starknetChainId.`);
    }
    if (profileId === "starknet_mainnet" && profile.enabled) {
      addIssue(issues, "mainnet_enabled", "mainnet profile must remain disabled until accepted deployment data exists.");
    }
    if (profile.usableForTransactionPreparation && profile.publicationContractDeploymentStatus !== "deployed") {
      addIssue(
        issues,
        "preparation_enabled_without_deployment",
        `${profileId} cannot be usable for transaction preparation before deployment.`
      );
    }
    if (profile.usableForTransactionPreparation && !config.expectedL2SenderBinding?.publicationContractAddress) {
      addIssue(
        issues,
        "preparation_enabled_without_l2_sender",
        `${profileId} cannot be usable for transaction preparation without expected L2 sender binding.`
      );
    }
  }

  const account = config.accountCallerModel || {};
  if (!account.recommendedModel) {
    addIssue(issues, "account_model_missing", "account/caller model recommendation is required.");
  }
  if (account.multiChainWalletImplementationRequired) {
    addIssue(issues, "multichain_wallet_required", "publication config must not require multi-chain wallet implementation.");
  }

  const secrets = config.secretsPolicy || {};
  for (const [key, value] of Object.entries(secrets)) {
    if (value !== false) addIssue(issues, "secrets_policy_not_false", `${key} must be false.`);
  }

  return {
    ok: issues.length === 0,
    issues,
    summary: {
      profileId: config.profileId,
      packageName: binding.packageName,
      contractName: binding.contractName,
      entrypoint: binding.entrypoint,
      deploymentReady: readiness.status?.deployment_ready === true,
      productionApproved: readiness.status?.production_approved === true,
      publicationContractAddress: config.expectedL2SenderBinding?.publicationContractAddress || null,
      configuredL1RecipientAddress: config.l1RecipientBinding?.configuredL1RecipientAddress || null,
      recommendedAccountModel: account.recommendedModel || null
    }
  };
}

function main() {
  const args = process.argv.slice(2);
  const configIndex = args.indexOf("--config");
  const readinessIndex = args.indexOf("--readiness");
  const configPath = configIndex >= 0 ? path.resolve(REPO_ROOT, args[configIndex + 1]) : DEFAULT_CONFIG;
  const readinessPath = readinessIndex >= 0 ? path.resolve(REPO_ROOT, args[readinessIndex + 1]) : DEFAULT_READINESS;
  const result = validateConfig(readJson(configPath), readJson(readinessPath));
  console.log(JSON.stringify(result, null, 2));
  if (!result.ok) process.exit(1);
}

if (require.main === module) {
  main();
}

module.exports = {
  validateConfig
};
