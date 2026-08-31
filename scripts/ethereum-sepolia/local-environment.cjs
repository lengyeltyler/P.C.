const fs = require("node:fs");
const path = require("node:path");
const { isAddress, isHexString } = require("ethers");
const dotenv = require("dotenv");

const LOCAL_ENV_FILENAME = ".env.sepolia.local";
const SAMPLEPHIL_VALIDATOR_ADDRESS = "0x43cdfEe77C8095B1590F7b43a8d420b26a73F1d3";
const EXPECTED_KEYS = Object.freeze([
  "PHILCORE_SEPOLIA_RPC_URL",
  "PHILCORE_SEPOLIA_DEPLOYER_ADDRESS",
  "PHILCORE_SEPOLIA_DEPLOYER_NONCE",
  "PHILCORE_SEPOLIA_VALIDATOR_ADDRESS",
  "PHILCORE_SEPOLIA_OWNER_COMMITMENT",
  "PHILCORE_SEPOLIA_VALIDATOR_KEY_ID",
  "PHILCORE_SEPOLIA_ACCOUNT_SALT",
  "PHILCORE_SEPOLIA_BUNDLER_URL"
]);
const OPTIONAL_O23R_LOCAL_KEYS = Object.freeze([
  "PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY",
  "PHILCORE_SEPOLIA_FUNDING_ADDRESS",
  "PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY"
]);
const FORBIDDEN_NAME =
  /(private|secret|seed|passphrase|password|mnemonic|recovery|approved|approval|submit|funding)/i;
const PLACEHOLDER = /(?:paste|placeholder|todo|changeme|<[^>]+>)/i;
const VALIDATOR_KEY_ID = /^validator_key_[0-9a-f]{16}$/;

function assertValidUrl(value, label, allowEmpty = false) {
  if (allowEmpty && value === "") return;
  if (!value || PLACEHOLDER.test(value)) throw new Error(`${label}_invalid`);
  const parsed = new URL(value);
  if (!["https:", "http:"].includes(parsed.protocol)) throw new Error(`${label}_invalid`);
}

function validateSepoliaLocalEnvironment(values) {
  const errors = [];
  for (const name of Object.keys(values)) {
    const isO23rSelector = OPTIONAL_O23R_LOCAL_KEYS.includes(name);
    if (!EXPECTED_KEYS.includes(name) && !isO23rSelector) {
      errors.push(`unexpected_field:${name}`);
    }
    if (FORBIDDEN_NAME.test(name) && !isO23rSelector) {
      errors.push(`forbidden_field:${name}`);
    }
  }
  for (const name of EXPECTED_KEYS) {
    if (values[name] === undefined) errors.push(`missing_field:${name}`);
  }
  try {
    assertValidUrl(values.PHILCORE_SEPOLIA_RPC_URL, "rpc_url");
  } catch (error) {
    errors.push(error.message);
  }
  try {
    assertValidUrl(values.PHILCORE_SEPOLIA_BUNDLER_URL, "bundler_url", true);
  } catch (error) {
    errors.push(error.message);
  }
  if (!isAddress(values.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS ?? "")) {
    errors.push("deployer_address_invalid");
  }
  if (
    values.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY !== undefined
    && !/^(0x)?[0-9a-fA-F]{64}$/.test(values.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY)
  ) {
    errors.push("deployer_private_key_invalid");
  }
  if (
    values.PHILCORE_SEPOLIA_FUNDING_ADDRESS !== undefined
    && !isAddress(values.PHILCORE_SEPOLIA_FUNDING_ADDRESS)
  ) {
    errors.push("funding_address_invalid");
  }
  if (
    values.PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY !== undefined
    && !/^(0x)?[0-9a-fA-F]{64}$/.test(values.PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY)
  ) {
    errors.push("funding_private_key_invalid");
  }
  if (!/^(0|[1-9][0-9]*)$/.test(values.PHILCORE_SEPOLIA_DEPLOYER_NONCE ?? "")) {
    errors.push("deployer_nonce_invalid");
  }
  if (!isAddress(values.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS ?? "")) {
    errors.push("validator_address_invalid");
  } else if (
    values.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS.toLowerCase()
      === SAMPLEPHIL_VALIDATOR_ADDRESS.toLowerCase()
  ) {
    errors.push("samplephil_validator_not_canonical");
  }
  if (!isHexString(values.PHILCORE_SEPOLIA_OWNER_COMMITMENT ?? "", 32)) {
    errors.push("owner_commitment_invalid");
  }
  if (!VALIDATOR_KEY_ID.test(values.PHILCORE_SEPOLIA_VALIDATOR_KEY_ID ?? "")) {
    errors.push("validator_key_id_invalid");
  }
  if (!isHexString(values.PHILCORE_SEPOLIA_ACCOUNT_SALT ?? "", 32)) {
    errors.push("account_salt_invalid");
  }
  if (
    isAddress(values.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS ?? "")
    && isAddress(values.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS ?? "")
    && values.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS.toLowerCase()
      === values.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS.toLowerCase()
  ) {
    errors.push("deployer_validator_role_collision");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

function readCanonicalDesktopIdentityBinding(options = {}) {
  const home = options.home ?? process.env.HOME;
  if (!home) throw new Error("home_directory_unavailable");
  const indexPath = options.indexPath ?? path.join(
    home,
    "Library/Application Support/PhilCore Desktop Local Alpha",
    "philcore-local-identities/identity-index.json"
  );
  const index = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  const identities = Array.isArray(index.identities) ? index.identities : [];
  const complete = identities.filter((identity) =>
    typeof identity.identityId === "string"
    && isHexString(identity.ownerCommitment, 32)
    && isAddress(identity.validatorPublicAddress)
    && VALIDATOR_KEY_ID.test(identity.validatorKeyReferenceId)
    && identity.validatorStatus === "available"
  );
  if (complete.length !== 1) throw new Error("CANONICAL_IDENTITY_RECORD_AMBIGUOUS");
  const identity = complete[0];
  return Object.freeze({
    identityId: identity.identityId,
    label: identity.label,
    ownerCommitment: identity.ownerCommitment,
    validatorAddress: identity.validatorPublicAddress,
    validatorKeyId: identity.validatorKeyReferenceId,
    identityStatus: identity.status,
    validatorStatus: identity.validatorStatus,
    createdAt: identity.createdAt
  });
}

function validateCanonicalIdentityBinding(values, identity) {
  const errors = [];
  if (values.PHILCORE_SEPOLIA_OWNER_COMMITMENT !== identity.ownerCommitment) {
    errors.push("canonical_owner_commitment_mismatch");
  }
  if (
    values.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS.toLowerCase()
      !== identity.validatorAddress.toLowerCase()
  ) {
    errors.push("canonical_validator_address_mismatch");
  }
  if (values.PHILCORE_SEPOLIA_VALIDATOR_KEY_ID !== identity.validatorKeyId) {
    errors.push("canonical_validator_key_id_mismatch");
  }
  return Object.freeze({ valid: errors.length === 0, errors: Object.freeze(errors) });
}

function loadSepoliaLocalEnvironment(options = {}) {
  const root = options.root ?? path.resolve(__dirname, "../..");
  const envPath = path.join(root, LOCAL_ENV_FILENAME);
  if (!fs.existsSync(envPath)) throw new Error("SEPOLIA_LOCAL_ENV_NOT_FOUND");
  const mode = fs.statSync(envPath).mode & 0o777;
  if (mode !== 0o600) throw new Error("SEPOLIA_LOCAL_ENV_PERMISSIONS_INVALID");
  const values = dotenv.parse(fs.readFileSync(envPath));
  const validation = validateSepoliaLocalEnvironment(values);
  if (!validation.valid) throw new Error(validation.errors.join(","));
  const identity = readCanonicalDesktopIdentityBinding(options);
  const binding = validateCanonicalIdentityBinding(values, identity);
  if (!binding.valid) throw new Error(binding.errors.join(","));
  const target = options.environment ?? process.env;
  for (const name of EXPECTED_KEYS) target[name] = values[name];
  if (options.includeO23rSensitiveSelectors === true) {
    for (const name of OPTIONAL_O23R_LOCAL_KEYS) {
      if (values[name] !== undefined) target[name] = values[name];
    }
  }
  const publicValues = Object.fromEntries(
    EXPECTED_KEYS.map((name) => [name, values[name]])
  );
  return Object.freeze({
    path: envPath,
    values: Object.freeze(publicValues),
    identity,
    permissions: "0600",
    processEnvironmentPrecedence: false,
    o23rSensitiveSelectorsConfigured: Object.freeze(
      Object.fromEntries(OPTIONAL_O23R_LOCAL_KEYS.map(
        (name) => [name, values[name] !== undefined]
      ))
    )
  });
}

module.exports = {
  EXPECTED_KEYS,
  LOCAL_ENV_FILENAME,
  OPTIONAL_O23R_LOCAL_KEYS,
  SAMPLEPHIL_VALIDATOR_ADDRESS,
  loadSepoliaLocalEnvironment,
  readCanonicalDesktopIdentityBinding,
  validateCanonicalIdentityBinding,
  validateSepoliaLocalEnvironment
};
