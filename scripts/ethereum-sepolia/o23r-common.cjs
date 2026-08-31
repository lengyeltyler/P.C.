require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const {
  AbiCoder,
  Transaction,
  Wallet,
  concat,
  getAddress,
  keccak256
} = require("ethers");

const {
  calculateLocalProofGatedProposedAddresses,
  deriveLocalProofGatedValidatorKeyIdBinding
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

const ROOT = path.resolve(__dirname, "../..");
const CONFIG_DIR = path.join(ROOT, "config/ethereum-sepolia");
const O22_PROPOSAL_PATH = path.join(
  CONFIG_DIR,
  "O22_CURRENT_SOURCE_DEPLOYMENT_PROPOSAL.json"
);
const O23R_PROPOSAL_PATH = path.join(
  CONFIG_DIR,
  "O23R_NEW_DEPLOYER_DEPLOYMENT_PROPOSAL.json"
);
const O23R_FUNDING_PATH = path.join(
  CONFIG_DIR,
  "O23R_NEW_DEPLOYER_FUNDING_READINESS.json"
);
const O23R_RECEIPT_PATH = path.join(
  CONFIG_DIR,
  "O23R_CONFIRMATION_TARGET_DEPLOYMENT_RECEIPT.json"
);
const EXPECTED_DEPLOYER = "0x549A5C770085b00B60F6D729DB99f8Bffb72eE12";
const EXPECTED_FUNDING = "0xaDef2F2fdA57e92b593943f367D37d8Ce6B2F598";
const EXPECTED_VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const OLD_ADDRESSES = Object.freeze({
  target: "0x7e26405275C84c541e9f9aB68D1C6F7234a16345",
  factory: "0x7096565D191e664390b7041cCf297F443793e266",
  account: "0x30283Bfd6D65472d9f3b0A173382675b947C69d1"
});
const ARTIFACTS = Object.freeze({
  target:
    "artifacts/contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol/PhilCoreLocalProofConfirmationTargetV1.json",
  factory:
    "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol/PhilCore4337LocalProofAccountFactoryV1.json",
  account:
    "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
});
const SOURCE_PATHS = Object.freeze([
  "contracts/base/PhilCoreLocalProofConfirmationTargetV1.sol",
  "contracts/base/interfaces/IPhilCoreLocalProofAccountV1.sol",
  "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol",
  "contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol"
]);
const TARGET_CONFIRMATIONS = 2;
const APPROVAL_LIFETIME_MS = 2 * 60 * 60 * 1000;
const MAX_FEE_PER_GAS = 100_000_000_000n;
const MAX_PRIORITY_FEE_PER_GAS = 5_000_000_000n;
const abiCoder = AbiCoder.defaultAbiCoder();

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function writeJson(location, value) {
  ensureNoSecrets(value);
  fs.writeFileSync(location, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function sha256File(relativePath) {
  return sha256(fs.readFileSync(path.join(ROOT, relativePath)));
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalDigest(value) {
  return `0x${sha256(canonicalJson(value))}`;
}

function runGit(args) {
  const result = spawnSync("git", args, {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, GIT_OPTIONAL_LOCKS: "0" }
  });
  if (result.status !== 0) throw new Error(`git_${args[0]}_failed`);
  return result.stdout.trim();
}

function requireCleanRepository() {
  if (runGit(["status", "--porcelain=v1"]) !== "") {
    throw new Error("repository_must_be_clean");
  }
}

function assertRoleSeparation(input) {
  const deployer = getAddress(input.deployer);
  const funding = getAddress(input.funding);
  const validator = getAddress(input.validator);
  if (deployer !== getAddress(EXPECTED_DEPLOYER)) throw new Error("deployer_address_mismatch");
  if (funding !== getAddress(EXPECTED_FUNDING)) throw new Error("funding_address_mismatch");
  if (validator !== getAddress(EXPECTED_VALIDATOR)) {
    throw new Error("canonical_validator_changed");
  }
  if (new Set([deployer, funding, validator]).size !== 3) {
    throw new Error("sepolia_account_roles_not_separate");
  }
  return Object.freeze({ deployer, funding, validator });
}

function verifyConfiguredKeyPairs(environment = process.env) {
  const roles = assertRoleSeparation({
    deployer: environment.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
    funding: environment.PHILCORE_SEPOLIA_FUNDING_ADDRESS,
    validator: environment.PHILCORE_SEPOLIA_VALIDATOR_ADDRESS
  });
  const deployerWallet = new Wallet(
    normalizePrivateKey(environment.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY)
  );
  const fundingWallet = new Wallet(
    normalizePrivateKey(environment.PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY)
  );
  if (deployerWallet.address !== roles.deployer || fundingWallet.address !== roles.funding) {
    throw new Error("SUPPLIED_PRIVATE_KEY_ADDRESS_MISMATCH");
  }
  return Object.freeze({
    deployer: Object.freeze({
      address: deployerWallet.address,
      privateMaterialConfigured: true,
      addressMatch: true
    }),
    funding: Object.freeze({
      address: fundingWallet.address,
      privateMaterialConfigured: true,
      addressMatch: true
    }),
    validator: Object.freeze({
      address: roles.validator,
      preserved: true
    })
  });
}

function normalizePrivateKey(value) {
  if (typeof value !== "string" || !/^(0x)?[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error("private_key_configuration_invalid");
  }
  return value.startsWith("0x") ? value : `0x${value}`;
}

function compilerBinding() {
  const buildInfoDir = path.join(ROOT, "artifacts/build-info");
  const files = fs.readdirSync(buildInfoDir).filter((name) => name.endsWith(".json"));
  if (files.length !== 1) throw new Error("compiler_build_info_ambiguous");
  const relativePath = path.relative(ROOT, path.join(buildInfoDir, files[0]));
  const buildInfo = readJson(path.join(ROOT, relativePath));
  const settings = buildInfo.input?.settings ?? {};
  const binding = {
    version: buildInfo.solcVersion,
    optimizerEnabled: settings.optimizer?.enabled === true,
    optimizerRuns: settings.optimizer?.runs,
    viaIR: settings.viaIR === true,
    evmVersion: settings.evmVersion,
    buildInfoSha256: sha256File(relativePath)
  };
  if (
    binding.version !== "0.8.24"
    || !binding.optimizerEnabled
    || binding.optimizerRuns !== 200
    || !binding.viaIR
    || binding.evmVersion !== "paris"
  ) {
    throw new Error("compiler_configuration_mismatch");
  }
  return binding;
}

function artifactBindings() {
  const o22 = readJson(O22_PROPOSAL_PATH);
  return o22.artifacts.map((expected) => {
    const artifact = readJson(path.join(ROOT, expected.artifact));
    const current = {
      ...expected,
      sourceSha256: sha256File(expected.source),
      abiSha256: sha256(canonicalJson(artifact.abi)),
      creationBytecodeHash: keccak256(artifact.bytecode),
      deployedBytecodeHash: keccak256(artifact.deployedBytecode),
      creationBytecodeSize: (artifact.bytecode.length - 2) / 2,
      deployedBytecodeSize: (artifact.deployedBytecode.length - 2) / 2
    };
    for (const field of [
      "sourceSha256",
      "abiSha256",
      "creationBytecodeHash",
      "deployedBytecodeHash",
      "creationBytecodeSize",
      "deployedBytecodeSize"
    ]) {
      if (current[field] !== expected[field]) {
        throw new Error(`CURRENT_SOURCE_BYTECODE_CHANGED:${expected.id}:${field}`);
      }
    }
    return current;
  });
}

function sourceBinding() {
  const sources = SOURCE_PATHS.map((sourcePath) => ({
    path: sourcePath,
    sha256: sha256File(sourcePath)
  }));
  return {
    sourceCommitAtGeneration: runGit(["rev-parse", "HEAD"]),
    deploymentSourceTreeSha256: sha256(canonicalJson(sources)),
    sources
  };
}

function calculateAddresses(identity, pendingNonce) {
  const accountArtifact = readJson(path.join(ROOT, ARTIFACTS.account));
  const result = calculateLocalProofGatedProposedAddresses({
    deployerAddress: process.env.PHILCORE_SEPOLIA_DEPLOYER_ADDRESS,
    deployerNonce: pendingNonce,
    ownerAddress: identity.validatorAddress,
    ownerCommitment: identity.ownerCommitment,
    validatorKeyId: deriveLocalProofGatedValidatorKeyIdBinding(identity.validatorKeyId),
    accountSalt: process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT,
    accountCreationBytecode: accountArtifact.bytecode
  });
  if (result.status !== "calculated") {
    throw new Error(`address_calculation_failed:${result.errors.join(",")}`);
  }
  return result;
}

function initializationBinding(addresses, identity) {
  const validatorKeyId = deriveLocalProofGatedValidatorKeyIdBinding(
    identity.validatorKeyId
  );
  const salt = BigInt(process.env.PHILCORE_SEPOLIA_ACCOUNT_SALT);
  const factoryConstructorArguments = [
    ERC4337_V07_CANONICAL_ENTRYPOINT,
    addresses.targetAddress,
    ETHEREUM_SEPOLIA_CHAIN_ID
  ];
  const accountConstructorArguments = [
    ERC4337_V07_CANONICAL_ENTRYPOINT,
    identity.validatorAddress,
    identity.ownerCommitment,
    addresses.targetAddress,
    validatorKeyId,
    ETHEREUM_SEPOLIA_CHAIN_ID
  ];
  const accountArtifact = readJson(path.join(ROOT, ARTIFACTS.account));
  const accountConstructorData = abiCoder.encode(
    ["address", "address", "bytes32", "address", "bytes32", "uint256"],
    accountConstructorArguments
  );
  return {
    targetConstructorArguments: [],
    targetConstructorData: "0x",
    targetConstructorHash: keccak256("0x"),
    factoryConstructorArguments,
    factoryConstructorData: abiCoder.encode(
      ["address", "address", "uint256"],
      factoryConstructorArguments
    ),
    accountConstructorArguments,
    accountConstructorData,
    create2: {
      factory: addresses.factoryAddress,
      accountSaltDecimal: salt.toString(),
      accountCreationBytecodeHash: keccak256(accountArtifact.bytecode),
      accountConstructorDataHash: keccak256(accountConstructorData),
      accountInitCodeHash: keccak256(concat([
        accountArtifact.bytecode,
        accountConstructorData
      ])),
      predictedAccount: addresses.accountAddress
    }
  };
}

function buildTargetDeploymentTransaction(input) {
  const transaction = {
    type: 2,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    nonce: Number(input.nonce),
    to: null,
    value: 0n,
    data: input.creationBytecode,
    gasLimit: BigInt(input.gasLimit),
    maxFeePerGas: BigInt(input.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(input.maxPriorityFeePerGas)
  };
  validateTargetDeploymentTransaction(transaction, input);
  return transaction;
}

function validateTargetDeploymentTransaction(transaction, expected) {
  if (Number(transaction.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("wrong_chain");
  }
  if (transaction.to !== null) throw new Error("target_deployment_to_must_be_null");
  if (BigInt(transaction.value) !== 0n) throw new Error("target_deployment_value_must_be_zero");
  if (BigInt(transaction.maxFeePerGas) > MAX_FEE_PER_GAS) {
    throw new Error("max_fee_exceeds_o23r_ceiling");
  }
  if (BigInt(transaction.maxPriorityFeePerGas) > MAX_PRIORITY_FEE_PER_GAS) {
    throw new Error("priority_fee_exceeds_o23r_ceiling");
  }
  if (expected) {
    if (String(transaction.nonce) !== String(expected.nonce)) throw new Error("nonce_mismatch");
    if (keccak256(transaction.data) !== expected.creationBytecodeHash) {
      throw new Error("target_creation_bytecode_mismatch");
    }
  }
  return true;
}

function verifySignedTargetDeployment(rawSignedTransaction, expected) {
  const parsed = Transaction.from(rawSignedTransaction);
  validateTargetDeploymentTransaction(parsed, expected);
  if (getAddress(parsed.from) !== getAddress(expected.signer)) {
    throw new Error("signer_recovery_failed");
  }
  if (parsed.hash !== expected.transactionHash) {
    throw new Error("transaction_hash_mismatch");
  }
  return parsed;
}

function ensureNoSecrets(value) {
  const serialized = JSON.stringify(value);
  if (
    /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey|recoverySecret/i
      .test(serialized)
  ) {
    throw new Error("secret_field_detected");
  }
  for (const candidate of [
    process.env.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY,
    process.env.PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY,
    process.env.PHILCORE_SEPOLIA_RPC_URL
  ]) {
    if (candidate && serialized.includes(candidate)) throw new Error("secret_value_detected");
  }
}

module.exports = {
  APPROVAL_LIFETIME_MS,
  ARTIFACTS,
  CONFIG_DIR,
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  MAX_FEE_PER_GAS,
  MAX_PRIORITY_FEE_PER_GAS,
  O22_PROPOSAL_PATH,
  O23R_FUNDING_PATH,
  O23R_PROPOSAL_PATH,
  O23R_RECEIPT_PATH,
  OLD_ADDRESSES,
  ROOT,
  SOURCE_PATHS,
  TARGET_CONFIRMATIONS,
  artifactBindings,
  assertRoleSeparation,
  buildTargetDeploymentTransaction,
  calculateAddresses,
  canonicalDigest,
  canonicalJson,
  compilerBinding,
  ensureNoSecrets,
  initializationBinding,
  normalizePrivateKey,
  readJson,
  requireCleanRepository,
  runGit,
  sha256,
  sha256File,
  sourceBinding,
  validateTargetDeploymentTransaction,
  verifyConfiguredKeyPairs,
  verifySignedTargetDeployment,
  writeJson
};
