require("tsx/cjs");

const fs = require("node:fs");
const path = require("node:path");
const {
  AbiCoder,
  Transaction,
  concat,
  getAddress,
  getCreate2Address,
  getCreateAddress,
  keccak256,
  toBeHex,
  zeroPadValue
} = require("ethers");

const {
  ARTIFACTS,
  EXPECTED_DEPLOYER,
  MAX_FEE_PER_GAS,
  MAX_PRIORITY_FEE_PER_GAS,
  ROOT,
  artifactBindings,
  canonicalDigest,
  ensureNoSecrets,
  readJson,
  sha256File,
  writeJson
} = require("./o23r-common.cjs");
const {
  deriveLocalProofGatedValidatorKeyIdBinding
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

const EXPECTED_TARGET = "0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7";
const EXPECTED_FACTORY = "0x6a9905Bc18620d9689e6a3214C43eC10B99b824e";
const EXPECTED_ACCOUNT = "0xF7212776373B51c1514Dd9C4490048270056C150";
const FACTORY_DEPLOYMENT_NONCE = "2";
const O23R_RECEIPT_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O23R_CONFIRMATION_TARGET_DEPLOYMENT_RECEIPT.json"
);
const O24_PROPOSAL_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O24_FACTORY_DEPLOYMENT_PROPOSAL.json"
);
const O24_RECEIPT_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O24_FACTORY_DEPLOYMENT_RECEIPT.json"
);
const abiCoder = AbiCoder.defaultAbiCoder();

function factoryConstructorBinding() {
  const arguments_ = [
    ERC4337_V07_CANONICAL_ENTRYPOINT,
    EXPECTED_TARGET,
    ETHEREUM_SEPOLIA_CHAIN_ID
  ];
  const data = abiCoder.encode(
    ["address", "address", "uint256"],
    arguments_
  );
  return Object.freeze({
    arguments: Object.freeze(arguments_),
    data,
    dataHash: keccak256(data),
    entryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
    approvedConfirmationTarget: EXPECTED_TARGET,
    expectedChainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    accountImplementationModel: "factory_embeds_creation_bytecode_and_uses_create2",
    standaloneImplementationRequired: false
  });
}

function calculateO24Addresses(identity, accountSalt) {
  const factory = getCreateAddress({
    from: EXPECTED_DEPLOYER,
    nonce: BigInt(FACTORY_DEPLOYMENT_NONCE)
  });
  if (factory !== EXPECTED_FACTORY) {
    throw new Error("FACTORY_ADDRESS_PREDICTION_CHANGED");
  }
  const accountArtifact = readJson(path.join(ROOT, ARTIFACTS.account));
  const validatorKeyIdBinding = deriveLocalProofGatedValidatorKeyIdBinding(
    identity.validatorKeyId
  );
  const accountConstructorArguments = [
    ERC4337_V07_CANONICAL_ENTRYPOINT,
    identity.validatorAddress,
    identity.ownerCommitment,
    EXPECTED_TARGET,
    validatorKeyIdBinding,
    ETHEREUM_SEPOLIA_CHAIN_ID
  ];
  const accountConstructorData = abiCoder.encode(
    ["address", "address", "bytes32", "address", "bytes32", "uint256"],
    accountConstructorArguments
  );
  const accountInitCode = concat([accountArtifact.bytecode, accountConstructorData]);
  const salt = BigInt(accountSalt);
  const account = getCreate2Address(
    factory,
    zeroPadValue(toBeHex(salt), 32),
    keccak256(accountInitCode)
  );
  if (account !== EXPECTED_ACCOUNT) {
    throw new Error("COUNTERFACTUAL_ACCOUNT_PREDICTION_CHANGED");
  }
  return Object.freeze({
    factory,
    account,
    accountSaltDecimal: salt.toString(),
    accountSaltBytes32: zeroPadValue(toBeHex(salt), 32),
    validatorKeyIdBinding,
    accountConstructorArguments: Object.freeze(accountConstructorArguments),
    accountConstructorData,
    accountCreationBytecodeHash: keccak256(accountArtifact.bytecode),
    accountConstructorDataHash: keccak256(accountConstructorData),
    accountInitCodeHash: keccak256(accountInitCode)
  });
}

function buildInfo() {
  const directory = path.join(ROOT, "artifacts/build-info");
  const files = fs.readdirSync(directory).filter((name) => name.endsWith(".json"));
  if (files.length !== 1) throw new Error("compiler_build_info_ambiguous");
  return readJson(path.join(directory, files[0]));
}

function collectVariableNames(ast) {
  const names = new Map();
  function visit(value) {
    if (!value || typeof value !== "object") return;
    if (value.nodeType === "VariableDeclaration" && value.id && value.name) {
      names.set(String(value.id), value.name);
    }
    for (const child of Object.values(value)) visit(child);
  }
  visit(ast);
  return names;
}

function expectedFactoryRuntimeBinding() {
  const info = buildInfo();
  const sourcePath =
    "contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol";
  const output = info.output.contracts[sourcePath]
    .PhilCore4337LocalProofAccountFactoryV1.evm.deployedBytecode;
  const names = collectVariableNames(info.output.sources[sourcePath].ast);
  const values = {
    entryPoint: zeroPadValue(ERC4337_V07_CANONICAL_ENTRYPOINT, 32),
    approvedConfirmationTarget: zeroPadValue(EXPECTED_TARGET, 32),
    expectedChainId: zeroPadValue(toBeHex(ETHEREUM_SEPOLIA_CHAIN_ID), 32)
  };
  let bytes = Buffer.from(output.object, "hex");
  const references = [];
  for (const [id, locations] of Object.entries(output.immutableReferences ?? {})) {
    const name = names.get(id);
    const encoded = values[name];
    if (!encoded) throw new Error(`unknown_factory_immutable:${id}`);
    const replacement = Buffer.from(encoded.slice(2), "hex");
    for (const location of locations) {
      if (location.length !== replacement.length) {
        throw new Error(`factory_immutable_length_mismatch:${name}`);
      }
      replacement.copy(bytes, location.start);
      references.push({
        id,
        name,
        start: location.start,
        length: location.length,
        encodedValue: encoded
      });
    }
  }
  const bytecode = `0x${bytes.toString("hex")}`;
  return Object.freeze({
    bytecode,
    bytecodeHash: keccak256(bytecode),
    immutableReferences: Object.freeze(references)
  });
}

function buildFactoryDeploymentData() {
  const artifact = readJson(path.join(ROOT, ARTIFACTS.factory));
  const constructor = factoryConstructorBinding();
  const data = concat([artifact.bytecode, constructor.data]);
  return Object.freeze({
    creationBytecode: artifact.bytecode,
    creationBytecodeHash: keccak256(artifact.bytecode),
    creationBytecodeLength: (artifact.bytecode.length - 2) / 2,
    constructorData: constructor.data,
    constructorDataHash: constructor.dataHash,
    constructorDataLength: (constructor.data.length - 2) / 2,
    data,
    dataHash: keccak256(data)
  });
}

function buildFactoryDeploymentTransaction(input) {
  const transaction = {
    type: 2,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    nonce: Number(FACTORY_DEPLOYMENT_NONCE),
    to: null,
    value: 0n,
    data: input.data,
    gasLimit: BigInt(input.gasLimit),
    maxFeePerGas: BigInt(input.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(input.maxPriorityFeePerGas)
  };
  validateFactoryDeploymentTransaction(transaction, input);
  return transaction;
}

function validateFactoryDeploymentTransaction(transaction, expected) {
  if (Number(transaction.chainId) !== ETHEREUM_SEPOLIA_CHAIN_ID) {
    throw new Error("wrong_chain");
  }
  if (String(transaction.nonce) !== FACTORY_DEPLOYMENT_NONCE) {
    throw new Error("factory_nonce_mismatch");
  }
  if (transaction.to !== null) throw new Error("factory_deployment_to_must_be_null");
  if (BigInt(transaction.value) !== 0n) throw new Error("factory_deployment_value_must_be_zero");
  if (BigInt(transaction.maxFeePerGas) > MAX_FEE_PER_GAS) {
    throw new Error("max_fee_exceeds_o24_ceiling");
  }
  if (BigInt(transaction.maxPriorityFeePerGas) > MAX_PRIORITY_FEE_PER_GAS) {
    throw new Error("priority_fee_exceeds_o24_ceiling");
  }
  if (expected?.dataHash && keccak256(transaction.data) !== expected.dataHash) {
    throw new Error("factory_deployment_data_mismatch");
  }
  return true;
}

function verifySignedFactoryDeployment(rawSignedTransaction, expected) {
  const parsed = Transaction.from(rawSignedTransaction);
  validateFactoryDeploymentTransaction(parsed, expected);
  if (getAddress(parsed.from) !== getAddress(expected.signer)) {
    throw new Error("factory_signer_recovery_failed");
  }
  if (parsed.hash !== expected.transactionHash) {
    throw new Error("factory_transaction_hash_mismatch");
  }
  const creationEnd = 2 + expected.creationBytecodeLength * 2;
  const creation = parsed.data.slice(0, creationEnd);
  const constructor = `0x${parsed.data.slice(creationEnd)}`;
  if (keccak256(creation) !== expected.creationBytecodeHash) {
    throw new Error("factory_creation_bytecode_mismatch");
  }
  if (keccak256(constructor) !== expected.constructorDataHash) {
    throw new Error("factory_constructor_data_mismatch");
  }
  return parsed;
}

function assertFreshO24ReceiptPath(receiptPath = O24_RECEIPT_PATH) {
  if (fs.existsSync(receiptPath)) throw new Error("O24_FACTORY_APPROVAL_ALREADY_CONSUMED");
}

function validateReviewedFactoryArtifacts() {
  const artifacts = artifactBindings();
  for (const artifact of artifacts) {
    if (
      sha256File(artifact.source) !== artifact.sourceSha256
      || artifact.creationBytecodeHash
        !== keccak256(readJson(path.join(ROOT, artifact.artifact)).bytecode)
      || artifact.deployedBytecodeHash
        !== keccak256(readJson(path.join(ROOT, artifact.artifact)).deployedBytecode)
    ) {
      throw new Error("FACTORY_SOURCE_BINDING_STALE");
    }
  }
  return artifacts;
}

module.exports = {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  FACTORY_DEPLOYMENT_NONCE,
  O23R_RECEIPT_PATH,
  O24_PROPOSAL_PATH,
  O24_RECEIPT_PATH,
  assertFreshO24ReceiptPath,
  buildFactoryDeploymentData,
  buildFactoryDeploymentTransaction,
  calculateO24Addresses,
  canonicalDigest,
  ensureNoSecrets,
  expectedFactoryRuntimeBinding,
  factoryConstructorBinding,
  readJson,
  validateFactoryDeploymentTransaction,
  validateReviewedFactoryArtifacts,
  verifySignedFactoryDeployment,
  writeJson
};
