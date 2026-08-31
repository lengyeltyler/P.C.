#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const DEFAULT_INPUT = path.join(
  ROOT,
  "config/ethereum-sepolia/O38_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json"
);
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CHAIN_ID = 11155111n;
const ACCOUNT_VERSION_ID =
  "0xe3809f55cf56b419ecaebf3d2a2e0a43278b5d9a0b4714c063933a87ba2085d4";
const SECURITY_MODEL_ID =
  "0xbfded32375d70119930c009b80e9a3774335bb0ae2fc4d3b7133fd8713753f44";
const CREATE2_SALT_DOMAIN = ethers.id("PHILCORE_V2_CREATE2_SALT_V1");
const RECOVERY_CONFIGURATION_TYPEHASH = ethers.id(
  "PhilCoreV2RecoveryConfigurationV2(uint8 configurationVersion,uint8 threshold,bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment)"
);
const CANONICAL = {
  ownerCommitment:
    "0xabab9766da60e39c0c69fc6ecd7e0f31d116c626c8ea36c6401e331d99f4a9b1",
  identityBindingCommitment:
    "0xdfe42e50f98d9ea25a188a26b1e5ed41acac3c16e4827d835ba1102f0d74b999",
  initialValidator: "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa",
  validatorKeyIdBinding:
    "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809",
  validatorCommitment:
    "0x3206c5e72ac57b685c5fa3d65df94aeb59dfb27b5024d3b05db96c2a52c83b68"
};
const ARTIFACT_PATHS = {
  verifier: path.join(
    ROOT,
    "artifacts/contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol/PhilCoreV2StaticAuthorityVerifier.json"
  ),
  account: path.join(
    ROOT,
    "artifacts/contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol/PhilCoreV2MinimalAccountV2.json"
  ),
  factory: path.join(
    ROOT,
    "artifacts/contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol/PhilCoreV2MinimalAccountFactoryV2.json"
  )
};
const abi = ethers.AbiCoder.defaultAbiCoder();

function fail(code, detail) {
  const error = new Error(`${code}${detail ? `:${detail}` : ""}`);
  error.code = code;
  throw error;
}

function parseArguments(argv) {
  const result = { input: DEFAULT_INPUT, broadcast: false, requireReady: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--input") {
      result.input = path.resolve(argv[++index] || fail("O38_INPUT_REQUIRED"));
    } else if (argument === "--broadcast") {
      result.broadcast = true;
    } else if (argument === "--require-ready") {
      result.requireReady = true;
    } else if (argument !== "--dry-run") {
      fail("O38_UNKNOWN_ARGUMENT", argument);
    }
  }
  return result;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function artifactHashes() {
  const result = {};
  for (const [name, file] of Object.entries(ARTIFACT_PATHS)) {
    if (!fs.existsSync(file)) fail("O38_ARTIFACT_MISSING", name);
    const artifact = readJson(file);
    result[`${name}RuntimeKeccak256`] = ethers.keccak256(
      artifact.deployedBytecode
    );
    result[`${name}CreationKeccak256`] = ethers.keccak256(
      artifact.bytecode
    );
  }
  return result;
}

function sameHex(left, right) {
  return typeof left === "string" && typeof right === "string"
    && left.toLowerCase() === right.toLowerCase();
}

function requireExact(label, actual, expected) {
  if (!sameHex(String(actual), String(expected))) {
    fail("O38_INITIALIZATION_MISMATCH", label);
  }
}

function recoveryConfigurationHash(initialization) {
  return ethers.keccak256(
    abi.encode(
      ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
      [
        RECOVERY_CONFIGURATION_TYPEHASH,
        2,
        2,
        initialization.primaryDeviceRecoveryCommitment,
        initialization.hardwareSecurityKeyCommitment,
        initialization.independentRecoveryFactorCommitment
      ]
    )
  );
}

function validateInitialization(input) {
  const initialization = input.initialization || {};
  const missing = [];
  for (const field of [
    "entryPoint",
    "deploymentChainId",
    "ownerCommitment",
    "identityBindingCommitment",
    "factoryBinding",
    "accountVersionId",
    "securityModelId",
    "confirmationTarget",
    "initialValidator",
    "validatorVerifierKind",
    "validatorKeyIdBinding",
    "validatorCommitment",
    "validatorEpoch",
    "primaryDeviceRecoveryCommitment",
    "hardwareSecurityKeyCommitment",
    "independentRecoveryFactorCommitment",
    "recoveryConfigurationHash",
    "recoveryEpoch",
    "recoveryDelaySeconds",
    "recoveryExpirySeconds"
  ]) {
    if (initialization[field] === null || initialization[field] === undefined) {
      missing.push(field);
    }
  }
  for (const field of [
    "futureVerifierAddress",
    "futureFactoryAddress",
    "confirmationTarget",
    "userSalt",
    "deploymentGasCeiling"
  ]) {
    if (input[field] === null || input[field] === undefined) missing.push(field);
  }
  if (missing.length > 0) {
    return {
      status: "INITIALIZATION_BLOCKED",
      missing: [...new Set(missing)]
    };
  }

  if (BigInt(initialization.deploymentChainId) !== CHAIN_ID) {
    fail("O38_INITIALIZATION_MISMATCH", "deploymentChainId");
  }
  requireExact("entryPoint", initialization.entryPoint, ENTRY_POINT);
  requireExact(
    "ownerCommitment",
    initialization.ownerCommitment,
    CANONICAL.ownerCommitment
  );
  requireExact(
    "identityBindingCommitment",
    initialization.identityBindingCommitment,
    CANONICAL.identityBindingCommitment
  );
  requireExact("factoryBinding", initialization.factoryBinding, input.futureFactoryAddress);
  requireExact(
    "confirmationTarget",
    initialization.confirmationTarget,
    input.confirmationTarget
  );
  requireExact(
    "accountVersionId",
    initialization.accountVersionId,
    ACCOUNT_VERSION_ID
  );
  requireExact(
    "securityModelId",
    initialization.securityModelId,
    SECURITY_MODEL_ID
  );
  requireExact(
    "initialValidator",
    initialization.initialValidator,
    CANONICAL.initialValidator
  );
  requireExact(
    "validatorKeyIdBinding",
    initialization.validatorKeyIdBinding,
    CANONICAL.validatorKeyIdBinding
  );
  requireExact(
    "validatorCommitment",
    initialization.validatorCommitment,
    CANONICAL.validatorCommitment
  );
  for (const [field, expected] of [
    ["validatorVerifierKind", 1],
    ["validatorEpoch", 1],
    ["recoveryEpoch", 1],
    ["recoveryDelaySeconds", 172800],
    ["recoveryExpirySeconds", 604800]
  ]) {
    if (Number(initialization[field]) !== expected) {
      fail("O38_INITIALIZATION_MISMATCH", field);
    }
  }
  const commitments = [
    initialization.primaryDeviceRecoveryCommitment,
    initialization.hardwareSecurityKeyCommitment,
    initialization.independentRecoveryFactorCommitment
  ];
  if (
    commitments.some((value) => !ethers.isHexString(value, 32)
      || value === ethers.ZeroHash)
    || new Set(commitments.map((value) => value.toLowerCase())).size !== 3
  ) {
    fail("O38_INITIALIZATION_MISMATCH", "recoveryCommitments");
  }
  requireExact(
    "recoveryConfigurationHash",
    initialization.recoveryConfigurationHash,
    recoveryConfigurationHash(initialization)
  );
  if (!ethers.isHexString(input.userSalt, 32) || input.userSalt === ethers.ZeroHash) {
    fail("O38_INITIALIZATION_MISMATCH", "userSalt");
  }
  if (!Number.isSafeInteger(input.deploymentGasCeiling)
      || input.deploymentGasCeiling <= 0) {
    fail("O38_COST_CEILING_INVALID");
  }
  return { status: "READY", missing: [] };
}

function calculateCreate2(input) {
  const accountArtifact = readJson(ARTIFACT_PATHS.account);
  const tupleType =
    "tuple(address entryPoint,uint256 deploymentChainId,bytes32 ownerCommitment,bytes32 identityBindingCommitment,address factoryBinding,bytes32 accountVersionId,bytes32 securityModelId,address confirmationTarget,address initialValidator,uint8 validatorVerifierKind,bytes32 validatorKeyIdBinding,bytes32 validatorCommitment,uint64 validatorEpoch,bytes32 primaryDeviceRecoveryCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 independentRecoveryFactorCommitment,bytes32 recoveryConfigurationHash,uint64 recoveryEpoch,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds)";
  const encodedInitialization = abi.encode(
    [tupleType],
    [input.initialization]
  );
  const initCode = ethers.concat([
    accountArtifact.bytecode,
    encodedInitialization
  ]);
  const initCodeHash = ethers.keccak256(initCode);
  const deploymentSalt = ethers.keccak256(
    abi.encode(
      [
        "bytes32",
        "uint256",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32",
        "bytes32"
      ],
      [
        CREATE2_SALT_DOMAIN,
        CHAIN_ID,
        ACCOUNT_VERSION_ID,
        SECURITY_MODEL_ID,
        input.initialization.ownerCommitment,
        input.initialization.identityBindingCommitment,
        input.userSalt
      ]
    )
  );
  return {
    initCodeHash,
    deploymentSalt,
    predictedAccount: ethers.getCreate2Address(
      input.futureFactoryAddress,
      deploymentSalt,
      initCodeHash
    )
  };
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.broadcast) {
    if (process.env.PHILCORE_O38_PUBLIC_MUTATION_APPROVED
        !== "O38_EXACT_PUBLIC_MUTATION_APPROVED") {
      fail("O38_PUBLIC_MUTATION_APPROVAL_REQUIRED");
    }
    fail("O38_BROADCAST_PATH_NOT_IMPLEMENTED");
  }
  const input = readJson(options.input);
  if (input.phase !== "O.38" || input.mode !== "DRY_RUN_ONLY") {
    fail("O38_CONFIGURATION_CLASSIFICATION_INVALID");
  }
  if (BigInt(input.chainId) !== CHAIN_ID) fail("O38_WRONG_CHAIN");
  requireExact("entryPoint", input.entryPoint, ENTRY_POINT);

  const observedHashes = artifactHashes();
  for (const [field, value] of Object.entries(observedHashes)) {
    requireExact(`artifact:${field}`, value, input.artifactExpectations[field]);
  }
  requireExact(
    "futureVerifierRuntimeCodeHash",
    input.futureVerifierRuntimeCodeHash,
    observedHashes.verifierRuntimeKeccak256
  );

  const initialization = validateInitialization(input);
  if (options.requireReady && initialization.status !== "READY") {
    fail("O38_INITIALIZATION_BLOCKED", initialization.missing.join(","));
  }
  const create2 = initialization.status === "READY"
    ? calculateCreate2(input)
    : null;
  process.stdout.write(`${JSON.stringify({
    phase: "O.38",
    mode: "DRY_RUN",
    publicMutationCount: 0,
    rpcAccessed: false,
    credentialsAccessed: false,
    artifactHashes: observedHashes,
    initialization,
    create2,
    broadcastPathImplemented: false
  }, null, 2)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
