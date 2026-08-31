#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const DEFAULT_INPUT = path.join(
  ROOT,
  "config/ethereum-sepolia/O40_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json"
);
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const CHAIN_ID = 11155111n;
const ACCOUNT_VERSION_ID =
  "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f";
const SECURITY_MODEL_ID =
  "0xbfded32375d70119930c009b80e9a3774335bb0ae2fc4d3b7133fd8713753f44";
const CREATE2_SALT_DOMAIN = ethers.id("PHILCORE_V2_CREATE2_SALT_V1");
const RECOVERY_CONFIGURATION_TYPEHASH = ethers.id(
  "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
);
const CANONICAL = Object.freeze({
  ownerCommitment:
    "0xabab9766da60e39c0c69fc6ecd7e0f31d116c626c8ea36c6401e331d99f4a9b1",
  identityBindingCommitment:
    "0xdfe42e50f98d9ea25a188a26b1e5ed41acac3c16e4827d835ba1102f0d74b999",
  initialValidator: "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa",
  validatorKeyIdBinding:
    "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809",
  validatorCommitment:
    "0x3206c5e72ac57b685c5fa3d65df94aeb59dfb27b5024d3b05db96c2a52c83b68"
});
const ARTIFACT_PATHS = Object.freeze({
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
});
const abi = ethers.AbiCoder.defaultAbiCoder();

function fail(code, detail) {
  throw new Error(`${code}${detail ? `:${detail}` : ""}`);
}

function sameHex(left, right) {
  return typeof left === "string"
    && typeof right === "string"
    && left.toLowerCase() === right.toLowerCase();
}

function requireExact(label, actual, expected) {
  if (!sameHex(String(actual), String(expected))) {
    fail("O40_INITIALIZATION_MISMATCH", label);
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function artifactHashes() {
  return Object.fromEntries(
    Object.entries(ARTIFACT_PATHS).flatMap(([name, file]) => {
      if (!fs.existsSync(file)) fail("O40_ARTIFACT_MISSING", name);
      const artifact = readJson(file);
      return [
        [`${name}RuntimeKeccak256`, ethers.keccak256(artifact.deployedBytecode)],
        [`${name}CreationKeccak256`, ethers.keccak256(artifact.bytecode)]
      ];
    })
  );
}

function recoveryConfigurationHash(initialization) {
  return ethers.keccak256(abi.encode(
    ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
    [
      RECOVERY_CONFIGURATION_TYPEHASH,
      3,
      2,
      initialization.primaryDeviceRecoveryCommitment,
      initialization.hardwareSecurityKeyCommitment,
      initialization.independentRecoveryFactorCommitment
    ]
  ));
}

function missingFields(input) {
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
  return [...new Set(missing)];
}

function validateCompleteInitialization(input) {
  const initialization = input.initialization;
  if (BigInt(initialization.deploymentChainId) !== CHAIN_ID) {
    fail("O40_INITIALIZATION_MISMATCH", "deploymentChainId");
  }
  for (const [label, actual, expected] of [
    ["entryPoint", initialization.entryPoint, ENTRY_POINT],
    ["ownerCommitment", initialization.ownerCommitment, CANONICAL.ownerCommitment],
    ["identityBindingCommitment", initialization.identityBindingCommitment, CANONICAL.identityBindingCommitment],
    ["factoryBinding", initialization.factoryBinding, input.futureFactoryAddress],
    ["confirmationTarget", initialization.confirmationTarget, input.confirmationTarget],
    ["accountVersionId", initialization.accountVersionId, ACCOUNT_VERSION_ID],
    ["securityModelId", initialization.securityModelId, SECURITY_MODEL_ID],
    ["initialValidator", initialization.initialValidator, CANONICAL.initialValidator],
    ["validatorKeyIdBinding", initialization.validatorKeyIdBinding, CANONICAL.validatorKeyIdBinding],
    ["validatorCommitment", initialization.validatorCommitment, CANONICAL.validatorCommitment]
  ]) requireExact(label, actual, expected);
  for (const [field, expected] of [
    ["validatorVerifierKind", 1],
    ["validatorEpoch", 1],
    ["recoveryEpoch", 1],
    ["recoveryDelaySeconds", 172800],
    ["recoveryExpirySeconds", 604800]
  ]) {
    if (Number(initialization[field]) !== expected) {
      fail("O40_INITIALIZATION_MISMATCH", field);
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
  ) fail("O40_INITIALIZATION_MISMATCH", "recoveryCommitments");
  requireExact(
    "recoveryConfigurationHash",
    initialization.recoveryConfigurationHash,
    recoveryConfigurationHash(initialization)
  );
  if (!ethers.isHexString(input.userSalt, 32) || input.userSalt === ethers.ZeroHash) {
    fail("O40_INITIALIZATION_MISMATCH", "userSalt");
  }
  if (!Number.isSafeInteger(input.deploymentGasCeiling)
    || input.deploymentGasCeiling <= 0) {
    fail("O40_COST_CEILING_INVALID");
  }
}

function calculateCreate2(input) {
  const accountArtifact = readJson(ARTIFACT_PATHS.account);
  const tupleType =
    "tuple(address entryPoint,uint256 deploymentChainId,bytes32 ownerCommitment,bytes32 identityBindingCommitment,address factoryBinding,bytes32 accountVersionId,bytes32 securityModelId,address confirmationTarget,address initialValidator,uint8 validatorVerifierKind,bytes32 validatorKeyIdBinding,bytes32 validatorCommitment,uint64 validatorEpoch,bytes32 primaryDeviceRecoveryCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 independentRecoveryFactorCommitment,bytes32 recoveryConfigurationHash,uint64 recoveryEpoch,uint64 recoveryDelaySeconds,uint64 recoveryExpirySeconds)";
  const initCodeHash = ethers.keccak256(ethers.concat([
    accountArtifact.bytecode,
    abi.encode([tupleType], [input.initialization])
  ]));
  const deploymentSalt = ethers.keccak256(abi.encode(
    ["bytes32", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      CREATE2_SALT_DOMAIN,
      CHAIN_ID,
      ACCOUNT_VERSION_ID,
      SECURITY_MODEL_ID,
      input.initialization.ownerCommitment,
      input.initialization.identityBindingCommitment,
      input.userSalt
    ]
  ));
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

function parseArguments(argv) {
  const result = { input: DEFAULT_INPUT, broadcast: false, requireReady: false };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--input") {
      result.input = path.resolve(argv[++index] || fail("O40_INPUT_REQUIRED"));
    } else if (argv[index] === "--broadcast") {
      result.broadcast = true;
    } else if (argv[index] === "--require-ready") {
      result.requireReady = true;
    } else if (argv[index] !== "--dry-run") {
      fail("O40_UNKNOWN_ARGUMENT", argv[index]);
    }
  }
  return result;
}

function run(argv) {
  const options = parseArguments(argv);
  if (options.broadcast) fail("O40_PUBLIC_MUTATION_PROHIBITED");
  const input = readJson(options.input);
  if (input.phase !== "O.40" || input.mode !== "DRY_RUN_ONLY") {
    fail("O40_CONFIGURATION_CLASSIFICATION_INVALID");
  }
  if (BigInt(input.chainId) !== CHAIN_ID) fail("O40_WRONG_CHAIN");
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
  const missing = missingFields(input);
  if (options.requireReady && missing.length > 0) {
    fail("O40_INITIALIZATION_BLOCKED", missing.join(","));
  }
  if (missing.length === 0) validateCompleteInitialization(input);
  return {
    phase: "O.40",
    mode: "DRY_RUN",
    publicMutationCount: 0,
    rpcAccessed: false,
    credentialsAccessed: false,
    artifactHashes: observedHashes,
    initialization: {
      status: missing.length === 0 ? "READY" : "INITIALIZATION_BLOCKED",
      missing
    },
    create2: missing.length === 0 ? calculateCreate2(input) : null,
    broadcastPathImplemented: false
  };
}

if (require.main === module) {
  try {
    process.stdout.write(`${JSON.stringify(run(process.argv.slice(2)), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { run };
