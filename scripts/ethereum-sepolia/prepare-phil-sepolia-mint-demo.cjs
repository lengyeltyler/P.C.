"use strict";

throw new Error("PHIL_SEPOLIA_MINT_LEGACY_ALPHA_RUNNER_RETIRED_USE_CONTROLLED_BETA_STAGES");

const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const CHAIN_ID = 11155111;
const ENTRY_POINT = "0x0000000071727de22e5e9d8baf0edac6f37da032";
const CONFIG_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_V1.json"
);
const EVIDENCE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_READ_ONLY_PREFLIGHT.json"
);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function required(name) {
  const value = process.env[name];
  if (!value) fail(`${name}_REQUIRED`);
  return value;
}

function artifact(relative) {
  const location = path.join(ROOT, "artifacts", relative);
  const value = JSON.parse(fs.readFileSync(location, "utf8"));
  if (!value?.abi || !/^0x[0-9a-f]+$/iu.test(value.bytecode || "")) {
    fail("PHIL_SEPOLIA_MINT_ARTIFACT_INVALID");
  }
  return value;
}

function sanitizedEndpoint(value) {
  const parsed = new URL(value);
  return `${parsed.protocol}//${parsed.hostname}/<redacted>`;
}

function writeJson(location, value) {
  fs.writeFileSync(location, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function assertFrozenConfiguration(configuration, evidence) {
  const frozenConfiguration = readJson(CONFIG_PATH);
  const frozenEvidence = readJson(EVIDENCE_PATH);
  const exactConfigurationFields = [
    "format", "version", "status", "chainId", "entryPoint", "deployer",
    "startingNonce", "infrastructure", "accountSalt",
    "authorizationWindowSeconds", "maximumTotalFeeWei",
    "publicMutationEnabled", "submissionEnabled"
  ];
  for (const field of exactConfigurationFields) {
    if (JSON.stringify(frozenConfiguration[field]) !== JSON.stringify(configuration[field])) {
      fail(`PHIL_SEPOLIA_MINT_FROZEN_CONFIGURATION_DRIFT:${field}`);
    }
  }
  if (JSON.stringify(frozenEvidence.bytecodeHashes) !== JSON.stringify(evidence.bytecodeHashes)) {
    fail("PHIL_SEPOLIA_MINT_FROZEN_BYTECODE_DRIFT");
  }
  if (frozenEvidence.entryPoint?.codeHash !== evidence.entryPoint.codeHash) {
    fail("PHIL_SEPOLIA_MINT_ENTRYPOINT_CODE_DRIFT");
  }
}

async function main() {
  const rpcUrl = required("PHILCORE_SEPOLIA_RPC_URL");
  const bundlerUrl = required("PHILCORE_SEPOLIA_BUNDLER_URL");
  const configuredDeployer = ethers.getAddress(required("PHILCORE_SEPOLIA_DEPLOYER_ADDRESS"));
  const provider = new ethers.JsonRpcProvider(rpcUrl, CHAIN_ID, { staticNetwork: true });
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== CHAIN_ID) fail("PHIL_SEPOLIA_MINT_WRONG_CHAIN");

  const entryPointCode = await provider.getCode(ENTRY_POINT);
  if (entryPointCode === "0x") fail("PHIL_SEPOLIA_MINT_ENTRYPOINT_MISSING");
  const pendingNonce = await provider.getTransactionCount(configuredDeployer, "pending");
  const latestNonce = await provider.getTransactionCount(configuredDeployer, "latest");
  if (pendingNonce !== latestNonce) fail("PHIL_SEPOLIA_MINT_DEPLOYER_PENDING_TRANSACTION");

  const addresses = Object.freeze({
    factory: ethers.getCreateAddress({ from: configuredDeployer, nonce: pendingNonce }),
    actionGate: ethers.getCreateAddress({ from: configuredDeployer, nonce: pendingNonce + 1 }),
    mintConsumer: ethers.getCreateAddress({ from: configuredDeployer, nonce: pendingNonce + 2 })
  });
  for (const address of Object.values(addresses)) {
    if (await provider.getCode(address) !== "0x") {
      fail("PHIL_SEPOLIA_MINT_PREDICTED_ADDRESS_OCCUPIED");
    }
  }

  const factoryArtifact = artifact(
    "contracts/base/erc4337/PhilSepoliaMintAccountFactoryV1.sol/PhilSepoliaMintAccountFactoryV1.json"
  );
  const accountArtifact = artifact(
    "contracts/base/erc4337/PhilSepoliaMintAccountV1.sol/PhilSepoliaMintAccountV1.json"
  );
  const gateArtifact = artifact(
    "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol/PhilSepoliaLocalComposedActionGateV1.json"
  );
  const consumerArtifact = artifact(
    "contracts/base/PhilSepoliaMintPassConsumerV1.sol/PhilSepoliaMintPassConsumerV1.json"
  );
  const factoryData = (await new ethers.ContractFactory(factoryArtifact.abi, factoryArtifact.bytecode)
    .getDeployTransaction(ENTRY_POINT, addresses.actionGate)).data;
  const gateData = (await new ethers.ContractFactory(gateArtifact.abi, gateArtifact.bytecode)
    .getDeployTransaction(CHAIN_ID, addresses.factory, addresses.mintConsumer)).data;
  const consumerData = (await new ethers.ContractFactory(consumerArtifact.abi, consumerArtifact.bytecode)
    .getDeployTransaction(addresses.actionGate)).data;
  const deploymentPlans = [
    ["factory", addresses.factory, pendingNonce, factoryData],
    ["actionGate", addresses.actionGate, pendingNonce + 1, gateData],
    ["mintConsumer", addresses.mintConsumer, pendingNonce + 2, consumerData]
  ];
  const gasEstimates = {};
  for (const [label, expectedAddress, nonce, data] of deploymentPlans) {
    gasEstimates[label] = (await provider.estimateGas({
      from: configuredDeployer,
      nonce,
      data
    })).toString();
    if (ethers.getCreateAddress({ from: configuredDeployer, nonce }) !== expectedAddress) {
      fail("PHIL_SEPOLIA_MINT_DEPLOYMENT_ADDRESS_MISMATCH");
    }
  }

  const block = await provider.getBlock("latest");
  const feeData = await provider.getFeeData();
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, CHAIN_ID, { staticNetwork: true });
  const supportedEntryPoints = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supportedEntryPoints)
    || !supportedEntryPoints.some((value) => value.toLowerCase() === ENTRY_POINT)) {
    fail("PHIL_SEPOLIA_MINT_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }

  const generatedAt = new Date().toISOString();
  const configuration = {
    format: "phil-sepolia-mint-demo-configuration-v1",
    version: 1,
    status: "predicted_not_deployed",
    generatedAt,
    chainId: String(CHAIN_ID),
    entryPoint: ENTRY_POINT,
    deployer: configuredDeployer,
    startingNonce: String(pendingNonce),
    infrastructure: addresses,
    accountSalt: ethers.id("PHIL_SEPOLIA_MINT_DEMO_ACCOUNT_SALT_V1"),
    authorizationWindowSeconds: "3600",
    maximumTotalFeeWei: ethers.parseEther("0.005").toString(),
    gasPolicy: {
      callGasLimit: "500000",
      verificationGasLimit: "1500000",
      preVerificationGas: "150000",
      maxFeePerGas: (feeData.maxFeePerGas || ethers.parseUnits("20", "gwei")).toString(),
      maxPriorityFeePerGas: (feeData.maxPriorityFeePerGas || ethers.parseUnits("2", "gwei")).toString()
    },
    publicMutationEnabled: false,
    submissionEnabled: false
  };
  const evidence = {
    format: "phil-sepolia-mint-read-only-preflight-v1",
    version: 1,
    status: "READ_ONLY_PREFLIGHT_PASSED_PUBLIC_MUTATION_NOT_AUTHORIZED",
    generatedAt,
    rpc: sanitizedEndpoint(rpcUrl),
    bundler: sanitizedEndpoint(bundlerUrl),
    chainId: String(CHAIN_ID),
    latestBlockNumber: String(block.number),
    latestBlockHash: block.hash,
    entryPoint: {
      address: ENTRY_POINT,
      codeHash: ethers.keccak256(entryPointCode),
      bundlerSupported: true
    },
    deployer: {
      address: configuredDeployer,
      pendingNonce: String(pendingNonce),
      latestNonce: String(latestNonce),
      balanceWei: (await provider.getBalance(configuredDeployer)).toString()
    },
    predictedInfrastructure: addresses,
    predictedAddressesUnoccupied: true,
    deploymentGasEstimates: gasEstimates,
    bytecodeHashes: {
      factoryCreationCode: ethers.keccak256(factoryArtifact.bytecode),
      accountCreationCode: ethers.keccak256(accountArtifact.bytecode),
      actionGateCreationCode: ethers.keccak256(gateArtifact.bytecode),
      mintConsumerCreationCode: ethers.keccak256(consumerArtifact.bytecode)
    },
    approvals: {
      deployment: false,
      funding: false,
      mintSubmission: false
    },
    publicMutationOccurred: false
  };
  const checkOnly = process.argv.slice(2).includes("--check");
  if (checkOnly) {
    assertFrozenConfiguration(configuration, evidence);
  } else {
    writeJson(CONFIG_PATH, configuration);
    writeJson(EVIDENCE_PATH, evidence);
  }
  process.stdout.write(`${JSON.stringify({
    status: checkOnly
      ? "FRESH_READ_ONLY_PREFLIGHT_PASSED_FROZEN_CONFIGURATION_UNCHANGED"
      : evidence.status,
    chainId: evidence.chainId,
    latestBlockNumber: evidence.latestBlockNumber,
    predictedInfrastructure: addresses,
    filesWritten: !checkOnly,
    publicMutationOccurred: false
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.code || error?.message || "PHIL_SEPOLIA_MINT_PREFLIGHT_FAILED"}\n`);
  process.exitCode = 1;
});
