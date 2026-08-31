const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");
const { ethers } = require("ethers");

const DEPLOYMENT_TARGETS = {
  baseCrossDomainMessenger: {
    contractName: "MockBaseCrossDomainMessenger",
    fullyQualifiedName:
      "contracts/base/mocks/MockBaseCrossDomainMessenger.sol:MockBaseCrossDomainMessenger"
  },
  adapter: {
    contractName: "PhilBaseCrossDomainMessengerAdapter",
    fullyQualifiedName:
      "contracts/l1/PhilBaseCrossDomainMessengerAdapter.sol:PhilBaseCrossDomainMessengerAdapter"
  },
  mirror: {
    contractName: "PhilBaseProofInputHashMirror",
    fullyQualifiedName:
      "contracts/base/PhilBaseProofInputHashMirror.sol:PhilBaseProofInputHashMirror"
  }
};

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function normalizeAddress(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizeTransactionHash(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizeBlockNumber(value, label) {
  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized <= 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return normalized;
}

function normalizeRecord(value, label) {
  if (!value || typeof value !== "object") {
    throw new Error(`Missing ${label}`);
  }

  return {
    contract: String(value.contract || "").trim(),
    address: normalizeAddress(value.address, `${label} address`),
    transactionHash: normalizeTransactionHash(
      value.transactionHash,
      `${label} transaction hash`
    ),
    blockNumber: normalizeBlockNumber(value.blockNumber, `${label} block number`)
  };
}

function normalizeHexBytecode(value, label) {
  const text = String(value || "").trim();
  if (!/^0x([0-9a-fA-F]{2})*$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text.toLowerCase();
}

function flattenImmutableReferences(immutableReferences = {}) {
  return Object.values(immutableReferences).flat();
}

function maskImmutableByteRanges(bytecode, immutableReferences = {}) {
  const normalized = normalizeHexBytecode(bytecode, "runtime bytecode");
  const chars = normalized.slice(2).split("");
  const references = flattenImmutableReferences(immutableReferences);

  for (const reference of references) {
    const start = Number(reference.start);
    const length = Number(reference.length);
    if (!Number.isInteger(start) || !Number.isInteger(length) || start < 0 || length < 0) {
      throw new Error(`Invalid immutable reference: ${JSON.stringify(reference)}`);
    }

    for (let i = start * 2; i < (start + length) * 2; i += 1) {
      chars[i] = "0";
    }
  }

  return `0x${chars.join("")}`;
}

async function loadArtifactMetadata(target) {
  const artifact = await hre.artifacts.readArtifact(target.contractName);
  const buildInfo = await hre.artifacts.getBuildInfo(target.fullyQualifiedName);
  if (!buildInfo) {
    throw new Error(`Missing build info for ${target.fullyQualifiedName}`);
  }

  const [sourceName, contractName] = target.fullyQualifiedName.split(":");
  const contractOutput = buildInfo.output.contracts[sourceName][contractName];

  return {
    artifact,
    immutableReferences:
      contractOutput.evm.deployedBytecode.immutableReferences || {}
  };
}

async function verifyDeploymentTarget({
  key,
  runnerRecord,
  receiptRecord,
  provider
}) {
  const target = DEPLOYMENT_TARGETS[key];
  if (!target) {
    throw new Error(`Unknown deployment target: ${key}`);
  }

  const normalizedRunner = normalizeRecord(runnerRecord, `${key} runner record`);
  const normalizedReceipt = normalizeRecord(receiptRecord, `${key} receipt record`);

  if (normalizedRunner.address.toLowerCase() !== normalizedReceipt.address.toLowerCase()) {
    throw new Error(`${key} address mismatch between runner output and receipt`);
  }
  if (normalizedRunner.transactionHash !== normalizedReceipt.transactionHash) {
    throw new Error(`${key} transaction hash mismatch between runner output and receipt`);
  }
  if (normalizedRunner.blockNumber !== normalizedReceipt.blockNumber) {
    throw new Error(`${key} block number mismatch between runner output and receipt`);
  }

  const txReceipt = await provider.getTransactionReceipt(normalizedReceipt.transactionHash);
  if (!txReceipt) {
    throw new Error(`Missing on-chain transaction receipt for ${key}`);
  }
  if (!txReceipt.contractAddress) {
    throw new Error(`Missing contractAddress in on-chain transaction receipt for ${key}`);
  }
  if (txReceipt.contractAddress.toLowerCase() !== normalizedReceipt.address.toLowerCase()) {
    throw new Error(`${key} contractAddress mismatch against receipt address`);
  }
  if (Number(txReceipt.blockNumber) !== normalizedReceipt.blockNumber) {
    throw new Error(`${key} block number mismatch against on-chain receipt`);
  }
  if (Number(txReceipt.status) !== 1) {
    throw new Error(`${key} deployment transaction did not succeed`);
  }

  const code = normalizeHexBytecode(
    await provider.getCode(normalizedReceipt.address),
    `${key} deployed code`
  );
  if (code === "0x") {
    throw new Error(`${key} address has no deployed code`);
  }

  const { artifact, immutableReferences } = await loadArtifactMetadata(target);
  const expectedRuntime = normalizeHexBytecode(
    artifact.deployedBytecode,
    `${key} artifact deployed bytecode`
  );
  const maskedExpectedRuntime = maskImmutableByteRanges(
    expectedRuntime,
    immutableReferences
  );
  const maskedDeployedRuntime = maskImmutableByteRanges(code, immutableReferences);
  const expectedRuntimeHash = ethers.keccak256(maskedExpectedRuntime);
  const deployedRuntimeHash = ethers.keccak256(maskedDeployedRuntime);

  if (expectedRuntimeHash !== deployedRuntimeHash) {
    throw new Error(`${key} runtime bytecode hash mismatch`);
  }

  return {
    contract: target.contractName,
    address: normalizedReceipt.address,
    transactionHash: normalizedReceipt.transactionHash,
    blockNumber: normalizedReceipt.blockNumber,
    codeExists: true,
    runtimeBytecodeMatch: true,
    expectedRuntimeHash,
    deployedRuntimeHash,
    immutableReferenceCount: flattenImmutableReferences(immutableReferences).length
  };
}

async function buildBaseMirrorDeploymentVerification({
  runnerOutput,
  deploymentReceipt,
  provider = hre.ethers.provider
}) {
  if (!runnerOutput || typeof runnerOutput !== "object") {
    throw new Error("runnerOutput is required");
  }
  if (!deploymentReceipt || typeof deploymentReceipt !== "object") {
    throw new Error("deploymentReceipt is required");
  }
  if (!deploymentReceipt.deploymentManifest || typeof deploymentReceipt.deploymentManifest !== "object") {
    throw new Error("deploymentReceipt.deploymentManifest is required");
  }
  if (!deploymentReceipt.deploymentReceipts || typeof deploymentReceipt.deploymentReceipts !== "object") {
    throw new Error("deploymentReceipt.deploymentReceipts is required");
  }

  const baseCrossDomainMessenger = await verifyDeploymentTarget({
    key: "baseCrossDomainMessenger",
    runnerRecord: runnerOutput.baseCrossDomainMessenger,
    receiptRecord: deploymentReceipt.deploymentReceipts.baseCrossDomainMessenger,
    provider
  });
  const adapter = await verifyDeploymentTarget({
    key: "adapter",
    runnerRecord: runnerOutput.adapter,
    receiptRecord: deploymentReceipt.deploymentReceipts.adapter,
    provider
  });
  const mirror = await verifyDeploymentTarget({
    key: "mirror",
    runnerRecord: runnerOutput.mirror,
    receiptRecord: deploymentReceipt.deploymentReceipts.mirror,
    provider
  });

  return {
    version: 1,
    path: "base-proof-input-hash-mirror-deployment-verification",
    networkName: String(deploymentReceipt.networkName || "").trim(),
    runnerSource: "scripts/base/run-local-base-mirror-deployment.cjs",
    receiptSource: "scripts/base/record-base-mirror-deployment-receipt.cjs",
    manifestSource:
      deploymentReceipt.manifestSource ||
      "scripts/base/record-base-mirror-deployment-manifest.cjs",
    configSource:
      deploymentReceipt.configSource ||
      deploymentReceipt.deploymentManifest.configSource ||
      "config/base-messenger-config.cjs",
    payloadShape:
      deploymentReceipt.payloadShape ||
      deploymentReceipt.deploymentManifest.payloadShape ||
      "[fact_high, fact_low]",
    mirrorWriteShape:
      deploymentReceipt.mirrorWriteShape ||
      deploymentReceipt.deploymentManifest.mirrorWriteShape,
    deploymentReceipt,
    deploymentVerification: {
      baseCrossDomainMessenger,
      adapter,
      mirror
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--runner-output") {
      parsed.runnerOutputPath = argv[i + 1];
      i += 1;
    } else if (arg === "--receipt") {
      parsed.receiptPath = argv[i + 1];
      i += 1;
    } else if (arg === "--help") {
      parsed.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function printUsage() {
  console.log(
    [
      "Usage:",
      "  node scripts/base/record-base-mirror-deployment-verification.cjs --runner-output <path> --receipt <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  (async () => {
    try {
      const parsed = parseArgs(process.argv.slice(2));
      if (parsed.help || !parsed.runnerOutputPath || !parsed.receiptPath) {
        printUsage();
        process.exit(parsed.help ? 0 : 1);
      }

      const runnerOutput = loadJson(path.resolve(parsed.runnerOutputPath));
      const deploymentReceipt = loadJson(path.resolve(parsed.receiptPath));
      const verification = await buildBaseMirrorDeploymentVerification({
        runnerOutput,
        deploymentReceipt
      });
      console.log(JSON.stringify(verification, null, 2));
    } catch (error) {
      console.error(String(error && error.message ? error.message : error));
      process.exit(1);
    }
  })();
}

module.exports = {
  buildBaseMirrorDeploymentVerification,
  maskImmutableByteRanges
};
