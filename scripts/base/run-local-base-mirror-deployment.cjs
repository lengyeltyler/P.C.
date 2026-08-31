const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");
const { ethers: standaloneEthers } = require("ethers");

const {
  buildBaseMessengerDeploymentPlan
} = require("./assemble-base-messenger-deploy-args.cjs");
const {
  buildBaseMirrorDeploymentManifest
} = require("./record-base-mirror-deployment-manifest.cjs");

async function deployContractByName(signer, contractName, args = []) {
  const artifact = await hre.artifacts.readArtifact(contractName);
  const factory = new standaloneEthers.ContractFactory(artifact.abi, artifact.bytecode, signer);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function deploymentRecord(contract, contractName) {
  const deploymentTx = contract.deploymentTransaction();
  if (!deploymentTx) {
    throw new Error(`Missing deployment transaction for ${contractName}`);
  }

  const receipt = await deploymentTx.wait();
  if (!receipt) {
    throw new Error(`Missing deployment receipt for ${contractName}`);
  }

  return {
    contract: contractName,
    address: await contract.getAddress(),
    transactionHash: deploymentTx.hash,
    blockNumber: Number(receipt.blockNumber)
  };
}

function writeJson(outputPath, value) {
  if (!outputPath) {
    return;
  }

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(value, null, 2));
}

async function runLocalBaseMirrorDeployment({
  signer,
  networkName,
  overrides = {},
  outputPath
} = {}) {
  const effectiveSigner = signer ?? (await hre.ethers.getSigners())[0];
  if (!effectiveSigner) {
    throw new Error("A signer is required for the local Base mirror deployment runner");
  }

  const effectiveNetworkName = networkName ?? hre.network.name;
  const baseCrossDomainMessenger = await deployContractByName(
    effectiveSigner,
    "MockBaseCrossDomainMessenger"
  );

  const effectiveOverrides = {
    ...overrides,
    canonicalBaseMessengerAddress: await baseCrossDomainMessenger.getAddress()
  };

  const deploymentPlan = buildBaseMessengerDeploymentPlan({
    networkName: effectiveNetworkName,
    overrides: effectiveOverrides
  });

  const crossDomainMessengerAdapter = await deployContractByName(
    effectiveSigner,
    deploymentPlan.adapter.contract,
    deploymentPlan.adapter.constructorArgs
  );

  const mirrorDeploymentPlan = buildBaseMessengerDeploymentPlan({
    networkName: effectiveNetworkName,
    authorizedL1Messenger: await crossDomainMessengerAdapter.getAddress(),
    overrides: effectiveOverrides
  });

  const baseMirror = await deployContractByName(
    effectiveSigner,
    mirrorDeploymentPlan.mirror.contract,
    mirrorDeploymentPlan.mirror.constructorArgs
  );

  const deploymentManifest = buildBaseMirrorDeploymentManifest({
    networkName: effectiveNetworkName,
    authorizedL1Messenger: await crossDomainMessengerAdapter.getAddress(),
    deployedAddresses: {
      adapter: await crossDomainMessengerAdapter.getAddress(),
      mirror: await baseMirror.getAddress()
    },
    overrides: effectiveOverrides
  });

  const output = {
    version: 1,
    path: "base-proof-input-hash-mirror-local-runner",
    networkName: effectiveNetworkName,
    deployArgSource: "scripts/base/assemble-base-messenger-deploy-args.cjs",
    manifestSource: "scripts/base/record-base-mirror-deployment-manifest.cjs",
    baseCrossDomainMessenger: await deploymentRecord(
      baseCrossDomainMessenger,
      "MockBaseCrossDomainMessenger"
    ),
    adapter: await deploymentRecord(
      crossDomainMessengerAdapter,
      deploymentPlan.adapter.contract
    ),
    mirror: await deploymentRecord(
      baseMirror,
      mirrorDeploymentPlan.mirror.contract
    ),
    deploymentPlan,
    deploymentManifest
  };

  writeJson(outputPath, output);

  return {
    output,
    baseCrossDomainMessenger,
    crossDomainMessengerAdapter,
    baseMirror,
    deploymentPlan,
    deploymentManifest
  };
}

function parseArgs(argv) {
  const parsed = {
    overrides: {}
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--out") {
      parsed.outputPath = argv[i + 1];
      i += 1;
    } else if (arg === "--adapter-min-gas-limit") {
      parsed.overrides.adapterMinGasLimit = argv[i + 1];
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
      "  node ./scripts/base/run-local-base-mirror-deployment.cjs --out <path> [--adapter-min-gas-limit <uint32>]"
    ].join("\n")
  );
}

if (require.main === module) {
  (async () => {
    try {
      const parsed = parseArgs(process.argv.slice(2));
      if (parsed.help) {
        printUsage();
        process.exit(0);
      }

      const result = await runLocalBaseMirrorDeployment(parsed);
      console.log(JSON.stringify(result.output, null, 2));
    } catch (error) {
      console.error(String(error && error.message ? error.message : error));
      process.exit(1);
    }
  })();
}

module.exports = {
  runLocalBaseMirrorDeployment
};
