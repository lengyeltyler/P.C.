const {
  buildBaseMessengerDeploymentPlan
} = require("./assemble-base-messenger-deploy-args.cjs");

function normalizeAddress(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function buildBaseMirrorDeploymentManifest({
  networkName,
  authorizedL1Messenger,
  deployedAddresses,
  overrides = {}
}) {
  if (!deployedAddresses || typeof deployedAddresses !== "object") {
    throw new Error("deployedAddresses is required");
  }

  const adapterAddress = normalizeAddress(
    deployedAddresses.adapter,
    "deployed adapter address"
  );
  const mirrorAddress = normalizeAddress(
    deployedAddresses.mirror,
    "deployed mirror address"
  );

  const deploymentPlan = buildBaseMessengerDeploymentPlan({
    networkName,
    authorizedL1Messenger,
    overrides
  });

  if (!deploymentPlan.mirror) {
    throw new Error("authorizedL1Messenger is required to build the Base mirror deployment manifest");
  }

  return {
    version: 1,
    path: "base-proof-input-hash-mirror",
    networkName: deploymentPlan.networkName,
    chainId: deploymentPlan.chainId,
    configSource: "config/base-messenger-config.cjs",
    deployArgSource: "scripts/base/assemble-base-messenger-deploy-args.cjs",
    payloadShape: "[fact_high, fact_low]",
    mirrorWriteShape: {
      mirroredProofInputHashFact: "mirroredProofInputHashFact[factHigh][factLow] = true",
      latestFactHigh: "latestFactHigh = factHigh",
      latestFactLow: "latestFactLow = factLow"
    },
    deploymentPlan,
    deployedAddresses: {
      adapter: adapterAddress,
      mirror: mirrorAddress
    }
  };
}

function parseArgs(argv) {
  const parsed = {
    deployedAddresses: {},
    overrides: {}
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--network") {
      parsed.networkName = argv[i + 1];
      i += 1;
    } else if (arg === "--authorized-l1-messenger") {
      parsed.authorizedL1Messenger = argv[i + 1];
      i += 1;
    } else if (arg === "--adapter-address") {
      parsed.deployedAddresses.adapter = argv[i + 1];
      i += 1;
    } else if (arg === "--mirror-address") {
      parsed.deployedAddresses.mirror = argv[i + 1];
      i += 1;
    } else if (arg === "--canonical-base-messenger-address") {
      parsed.overrides.canonicalBaseMessengerAddress = argv[i + 1];
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
      "  node scripts/base/record-base-mirror-deployment-manifest.cjs --network <name> --authorized-l1-messenger <address> --adapter-address <address> --mirror-address <address> [--canonical-base-messenger-address <address>] [--adapter-min-gas-limit <uint32>]"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (
      parsed.help ||
      !parsed.networkName ||
      !parsed.authorizedL1Messenger ||
      !parsed.deployedAddresses.adapter ||
      !parsed.deployedAddresses.mirror
    ) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const manifest = buildBaseMirrorDeploymentManifest(parsed);
    console.log(JSON.stringify(manifest, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildBaseMirrorDeploymentManifest
};
