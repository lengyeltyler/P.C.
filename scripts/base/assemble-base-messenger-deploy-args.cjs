const {
  resolveBaseMessengerConfig
} = require("../../config/base-messenger-config.cjs");

function normalizeAddress(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function buildBaseMessengerDeploymentPlan({
  networkName,
  authorizedL1Messenger,
  overrides = {}
}) {
  if (!networkName) {
    throw new Error("networkName is required");
  }

  const config = resolveBaseMessengerConfig(networkName, overrides);
  const plan = {
    networkName: config.networkName,
    chainId: config.chainId,
    canonicalBaseMessengerAddress: config.canonicalBaseMessengerAddress,
    adapterMinGasLimit: config.adapterMinGasLimit,
    adapter: {
      contract: "PhilBaseCrossDomainMessengerAdapter",
      constructorArgs: [
        config.canonicalBaseMessengerAddress,
        config.adapterMinGasLimit
      ]
    }
  };

  if (authorizedL1Messenger !== undefined) {
    const normalizedAuthorizedL1Messenger = normalizeAddress(
      authorizedL1Messenger,
      "authorizedL1Messenger"
    );
    plan.authorizedL1Messenger = normalizedAuthorizedL1Messenger;
    plan.mirror = {
      contract: "PhilBaseProofInputHashMirror",
      constructorArgs: [
        config.canonicalBaseMessengerAddress,
        normalizedAuthorizedL1Messenger
      ]
    };
  }

  return plan;
}

function parseArgs(argv) {
  const parsed = {
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
      "  node scripts/base/assemble-base-messenger-deploy-args.cjs --network <name> [--authorized-l1-messenger <address>] [--canonical-base-messenger-address <address>] [--adapter-min-gas-limit <uint32>]"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.networkName) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const plan = buildBaseMessengerDeploymentPlan(parsed);
    console.log(JSON.stringify(plan, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildBaseMessengerDeploymentPlan
};
