const fs = require("node:fs");
const path = require("node:path");

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function assertTrue(value, label) {
  if (value !== true) {
    throw new Error(`${label} must be true`);
  }
}

function normalizeHex(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]+$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text.toLowerCase();
}

function normalizeAddress(value, label) {
  const text = String(value || "").trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) {
    throw new Error(`Invalid ${label}: ${text || "<empty>"}`);
  }
  return text;
}

function normalizePositiveInteger(value, label) {
  const integerValue = Number(value);
  if (!Number.isInteger(integerValue) || integerValue <= 0) {
    throw new Error(`Invalid ${label}: ${value}`);
  }
  return integerValue;
}

function buildMintClaimStatus({ mintClaimConsumption }) {
  if (!mintClaimConsumption || typeof mintClaimConsumption !== "object") {
    throw new Error("mintClaimConsumption is required");
  }

  assertEqual(
    mintClaimConsumption.path,
    "phil-mint-claim-index-consumption",
    "mintClaimConsumption.path"
  );
  assertEqual(
    mintClaimConsumption.payloadShape,
    "[fact_high, fact_low]",
    "mintClaimConsumption.payloadShape"
  );

  if (
    !mintClaimConsumption.validationChecks ||
    typeof mintClaimConsumption.validationChecks !== "object"
  ) {
    throw new Error("mintClaimConsumption.validationChecks is required");
  }
  if (
    !mintClaimConsumption.appReadModel ||
    typeof mintClaimConsumption.appReadModel !== "object"
  ) {
    throw new Error("mintClaimConsumption.appReadModel is required");
  }
  if (!Array.isArray(mintClaimConsumption.appReadModel.claims)) {
    throw new Error("mintClaimConsumption.appReadModel.claims is required");
  }

  assertTrue(
    mintClaimConsumption.validationChecks.indexPathValid,
    "mintClaimConsumption.validationChecks.indexPathValid"
  );
  assertTrue(
    mintClaimConsumption.validationChecks.claimCountMatches,
    "mintClaimConsumption.validationChecks.claimCountMatches"
  );
  assertTrue(
    mintClaimConsumption.validationChecks.claimShapeValid,
    "mintClaimConsumption.validationChecks.claimShapeValid"
  );

  const claimCount = normalizePositiveInteger(
    mintClaimConsumption.appReadModel.claimCount,
    "mintClaimConsumption.appReadModel.claimCount"
  );
  assertEqual(
    claimCount,
    mintClaimConsumption.appReadModel.claims.length,
    "mintClaimConsumption.appReadModel.claimCount/claims.length"
  );

  const claims = mintClaimConsumption.appReadModel.claims.map((claim, index) => {
    if (!claim || typeof claim !== "object") {
      throw new Error(`mintClaimConsumption.appReadModel.claims[${index}] is required`);
    }

    return {
      nullifier: normalizeHex(claim.nullifier, `claims[${index}].nullifier`),
      recipient: normalizeAddress(claim.recipient, `claims[${index}].recipient`),
      tokenId: normalizePositiveInteger(claim.tokenId, `claims[${index}].tokenId`),
      factHigh: normalizeHex(claim.factHigh, `claims[${index}].factHigh`),
      factLow: normalizeHex(claim.factLow, `claims[${index}].factLow`),
      ready: true,
      status: "ready"
    };
  });

  return {
    version: 1,
    path: "phil-mint-claim-index-status",
    statusSource: "scripts/base/build-mint-claim-status.cjs",
    consumptionSource: mintClaimConsumption.consumptionSource,
    consumedPath: mintClaimConsumption.path,
    networkName: mintClaimConsumption.networkName,
    proofType: mintClaimConsumption.proofType,
    payloadShape: mintClaimConsumption.payloadShape,
    validationChecks: {
      consumptionPathValid: true,
      payloadShapeValid: true,
      upstreamValidationPassed: true,
      claimCountMatches: true,
      claimShapeValid: true
    },
    readinessSummary: {
      ready: true,
      status: "ready",
      reason: "validated-mint-claims-present",
      claimCount: claims.length,
      readyClaimCount: claims.length
    },
    primaryClaim: {
      recipient: claims[0].recipient,
      tokenId: claims[0].tokenId,
      factHigh: claims[0].factHigh,
      factLow: claims[0].factLow
    },
    appReadiness: {
      claimCount: claims.length,
      claims
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-index-consumption") {
      parsed.mintIndexConsumptionPath = argv[i + 1];
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
      "  node scripts/base/build-mint-claim-status.cjs --mint-index-consumption <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIndexConsumptionPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const status = buildMintClaimStatus({
      mintClaimConsumption: loadJson(path.resolve(parsed.mintIndexConsumptionPath))
    });
    console.log(JSON.stringify(status, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintClaimStatus
};
