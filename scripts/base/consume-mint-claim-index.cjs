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

function buildMintClaimIndexConsumption({ mintClaimIndex }) {
  if (!mintClaimIndex || typeof mintClaimIndex !== "object") {
    throw new Error("mintClaimIndex is required");
  }

  assertEqual(mintClaimIndex.path, "phil-mint-claim-index", "mintClaimIndex.path");
  assertEqual(
    mintClaimIndex.payloadShape,
    "[fact_high, fact_low]",
    "mintClaimIndex.payloadShape"
  );

  if (!Array.isArray(mintClaimIndex.claims)) {
    throw new Error("mintClaimIndex.claims is required");
  }

  assertEqual(
    normalizePositiveInteger(mintClaimIndex.claimCount, "mintClaimIndex.claimCount"),
    mintClaimIndex.claims.length,
    "mintClaimIndex.claimCount/claims.length"
  );

  const claims = mintClaimIndex.claims.map((claim, index) => {
    if (!claim || typeof claim !== "object") {
      throw new Error(`mintClaimIndex.claims[${index}] is required`);
    }

    return {
      nullifier: normalizeHex(claim.nullifier, `claims[${index}].nullifier`),
      ownerCommitment: normalizeHex(
        claim.ownerCommitment,
        `claims[${index}].ownerCommitment`
      ),
      consumerDataHash: normalizeHex(
        claim.consumerDataHash,
        `claims[${index}].consumerDataHash`
      ),
      recipient: normalizeAddress(claim.recipient, `claims[${index}].recipient`),
      tokenId: normalizePositiveInteger(claim.tokenId, `claims[${index}].tokenId`),
      factHigh: normalizeHex(claim.factHigh, `claims[${index}].factHigh`),
      factLow: normalizeHex(claim.factLow, `claims[${index}].factLow`)
    };
  });

  return {
    version: 1,
    path: "phil-mint-claim-index-consumption",
    consumptionSource: "scripts/base/consume-mint-claim-index.cjs",
    indexSource: mintClaimIndex.exportSource,
    consumedIndexPath: mintClaimIndex.path,
    networkName: mintClaimIndex.networkName,
    proofType: mintClaimIndex.proofType,
    payloadShape: mintClaimIndex.payloadShape,
    validationChecks: {
      indexPathValid: true,
      claimCountMatches: true,
      claimShapeValid: true
    },
    appReadModel: {
      claimCount: claims.length,
      claims
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-index") {
      parsed.mintIndexPath = argv[i + 1];
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
      "  node scripts/base/consume-mint-claim-index.cjs --mint-index <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIndexPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const consumption = buildMintClaimIndexConsumption({
      mintClaimIndex: loadJson(path.resolve(parsed.mintIndexPath))
    });
    console.log(JSON.stringify(consumption, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintClaimIndexConsumption
};
