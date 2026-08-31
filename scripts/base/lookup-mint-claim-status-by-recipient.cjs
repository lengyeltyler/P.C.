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

function resolveMintClaimStatusesByRecipient({ mintClaimStatus, recipient }) {
  if (!mintClaimStatus || typeof mintClaimStatus !== "object") {
    throw new Error("mintClaimStatus is required");
  }

  const normalizedRecipient = normalizeAddress(recipient, "recipient");

  assertEqual(
    mintClaimStatus.path,
    "phil-mint-claim-index-status",
    "mintClaimStatus.path"
  );
  assertEqual(
    mintClaimStatus.payloadShape,
    "[fact_high, fact_low]",
    "mintClaimStatus.payloadShape"
  );

  if (!mintClaimStatus.validationChecks || typeof mintClaimStatus.validationChecks !== "object") {
    throw new Error("mintClaimStatus.validationChecks is required");
  }
  if (!mintClaimStatus.appReadiness || typeof mintClaimStatus.appReadiness !== "object") {
    throw new Error("mintClaimStatus.appReadiness is required");
  }
  if (!Array.isArray(mintClaimStatus.appReadiness.claims)) {
    throw new Error("mintClaimStatus.appReadiness.claims is required");
  }

  assertTrue(
    mintClaimStatus.validationChecks.consumptionPathValid,
    "mintClaimStatus.validationChecks.consumptionPathValid"
  );
  assertTrue(
    mintClaimStatus.validationChecks.payloadShapeValid,
    "mintClaimStatus.validationChecks.payloadShapeValid"
  );
  assertTrue(
    mintClaimStatus.validationChecks.upstreamValidationPassed,
    "mintClaimStatus.validationChecks.upstreamValidationPassed"
  );
  assertTrue(
    mintClaimStatus.validationChecks.claimCountMatches,
    "mintClaimStatus.validationChecks.claimCountMatches"
  );
  assertTrue(
    mintClaimStatus.validationChecks.claimShapeValid,
    "mintClaimStatus.validationChecks.claimShapeValid"
  );

  const claimCount = normalizePositiveInteger(
    mintClaimStatus.appReadiness.claimCount,
    "mintClaimStatus.appReadiness.claimCount"
  );
  assertEqual(
    claimCount,
    mintClaimStatus.appReadiness.claims.length,
    "mintClaimStatus.appReadiness.claimCount/claims.length"
  );

  const readyClaims = mintClaimStatus.appReadiness.claims.map((claim, index) => {
    if (!claim || typeof claim !== "object") {
      throw new Error(`mintClaimStatus.appReadiness.claims[${index}] is required`);
    }

    const normalizedClaim = {
      nullifier: normalizeHex(claim.nullifier, `claims[${index}].nullifier`),
      recipient: normalizeAddress(claim.recipient, `claims[${index}].recipient`),
      tokenId: normalizePositiveInteger(claim.tokenId, `claims[${index}].tokenId`),
      factHigh: normalizeHex(claim.factHigh, `claims[${index}].factHigh`),
      factLow: normalizeHex(claim.factLow, `claims[${index}].factLow`),
      ready: claim.ready === true,
      status: String(claim.status || "")
    };

    if (!normalizedClaim.ready) {
      throw new Error(`Claim is not ready at index ${index}`);
    }
    if (normalizedClaim.status !== "ready") {
      throw new Error(`Claim has invalid status at index ${index}`);
    }

    return normalizedClaim;
  });

  const matchedClaims = readyClaims.filter(
    (claim) => claim.recipient.toLowerCase() === normalizedRecipient.toLowerCase()
  );

  return {
    version: 1,
    path: "phil-mint-claim-index-recipient-lookup",
    recipientLookupSource: "scripts/base/lookup-mint-claim-status-by-recipient.cjs",
    statusSource: mintClaimStatus.statusSource,
    lookedUpPath: mintClaimStatus.path,
    networkName: mintClaimStatus.networkName,
    proofType: mintClaimStatus.proofType,
    payloadShape: mintClaimStatus.payloadShape,
    lookupQuery: {
      recipient: normalizedRecipient
    },
    validationChecks: {
      statusPathValid: true,
      payloadShapeValid: true,
      upstreamStatusValid: true,
      claimCountMatches: true,
      lookupCompleted: true
    },
    recipientSummary: {
      recipient: normalizedRecipient,
      matchedClaimCount: matchedClaims.length,
      readyClaimCount: matchedClaims.length
    },
    claimStatuses: matchedClaims
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-index-status") {
      parsed.mintIndexStatusPath = argv[i + 1];
      i += 1;
    } else if (arg === "--recipient") {
      parsed.recipient = argv[i + 1];
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
      "  node scripts/base/lookup-mint-claim-status-by-recipient.cjs --mint-index-status <path> --recipient <address>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIndexStatusPath || !parsed.recipient) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const lookup = resolveMintClaimStatusesByRecipient({
      mintClaimStatus: loadJson(path.resolve(parsed.mintIndexStatusPath)),
      recipient: parsed.recipient
    });
    console.log(JSON.stringify(lookup, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  resolveMintClaimStatusesByRecipient
};
