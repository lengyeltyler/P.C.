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

function resolveMintClaimStatusOrNotFound({ mintClaimStatus, nullifier }) {
  if (!mintClaimStatus || typeof mintClaimStatus !== "object") {
    throw new Error("mintClaimStatus is required");
  }

  const normalizedNullifier = normalizeHex(nullifier, "nullifier");

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
  if (!mintClaimStatus.readinessSummary || typeof mintClaimStatus.readinessSummary !== "object") {
    throw new Error("mintClaimStatus.readinessSummary is required");
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

  const resolvedClaim = mintClaimStatus.appReadiness.claims.find(
    (claim) => normalizeHex(claim.nullifier, "claim.nullifier") === normalizedNullifier
  );

  if (!resolvedClaim) {
    return {
      version: 1,
      path: "phil-mint-claim-index-lookup-miss",
      lookupMissSource: "scripts/base/lookup-mint-claim-status-miss.cjs",
      statusSource: mintClaimStatus.statusSource,
      lookedUpPath: mintClaimStatus.path,
      networkName: mintClaimStatus.networkName,
      proofType: mintClaimStatus.proofType,
      payloadShape: mintClaimStatus.payloadShape,
      lookupQuery: {
        nullifier: normalizedNullifier
      },
      validationChecks: {
        statusPathValid: true,
        payloadShapeValid: true,
        upstreamStatusValid: true,
        claimCountMatches: true,
        lookupCompleted: true,
        lookupFound: false
      },
      lookupResult: {
        found: false,
        status: "not-found",
        reason: "nullifier-not-found"
      },
      claimStatus: null
    };
  }

  const normalizedClaim = {
    nullifier: normalizeHex(resolvedClaim.nullifier, "resolvedClaim.nullifier"),
    recipient: normalizeAddress(resolvedClaim.recipient, "resolvedClaim.recipient"),
    tokenId: normalizePositiveInteger(resolvedClaim.tokenId, "resolvedClaim.tokenId"),
    factHigh: normalizeHex(resolvedClaim.factHigh, "resolvedClaim.factHigh"),
    factLow: normalizeHex(resolvedClaim.factLow, "resolvedClaim.factLow"),
    ready: resolvedClaim.ready === true,
    status: String(resolvedClaim.status || "")
  };

  if (!normalizedClaim.ready) {
    throw new Error(`Resolved claim is not ready for nullifier: ${normalizedNullifier}`);
  }
  if (normalizedClaim.status !== "ready") {
    throw new Error(`Resolved claim has invalid status for nullifier: ${normalizedNullifier}`);
  }

  return {
    version: 1,
    path: "phil-mint-claim-index-lookup-miss",
    lookupMissSource: "scripts/base/lookup-mint-claim-status-miss.cjs",
    statusSource: mintClaimStatus.statusSource,
    lookedUpPath: mintClaimStatus.path,
    networkName: mintClaimStatus.networkName,
    proofType: mintClaimStatus.proofType,
    payloadShape: mintClaimStatus.payloadShape,
    lookupQuery: {
      nullifier: normalizedNullifier
    },
    validationChecks: {
      statusPathValid: true,
      payloadShapeValid: true,
      upstreamStatusValid: true,
      claimCountMatches: true,
      lookupCompleted: true,
      lookupFound: true
    },
    lookupResult: {
      found: true,
      status: "ready",
      reason: "resolved-claim-status"
    },
    claimStatus: normalizedClaim
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mint-index-status") {
      parsed.mintIndexStatusPath = argv[i + 1];
      i += 1;
    } else if (arg === "--nullifier") {
      parsed.nullifier = argv[i + 1];
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
      "  node scripts/base/lookup-mint-claim-status-miss.cjs --mint-index-status <path> --nullifier <hex>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.mintIndexStatusPath || !parsed.nullifier) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const lookup = resolveMintClaimStatusOrNotFound({
      mintClaimStatus: loadJson(path.resolve(parsed.mintIndexStatusPath)),
      nullifier: parsed.nullifier
    });
    console.log(JSON.stringify(lookup, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  resolveMintClaimStatusOrNotFound
};
