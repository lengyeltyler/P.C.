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

function buildMintClaimIndex({ mintClaimSource }) {
  if (!mintClaimSource || typeof mintClaimSource !== "object") {
    throw new Error("mintClaimSource is required");
  }

  assertEqual(
    mintClaimSource.path,
    "phil-mint-claim-source",
    "mintClaimSource.path"
  );
  assertEqual(
    mintClaimSource.payloadShape,
    "[fact_high, fact_low]",
    "mintClaimSource.payloadShape"
  );
  assertEqual(
    mintClaimSource.claimRecord?.minted,
    true,
    "mintClaimSource.claimRecord.minted"
  );

  const authorization = mintClaimSource.authorization;
  const claimPreview = mintClaimSource.claimPreview;
  const claimRecord = mintClaimSource.claimRecord;
  const factPayload = mintClaimSource.factPayload;

  if (!authorization || typeof authorization !== "object") {
    throw new Error("mintClaimSource.authorization is required");
  }
  if (!claimPreview || typeof claimPreview !== "object") {
    throw new Error("mintClaimSource.claimPreview is required");
  }
  if (!claimRecord || typeof claimRecord !== "object") {
    throw new Error("mintClaimSource.claimRecord is required");
  }
  if (!factPayload || typeof factPayload !== "object") {
    throw new Error("mintClaimSource.factPayload is required");
  }

  normalizeHex(authorization.ownerCommitment, "authorization.ownerCommitment");
  normalizeHex(authorization.actionHash, "authorization.actionHash");
  normalizeHex(authorization.policyHash, "authorization.policyHash");
  normalizeHex(authorization.nullifier, "authorization.nullifier");
  normalizeHex(authorization.consumerDataHash, "authorization.consumerDataHash");

  const previewRecipient = normalizeAddress(
    claimPreview.recipient,
    "claimPreview.recipient"
  );
  const recordRecipient = normalizeAddress(
    claimRecord.recipient,
    "claimRecord.recipient"
  );
  const previewTokenId = normalizePositiveInteger(
    claimPreview.tokenId,
    "claimPreview.tokenId"
  );
  const recordTokenId = normalizePositiveInteger(
    claimRecord.tokenId,
    "claimRecord.tokenId"
  );

  assertEqual(previewRecipient, recordRecipient, "claim preview/record recipient");
  assertEqual(previewTokenId, recordTokenId, "claim preview/record tokenId");

  return {
    version: 1,
    path: "phil-mint-claim-index",
    exportSource: "scripts/base/export-mint-claim-index.cjs",
    sourcePath: mintClaimSource.path,
    networkName: mintClaimSource.networkName,
    proofType: mintClaimSource.proofType,
    payloadShape: mintClaimSource.payloadShape,
    claimCount: 1,
    claims: [
      {
        nullifier: normalizeHex(authorization.nullifier, "authorization.nullifier"),
        ownerCommitment: normalizeHex(
          authorization.ownerCommitment,
          "authorization.ownerCommitment"
        ),
        consumerDataHash: normalizeHex(
          authorization.consumerDataHash,
          "authorization.consumerDataHash"
        ),
        recipient: recordRecipient,
        tokenId: recordTokenId,
        factHigh: normalizeHex(factPayload.factHigh, "factPayload.factHigh"),
        factLow: normalizeHex(factPayload.factLow, "factPayload.factLow")
      }
    ]
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--claim-source") {
      parsed.claimSourcePath = argv[i + 1];
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
      "  node scripts/base/export-mint-claim-index.cjs --claim-source <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.claimSourcePath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const index = buildMintClaimIndex({
      mintClaimSource: loadJson(path.resolve(parsed.claimSourcePath))
    });
    console.log(JSON.stringify(index, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildMintClaimIndex
};
