const fs = require("node:fs");
const path = require("node:path");

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function stableStringify(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function assertDeepEqual(actual, expected, label) {
  if (stableStringify(actual) !== stableStringify(expected)) {
    throw new Error(`${label} mismatch`);
  }
}

function buildBaseMirrorDeploymentBundle({
  runnerOutput,
  deploymentReceipt,
  deploymentVerification
}) {
  if (!runnerOutput || typeof runnerOutput !== "object") {
    throw new Error("runnerOutput is required");
  }
  if (!deploymentReceipt || typeof deploymentReceipt !== "object") {
    throw new Error("deploymentReceipt is required");
  }
  if (!deploymentVerification || typeof deploymentVerification !== "object") {
    throw new Error("deploymentVerification is required");
  }

  if (!runnerOutput.deploymentManifest || typeof runnerOutput.deploymentManifest !== "object") {
    throw new Error("runnerOutput.deploymentManifest is required");
  }
  if (!deploymentReceipt.deploymentManifest || typeof deploymentReceipt.deploymentManifest !== "object") {
    throw new Error("deploymentReceipt.deploymentManifest is required");
  }
  if (!deploymentVerification.deploymentReceipt || typeof deploymentVerification.deploymentReceipt !== "object") {
    throw new Error("deploymentVerification.deploymentReceipt is required");
  }

  assertEqual(
    String(runnerOutput.networkName || "").trim(),
    String(deploymentReceipt.networkName || "").trim(),
    "runner/receipt networkName"
  );
  assertEqual(
    String(deploymentReceipt.networkName || "").trim(),
    String(deploymentVerification.networkName || "").trim(),
    "receipt/verification networkName"
  );

  assertDeepEqual(
    runnerOutput.deploymentManifest,
    deploymentReceipt.deploymentManifest,
    "runner manifest / receipt manifest"
  );
  assertDeepEqual(
    deploymentReceipt,
    deploymentVerification.deploymentReceipt,
    "receipt / verification receipt"
  );

  const payloadShape =
    runnerOutput.deploymentManifest.payloadShape || "[fact_high, fact_low]";
  const mirrorWriteShape = runnerOutput.deploymentManifest.mirrorWriteShape;

  assertEqual(
    payloadShape,
    deploymentReceipt.payloadShape || payloadShape,
    "runner/receipt payloadShape"
  );
  assertEqual(
    payloadShape,
    deploymentVerification.payloadShape || payloadShape,
    "runner/verification payloadShape"
  );
  assertDeepEqual(
    mirrorWriteShape,
    deploymentReceipt.mirrorWriteShape,
    "runner/receipt mirrorWriteShape"
  );
  assertDeepEqual(
    mirrorWriteShape,
    deploymentVerification.mirrorWriteShape,
    "runner/verification mirrorWriteShape"
  );

  return {
    version: 1,
    path: "base-proof-input-hash-mirror-deployment-bundle",
    networkName: String(runnerOutput.networkName || "").trim(),
    packageSource: "scripts/base/package-base-mirror-deployment.cjs",
    runnerSource: "scripts/base/run-local-base-mirror-deployment.cjs",
    receiptSource: "scripts/base/record-base-mirror-deployment-receipt.cjs",
    verificationSource: "scripts/base/record-base-mirror-deployment-verification.cjs",
    configSource:
      runnerOutput.deploymentManifest.configSource || "config/base-messenger-config.cjs",
    payloadShape,
    mirrorWriteShape,
    deploymentManifest: runnerOutput.deploymentManifest,
    runnerOutput,
    deploymentReceipt,
    deploymentVerification
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
    } else if (arg === "--verification") {
      parsed.verificationPath = argv[i + 1];
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
      "  node scripts/base/package-base-mirror-deployment.cjs --runner-output <path> --receipt <path> --verification <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (
      parsed.help ||
      !parsed.runnerOutputPath ||
      !parsed.receiptPath ||
      !parsed.verificationPath
    ) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const bundle = buildBaseMirrorDeploymentBundle({
      runnerOutput: loadJson(path.resolve(parsed.runnerOutputPath)),
      deploymentReceipt: loadJson(path.resolve(parsed.receiptPath)),
      deploymentVerification: loadJson(path.resolve(parsed.verificationPath))
    });
    console.log(JSON.stringify(bundle, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  buildBaseMirrorDeploymentBundle
};
