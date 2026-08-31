const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  runLocalSmartAccountDeployDrill
} = require("./run-local-smart-account-deploy-drill.cjs");
const {
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
} = require("./run-local-bundler-stub.cjs");

const LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_LABEL =
  "PHIL_LOCAL_SUBMISSION_DRILL_MATRIX_V1";
const LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_LABEL)
);
const LOCAL_SUBMISSION_DRILL_MATRIX_KIND =
  "controlled-local-smart-account-deploy-submission-drill-matrix-v1";
const LOCAL_SUBMISSION_DRILL_MATRIX_SOURCE_PATH =
  "phil-smart-account-deploy-submission-attempt-runner";
const LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_TIMEOUT_MS = 15000;
const LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_OUT_DIR =
  "./proving/out/local_submission_drill_matrix";
const LOCAL_SUBMISSION_DRILL_MATRIX_SCENARIOS = Object.freeze([
  {
    scenarioName: "accepted",
    mode: LOCAL_BUNDLER_STUB_MODE_ACCEPTED
  },
  {
    scenarioName: "rejected",
    mode: LOCAL_BUNDLER_STUB_MODE_REJECTED
  },
  {
    scenarioName: "transport",
    mode: LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
  }
]);

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function writeJson(jsonPath, value) {
  fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(value, null, 2)}\n`);
}

function normalizeString(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    throw new Error(`Invalid ${label}: <empty>`);
  }
  return normalized;
}

function normalizePositiveInteger(value, label) {
  const normalized = Number.parseInt(String(value || ""), 10);
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
  return normalized;
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

async function runScenario({
  scenarioName,
  mode,
  smartAccountDeployAttemptRunner,
  outDir,
  timeoutMs
}) {
  const scenarioRunDir = path.join(outDir, `${scenarioName}_run`);
  const drillArtifact = await runLocalSmartAccountDeployDrill({
    smartAccountDeployAttemptRunner,
    mode,
    outDir: scenarioRunDir,
    timeoutMs
  });
  const drillResultPath = path.join(outDir, `${scenarioName}_drill_result.json`);
  writeJson(drillResultPath, drillArtifact);

  return {
    scenarioName,
    mode,
    localEndpoint: drillArtifact.localSubmissionDrill.localEndpoint,
    drillResultPath,
    classification: drillArtifact.localSubmissionDrillSummary.classification,
    responseCaptured: drillArtifact.localSubmissionDrillSummary.responseCaptured,
    localHttpExchangeOccurred:
      drillArtifact.localSubmissionDrillSummary.localHttpExchangeOccurred,
    runnerStatus: drillArtifact.localSubmissionDrill.drillRecord.runnerStatus,
    transportResult: drillArtifact.localSubmissionDrill.drillRecord.transportResult,
    responseStatus: drillArtifact.localSubmissionDrill.drillRecord.responseStatus,
    internalArtifacts: {
      stubRequestArtifactPath:
        drillArtifact.localSubmissionDrill.drillRecord.stubRequestArtifactPath,
      stubResponseArtifactPath:
        drillArtifact.localSubmissionDrill.drillRecord.stubResponseArtifactPath,
      liveRunnerResultPath:
        drillArtifact.localSubmissionDrill.drillRecord.liveRunnerResultPath
    },
    continuity: {
      ownerCommitment: drillArtifact.localSubmissionDrill.ownerCommitment,
      canonicalRecipient: drillArtifact.localSubmissionDrill.canonicalRecipient,
      targetAddress: drillArtifact.localSubmissionDrill.targetAddress,
      entryPointAddress: drillArtifact.localSubmissionDrill.entryPointAddress,
      chainId: drillArtifact.localSubmissionDrill.chainId,
      proofType: drillArtifact.proofType,
      payloadShape: drillArtifact.payloadShape
    }
  };
}

async function runLocalSmartAccountDeployDrillMatrix({
  smartAccountDeployAttemptRunner,
  outDir = LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_OUT_DIR,
  timeoutMs = LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_TIMEOUT_MS,
  now = () => new Date().toISOString()
}) {
  if (
    !smartAccountDeployAttemptRunner ||
    typeof smartAccountDeployAttemptRunner !== "object"
  ) {
    throw new Error("smartAccountDeployAttemptRunner is required");
  }

  assertEqual(
    smartAccountDeployAttemptRunner.path,
    LOCAL_SUBMISSION_DRILL_MATRIX_SOURCE_PATH,
    "smartAccountDeployAttemptRunner.path"
  );

  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");
  const scenarios = [];

  for (const scenario of LOCAL_SUBMISSION_DRILL_MATRIX_SCENARIOS) {
    scenarios.push(
      await runScenario({
        scenarioName: scenario.scenarioName,
        mode: scenario.mode,
        smartAccountDeployAttemptRunner,
        outDir: normalizedOutDir,
        timeoutMs: normalizedTimeoutMs
      })
    );
  }

  for (const scenario of scenarios) {
    assertEqual(
      scenario.continuity.payloadShape,
      "[fact_high, fact_low]",
      `${scenario.scenarioName}.payloadShape`
    );
    assertEqual(
      scenario.continuity.proofType,
      "stwo-unlock-keccak-v1",
      `${scenario.scenarioName}.proofType`
    );
  }
  assertEqual(
    scenarios[0].continuity.ownerCommitment,
    scenarios[1].continuity.ownerCommitment,
    "accepted/rejected ownerCommitment"
  );
  assertEqual(
    scenarios[0].continuity.ownerCommitment,
    scenarios[2].continuity.ownerCommitment,
    "accepted/transport ownerCommitment"
  );
  assertEqual(
    scenarios[0].continuity.canonicalRecipient,
    scenarios[1].continuity.canonicalRecipient,
    "accepted/rejected canonicalRecipient"
  );
  assertEqual(
    scenarios[0].continuity.canonicalRecipient,
    scenarios[2].continuity.canonicalRecipient,
    "accepted/transport canonicalRecipient"
  );
  assertEqual(
    scenarios[0].classification,
    "accepted-json-rpc-response",
    "accepted classification"
  );
  assertEqual(
    scenarios[1].classification,
    "rejected-json-rpc-response",
    "rejected classification"
  );
  assertEqual(
    scenarios[2].classification,
    "transport-error-response",
    "transport classification"
  );
  assertTrue(scenarios[0].responseCaptured, "accepted responseCaptured");
  assertTrue(scenarios[1].responseCaptured, "rejected responseCaptured");
  assertEqual(scenarios[2].responseCaptured, false, "transport responseCaptured");

  const compactScenarios = scenarios.map((scenario) => ({
    scenarioName: scenario.scenarioName,
    mode: scenario.mode,
    localEndpoint: scenario.localEndpoint,
    drillResultPath: scenario.drillResultPath,
    classification: scenario.classification,
    responseCaptured: scenario.responseCaptured,
    localHttpExchangeOccurred: scenario.localHttpExchangeOccurred,
    runnerStatus: scenario.runnerStatus,
    transportResult: scenario.transportResult,
    responseStatus: scenario.responseStatus
  }));
  const matrixJson = JSON.stringify(compactScenarios);
  const matrixHash = ethers.keccak256(ethers.toUtf8Bytes(matrixJson));
  const matrixId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_HASH, matrixHash]
    )
  );

  return {
    version: 1,
    path: "phil-local-smart-account-deploy-submission-drill-matrix",
    localSubmissionDrillMatrixSource:
      "scripts/base/run-local-smart-account-deploy-drill-matrix.cjs",
    localSubmissionDrillSource:
      "scripts/base/run-local-smart-account-deploy-drill.cjs",
    consumedPath: smartAccountDeployAttemptRunner.path,
    proofType: smartAccountDeployAttemptRunner.proofType,
    payloadShape: smartAccountDeployAttemptRunner.payloadShape,
    localSubmissionDrillMatrixDomain: {
      label: LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_LABEL,
      hash: LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_HASH
    },
    validationChecks: {
      attemptRunnerPathValid: true,
      payloadShapeValid: true,
      drillRunnerReused: true,
      acceptedDrillExercised: true,
      rejectedDrillExercised: true,
      transportDrillExercised: true,
      continuityPreserved: true
    },
    localSubmissionDrillMatrixSummary: {
      ready: true,
      status: "local-submission-drill-matrix-complete",
      scenarioCount: compactScenarios.length,
      acceptedClassification: compactScenarios[0].classification,
      rejectedClassification: compactScenarios[1].classification,
      transportClassification: compactScenarios[2].classification,
      parityProven: true,
      generatedAt: now()
    },
    localSubmissionDrillMatrix: {
      matrixKind: LOCAL_SUBMISSION_DRILL_MATRIX_KIND,
      matrixId,
      matrixHash,
      timeoutMs: normalizedTimeoutMs,
      scenarios: compactScenarios
    },
    appLocalSubmissionDrillMatrix: {
      recipient: scenarios[0].continuity.canonicalRecipient,
      sender: scenarios[0].continuity.targetAddress,
      entryPointAddress: scenarios[0].continuity.entryPointAddress,
      chainId: scenarios[0].continuity.chainId,
      acceptedClassification: compactScenarios[0].classification,
      rejectedClassification: compactScenarios[1].classification,
      transportClassification: compactScenarios[2].classification,
      ready: true,
      status: "local-submission-drill-matrix-complete",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-attempt-runner") {
      parsed.smartAccountDeployAttemptRunnerPath = argv[i + 1];
      i += 1;
    } else if (arg === "--out-dir") {
      parsed.outDir = argv[i + 1];
      i += 1;
    } else if (arg === "--timeout-ms") {
      parsed.timeoutMs = argv[i + 1];
      i += 1;
    } else if (arg === "--out") {
      parsed.out = argv[i + 1];
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
      "  node scripts/base/run-local-smart-account-deploy-drill-matrix.cjs \\",
      "    --smart-account-deploy-attempt-runner <path> \\",
      `    [--out-dir ${LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_OUT_DIR}] \\`,
      `    [--timeout-ms ${LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_TIMEOUT_MS}] \\`,
      "    [--out ./proving/out/local_submission_drill_matrix/drill_matrix.json]"
    ].join("\n")
  );
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help) {
    printUsage();
    return 0;
  }
  if (!parsed.smartAccountDeployAttemptRunnerPath) {
    throw new Error("--smart-account-deploy-attempt-runner is required");
  }

  const outDir = parsed.outDir || LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_OUT_DIR;
  const outPath =
    parsed.out || path.join(path.resolve(outDir), "drill_matrix.json");
  const artifact = await runLocalSmartAccountDeployDrillMatrix({
    smartAccountDeployAttemptRunner: loadJson(
      path.resolve(parsed.smartAccountDeployAttemptRunnerPath)
    ),
    outDir,
    timeoutMs:
      parsed.timeoutMs || LOCAL_SUBMISSION_DRILL_MATRIX_DEFAULT_TIMEOUT_MS
  });

  writeJson(path.resolve(outPath), artifact);
  console.log(JSON.stringify(artifact, null, 2));
  return 0;
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exit(code);
    })
    .catch((error) => {
      console.error(String(error && error.message ? error.message : error));
      process.exit(1);
    });
}

module.exports = {
  LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_LABEL,
  LOCAL_SUBMISSION_DRILL_MATRIX_DOMAIN_HASH,
  LOCAL_SUBMISSION_DRILL_MATRIX_KIND,
  runLocalSmartAccountDeployDrillMatrix
};
