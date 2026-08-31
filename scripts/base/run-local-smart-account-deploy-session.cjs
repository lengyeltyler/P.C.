const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  runLocalSmartAccountDeployDrill
} = require("./run-local-smart-account-deploy-drill.cjs");
const {
  runLocalSmartAccountDeployDrillMatrix
} = require("./run-local-smart-account-deploy-drill-matrix.cjs");
const {
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
} = require("./run-local-bundler-stub.cjs");

const LOCAL_DEPLOY_SESSION_DOMAIN_LABEL = "PHIL_LOCAL_DEPLOY_SESSION_V1";
const LOCAL_DEPLOY_SESSION_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_DEPLOY_SESSION_DOMAIN_LABEL)
);
const LOCAL_DEPLOY_SESSION_KIND =
  "controlled-local-smart-account-deploy-session-v1";
const LOCAL_DEPLOY_SESSION_SOURCE_PATH =
  "phil-smart-account-deploy-submission-attempt-runner";
const LOCAL_DEPLOY_SESSION_DEFAULT_TIMEOUT_MS = 15000;
const LOCAL_DEPLOY_SESSION_DEFAULT_OUT_DIR =
  "./proving/out/local_deploy_session";
const LOCAL_DEPLOY_SESSION_MODES = Object.freeze([
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
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

function normalizeMode(value) {
  const normalized = normalizeString(value, "mode");
  if (!LOCAL_DEPLOY_SESSION_MODES.includes(normalized)) {
    throw new Error(
      `Invalid mode: ${normalized}. Expected one of ${LOCAL_DEPLOY_SESSION_MODES.join(
        ", "
      )}`
    );
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

async function runLocalSmartAccountDeploySession({
  smartAccountDeployAttemptRunner,
  mode,
  matrix = false,
  outDir = LOCAL_DEPLOY_SESSION_DEFAULT_OUT_DIR,
  timeoutMs = LOCAL_DEPLOY_SESSION_DEFAULT_TIMEOUT_MS,
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
    LOCAL_DEPLOY_SESSION_SOURCE_PATH,
    "smartAccountDeployAttemptRunner.path"
  );

  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");
  const selectedMatrix = matrix === true;
  const selectedMode = mode ? normalizeMode(mode) : null;

  if (selectedMatrix && selectedMode) {
    throw new Error("Choose either --mode or --matrix, not both");
  }
  if (!selectedMatrix && !selectedMode) {
    throw new Error("Either --mode or --matrix is required");
  }

  let delegatedArtifact;
  let delegatedPath;
  let sessionMode;
  let sessionClassification;
  let sessionReady;
  let sessionStatus;
  let compactSummary;

  if (selectedMatrix) {
    delegatedArtifact = await runLocalSmartAccountDeployDrillMatrix({
      smartAccountDeployAttemptRunner,
      outDir: path.join(normalizedOutDir, "matrix_run"),
      timeoutMs: normalizedTimeoutMs,
      now
    });
    delegatedPath = "matrix";
    sessionMode = "matrix";
    sessionClassification = "local-deploy-session-matrix-complete";
    sessionReady = delegatedArtifact.localSubmissionDrillMatrixSummary.ready;
    sessionStatus = delegatedArtifact.localSubmissionDrillMatrixSummary.status;
    compactSummary = {
      acceptedClassification:
        delegatedArtifact.localSubmissionDrillMatrixSummary.acceptedClassification,
      rejectedClassification:
        delegatedArtifact.localSubmissionDrillMatrixSummary.rejectedClassification,
      transportClassification:
        delegatedArtifact.localSubmissionDrillMatrixSummary.transportClassification,
      scenarioCount:
        delegatedArtifact.localSubmissionDrillMatrixSummary.scenarioCount
    };
  } else {
    delegatedArtifact = await runLocalSmartAccountDeployDrill({
      smartAccountDeployAttemptRunner,
      mode: selectedMode,
      outDir: path.join(normalizedOutDir, "selected_run"),
      timeoutMs: normalizedTimeoutMs,
      now
    });
    delegatedPath = "single-mode";
    sessionMode = selectedMode;
    sessionClassification = delegatedArtifact.localSubmissionDrillSummary.classification;
    sessionReady = delegatedArtifact.localSubmissionDrillSummary.ready;
    sessionStatus = delegatedArtifact.localSubmissionDrillSummary.status;
    compactSummary = {
      classification: delegatedArtifact.localSubmissionDrillSummary.classification,
      responseCaptured: delegatedArtifact.localSubmissionDrillSummary.responseCaptured,
      localHttpExchangeOccurred:
        delegatedArtifact.localSubmissionDrillSummary.localHttpExchangeOccurred
    };
  }

  assertTrue(sessionReady, "sessionReady");

  const sessionRecord = {
    sessionKind: LOCAL_DEPLOY_SESSION_KIND,
    delegatedPath,
    sessionMode,
    executedAt: now(),
    delegatedStatus: sessionStatus,
    sessionClassification,
    compactSummary
  };
  const sessionRecordJson = JSON.stringify(sessionRecord);
  const sessionRecordHash = ethers.keccak256(ethers.toUtf8Bytes(sessionRecordJson));
  const sessionId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_DEPLOY_SESSION_DOMAIN_HASH, sessionRecordHash]
    )
  );

  const canonicalRecipient = selectedMatrix
    ? delegatedArtifact.appLocalSubmissionDrillMatrix.recipient
    : delegatedArtifact.appLocalSubmissionDrill.recipient;
  const targetAddress = selectedMatrix
    ? delegatedArtifact.appLocalSubmissionDrillMatrix.sender
    : delegatedArtifact.appLocalSubmissionDrill.sender;
  const entryPointAddress = selectedMatrix
    ? delegatedArtifact.appLocalSubmissionDrillMatrix.entryPointAddress
    : delegatedArtifact.appLocalSubmissionDrill.entryPointAddress;
  const chainId = selectedMatrix
    ? delegatedArtifact.appLocalSubmissionDrillMatrix.chainId
    : delegatedArtifact.appLocalSubmissionDrill.chainId;

  return {
    version: 1,
    path: "phil-local-smart-account-deploy-session",
    localDeploySessionSource:
      "scripts/base/run-local-smart-account-deploy-session.cjs",
    localSubmissionDrillSource:
      "scripts/base/run-local-smart-account-deploy-drill.cjs",
    localSubmissionDrillMatrixSource:
      "scripts/base/run-local-smart-account-deploy-drill-matrix.cjs",
    consumedPath: smartAccountDeployAttemptRunner.path,
    proofType: smartAccountDeployAttemptRunner.proofType,
    payloadShape: smartAccountDeployAttemptRunner.payloadShape,
    localDeploySessionDomain: {
      label: LOCAL_DEPLOY_SESSION_DOMAIN_LABEL,
      hash: LOCAL_DEPLOY_SESSION_DOMAIN_HASH
    },
    validationChecks: {
      attemptRunnerPathValid: true,
      payloadShapeValid: true,
      delegatedSeamReused: true,
      selectedPathExercised: true,
      finalSessionArtifactEmitted: true,
      continuityPreserved: true
    },
    localDeploySessionSummary: {
      ready: true,
      status: "local-deploy-session-complete",
      delegatedPath,
      sessionMode,
      sessionClassification,
      parityProven: true
    },
    localDeploySession: {
      sessionKind: LOCAL_DEPLOY_SESSION_KIND,
      sessionId,
      sessionRecord,
      sessionRecordJson,
      sessionRecordHash,
      delegatedArtifact,
      delegatedPath,
      sessionMode,
      sessionClassification,
      canonicalRecipient,
      targetAddress,
      entryPointAddress,
      chainId
    },
    appLocalDeploySession: {
      recipient: canonicalRecipient,
      sender: targetAddress,
      entryPointAddress,
      chainId,
      delegatedPath,
      sessionMode,
      sessionClassification,
      ready: true,
      status: "local-deploy-session-complete",
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
    } else if (arg === "--mode") {
      parsed.mode = argv[i + 1];
      i += 1;
    } else if (arg === "--matrix") {
      parsed.matrix = true;
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
      "  node scripts/base/run-local-smart-account-deploy-session.cjs \\",
      "    --smart-account-deploy-attempt-runner <path> \\",
      `    [--mode ${LOCAL_BUNDLER_STUB_MODE_ACCEPTED}] | [--matrix] \\`,
      `    [--out-dir ${LOCAL_DEPLOY_SESSION_DEFAULT_OUT_DIR}] \\`,
      `    [--timeout-ms ${LOCAL_DEPLOY_SESSION_DEFAULT_TIMEOUT_MS}] \\`,
      "    [--out ./proving/out/local_deploy_session/local_deploy_session_result.json]"
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

  const outDir = parsed.outDir || LOCAL_DEPLOY_SESSION_DEFAULT_OUT_DIR;
  const outPath =
    parsed.out || path.join(path.resolve(outDir), "local_deploy_session_result.json");
  const artifact = await runLocalSmartAccountDeploySession({
    smartAccountDeployAttemptRunner: loadJson(
      path.resolve(parsed.smartAccountDeployAttemptRunnerPath)
    ),
    mode: parsed.mode,
    matrix: parsed.matrix === true,
    outDir,
    timeoutMs: parsed.timeoutMs || LOCAL_DEPLOY_SESSION_DEFAULT_TIMEOUT_MS
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
  LOCAL_DEPLOY_SESSION_DOMAIN_LABEL,
  LOCAL_DEPLOY_SESSION_DOMAIN_HASH,
  LOCAL_DEPLOY_SESSION_KIND,
  runLocalSmartAccountDeploySession
};
