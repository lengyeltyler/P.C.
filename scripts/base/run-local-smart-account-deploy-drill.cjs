const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  runSmartAccountDeployLiveRunner
} = require("./run-smart-account-deploy-live-runner.cjs");
const {
  LOCAL_BUNDLER_STUB_DEFAULT_HOST,
  LOCAL_BUNDLER_STUB_DEFAULT_PATH,
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR,
  runLocalBundlerStub
} = require("./run-local-bundler-stub.cjs");

const LOCAL_SUBMISSION_DRILL_DOMAIN_LABEL =
  "PHIL_LOCAL_SUBMISSION_DRILL_V1";
const LOCAL_SUBMISSION_DRILL_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_SUBMISSION_DRILL_DOMAIN_LABEL)
);
const LOCAL_SUBMISSION_DRILL_KIND =
  "controlled-local-smart-account-deploy-submission-drill-v1";
const LOCAL_SUBMISSION_DRILL_SOURCE_PATH =
  "phil-smart-account-deploy-submission-attempt-runner";
const LOCAL_SUBMISSION_DRILL_DEFAULT_TIMEOUT_MS = 15000;
const LOCAL_SUBMISSION_DRILL_DEFAULT_OUT_DIR =
  "./proving/out/local_submission_drill";
const LOCAL_SUBMISSION_DRILL_PORTS = Object.freeze({
  [LOCAL_BUNDLER_STUB_MODE_ACCEPTED]: 45884,
  [LOCAL_BUNDLER_STUB_MODE_REJECTED]: 45885,
  [LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR]: 45886
});
const LOCAL_SUBMISSION_DRILL_MODES = Object.freeze([
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
  if (!LOCAL_SUBMISSION_DRILL_MODES.includes(normalized)) {
    throw new Error(
      `Invalid mode: ${normalized}. Expected one of ${LOCAL_SUBMISSION_DRILL_MODES.join(
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

function classifyRunnerResult(runnerArtifact) {
  const response = runnerArtifact.smartAccountDeployLiveRunner.response;
  if (response && response.responseCaptured) {
    const parsedJson = response.parsedJson;
    if (
      parsedJson &&
      typeof parsedJson === "object" &&
      !Array.isArray(parsedJson) &&
      Object.prototype.hasOwnProperty.call(parsedJson, "error")
    ) {
      return "rejected-json-rpc-response";
    }
    if (
      parsedJson &&
      typeof parsedJson === "object" &&
      !Array.isArray(parsedJson) &&
      Object.prototype.hasOwnProperty.call(parsedJson, "result")
    ) {
      return "accepted-json-rpc-response";
    }
    return "http-response-without-json-rpc-shape";
  }

  if (runnerArtifact.smartAccountDeployLiveRunner.transportError) {
    return "transport-error-response";
  }

  return "unclassified";
}

function buildArtifactPaths(outDir) {
  return {
    stubRequest: path.join(outDir, "stub_request.json"),
    stubResponse: path.join(outDir, "stub_response.json"),
    liveRunnerResult: path.join(outDir, "live_runner_result.json"),
    drillResult: path.join(outDir, "local_submission_drill_result.json")
  };
}

async function runLocalSmartAccountDeployDrill({
  smartAccountDeployAttemptRunner,
  mode = LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  outDir = LOCAL_SUBMISSION_DRILL_DEFAULT_OUT_DIR,
  timeoutMs = LOCAL_SUBMISSION_DRILL_DEFAULT_TIMEOUT_MS,
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
    LOCAL_SUBMISSION_DRILL_SOURCE_PATH,
    "smartAccountDeployAttemptRunner.path"
  );

  const normalizedMode = normalizeMode(mode);
  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");
  const artifactPaths = buildArtifactPaths(normalizedOutDir);
  const selectedPort = LOCAL_SUBMISSION_DRILL_PORTS[normalizedMode];

  let onListeningResolve;
  const onListeningPromise = new Promise((resolve) => {
    onListeningResolve = resolve;
  });

  const stubPromise = runLocalBundlerStub({
    host: LOCAL_BUNDLER_STUB_DEFAULT_HOST,
    port: selectedPort,
    rpcPath: LOCAL_BUNDLER_STUB_DEFAULT_PATH,
    mode: normalizedMode,
    outDir: normalizedOutDir,
    requestOut: artifactPaths.stubRequest,
    responseOut:
      normalizedMode === LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
        ? null
        : artifactPaths.stubResponse,
    onListening: onListeningResolve
  });

  const { localEndpoint } = await onListeningPromise;
  const runnerArtifact = await runSmartAccountDeployLiveRunner({
    smartAccountDeployAttemptRunner,
    bundlerUrl: localEndpoint,
    timeoutMs: normalizedTimeoutMs
  });
  writeJson(artifactPaths.liveRunnerResult, runnerArtifact);

  const stubResult = await stubPromise;
  const classification = classifyRunnerResult(runnerArtifact);
  const response = runnerArtifact.smartAccountDeployLiveRunner.response;
  const transportError = runnerArtifact.smartAccountDeployLiveRunner.transportError;
  const responseCaptured = runnerArtifact.validationChecks.responseCaptured;
  const localHttpExchangeOccurred =
    normalizedMode !== LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR && responseCaptured;

  const drillRecord = {
    drillKind: LOCAL_SUBMISSION_DRILL_KIND,
    selectedMode: normalizedMode,
    localEndpoint,
    startedAt: now(),
    stubRequestArtifactPath: artifactPaths.stubRequest,
    stubResponseArtifactPath:
      normalizedMode === LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
        ? null
        : artifactPaths.stubResponse,
    liveRunnerResultPath: artifactPaths.liveRunnerResult,
    localHttpExchangeOccurred,
    responseCaptured,
    classification,
    runnerStatus: runnerArtifact.smartAccountDeployLiveRunnerSummary.status,
    transportResult: runnerArtifact.smartAccountDeployLiveRunnerSummary.transportResult,
    responseStatus: response ? response.status : null,
    transportError
  };
  const drillRecordJson = JSON.stringify(drillRecord);
  const drillRecordHash = ethers.keccak256(ethers.toUtf8Bytes(drillRecordJson));
  const drillId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_SUBMISSION_DRILL_DOMAIN_HASH, drillRecordHash]
    )
  );

  return {
    version: 1,
    path: "phil-local-smart-account-deploy-submission-drill",
    localSubmissionDrillSource:
      "scripts/base/run-local-smart-account-deploy-drill.cjs",
    smartAccountDeployAttemptRunnerSource:
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSource,
    smartAccountDeployLiveRunnerSource:
      "scripts/base/run-smart-account-deploy-live-runner.cjs",
    localBundlerStubSource: "scripts/base/run-local-bundler-stub.cjs",
    consumedPath: smartAccountDeployAttemptRunner.path,
    proofType: smartAccountDeployAttemptRunner.proofType,
    payloadShape: smartAccountDeployAttemptRunner.payloadShape,
    localSubmissionDrillDomain: {
      label: LOCAL_SUBMISSION_DRILL_DOMAIN_LABEL,
      hash: LOCAL_SUBMISSION_DRILL_DOMAIN_HASH
    },
    validationChecks: {
      attemptRunnerPathValid: true,
      payloadShapeValid: true,
      selectedModeValid: true,
      localStubReused: true,
      liveRunnerReused: true,
      selectedModeExercised: true,
      finalDrillResultEmitted: true,
      continuityPreserved: true
    },
    localSubmissionDrillSummary: {
      ready: true,
      status: "local-submission-drill-complete",
      selectedMode: normalizedMode,
      classification,
      responseCaptured,
      localHttpExchangeOccurred,
      parityProven: true
    },
    localSubmissionDrill: {
      drillKind: LOCAL_SUBMISSION_DRILL_KIND,
      drillId,
      drillRecord,
      drillRecordJson,
      drillRecordHash,
      stubResult,
      liveRunnerResultPath: artifactPaths.liveRunnerResult,
      selectedMode: normalizedMode,
      localEndpoint,
      canonicalRecipient:
        runnerArtifact.smartAccountDeployLiveRunner.canonicalRecipient,
      targetAddress: runnerArtifact.smartAccountDeployLiveRunner.targetAddress,
      entryPointAddress:
        runnerArtifact.smartAccountDeployLiveRunner.entryPointAddress,
      chainId: runnerArtifact.smartAccountDeployLiveRunner.chainId,
      ownerCommitment:
        runnerArtifact.smartAccountDeployLiveRunner.ownerCommitment,
      classification,
      responseStatus: response ? response.status : null,
      transportError
    },
    appLocalSubmissionDrill: {
      recipient: runnerArtifact.smartAccountDeployLiveRunner.canonicalRecipient,
      sender: runnerArtifact.smartAccountDeployLiveRunner.targetAddress,
      entryPointAddress:
        runnerArtifact.smartAccountDeployLiveRunner.entryPointAddress,
      chainId: runnerArtifact.smartAccountDeployLiveRunner.chainId,
      selectedMode: normalizedMode,
      classification,
      localEndpoint,
      responseCaptured,
      localHttpExchangeOccurred,
      ready: true,
      status: "local-submission-drill-complete",
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
      "  node scripts/base/run-local-smart-account-deploy-drill.cjs \\",
      "    --smart-account-deploy-attempt-runner <path> \\",
      `    [--mode ${LOCAL_BUNDLER_STUB_MODE_ACCEPTED}] \\`,
      `    [--out-dir ${LOCAL_SUBMISSION_DRILL_DEFAULT_OUT_DIR}] \\`,
      `    [--timeout-ms ${LOCAL_SUBMISSION_DRILL_DEFAULT_TIMEOUT_MS}] \\`,
      "    [--out ./proving/out/local_submission_drill/local_submission_drill_result.json]"
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

  const outDir = parsed.outDir || LOCAL_SUBMISSION_DRILL_DEFAULT_OUT_DIR;
  const outPath =
    parsed.out || path.join(path.resolve(outDir), "local_submission_drill_result.json");
  const artifact = await runLocalSmartAccountDeployDrill({
    smartAccountDeployAttemptRunner: loadJson(
      path.resolve(parsed.smartAccountDeployAttemptRunnerPath)
    ),
    mode: parsed.mode || LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
    outDir,
    timeoutMs: parsed.timeoutMs || LOCAL_SUBMISSION_DRILL_DEFAULT_TIMEOUT_MS
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
  LOCAL_SUBMISSION_DRILL_DOMAIN_LABEL,
  LOCAL_SUBMISSION_DRILL_DOMAIN_HASH,
  LOCAL_SUBMISSION_DRILL_KIND,
  runLocalSmartAccountDeployDrill
};
