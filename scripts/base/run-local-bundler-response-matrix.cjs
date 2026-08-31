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

const LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_LABEL =
  "PHIL_LOCAL_BUNDLER_RESPONSE_MATRIX_V1";
const LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_LABEL)
);
const LOCAL_BUNDLER_RESPONSE_MATRIX_KIND =
  "controlled-local-bundler-response-matrix-runner-v1";
const LOCAL_BUNDLER_RESPONSE_MATRIX_SOURCE_PATH =
  "phil-smart-account-deploy-submission-attempt-runner";
const LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_TIMEOUT_MS = 15000;
const LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_OUT_DIR =
  "./proving/out/local_bundler_matrix";
const LOCAL_BUNDLER_RESPONSE_MATRIX_PORTS = Object.freeze({
  accepted: 45874,
  rejected: 45875,
  transport: 45876
});

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

function buildScenarioPaths(outDir, scenario) {
  return {
    request: path.join(outDir, `${scenario}_request.json`),
    response: path.join(outDir, `${scenario}_response.json`),
    runnerResult: path.join(outDir, `${scenario}_runner_result.json`)
  };
}

async function runScenario({
  scenarioName,
  stubMode,
  port,
  attemptRunnerArtifact,
  outDir,
  timeoutMs
}) {
  const paths = buildScenarioPaths(outDir, scenarioName);
  let onListeningResolve;
  let onListeningReject;
  const onListeningPromise = new Promise((resolve, reject) => {
    onListeningResolve = resolve;
    onListeningReject = reject;
  });

  const stubPromise = runLocalBundlerStub({
    host: LOCAL_BUNDLER_STUB_DEFAULT_HOST,
    port,
    rpcPath: LOCAL_BUNDLER_STUB_DEFAULT_PATH,
    mode: stubMode,
    outDir,
    requestOut: paths.request,
    responseOut:
      stubMode === LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR ? null : paths.response,
    onListening: onListeningResolve
  });

  let localEndpoint;
  try {
    ({ localEndpoint } = await onListeningPromise);
  } catch (error) {
    onListeningReject && onListeningReject(error);
    throw error;
  }

  const runnerArtifact = await runSmartAccountDeployLiveRunner({
    smartAccountDeployAttemptRunner: attemptRunnerArtifact,
    bundlerUrl: localEndpoint,
    timeoutMs
  });
  writeJson(paths.runnerResult, runnerArtifact);

  const stubResult = await stubPromise;
  const classification = classifyRunnerResult(runnerArtifact);
  const response = runnerArtifact.smartAccountDeployLiveRunner.response;
  const transportError = runnerArtifact.smartAccountDeployLiveRunner.transportError;

  return {
    scenarioName,
    mode: stubMode,
    localEndpoint,
    requestArtifactPath: paths.request,
    responseArtifactPath:
      stubMode === LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR ? null : paths.response,
    runnerResultPath: paths.runnerResult,
    stubRequestBodyHash: stubResult.requestBodyHash,
    stubResponseBodyHash: stubResult.responseBodyHash,
    runnerObserved: {
      summaryStatus: runnerArtifact.smartAccountDeployLiveRunnerSummary.status,
      transportResult: runnerArtifact.smartAccountDeployLiveRunnerSummary.transportResult,
      responseCaptured: runnerArtifact.validationChecks.responseCaptured,
      responseStatus: response ? response.status : null,
      jsonRpcResultPresent:
        !!response &&
        !!response.parsedJson &&
        Object.prototype.hasOwnProperty.call(response.parsedJson, "result"),
      jsonRpcErrorPresent:
        !!response &&
        !!response.parsedJson &&
        Object.prototype.hasOwnProperty.call(response.parsedJson, "error"),
      transportErrorName: transportError ? transportError.name : null,
      classification
    },
    continuity: {
      ownerCommitment:
        runnerArtifact.smartAccountDeployLiveRunner.ownerCommitment,
      canonicalRecipient:
        runnerArtifact.smartAccountDeployLiveRunner.canonicalRecipient,
      targetAddress: runnerArtifact.smartAccountDeployLiveRunner.targetAddress,
      entryPointAddress:
        runnerArtifact.smartAccountDeployLiveRunner.entryPointAddress,
      chainId: runnerArtifact.smartAccountDeployLiveRunner.chainId,
      payloadShape: runnerArtifact.payloadShape,
      proofType: runnerArtifact.proofType
    }
  };
}

async function runLocalBundlerResponseMatrix({
  smartAccountDeployAttemptRunner,
  outDir = LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_OUT_DIR,
  timeoutMs = LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_TIMEOUT_MS,
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
    LOCAL_BUNDLER_RESPONSE_MATRIX_SOURCE_PATH,
    "smartAccountDeployAttemptRunner.path"
  );

  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");

  const accepted = await runScenario({
    scenarioName: "accepted",
    stubMode: LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
    port: LOCAL_BUNDLER_RESPONSE_MATRIX_PORTS.accepted,
    attemptRunnerArtifact: smartAccountDeployAttemptRunner,
    outDir: normalizedOutDir,
    timeoutMs: normalizedTimeoutMs
  });
  const rejected = await runScenario({
    scenarioName: "rejected",
    stubMode: LOCAL_BUNDLER_STUB_MODE_REJECTED,
    port: LOCAL_BUNDLER_RESPONSE_MATRIX_PORTS.rejected,
    attemptRunnerArtifact: smartAccountDeployAttemptRunner,
    outDir: normalizedOutDir,
    timeoutMs: normalizedTimeoutMs
  });
  const transport = await runScenario({
    scenarioName: "transport",
    stubMode: LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR,
    port: LOCAL_BUNDLER_RESPONSE_MATRIX_PORTS.transport,
    attemptRunnerArtifact: smartAccountDeployAttemptRunner,
    outDir: normalizedOutDir,
    timeoutMs: normalizedTimeoutMs
  });

  const scenarios = [accepted, rejected, transport];
  for (const scenario of scenarios) {
    assertEqual(scenario.continuity.payloadShape, "[fact_high, fact_low]", `${scenario.scenarioName}.payloadShape`);
    assertEqual(scenario.continuity.proofType, "stwo-unlock-keccak-v1", `${scenario.scenarioName}.proofType`);
  }
  assertEqual(
    accepted.continuity.ownerCommitment,
    rejected.continuity.ownerCommitment,
    "accepted/rejected ownerCommitment"
  );
  assertEqual(
    accepted.continuity.ownerCommitment,
    transport.continuity.ownerCommitment,
    "accepted/transport ownerCommitment"
  );
  assertEqual(
    accepted.continuity.canonicalRecipient,
    rejected.continuity.canonicalRecipient,
    "accepted/rejected canonicalRecipient"
  );
  assertEqual(
    accepted.continuity.canonicalRecipient,
    transport.continuity.canonicalRecipient,
    "accepted/transport canonicalRecipient"
  );
  assertEqual(
    accepted.runnerObserved.classification,
    "accepted-json-rpc-response",
    "accepted classification"
  );
  assertEqual(
    rejected.runnerObserved.classification,
    "rejected-json-rpc-response",
    "rejected classification"
  );
  assertEqual(
    transport.runnerObserved.classification,
    "transport-error-response",
    "transport classification"
  );
  assertTrue(accepted.runnerObserved.responseCaptured, "accepted responseCaptured");
  assertTrue(rejected.runnerObserved.responseCaptured, "rejected responseCaptured");
  assertEqual(transport.runnerObserved.responseCaptured, false, "transport responseCaptured");

  const matrixScenarios = scenarios.map((scenario) => ({
    scenarioName: scenario.scenarioName,
    mode: scenario.mode,
    localEndpoint: scenario.localEndpoint,
    requestArtifactPath: scenario.requestArtifactPath,
    responseArtifactPath: scenario.responseArtifactPath,
    runnerResultPath: scenario.runnerResultPath,
    runnerObserved: scenario.runnerObserved
  }));
  const matrixJson = JSON.stringify(matrixScenarios);
  const matrixHash = ethers.keccak256(ethers.toUtf8Bytes(matrixJson));
  const matrixId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_HASH, matrixHash]
    )
  );

  return {
    version: 1,
    path: "phil-local-bundler-response-matrix",
    localBundlerResponseMatrixSource:
      "scripts/base/run-local-bundler-response-matrix.cjs",
    smartAccountDeployLiveRunnerSource:
      "scripts/base/run-smart-account-deploy-live-runner.cjs",
    localBundlerStubSource: "scripts/base/run-local-bundler-stub.cjs",
    consumedPath: smartAccountDeployAttemptRunner.path,
    proofType: smartAccountDeployAttemptRunner.proofType,
    payloadShape: smartAccountDeployAttemptRunner.payloadShape,
    localBundlerResponseMatrixDomain: {
      label: LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_LABEL,
      hash: LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_HASH
    },
    validationChecks: {
      attemptRunnerPathValid: true,
      payloadShapeValid: true,
      acceptedScenarioExercised: true,
      rejectedScenarioExercised: true,
      transportScenarioExercised: true,
      liveRunnerReused: true,
      localStubReused: true,
      continuityPreserved: true
    },
    localBundlerResponseMatrixSummary: {
      ready: true,
      status: "local-bundler-response-matrix-complete",
      scenarioCount: scenarios.length,
      acceptedClassification: accepted.runnerObserved.classification,
      rejectedClassification: rejected.runnerObserved.classification,
      transportClassification: transport.runnerObserved.classification,
      parityProven: true,
      generatedAt: now()
    },
    localBundlerResponseMatrix: {
      matrixKind: LOCAL_BUNDLER_RESPONSE_MATRIX_KIND,
      matrixId,
      matrixHash,
      timeoutMs: normalizedTimeoutMs,
      scenarios: matrixScenarios
    },
    appLocalBundlerResponseMatrix: {
      recipient: accepted.continuity.canonicalRecipient,
      sender: accepted.continuity.targetAddress,
      entryPointAddress: accepted.continuity.entryPointAddress,
      chainId: accepted.continuity.chainId,
      acceptedClassification: accepted.runnerObserved.classification,
      rejectedClassification: rejected.runnerObserved.classification,
      transportClassification: transport.runnerObserved.classification,
      ready: true,
      status: "local-bundler-response-matrix-complete",
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
      "  node scripts/base/run-local-bundler-response-matrix.cjs \\",
      "    --smart-account-deploy-attempt-runner <path> \\",
      `    [--out-dir ${LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_OUT_DIR}] \\`,
      `    [--timeout-ms ${LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_TIMEOUT_MS}] \\`,
      "    [--out ./proving/out/local_bundler_matrix/response_matrix.json]"
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

  const outDir = parsed.outDir || LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_OUT_DIR;
  const outPath =
    parsed.out || path.join(path.resolve(outDir), "response_matrix.json");
  const artifact = await runLocalBundlerResponseMatrix({
    smartAccountDeployAttemptRunner: loadJson(
      path.resolve(parsed.smartAccountDeployAttemptRunnerPath)
    ),
    outDir,
    timeoutMs:
      parsed.timeoutMs || LOCAL_BUNDLER_RESPONSE_MATRIX_DEFAULT_TIMEOUT_MS
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
  LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_LABEL,
  LOCAL_BUNDLER_RESPONSE_MATRIX_DOMAIN_HASH,
  LOCAL_BUNDLER_RESPONSE_MATRIX_KIND,
  runLocalBundlerResponseMatrix
};
