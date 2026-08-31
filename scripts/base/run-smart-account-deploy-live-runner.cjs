const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_V1";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_KIND =
  "erc4337-smart-account-deploy-live-submission-runner-v1";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_ACTION =
  "perform-exactly-one-configured-bundler-rpc-call";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_STAGE =
  "live-submission-attempted-once";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_SOURCE_KIND =
  "erc4337-smart-account-deploy-submission-attempt-runner-v1";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_SOURCE_STATUS =
  "smart-account-deploy-attempt-runner-ready";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_REQUEST_METHOD = "POST";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_RPC_METHOD = "eth_sendUserOperation";
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DEFAULT_TIMEOUT_MS = 15000;
const SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_BUNDLER_ENV_KEYS = Object.freeze([
  "PHIL_BASE_BUNDLER_URL",
  "BASE_BUNDLER_RPC_URL",
  "SMART_ACCOUNT_DEPLOY_BUNDLER_URL",
  "BUNDLER_RPC_URL"
]);

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function writeJson(jsonPath, value) {
  fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(value, null, 2)}\n`);
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

function assertFalse(value, label) {
  if (value !== false) {
    throw new Error(`${label} must be false`);
  }
}

function normalizeBytes(value, label) {
  try {
    return ethers.hexlify(ethers.getBytes(value)).toLowerCase();
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function normalizeHex32(value, label) {
  const normalized = normalizeBytes(value, label);
  if (normalized.length !== 66) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  return normalized;
}

function normalizeAddress(value, label) {
  try {
    return ethers.getAddress(value);
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function normalizeString(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    throw new Error(`Invalid ${label}: <empty>`);
  }
  return normalized;
}

function normalizeBoolean(value, label) {
  if (value !== true && value !== false) {
    throw new Error(`Invalid ${label}: ${String(value)}`);
  }
  return value;
}

function normalizeUintString(value, label) {
  const normalized = String(value || "").trim();
  if (!/^[0-9]+$/.test(normalized)) {
    throw new Error(`Invalid ${label}: ${normalized || "<empty>"}`);
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

function normalizeConfiguredBundlerUrl(value) {
  const raw = normalizeString(value, "bundlerUrl");
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`Invalid bundlerUrl: ${raw}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("bundlerUrl must use http or https");
  }
  return parsed.toString();
}

function resolveConfiguredBundlerUrl({ bundlerUrl, env = process.env }) {
  if (bundlerUrl) {
    return {
      url: normalizeConfiguredBundlerUrl(bundlerUrl),
      source: "cli"
    };
  }

  for (const key of SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_BUNDLER_ENV_KEYS) {
    if (env && env[key]) {
      return {
        url: normalizeConfiguredBundlerUrl(env[key]),
        source: `env:${key}`
      };
    }
  }

  throw new Error(
    `bundler URL is required via --bundler-url or one of ${SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_BUNDLER_ENV_KEYS.join(
      ", "
    )}`
  );
}

function normalizeHeaders(headers, label) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    throw new Error(`${label} is required`);
  }

  const normalized = {};
  for (const [key, value] of Object.entries(headers)) {
    normalized[String(key).toLowerCase()] = normalizeString(
      value,
      `${label}.${String(key)}`
    );
  }
  return normalized;
}

function ensureObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function parseJsonMaybe(raw) {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function makeResponseHeaders(headers) {
  const responseHeaders = {};
  for (const [key, value] of headers.entries()) {
    responseHeaders[key] = value;
  }
  return responseHeaders;
}

function makeTransportError(error) {
  return {
    name: String(error && error.name ? error.name : "Error"),
    message: String(error && error.message ? error.message : error),
    code:
      error && typeof error === "object" && "code" in error
        ? String(error.code)
        : null,
    cause:
      error && error.cause && typeof error.cause === "object"
        ? {
            name: String(error.cause.name || "Error"),
            message: String(error.cause.message || error.cause),
            code:
              "code" in error.cause && error.cause.code
                ? String(error.cause.code)
                : null
          }
        : null
  };
}

function buildOutboundHeaders({ sourceHeaders, configuredBundlerUrl, proofType }) {
  const parsed = new URL(configuredBundlerUrl);
  const endpointUrlHash = ethers.keccak256(ethers.toUtf8Bytes(configuredBundlerUrl));
  const headers = {
    ...sourceHeaders,
    accept: sourceHeaders.accept || "application/json",
    "content-type": sourceHeaders["content-type"] || "application/json",
    host: parsed.host,
    origin: parsed.origin,
    "x-phil-proof-type": proofType,
    "x-phil-live-runner": SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_KIND,
    "x-phil-configured-bundler-url-hash": endpointUrlHash,
    "x-phil-endpoint-url-hash": endpointUrlHash
  };

  return Object.fromEntries(
    Object.entries(headers)
      .filter(([, value]) => value !== undefined && value !== null && value !== "")
      .sort(([left], [right]) => left.localeCompare(right))
  );
}

function validateAttemptRunnerSource(smartAccountDeployAttemptRunner) {
  if (!smartAccountDeployAttemptRunner || typeof smartAccountDeployAttemptRunner !== "object") {
    throw new Error("smartAccountDeployAttemptRunner is required");
  }

  assertEqual(
    smartAccountDeployAttemptRunner.path,
    "phil-smart-account-deploy-submission-attempt-runner",
    "smartAccountDeployAttemptRunner.path"
  );
  assertEqual(
    smartAccountDeployAttemptRunner.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployAttemptRunner.payloadShape"
  );

  const validationChecks = ensureObject(
    smartAccountDeployAttemptRunner.validationChecks,
    "smartAccountDeployAttemptRunner.validationChecks"
  );
  assertTrue(
    validationChecks.smartAccountDeployDispatchAttemptPathValid,
    "validationChecks.smartAccountDeployDispatchAttemptPathValid"
  );
  assertTrue(validationChecks.payloadShapeValid, "validationChecks.payloadShapeValid");
  assertTrue(
    validationChecks.upstreamSmartAccountDeployDispatchAttemptValid,
    "validationChecks.upstreamSmartAccountDeployDispatchAttemptValid"
  );
  assertTrue(
    validationChecks.localNoSendRunnerStepExecuted,
    "validationChecks.localNoSendRunnerStepExecuted"
  );

  const summary = ensureObject(
    smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSummary,
    "smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSummary"
  );
  assertTrue(summary.ready, "smartAccountDeployAttemptRunnerSummary.ready");
  assertEqual(
    summary.status,
    SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_SOURCE_STATUS,
    "smartAccountDeployAttemptRunnerSummary.status"
  );
  assertFalse(
    summary.networkSubmissionPerformed,
    "smartAccountDeployAttemptRunnerSummary.networkSubmissionPerformed"
  );
  assertTrue(
    summary.parityProven,
    "smartAccountDeployAttemptRunnerSummary.parityProven"
  );

  const runner = ensureObject(
    smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner,
    "smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunner"
  );
  const appRunner = ensureObject(
    smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner,
    "smartAccountDeployAttemptRunner.appSmartAccountDeployAttemptRunner"
  );

  const normalized = {
    proofType: normalizeString(smartAccountDeployAttemptRunner.proofType, "proofType"),
    payloadShape: smartAccountDeployAttemptRunner.payloadShape,
    ownerCommitment: normalizeHex32(runner.ownerCommitment, "ownerCommitment"),
    consumerDataHash: normalizeHex32(runner.consumerDataHash, "consumerDataHash"),
    canonicalRecipient: normalizeAddress(runner.canonicalRecipient, "canonicalRecipient"),
    walletId: normalizeHex32(runner.walletId, "walletId"),
    targetId: normalizeHex32(runner.targetId, "targetId"),
    targetAddress: normalizeAddress(runner.targetAddress, "targetAddress"),
    entryPointAddress: normalizeAddress(runner.entryPointAddress, "entryPointAddress"),
    chainId: normalizeUintString(runner.chainId, "chainId"),
    userOpHash: normalizeHex32(runner.userOpHash, "userOpHash"),
    dispatchAttemptId: normalizeHex32(runner.dispatchAttemptId, "dispatchAttemptId"),
    dispatchAttemptHash: normalizeHex32(
      runner.dispatchAttemptHash,
      "dispatchAttemptHash"
    ),
    runnerKind: normalizeString(runner.runnerKind, "runnerKind"),
    upstreamRunnerId: normalizeHex32(runner.runnerId, "runnerId"),
    localPreSendExecutionRecordHash: normalizeHex32(
      runner.localPreSendExecutionRecordHash,
      "localPreSendExecutionRecordHash"
    ),
    request: ensureObject(runner.request, "runner.request"),
    requestHash: normalizeHex32(runner.requestHash, "runner.requestHash"),
    requestBytes: normalizeBytes(runner.requestBytes, "runner.requestBytes"),
    appRecipient: normalizeAddress(appRunner.recipient, "appRunner.recipient"),
    appSender: normalizeAddress(appRunner.sender, "appRunner.sender"),
    appStatus: normalizeString(appRunner.status, "appRunner.status"),
    appReadyForLiveCall: normalizeBoolean(
      appRunner.readyForLiveCall,
      "appRunner.readyForLiveCall"
    ),
    appLiveNetworkCallPerformed: normalizeBoolean(
      appRunner.liveNetworkCallPerformed,
      "appRunner.liveNetworkCallPerformed"
    ),
    appNetworkSubmissionPerformed: normalizeBoolean(
      appRunner.networkSubmissionPerformed,
      "appRunner.networkSubmissionPerformed"
    ),
    appReady: normalizeBoolean(appRunner.ready, "appRunner.ready"),
    appParityProven: normalizeBoolean(appRunner.parityProven, "appRunner.parityProven")
  };

  assertEqual(
    normalized.runnerKind,
    SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_SOURCE_KIND,
    "runner.runnerKind"
  );
  assertEqual(normalized.request.method, SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_REQUEST_METHOD, "request.method");
  assertEqual(
    ensureObject(normalized.request.body, "request.body").method,
    SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_RPC_METHOD,
    "request.body.method"
  );
  assertEqual(
    normalizeAddress(normalized.request.body.params[0].sender, "request.body.params[0].sender").toLowerCase(),
    normalized.targetAddress.toLowerCase(),
    "request.body.params[0].sender/targetAddress"
  );
  assertEqual(
    normalizeAddress(normalized.request.body.params[1], "request.body.params[1]").toLowerCase(),
    normalized.entryPointAddress.toLowerCase(),
    "request.body.params[1]/entryPointAddress"
  );
  assertEqual(
    normalized.appRecipient.toLowerCase(),
    normalized.canonicalRecipient.toLowerCase(),
    "appRunner.recipient/canonicalRecipient"
  );
  assertEqual(
    normalized.appSender.toLowerCase(),
    normalized.targetAddress.toLowerCase(),
    "appRunner.sender/targetAddress"
  );
  assertTrue(normalized.appReady, "appRunner.ready");
  assertEqual(
    normalized.appStatus,
    "smart-account-deploy-attempt-runner-ready",
    "appRunner.status"
  );
  assertTrue(normalized.appReadyForLiveCall, "appRunner.readyForLiveCall");
  assertFalse(
    normalized.appLiveNetworkCallPerformed,
    "appRunner.liveNetworkCallPerformed"
  );
  assertFalse(
    normalized.appNetworkSubmissionPerformed,
    "appRunner.networkSubmissionPerformed"
  );
  assertTrue(normalized.appParityProven, "appRunner.parityProven");

  const requestJson = JSON.stringify(normalized.request);
  const requestBytes = ethers.hexlify(ethers.toUtf8Bytes(requestJson));
  const requestHash = ethers.keccak256(ethers.toUtf8Bytes(requestJson));
  assertEqual(requestBytes, normalized.requestBytes, "requestBytes");
  assertEqual(requestHash, normalized.requestHash, "requestHash");

  return normalized;
}

async function runSmartAccountDeployLiveRunner({
  smartAccountDeployAttemptRunner,
  bundlerUrl,
  timeoutMs = SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DEFAULT_TIMEOUT_MS,
  fetchImpl = globalThis.fetch,
  env = process.env,
  now = () => new Date().toISOString()
}) {
  if (typeof fetchImpl !== "function") {
    throw new Error("fetch is required for live submission");
  }

  const source = validateAttemptRunnerSource(smartAccountDeployAttemptRunner);
  const configuredBundler = resolveConfiguredBundlerUrl({
    bundlerUrl,
    env
  });
  const configuredBundlerUrl = configuredBundler.url;
  const configuredBundlerSource = configuredBundler.source;
  const normalizedTimeoutMs = normalizePositiveInteger(timeoutMs, "timeoutMs");
  const sourceHeaders = normalizeHeaders(source.request.headers, "source.request.headers");
  const outboundHeaders = buildOutboundHeaders({
    sourceHeaders,
    configuredBundlerUrl,
    proofType: source.proofType
  });
  const outboundBody = source.request.body;
  const outboundBodyJson = JSON.stringify(outboundBody);
  const outboundBodyBytes = ethers.hexlify(ethers.toUtf8Bytes(outboundBodyJson));
  const outboundBodyHash = ethers.keccak256(ethers.toUtf8Bytes(outboundBodyJson));
  const outboundRequest = {
    url: configuredBundlerUrl,
    method: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_REQUEST_METHOD,
    headers: outboundHeaders,
    body: outboundBody
  };
  const outboundRequestJson = JSON.stringify(outboundRequest);
  const outboundRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(outboundRequestJson)
  );
  const outboundRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(outboundRequestJson)
  );
  const configuredBundlerUrlHash = ethers.keccak256(
    ethers.toUtf8Bytes(configuredBundlerUrl)
  );
  const liveRunnerId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_HASH,
        source.targetId,
        source.upstreamRunnerId,
        configuredBundlerUrlHash,
        outboundRequestHash
      ]
    )
  );
  const attemptedAt = now();

  let responseRecord = null;
  let transportError = null;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), normalizedTimeoutMs);
  try {
    const response = await fetchImpl(configuredBundlerUrl, {
      method: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_REQUEST_METHOD,
      headers: outboundHeaders,
      body: outboundBodyJson,
      signal: controller.signal,
      redirect: "manual"
    });
    const rawResponseBody = await response.text();
    const rawResponseBodyBytes = ethers.hexlify(
      ethers.toUtf8Bytes(rawResponseBody)
    );
    const rawResponseBodyHash = ethers.keccak256(
      ethers.toUtf8Bytes(rawResponseBody)
    );
    const parsedJson = parseJsonMaybe(rawResponseBody);
    responseRecord = {
      responseCaptured: true,
      status: response.status,
      statusText: response.statusText,
      ok: response.ok,
      headers: makeResponseHeaders(response.headers),
      rawResponseBody,
      rawResponseBodyBytes,
      rawResponseBodyHash,
      parsedJson
    };
  } catch (error) {
    transportError = makeTransportError(error);
  } finally {
    clearTimeout(timeout);
  }

  const transportResult = responseRecord ? "http-response" : "transport-error";
  const liveSubmissionRecord = {
    liveRunnerId,
    runnerKind: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_KIND,
    runnerAction: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_ACTION,
    runnerStage: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_STAGE,
    attemptedAt,
    configuredBundlerUrl,
    configuredBundlerSource,
    configuredBundlerUrlHash,
    timeoutMs: normalizedTimeoutMs,
    callCount: 1,
    retriesPerformed: 0,
    pollingPerformed: false,
    receiptFollowed: false,
    outboundRequest,
    response: responseRecord,
    transportError
  };
  const liveSubmissionRecordJson = JSON.stringify(liveSubmissionRecord);
  const liveSubmissionRecordBytes = ethers.hexlify(
    ethers.toUtf8Bytes(liveSubmissionRecordJson)
  );
  const liveSubmissionRecordHash = ethers.keccak256(
    ethers.toUtf8Bytes(liveSubmissionRecordJson)
  );

  return {
    version: 1,
    path: "phil-smart-account-deploy-live-submission-runner",
    smartAccountDeployLiveRunnerSource:
      "scripts/base/run-smart-account-deploy-live-runner.cjs",
    smartAccountDeployAttemptRunnerSource:
      smartAccountDeployAttemptRunner.smartAccountDeployAttemptRunnerSource,
    consumedPath: smartAccountDeployAttemptRunner.path,
    proofType: smartAccountDeployAttemptRunner.proofType,
    payloadShape: smartAccountDeployAttemptRunner.payloadShape,
    smartAccountDeployLiveRunnerDomain: {
      label: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployAttemptRunnerPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployAttemptRunnerValid: true,
      outboundRequestFormed: true,
      exactlyOneRpcCallAttempted: true,
      responseCaptured: responseRecord !== null
    },
    smartAccountDeployLiveRunnerSummary: {
      ready: responseRecord !== null,
      status: responseRecord
        ? "smart-account-deploy-live-runner-response-captured"
        : "smart-account-deploy-live-runner-transport-error",
      transportResult,
      exactlyOneRpcCallAttempted: true,
      responseCaptured: responseRecord !== null,
      networkSubmissionPerformed: true,
      retriesPerformed: 0,
      pollingPerformed: false,
      parityProven: true
    },
    smartAccountDeployLiveRunner: {
      ownerCommitment: source.ownerCommitment,
      consumerDataHash: source.consumerDataHash,
      canonicalRecipient: source.canonicalRecipient,
      walletId: source.walletId,
      targetId: source.targetId,
      targetAddress: source.targetAddress,
      entryPointAddress: source.entryPointAddress,
      chainId: source.chainId,
      userOpHash: source.userOpHash,
      dispatchAttemptId: source.dispatchAttemptId,
      dispatchAttemptHash: source.dispatchAttemptHash,
      sourceRunnerKind: source.runnerKind,
      sourceRunnerId: source.upstreamRunnerId,
      sourceLocalPreSendExecutionRecordHash:
        source.localPreSendExecutionRecordHash,
      liveRunnerKind: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_KIND,
      liveRunnerId,
      configuredBundlerUrl,
      configuredBundlerSource,
      configuredBundlerUrlHash,
      outboundRequest,
      outboundRequestJson,
      outboundRequestBytes,
      outboundRequestHash,
      outboundBodyJson,
      outboundBodyBytes,
      outboundBodyHash,
      response: responseRecord,
      transportError,
      liveSubmissionRecord,
      liveSubmissionRecordJson,
      liveSubmissionRecordBytes,
      liveSubmissionRecordHash
    },
    appSmartAccountDeployLiveRunner: {
      recipient: source.canonicalRecipient,
      sender: source.targetAddress,
      entryPointAddress: source.entryPointAddress,
      chainId: source.chainId,
      configuredBundlerUrl,
      configuredBundlerSource,
      requestMethod: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_REQUEST_METHOD,
      rpcMethod: SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_RPC_METHOD,
      liveRunnerId,
      liveSubmissionRecordHash,
      transportResult,
      responseCaptured: responseRecord !== null,
      responseStatus: responseRecord ? responseRecord.status : null,
      exactlyOneRpcCallAttempted: true,
      networkSubmissionPerformed: true,
      retriesPerformed: 0,
      pollingPerformed: false,
      ready: responseRecord !== null,
      status: responseRecord
        ? "smart-account-deploy-live-runner-response-captured"
        : "smart-account-deploy-live-runner-transport-error",
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
    } else if (arg === "--bundler-url") {
      parsed.bundlerUrl = argv[i + 1];
      i += 1;
    } else if (arg === "--timeout-ms") {
      parsed.timeoutMs = argv[i + 1];
      i += 1;
    } else if (arg === "--out") {
      parsed.out = argv[i + 1];
      i += 1;
    } else if (arg === "--i-understand-this-performs-one-live-call") {
      parsed.liveOptIn = true;
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
      "  node scripts/base/run-smart-account-deploy-live-runner.cjs \\",
      "    --smart-account-deploy-attempt-runner <path> \\",
      "    [--bundler-url <explicit-bundler-url>] \\",
      "    --i-understand-this-performs-one-live-call \\",
      "    [--timeout-ms 15000] [--out <path>]",
      "",
      `Configured URL fallback env vars: ${SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_BUNDLER_ENV_KEYS.join(
        ", "
      )}`
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
  if (!parsed.liveOptIn) {
    throw new Error(
      "--i-understand-this-performs-one-live-call is required for live submission"
    );
  }

  const artifact = await runSmartAccountDeployLiveRunner({
    smartAccountDeployAttemptRunner: loadJson(
      path.resolve(parsed.smartAccountDeployAttemptRunnerPath)
    ),
    bundlerUrl: parsed.bundlerUrl,
    timeoutMs: parsed.timeoutMs || SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DEFAULT_TIMEOUT_MS
  });

  if (parsed.out) {
    writeJson(path.resolve(parsed.out), artifact);
  } else {
    console.log(JSON.stringify(artifact, null, 2));
  }

  return artifact.validationChecks.responseCaptured ? 0 : 2;
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
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_KIND,
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_ACTION,
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_STAGE,
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_DEFAULT_TIMEOUT_MS,
  SMART_ACCOUNT_DEPLOY_LIVE_RUNNER_BUNDLER_ENV_KEYS,
  resolveConfiguredBundlerUrl,
  runSmartAccountDeployLiveRunner
};
