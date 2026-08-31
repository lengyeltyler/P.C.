const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { ethers } = require("ethers");

const LOCAL_BUNDLER_STUB_DOMAIN_LABEL = "PHIL_LOCAL_BUNDLER_STUB_V1";
const LOCAL_BUNDLER_STUB_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_BUNDLER_STUB_DOMAIN_LABEL)
);
const LOCAL_BUNDLER_STUB_KIND =
  "controlled-local-smart-account-bundler-stub-v1";
const LOCAL_BUNDLER_STUB_RPC_METHOD = "eth_sendUserOperation";
const LOCAL_BUNDLER_STUB_REQUEST_METHOD = "POST";
const LOCAL_BUNDLER_STUB_DEFAULT_HOST = "127.0.0.1";
const LOCAL_BUNDLER_STUB_DEFAULT_PORT = 45873;
const LOCAL_BUNDLER_STUB_DEFAULT_PATH = "/rpc";
const LOCAL_BUNDLER_STUB_MODE_ACCEPTED = "accepted";
const LOCAL_BUNDLER_STUB_MODE_REJECTED = "rejected";
const LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR = "transport-error";
const LOCAL_BUNDLER_STUB_MODES = Object.freeze([
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
]);
const LOCAL_BUNDLER_STUB_SUCCESS_STATUS = 200;

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

function normalizeHost(value) {
  return normalizeString(value, "host");
}

function normalizePort(value) {
  const parsed = Number.parseInt(String(value || ""), 10);
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 65535) {
    throw new Error(`Invalid port: ${String(value || "").trim() || "<empty>"}`);
  }
  return parsed;
}

function normalizeRpcPath(value) {
  const normalized = normalizeString(value, "rpcPath");
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function normalizeMode(value) {
  const normalized = normalizeString(value, "mode");
  if (!LOCAL_BUNDLER_STUB_MODES.includes(normalized)) {
    throw new Error(
      `Invalid mode: ${normalized}. Expected one of ${LOCAL_BUNDLER_STUB_MODES.join(
        ", "
      )}`
    );
  }
  return normalized;
}

function parseJsonOrNull(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function makeRawBodyBytes(rawBody) {
  return ethers.hexlify(ethers.toUtf8Bytes(rawBody));
}

function makeRawBodyHash(rawBody) {
  return ethers.keccak256(ethers.toUtf8Bytes(rawBody));
}

function buildDeterministicJsonRpcResult(rawRequestBody) {
  const requestBodyHash = makeRawBodyHash(rawRequestBody);
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_BUNDLER_STUB_DOMAIN_HASH, requestBodyHash]
    )
  );
}

function buildSuccessResponse(parsedRequest, rawRequestBody) {
  return {
    jsonrpc: "2.0",
    id:
      parsedRequest &&
      typeof parsedRequest === "object" &&
      Object.prototype.hasOwnProperty.call(parsedRequest, "id")
        ? parsedRequest.id
        : null,
    result: buildDeterministicJsonRpcResult(rawRequestBody)
  };
}

function buildRejectedResponse(parsedRequest, rawRequestBody) {
  const requestBodyHash = makeRawBodyHash(rawRequestBody);
  return {
    jsonrpc: "2.0",
    id:
      parsedRequest &&
      typeof parsedRequest === "object" &&
      Object.prototype.hasOwnProperty.call(parsedRequest, "id")
        ? parsedRequest.id
        : null,
    error: {
      code: -32500,
      message: "UserOperation rejected by controlled local bundler stub",
      data: {
        stubMode: LOCAL_BUNDLER_STUB_MODE_REJECTED,
        requestBodyHash
      }
    }
  };
}

function buildErrorResponse(parsedRequest, code, message) {
  return {
    jsonrpc: "2.0",
    id:
      parsedRequest &&
      typeof parsedRequest === "object" &&
      Object.prototype.hasOwnProperty.call(parsedRequest, "id")
        ? parsedRequest.id
        : null,
    error: {
      code,
      message
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--host") {
      parsed.host = argv[i + 1];
      i += 1;
    } else if (arg === "--port") {
      parsed.port = argv[i + 1];
      i += 1;
    } else if (arg === "--rpc-path") {
      parsed.rpcPath = argv[i + 1];
      i += 1;
    } else if (arg === "--mode") {
      parsed.mode = argv[i + 1];
      i += 1;
    } else if (arg === "--out-dir") {
      parsed.outDir = argv[i + 1];
      i += 1;
    } else if (arg === "--request-out") {
      parsed.requestOut = argv[i + 1];
      i += 1;
    } else if (arg === "--response-out") {
      parsed.responseOut = argv[i + 1];
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
      "  node scripts/base/run-local-bundler-stub.cjs \\",
      `    [--host ${LOCAL_BUNDLER_STUB_DEFAULT_HOST}] \\`,
      `    [--port ${LOCAL_BUNDLER_STUB_DEFAULT_PORT}] \\`,
      `    [--rpc-path ${LOCAL_BUNDLER_STUB_DEFAULT_PATH}] \\`,
      `    [--mode ${LOCAL_BUNDLER_STUB_MODE_ACCEPTED}] \\`,
      "    [--out-dir ./proving/out/local_bundler_stub] \\",
      "    [--request-out <path>] [--response-out <path>]"
    ].join("\n")
  );
}

async function runLocalBundlerStub({
  host = LOCAL_BUNDLER_STUB_DEFAULT_HOST,
  port = LOCAL_BUNDLER_STUB_DEFAULT_PORT,
  rpcPath = LOCAL_BUNDLER_STUB_DEFAULT_PATH,
  mode = LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  outDir = "./proving/out/local_bundler_stub",
  requestOut,
  responseOut,
  onListening = null,
  now = () => new Date().toISOString()
} = {}) {
  const normalizedHost = normalizeHost(host);
  const normalizedPort = normalizePort(port);
  const normalizedRpcPath = normalizeRpcPath(rpcPath);
  const normalizedMode = normalizeMode(mode);
  const normalizedOutDir = path.resolve(normalizeString(outDir, "outDir"));

  const requestOutputPath = path.resolve(
    requestOut || path.join(normalizedOutDir, "stub_request.json")
  );
  const responseOutputPath =
    responseOut !== undefined
      ? responseOut === null
        ? null
        : path.resolve(responseOut)
      : normalizedMode === LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR
        ? null
        : path.resolve(path.join(normalizedOutDir, "stub_response.json"));

  return await new Promise((resolve, reject) => {
    let settled = false;

    function finishWithError(error) {
      if (settled) {
        return;
      }
      settled = true;
      reject(error);
    }

    const server = http.createServer(async (request, response) => {
      const receivedAt = now();
      const chunks = [];

      try {
        for await (const chunk of request) {
          chunks.push(Buffer.from(chunk));
        }

        const rawRequestBody = Buffer.concat(chunks).toString("utf8");
        const parsedRequest = parseJsonOrNull(rawRequestBody);
        const requestBodyBytes = makeRawBodyBytes(rawRequestBody);
        const requestBodyHash = makeRawBodyHash(rawRequestBody);
        const address = server.address();
        const portValue =
          address && typeof address === "object" ? address.port : normalizedPort;
        const localEndpoint = `http://${normalizedHost}:${portValue}${normalizedRpcPath}`;
        const requestArtifact = {
          version: 1,
          path: "phil-local-bundler-stub-request",
          localBundlerStubSource: "scripts/base/run-local-bundler-stub.cjs",
          localBundlerStubDomain: {
            label: LOCAL_BUNDLER_STUB_DOMAIN_LABEL,
            hash: LOCAL_BUNDLER_STUB_DOMAIN_HASH
          },
          localBundlerStubKind: LOCAL_BUNDLER_STUB_KIND,
          mode: normalizedMode,
          receivedAt,
          localEndpoint,
          request: {
            method: request.method || null,
            url: request.url || null,
            headers: request.headers,
            rawBody: rawRequestBody,
            rawBodyBytes: requestBodyBytes,
            rawBodyHash: requestBodyHash,
            parsedJson: parsedRequest
          }
        };
        writeJson(requestOutputPath, requestArtifact);

        const validJsonRpcPost =
          request.method === LOCAL_BUNDLER_STUB_REQUEST_METHOD &&
          request.url === normalizedRpcPath &&
          parsedRequest &&
          parsedRequest.jsonrpc === "2.0" &&
          parsedRequest.method === LOCAL_BUNDLER_STUB_RPC_METHOD;

        if (normalizedMode === LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR) {
          request.socket.destroy();
          server.close((closeError) => {
            if (closeError) {
              finishWithError(closeError);
              return;
            }
            if (settled) {
              return;
            }
            settled = true;
            resolve({
              mode: normalizedMode,
              localEndpoint,
              requestOutputPath,
              responseOutputPath,
              requestBodyHash,
              responseBodyHash: null
            });
          });
          return;
        }

        const responseBodyObject = !validJsonRpcPost
          ? buildErrorResponse(parsedRequest, -32600, "Invalid Request")
          : normalizedMode === LOCAL_BUNDLER_STUB_MODE_REJECTED
            ? buildRejectedResponse(parsedRequest, rawRequestBody)
            : buildSuccessResponse(parsedRequest, rawRequestBody);
        const rawResponseBody = JSON.stringify(responseBodyObject);
        const responseBodyBytes = makeRawBodyBytes(rawResponseBody);
        const responseBodyHash = makeRawBodyHash(rawResponseBody);
        const statusCode = validJsonRpcPost ? LOCAL_BUNDLER_STUB_SUCCESS_STATUS : 400;
        const responseHeaders = {
          "content-type": "application/json",
          "cache-control": "no-store",
          "x-phil-local-bundler-stub": LOCAL_BUNDLER_STUB_KIND
        };
        const responseArtifact = {
          version: 1,
          path: "phil-local-bundler-stub-response",
          localBundlerStubSource: "scripts/base/run-local-bundler-stub.cjs",
          localBundlerStubDomain: {
            label: LOCAL_BUNDLER_STUB_DOMAIN_LABEL,
            hash: LOCAL_BUNDLER_STUB_DOMAIN_HASH
          },
          localBundlerStubKind: LOCAL_BUNDLER_STUB_KIND,
          mode: normalizedMode,
          respondedAt: now(),
          localEndpoint,
          requestValidation: {
            requestMethodValid:
              request.method === LOCAL_BUNDLER_STUB_REQUEST_METHOD,
            requestPathValid: request.url === normalizedRpcPath,
            jsonRpcValid: !!parsedRequest && parsedRequest.jsonrpc === "2.0",
            rpcMethodValid:
              !!parsedRequest &&
              parsedRequest.method === LOCAL_BUNDLER_STUB_RPC_METHOD
          },
          response: {
            statusCode,
            headers: responseHeaders,
            rawBody: rawResponseBody,
            rawBodyBytes: responseBodyBytes,
            rawBodyHash: responseBodyHash,
            parsedJson: responseBodyObject
          }
        };
        if (responseOutputPath) {
          writeJson(responseOutputPath, responseArtifact);
        }

        response.on("finish", () => {
          server.close((closeError) => {
            if (closeError) {
              finishWithError(closeError);
              return;
            }
            if (settled) {
              return;
            }
            settled = true;
            resolve({
              mode: normalizedMode,
              localEndpoint,
              requestOutputPath,
              responseOutputPath,
              requestBodyHash,
              responseBodyHash
            });
          });
        });
        response.writeHead(statusCode, responseHeaders);
        response.end(rawResponseBody, "utf8");
      } catch (error) {
        response.statusCode = 500;
        response.end(
          JSON.stringify(buildErrorResponse(null, -32603, "Internal error")),
          "utf8"
        );
        finishWithError(error);
      }
    });

    server.on("error", (error) => {
      finishWithError(error);
    });

    server.listen(normalizedPort, normalizedHost, () => {
      const address = server.address();
      const boundPort =
        address && typeof address === "object" ? address.port : normalizedPort;
      const localEndpoint = `http://${normalizedHost}:${boundPort}${normalizedRpcPath}`;
      if (typeof onListening === "function") {
        onListening({
          mode: normalizedMode,
          localEndpoint
        });
      }
      console.log(
        `LOCAL_BUNDLER_STUB_LISTENING ${localEndpoint} mode=${normalizedMode}`
      );
    });
  });
}

async function main() {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.help) {
    printUsage();
    return 0;
  }

  const result = await runLocalBundlerStub({
    host: parsed.host || LOCAL_BUNDLER_STUB_DEFAULT_HOST,
    port: parsed.port || LOCAL_BUNDLER_STUB_DEFAULT_PORT,
    rpcPath: parsed.rpcPath || LOCAL_BUNDLER_STUB_DEFAULT_PATH,
    mode: parsed.mode || LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
    outDir: parsed.outDir || "./proving/out/local_bundler_stub",
    requestOut: parsed.requestOut,
    responseOut: parsed.responseOut
  });
  console.log(JSON.stringify(result, null, 2));
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
  LOCAL_BUNDLER_STUB_DOMAIN_LABEL,
  LOCAL_BUNDLER_STUB_DOMAIN_HASH,
  LOCAL_BUNDLER_STUB_KIND,
  LOCAL_BUNDLER_STUB_RPC_METHOD,
  LOCAL_BUNDLER_STUB_REQUEST_METHOD,
  LOCAL_BUNDLER_STUB_DEFAULT_HOST,
  LOCAL_BUNDLER_STUB_DEFAULT_PORT,
  LOCAL_BUNDLER_STUB_DEFAULT_PATH,
  LOCAL_BUNDLER_STUB_MODE_ACCEPTED,
  LOCAL_BUNDLER_STUB_MODE_REJECTED,
  LOCAL_BUNDLER_STUB_MODE_TRANSPORT_ERROR,
  runLocalBundlerStub
};
