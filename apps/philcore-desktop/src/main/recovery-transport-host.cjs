"use strict";

const crypto = require("node:crypto");
require("tsx/cjs");
const { getBytes, keccak256 } = require("ethers");
const {
  parseWebAuthnAuthenticatorData
} = require("../../../phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  computePhilCoreV2RecoveryFactorDigest
} = require("../../../phil-device-sdk/src/v2Authorization.ts");
const {
  computePhilCoreV2ConsumerRecoveryEvidenceContextHash
} = require("../../../phil-device-sdk/src/v2ConsumerRecoveryEvidenceContext.ts");
const {
  encodePhilCoreO372WebAuthnEvidence
} = require("../../../phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS
} = require("../../../phil-device-sdk/src/v2RecoveryEvidence.ts");
const transport = require("../../../phil-device-sdk/src/v2RecoveryTransport.ts");
const bootstrap = require("../../../phil-device-sdk/src/v2RecoveryBootstrap.ts");
const {
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require("./recovery-secure-origin.cjs");
const http = require("node:http");

const SESSION_TTL_MS = 5 * 60 * 1000;
const SUCCESS_MAGIC = "0x15c57f54";
const ALLOWED_BITMAPS = new Set([3, 5, 6]);
const LISTENER_REQUEST_BODY_MAX = 1024;
const LISTENER_COMPLETE_BODY_MAX = 16384;
const LISTENER_HEADERS_MAX = 4096;
const LISTENER_IDLE_MS = 5000;
const LISTENER_MAX_FETCH_ATTEMPTS = 3;
const LISTENER_JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const LISTENER_PHASES = Object.freeze({
  UNBOUND: "UNBOUND",
  BOUND_INACTIVE: "BOUND_INACTIVE",
  SESSION_ACTIVE: "SESSION_ACTIVE",
  COMPLETION_PENDING: "COMPLETION_PENDING",
  CLOSED: "CLOSED"
});
const CANONICAL_IPV4_RE =
  /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u;

const STATES = Object.freeze({
  NOT_STARTED: "NOT_STARTED",
  REQUEST_CONSTRUCTED: "REQUEST_CONSTRUCTED",
  AWAITING_FIRST_FACTOR: "AWAITING_FIRST_FACTOR",
  AWAITING_SECOND_FACTOR: "AWAITING_SECOND_FACTOR",
  ENVELOPE_ASSEMBLED: "ENVELOPE_ASSEMBLED",
  LOCAL_DRILL_PASSED: "LOCAL_DRILL_PASSED",
  SESSION_CANCELLED: "SESSION_CANCELLED"
});

const COLLECTING_STATES = new Set([
  STATES.AWAITING_FIRST_FACTOR,
  STATES.AWAITING_SECOND_FACTOR
]);

class RecoveryTransportError extends Error {
  constructor(code) {
    const safeCode = /^[A-Z0-9_]{3,96}$/u.test(String(code))
      ? String(code)
      : "RECOVERY_TRANSPORT_INTERNAL_ERROR";
    super(safeCode);
    this.name = "RecoveryTransportError";
    this.code = safeCode;
  }

  toJSON() {
    return { name: this.name, code: this.code };
  }
}

class SecretValue {
  #value;
  constructor(value) {
    this.#value = value;
  }
  consume(callback) {
    if (this.#value === null) {
      throw new RecoveryTransportError("SECRET_ALREADY_CLEARED");
    }
    return callback(this.#value);
  }
  peek() {
    if (this.#value === null) {
      throw new RecoveryTransportError("SECRET_ALREADY_CLEARED");
    }
    return this.#value;
  }
  clear() {
    if (Buffer.isBuffer(this.#value)) {
      this.#value.fill(0);
    }
    this.#value = null;
  }
  toString() {
    return "[REDACTED_SECRET]";
  }
  toJSON() {
    return "[REDACTED_SECRET]";
  }
}

function safeError(error) {
  return Object.freeze({
    ok: false,
    errorCode: error instanceof RecoveryTransportError
      ? error.code
      : "RECOVERY_TRANSPORT_INTERNAL_ERROR"
  });
}

function requireFunction(value, label) {
  if (typeof value !== "function") {
    throw new RecoveryTransportError(`${label}_REQUIRED`);
  }
  return value;
}

function requireObject(value, label) {
  if (!value || typeof value !== "object") {
    throw new RecoveryTransportError(`${label}_REQUIRED`);
  }
  return value;
}

function asBytes32Hex(bytes) {
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function canonicalUnsignedDecimalString(value) {
  if (typeof value !== "bigint") {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_BIGINT_INVALID");
  }
  if (value < 0n) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_BIGINT_NEGATIVE");
  }
  const asString = value.toString(10);
  if (!/^(0|[1-9]\d*)$/u.test(asString)) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_BIGINT_INVALID");
  }
  if (String(BigInt(asString)) !== asString) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_BIGINT_INVALID");
  }
  return asString;
}

function cloneJsonSafePublicSnapshot(value, seen = new WeakSet()) {
  const valueType = typeof value;
  if (valueType === "bigint") {
    return canonicalUnsignedDecimalString(value);
  }
  if (valueType === "string" || valueType === "boolean" || value === null) {
    return value;
  }
  if (valueType === "number") {
    if (!Number.isFinite(value)) {
      throw new RecoveryTransportError("ROLE1_PRESENTATION_NUMBER_INVALID");
    }
    return value;
  }
  if (
    valueType === "undefined"
    || valueType === "function"
    || valueType === "symbol"
  ) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_VALUE_UNSUPPORTED");
  }
  if (valueType !== "object") {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_VALUE_UNSUPPORTED");
  }
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_BUFFER_REJECTED");
  }
  if (seen.has(value)) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_CYCLE_REJECTED");
  }
  seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new RecoveryTransportError("ROLE1_PRESENTATION_PROTOTYPE_REJECTED");
    }
    return Object.freeze(
      value.map((entry) => cloneJsonSafePublicSnapshot(entry, seen))
    );
  }

  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new RecoveryTransportError("ROLE1_PRESENTATION_PROTOTYPE_REJECTED");
  }

  const out = {};
  for (const key of Object.keys(value)) {
    // Never invoke toJSON or other conversion hooks; clone own enumerable fields only.
    out[key] = cloneJsonSafePublicSnapshot(value[key], seen);
  }
  return Object.freeze(out);
}

function buildRole1PublicPresentation({
  approvalRequest,
  validated,
  transcriptHash,
  bootstrapUri
}) {
  const transcriptHashHex = asBytes32Hex(transcriptHash);
  const comparisonFingerprint =
    transport.displayPhilCoreRecoveryComparisonFingerprint(transcriptHash);
  const actionText = validated.actionText;
  const networkText = validated.networkText;
  const requestSnapshot = cloneJsonSafePublicSnapshot({
    protocolVersion: approvalRequest.protocolVersion,
    context: approvalRequest.context,
    claimedContextHash: approvalRequest.claimedContextHash,
    claimedRecoveryFactorDigest: approvalRequest.claimedRecoveryFactorDigest,
    accountVersionId: approvalRequest.accountVersionId,
    securityModelId: approvalRequest.securityModelId,
    nativeRecoveryDomainId: approvalRequest.nativeRecoveryDomainId,
    applicationIdentity: approvalRequest.applicationIdentity,
    localApprovalPolicy: approvalRequest.localApprovalPolicy,
    selectedRole1CredentialIdentifierCommitment:
      approvalRequest.selectedRole1CredentialIdentifierCommitment,
    selectedRole1CredentialGeneration:
      approvalRequest.selectedRole1CredentialGeneration,
    trustedRole1Descriptor: approvalRequest.trustedRole1Descriptor,
    trustedRole1PublicKey: approvalRequest.trustedRole1PublicKey,
    sessionId: approvalRequest.sessionId,
    sessionChallenge: approvalRequest.sessionChallenge,
    desktopEphemeralPublicKey: approvalRequest.desktopEphemeralPublicKey,
    issuedAt: approvalRequest.issuedAt,
    expiresAt: approvalRequest.expiresAt,
    endpoint: approvalRequest.endpoint,
    now: approvalRequest.now,
    actionText,
    networkText
  });
  const presentation = {
    protocolVersion: approvalRequest.protocolVersion,
    sessionId: approvalRequest.sessionId,
    issuedAt: approvalRequest.issuedAt,
    expiresAt: approvalRequest.expiresAt,
    endpoint: approvalRequest.endpoint,
    desktopEphemeralPublicKey: approvalRequest.desktopEphemeralPublicKey,
    request: requestSnapshot,
    transcriptHash: transcriptHashHex,
    comparisonFingerprint,
    actionText,
    networkText
  };
  if (typeof bootstrapUri === "string" && bootstrapUri.length > 0) {
    presentation.bootstrapUri = bootstrapUri;
  }
  return cloneJsonSafePublicSnapshot(presentation);
}

function requireCanonicalRfc1918Ipv4(address) {
  if (typeof address !== "string" || !CANONICAL_IPV4_RE.test(address)) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  const octets = address.split(".").map((part) => Number(part));
  if (
    octets.length !== 4
    || octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)
  ) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  if (octets[0] === 0 || octets[0] === 127) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  if (octets[0] >= 224) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  if (octets[0] === 169 && octets[1] === 254) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  const isPrivate = octets[0] === 10
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168);
  if (!isPrivate) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  return address;
}

function resolveBindAddress(bindAddressProvider) {
  if (typeof bindAddressProvider !== "function") {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  let provided;
  try {
    provided = bindAddressProvider();
  } catch {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  if (Array.isArray(provided)) {
    throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
  }
  return requireCanonicalRfc1918Ipv4(provided);
}

function requireListenerPort(port) {
  if (typeof port !== "number" || !Number.isInteger(port)) {
    throw new RecoveryTransportError("ROLE1_BIND_PORT_INVALID");
  }
  if (port < 1024 || port > 65535) {
    throw new RecoveryTransportError("ROLE1_BIND_PORT_INVALID");
  }
  return port;
}

function parseCompletionEndpointAuthority(endpoint) {
  if (
    typeof endpoint !== "string"
    || !transport.isRfc1918RecoveryApprovalEndpoint(endpoint)
  ) {
    throw new RecoveryTransportError("ROLE1_ENDPOINT_INVALID");
  }
  let url;
  try {
    url = new URL(endpoint);
  } catch {
    throw new RecoveryTransportError("ROLE1_ENDPOINT_INVALID");
  }
  const host = requireCanonicalRfc1918Ipv4(url.hostname);
  const port = requireListenerPort(Number(url.port));
  return { host, port, completionEndpoint: endpoint };
}

function decodeBase64url(value, exactLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,8192}$/u.test(value)) {
    throw new RecoveryTransportError("BASE64URL_INVALID");
  }
  const decoded = Buffer.from(value, "base64url");
  if (exactLength !== undefined && decoded.length !== exactLength) {
    throw new RecoveryTransportError("BASE64URL_LENGTH_INVALID");
  }
  return decoded;
}

function encodeBase64url(value) {
  return Buffer.from(value).toString("base64url");
}

function isSuccessMagic(value) {
  return typeof value === "string"
    && value.toLowerCase() === SUCCESS_MAGIC.toLowerCase();
}

function rolesSelected(bitmap) {
  return transport.rolesForRecoveryFactorBitmap(bitmap);
}

function bitmapIncludesRole(bitmap, role) {
  return rolesSelected(bitmap).includes(role);
}

function buildEvidenceContext(config, bitmap) {
  const roles = rolesSelected(bitmap);
  const commitments = config.commitments;
  if (!Array.isArray(commitments) || commitments.length !== 3) {
    throw new RecoveryTransportError("TRUSTED_COMMITMENTS_INVALID");
  }
  return {
    envelopeVersion: 2,
    authorityKind: 2,
    actionType: config.actionType,
    factorBitmap: bitmap,
    account: config.account,
    chainId: config.chainId,
    entryPoint: config.entryPoint,
    authorizedIntentHash: config.authorizedIntentHash,
    userOperationHash: config.userOpHash,
    requestId: config.requestId,
    currentRecoveryConfigHash: config.recoveryConfigHash,
    validatorEpoch: config.validatorEpoch,
    recoveryEpoch: config.recoveryEpoch,
    validAfter: config.validAfter,
    validUntil: config.validUntil,
    recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
    recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
    proposedValidatorCommitment: config.proposedValidatorCommitment,
    proposedRecoveryConfigHash: config.proposedRecoveryConfigHash,
    proposedRecoveryEpoch: config.proposedRecoveryEpoch,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2],
    firstFactorCommitment: commitments[roles[0]],
    secondFactorCommitment: commitments[roles[1]]
  };
}

function recomputeDigest(config, bitmap) {
  return computePhilCoreV2RecoveryFactorDigest(
    { chainId: config.chainId, account: config.account },
    {
      authorizedIntentHash: config.authorizedIntentHash,
      userOperationHash: config.userOpHash,
      recoveryConfigHash: config.recoveryConfigHash,
      recoveryEpoch: config.recoveryEpoch,
      factorBitmap: bitmap
    }
  ).digest;
}

function clearBuffer(value) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    value.fill(0);
  }
}

function clearEcdh(ecdh) {
  if (!ecdh) return;
  try {
    ecdh.setPrivateKey(Buffer.alloc(32, 0));
  } catch {
    // Best-effort private key overwrite; V8 heap zeroization is not guaranteed.
  }
}

function clearAesKey(key) {
  clearBuffer(key);
}

function parseAndValidateRole0ClientData(assertion, expectedChallenge) {
  if (
    !assertion
    || typeof assertion !== "object"
    || !assertion.response
    || typeof assertion.response.clientDataJSON !== "string"
  ) {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_INVALID");
  }
  const raw = decodeBase64url(assertion.response.clientDataJSON);
  let parsed;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_INVALID");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_INVALID");
  }
  if (parsed.type !== "webauthn.get") {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_TYPE_INVALID");
  }
  if (parsed.challenge !== expectedChallenge) {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_CHALLENGE_INVALID");
  }

  const challengeNeedle = Buffer.from(
    `"challenge":"${expectedChallenge}"`,
    "utf8"
  );
  const typeNeedle = Buffer.from('"type":"webauthn.get"', "utf8");
  const challengeIndex = raw.indexOf(challengeNeedle);
  const typeIndex = raw.indexOf(typeNeedle);
  if (challengeIndex < 0 || typeIndex < 0) {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_INDEX_INVALID");
  }
  if (raw.indexOf(challengeNeedle, challengeIndex + 1) !== -1) {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_INDEX_INVALID");
  }
  if (raw.indexOf(typeNeedle, typeIndex + 1) !== -1) {
    throw new RecoveryTransportError("ROLE0_CLIENT_DATA_INDEX_INVALID");
  }

  return {
    clientDataJSON: raw.toString("utf8"),
    challengeIndex,
    typeIndex
  };
}

function defaultEncodeRole0Evidence({ assertion, role0, digest }) {
  const expectedChallenge = encodeBase64url(getBytes(digest));
  const { clientDataJSON, challengeIndex, typeIndex } =
    parseAndValidateRole0ClientData(assertion, expectedChallenge);
  const authenticatorDataBytes = decodeBase64url(
    assertion.response.authenticatorData
  );
  const derSignature = decodeBase64url(assertion.response.signature);
  const parsed = transport.parseDerEcdsaP256Signature(derSignature);
  const signature = transport.normalizeP256SignatureLowS(parsed);
  return encodePhilCoreO372WebAuthnEvidence({
    descriptor: role0.descriptor,
    factorCommitment: role0.factorCommitment,
    qx: role0.qx,
    qy: role0.qy,
    r: signature.r,
    s: signature.s,
    challengeIndex,
    typeIndex,
    authenticatorData: `0x${authenticatorDataBytes.toString("hex")}`,
    clientDataJSON
  });
}

function createInMemoryRole1TransportAdapter({ simulatePhoneResponse, testOnly } = {}) {
  if (testOnly !== true) {
    throw new RecoveryTransportError("IN_MEMORY_ROLE1_ADAPTER_TEST_ONLY");
  }

  let lastRequest = null;
  let presentation = null;
  let cancelled = false;
  let lastAcknowledgement = null;

  return Object.freeze({
    testOnly: true,
    async preparePresentation({ sessionId: _sessionId }) {
      const host = "10.0.0.1";
      const port = 18787;
      const completionEndpoint =
        `http://${host}:${port}${bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH}`;
      const requestEndpoint =
        `http://${host}:${port}${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`;
      return {
        endpoint: completionEndpoint,
        completionEndpoint,
        requestEndpoint,
        host,
        port
      };
    },
    async startSession(sessionPresentation) {
      cancelled = false;
      lastAcknowledgement = null;
      presentation = sessionPresentation;
      lastRequest = sessionPresentation?.request || null;
    },
    async waitForResponse({
      sessionId,
      timeoutMs: _timeoutMs,
      captureSessionId,
      cancelledSignal
    }) {
      if (cancelled || cancelledSignal?.cancelled === true) {
        throw new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED");
      }
      if (!presentation) {
        throw new RecoveryTransportError("ROLE1_TRANSPORT_NOT_STARTED");
      }
      const expectedSessionId =
        presentation.request?.sessionId || presentation.sessionId;
      if (
        (sessionId && expectedSessionId && sessionId !== expectedSessionId)
        || (
          captureSessionId
          && expectedSessionId
          && captureSessionId !== expectedSessionId
        )
      ) {
        throw new RecoveryTransportError("ROLE1_TRANSPORT_SESSION_MISMATCH");
      }
      if (typeof simulatePhoneResponse !== "function") {
        throw new RecoveryTransportError("ROLE1_SIMULATOR_REQUIRED");
      }
      return simulatePhoneResponse({
        request: presentation.request,
        transcriptHash: presentation.transcriptHash,
        desktopEcdhPublicKey:
          presentation.desktopEcdhPublicKey
          || presentation.request?.desktopEphemeralPublicKey
      });
    },
    async sendAcknowledgement(ack, options = {}) {
      if (cancelled || options.cancelledSignal?.cancelled === true) {
        lastAcknowledgement = null;
        throw new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED");
      }
      if (!presentation) {
        throw new RecoveryTransportError("ROLE1_TRANSPORT_NOT_STARTED");
      }
      const expectedSessionId =
        presentation.request?.sessionId || presentation.sessionId;
      if (
        options.sessionId
        && expectedSessionId
        && options.sessionId !== expectedSessionId
      ) {
        throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
      }
      lastAcknowledgement = ack;
    },
    cancel() {
      cancelled = true;
      presentation = null;
      lastRequest = null;
      lastAcknowledgement = null;
    },
    getLastRequest() {
      return lastRequest;
    },
    getLastAcknowledgement() {
      if (cancelled) return null;
      return lastAcknowledgement;
    }
  });
}

function createProductionRole1TransportListenerAdapter(options = {}) {
  const bindAddressProvider = options.bindAddressProvider;
  const defaultHttpServerOptions = Object.freeze({
    maxHeaderSize: LISTENER_HEADERS_MAX,
    headersTimeout: LISTENER_IDLE_MS,
    requestTimeout: LISTENER_IDLE_MS
  });
  const createHttpServer = typeof options.createHttpServer === "function"
    ? options.createHttpServer
    : (serverOptions = defaultHttpServerOptions) => http.createServer(serverOptions);
  const setTimeoutFn = typeof options.setTimeout === "function"
    ? options.setTimeout
    : setTimeout;
  const clearTimeoutFn = typeof options.clearTimeout === "function"
    ? options.clearTimeout
    : clearTimeout;
  const nowFn = typeof options.now === "function" ? options.now : () => Date.now();

  let phase = LISTENER_PHASES.UNBOUND;
  let generation = 0;
  let server = null;
  const sockets = new Set();
  let boundHost = null;
  let boundPort = null;
  let completionEndpoint = null;
  let requestEndpoint = null;
  let sessionId = null;
  let expiresAtMs = null;
  let requestDeliveryCapability = null;
  let adapterPhoneKeyLock = null;
  let fetchAttemptsReserved = 0;
  let successfulDeliveries = 0;
  let completionConsumed = false;
  let pendingComplete = null;
  let completedEncryptedResponse = null;
  let waiters = [];
  let closedReason = null;
  let expiryTimer = null;
  let ackFallbackTimer = null;
  let seenDeliveryNonces = new Set();

  function publicStatus() {
    return Object.freeze({
      phase,
      host: boundHost,
      port: boundPort,
      sessionId,
      hasPhoneKeyLock: adapterPhoneKeyLock !== null,
      fetchAttemptsReserved,
      successfulDeliveries,
      completionConsumed
    });
  }

  function assertGeneration(expected) {
    return generation === expected && phase !== LISTENER_PHASES.CLOSED;
  }

  function isIpv4Family(family) {
    return family === "IPv4" || family === 4;
  }

  function clearExpiryTimer() {
    if (expiryTimer !== null) {
      clearTimeoutFn(expiryTimer);
      expiryTimer = null;
    }
  }

  function clearAckFallbackTimer() {
    if (ackFallbackTimer !== null) {
      clearTimeoutFn(ackFallbackTimer);
      ackFallbackTimer = null;
    }
  }

  function clearGenerationState() {
    clearExpiryTimer();
    clearAckFallbackTimer();
    requestDeliveryCapability = null;
    adapterPhoneKeyLock = null;
    seenDeliveryNonces = new Set();
    sessionId = null;
    expiresAtMs = null;
    boundHost = null;
    boundPort = null;
    completionEndpoint = null;
    requestEndpoint = null;
    fetchAttemptsReserved = 0;
    successfulDeliveries = 0;
    completionConsumed = false;
    completedEncryptedResponse = null;
    pendingComplete = null;
    waiters = [];
  }

  function writeSanitized(res, statusCode) {
    if (!res || res.headersSent || res.writableEnded) {
      try {
        if (res && typeof res.destroy === "function") res.destroy();
      } catch {
        // ignore
      }
      return;
    }
    const body = Buffer.from("{\"ok\":false}", "utf8");
    try {
      res.writeHead(statusCode, {
        "Content-Type": LISTENER_JSON_CONTENT_TYPE,
        "Cache-Control": "no-store",
        "Connection": "close",
        "Content-Length": body.length
      });
      res.end(body);
    } catch {
      try {
        if (typeof res.destroy === "function") res.destroy();
      } catch {
        // ignore
      }
    }
  }

  function writeJson(res, statusCode, value) {
    if (!res || res.headersSent || res.writableEnded) return;
    const body = Buffer.from(JSON.stringify(value), "utf8");
    res.writeHead(statusCode, {
      "Content-Type": LISTENER_JSON_CONTENT_TYPE,
      "Cache-Control": "no-store",
      "Connection": "close",
      "Content-Length": body.length
    });
    res.end(body);
  }

  function headerBytes(req) {
    if (Array.isArray(req.rawHeaders) && req.rawHeaders.length > 0) {
      let total = 0;
      for (const part of req.rawHeaders) {
        total += Buffer.byteLength(String(part), "utf8");
      }
      return total;
    }
    let total = 0;
    for (const [key, value] of Object.entries(req.headers || {})) {
      total += Buffer.byteLength(String(key), "utf8");
      total += Buffer.byteLength(String(value), "utf8");
    }
    return total;
  }

  function destroySocket(reqOrSocket) {
    try {
      const socket = reqOrSocket?.socket || reqOrSocket;
      if (socket && typeof socket.destroy === "function") {
        socket.destroy();
      }
    } catch {
      // ignore
    }
  }

  function rejectWaiters(code) {
    const pending = waiters.splice(0);
    for (const waiter of pending) {
      try {
        waiter.reject(new RecoveryTransportError(code));
      } catch {
        // ignore
      }
    }
  }

  function closeServerAndSockets({ exceptSocket = null } = {}) {
    for (const socket of sockets) {
      if (exceptSocket && socket === exceptSocket) continue;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      sockets.delete(socket);
    }
    if (exceptSocket) {
      // Keep only the excepted socket tracked until graceful close.
      if (!sockets.has(exceptSocket)) {
        sockets.clear();
        sockets.add(exceptSocket);
      }
    } else {
      sockets.clear();
    }
    if (server) {
      try {
        server.close();
      } catch {
        // ignore
      }
    }
    if (!exceptSocket) {
      server = null;
    }
  }

  function terminate(
    reason,
    statusForPending = 410,
    waiterCode = "ROLE1_TRANSPORT_CANCELLED"
  ) {
    if (phase === LISTENER_PHASES.CLOSED) return;
    phase = LISTENER_PHASES.CLOSED;
    closedReason = reason || "CANCELLED";
    generation += 1;
    if (pendingComplete) {
      writeSanitized(pendingComplete.res, statusForPending);
      pendingComplete = null;
    }
    rejectWaiters(waiterCode);
    closeServerAndSockets();
    clearGenerationState();
  }

  function armExpiryTimer(capturedGeneration) {
    clearExpiryTimer();
    if (!Number.isFinite(expiresAtMs)) return;
    const delay = Math.max(1, expiresAtMs - nowFn());
    expiryTimer = setTimeoutFn(() => {
      expiryTimer = null;
      if (!assertGeneration(capturedGeneration)) return;
      terminate("EXPIRED", 410);
    }, delay);
  }

  function decodeUtf8Fatal(bytes) {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return decoder.decode(bytes);
  }

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      let settled = false;
      let idleTimer = null;

      function clearIdle() {
        if (idleTimer !== null) {
          clearTimeoutFn(idleTimer);
          idleTimer = null;
        }
      }

      function armIdle() {
        clearIdle();
        idleTimer = setTimeoutFn(() => {
          if (settled) return;
          settled = true;
          clearIdle();
          destroySocket(req);
          reject(new RecoveryTransportError("ROLE1_TRANSPORT_IDLE_TIMEOUT"));
        }, LISTENER_IDLE_MS);
      }

      function fail(error) {
        if (settled) return;
        settled = true;
        clearIdle();
        reject(error);
      }

      armIdle();
      req.on("data", (chunk) => {
        if (settled) return;
        armIdle();
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buf.length;
        if (size > limit) {
          destroySocket(req);
          fail(new RecoveryTransportError("ROLE1_TRANSPORT_BODY_TOO_LARGE"));
          return;
        }
        chunks.push(buf);
      });
      req.on("end", () => {
        if (settled) return;
        settled = true;
        clearIdle();
        resolve(Buffer.concat(chunks));
      });
      req.on("error", () => {
        fail(new RecoveryTransportError("ROLE1_TRANSPORT_BODY_READ_FAILED"));
      });
      req.on("aborted", () => {
        fail(new RecoveryTransportError("ROLE1_TRANSPORT_BODY_READ_FAILED"));
      });
    });
  }

  function framingRejected(req, bodyLimit) {
    const headers = req.headers || {};
    const hasTe = Object.prototype.hasOwnProperty.call(headers, "transfer-encoding");
    const hasCl = Object.prototype.hasOwnProperty.call(headers, "content-length");
    if (hasTe && hasCl) return { reject: true, statusCode: 400 };
    if (hasCl) {
      const raw = String(headers["content-length"]);
      if (!/^(0|[1-9]\d{0,15})$/u.test(raw)) {
        return { reject: true, statusCode: 400 };
      }
      const contentLength = Number(raw);
      if (contentLength > bodyLimit) {
        return { reject: true, statusCode: 413 };
      }
    }
    return { reject: false };
  }

  async function handleRequestRoute(req, res, capturedGeneration) {
    if (!assertGeneration(capturedGeneration) || phase !== LISTENER_PHASES.SESSION_ACTIVE) {
      writeSanitized(res, phase === LISTENER_PHASES.BOUND_INACTIVE ? 503 : 410);
      return;
    }
    if (nowFn() >= expiresAtMs) {
      terminate("EXPIRED", 410);
      writeSanitized(res, 410);
      return;
    }
    if (fetchAttemptsReserved >= LISTENER_MAX_FETCH_ATTEMPTS) {
      writeSanitized(res, 429);
      return;
    }

    const framing = framingRejected(req, LISTENER_REQUEST_BODY_MAX);
    if (framing.reject) {
      writeSanitized(res, framing.statusCode);
      return;
    }

    let body;
    try {
      body = await readBody(req, LISTENER_REQUEST_BODY_MAX);
    } catch (error) {
      if (error instanceof RecoveryTransportError
        && error.code === "ROLE1_TRANSPORT_BODY_TOO_LARGE") {
        writeSanitized(res, 413);
        return;
      }
      if (error instanceof RecoveryTransportError
        && error.code === "ROLE1_TRANSPORT_IDLE_TIMEOUT") {
        return;
      }
      writeSanitized(res, 400);
      return;
    }
    if (!assertGeneration(capturedGeneration) || phase !== LISTENER_PHASES.SESSION_ACTIVE) {
      writeSanitized(res, 410);
      return;
    }

    const headers = req.headers || {};
    if (Object.prototype.hasOwnProperty.call(headers, "content-length")) {
      const declared = Number(headers["content-length"]);
      if (body.length !== declared) {
        writeSanitized(res, 400);
        return;
      }
    }

    let bodyText;
    try {
      bodyText = decodeUtf8Fatal(body);
    } catch {
      writeSanitized(res, 400);
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      writeSanitized(res, 400);
      return;
    }

    let fetchInit;
    try {
      fetchInit = bootstrap.validateFetchInit(parsed);
    } catch {
      writeSanitized(res, 400);
      return;
    }
    if (fetchInit.sessionId !== sessionId) {
      writeSanitized(res, 400);
      return;
    }

    if (
      adapterPhoneKeyLock
      && adapterPhoneKeyLock !== fetchInit.phoneEphemeralPublicKey
    ) {
      terminate("PHONE_KEY_MISMATCH", 410);
      writeSanitized(res, 410);
      return;
    }

    // Atomically reserve attempt before awaiting capability.
    fetchAttemptsReserved += 1;
    if (fetchAttemptsReserved > LISTENER_MAX_FETCH_ATTEMPTS) {
      writeSanitized(res, 429);
      return;
    }

    if (!adapterPhoneKeyLock) {
      adapterPhoneKeyLock = fetchInit.phoneEphemeralPublicKey;
    }

    const capability = requestDeliveryCapability;
    if (typeof capability !== "function") {
      terminate("CAPABILITY_MISSING", 410);
      writeSanitized(res, 410);
      return;
    }

    let delivery;
    try {
      delivery = await capability(fetchInit);
    } catch {
      terminate("REQUEST_DELIVERY_FAILED", 410);
      writeSanitized(res, 410);
      return;
    }

    if (!assertGeneration(capturedGeneration) || phase !== LISTENER_PHASES.SESSION_ACTIVE) {
      writeSanitized(res, 410);
      return;
    }

    if (
      !delivery
      || typeof delivery !== "object"
      || delivery.sessionId !== sessionId
      || typeof delivery.nonce !== "string"
      || typeof delivery.ciphertext !== "string"
      || typeof delivery.tag !== "string"
    ) {
      terminate("REQUEST_DELIVERY_INVALID", 410);
      writeSanitized(res, 410);
      return;
    }

    if (seenDeliveryNonces.has(delivery.nonce)) {
      terminate("REQUEST_NONCE_REUSED", 410);
      writeSanitized(res, 410);
      return;
    }
    seenDeliveryNonces.add(delivery.nonce);

    successfulDeliveries += 1;
    writeJson(res, 200, {
      protocolVersion: bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_PROTOCOL_VERSION,
      sessionId: delivery.sessionId,
      nonce: delivery.nonce,
      ciphertext: delivery.ciphertext,
      tag: delivery.tag
    });
  }

  async function handleCompleteRoute(req, res, capturedGeneration) {
    if (!assertGeneration(capturedGeneration) || phase !== LISTENER_PHASES.SESSION_ACTIVE) {
      writeSanitized(res, phase === LISTENER_PHASES.BOUND_INACTIVE ? 503 : 410);
      return;
    }
    if (nowFn() >= expiresAtMs) {
      terminate("EXPIRED", 410);
      writeSanitized(res, 410);
      return;
    }
    if (successfulDeliveries < 1 || !adapterPhoneKeyLock) {
      writeSanitized(res, 400);
      return;
    }
    if (completionConsumed || pendingComplete) {
      writeSanitized(res, 409);
      return;
    }

    const framing = framingRejected(req, LISTENER_COMPLETE_BODY_MAX);
    if (framing.reject) {
      writeSanitized(res, framing.statusCode);
      return;
    }

    let body;
    try {
      body = await readBody(req, LISTENER_COMPLETE_BODY_MAX);
    } catch (error) {
      if (error instanceof RecoveryTransportError
        && error.code === "ROLE1_TRANSPORT_BODY_TOO_LARGE") {
        writeSanitized(res, 413);
        return;
      }
      if (error instanceof RecoveryTransportError
        && error.code === "ROLE1_TRANSPORT_IDLE_TIMEOUT") {
        return;
      }
      writeSanitized(res, 400);
      return;
    }
    if (!assertGeneration(capturedGeneration) || phase !== LISTENER_PHASES.SESSION_ACTIVE) {
      writeSanitized(res, 410);
      return;
    }

    const headers = req.headers || {};
    if (Object.prototype.hasOwnProperty.call(headers, "content-length")) {
      const declared = Number(headers["content-length"]);
      if (body.length !== declared) {
        writeSanitized(res, 400);
        return;
      }
    }

    let bodyText;
    try {
      bodyText = decodeUtf8Fatal(body);
    } catch {
      writeSanitized(res, 400);
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      writeSanitized(res, 400);
      return;
    }

    let validated;
    try {
      validated = transport.validateEncryptedNativeRecoveryResponse(parsed);
    } catch {
      writeSanitized(res, 400);
      return;
    }
    if (validated.sessionId !== sessionId) {
      writeSanitized(res, 400);
      return;
    }
    if (validated.phoneEphemeralPublicKey !== adapterPhoneKeyLock) {
      terminate("PHONE_KEY_MISMATCH", 410);
      writeSanitized(res, 410);
      return;
    }

    // Atomically consume sole completion attempt before host handoff.
    completionConsumed = true;
    phase = LISTENER_PHASES.COMPLETION_PENDING;
    const rawEncrypted = {
      version: validated.version,
      sessionId: validated.sessionId,
      phoneEphemeralPublicKey: validated.phoneEphemeralPublicKey,
      nonce: validated.nonce,
      ciphertext: validated.ciphertext,
      tag: validated.tag
    };
    completedEncryptedResponse = rawEncrypted;
    pendingComplete = { req, res, generation: capturedGeneration };
    const currentWaiters = waiters.splice(0);
    for (const waiter of currentWaiters) {
      waiter.resolve(rawEncrypted);
    }
  }

  async function onRequest(req, res, capturedGeneration) {
    if (!assertGeneration(capturedGeneration)) {
      writeSanitized(res, 410);
      return;
    }
    if (phase === LISTENER_PHASES.BOUND_INACTIVE) {
      writeSanitized(res, 503);
      return;
    }
    if (phase === LISTENER_PHASES.CLOSED) {
      writeSanitized(res, 410);
      return;
    }

    if (headerBytes(req) > LISTENER_HEADERS_MAX) {
      try {
        writeSanitized(res, 431);
      } catch {
        destroySocket(req);
      }
      return;
    }

    const method = String(req.method || "").toUpperCase();
    const urlPath = String(req.url || "");
    if (
      urlPath !== bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH
      && urlPath !== bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH
    ) {
      writeSanitized(res, 404);
      return;
    }
    if (method !== "POST") {
      writeSanitized(res, 405);
      return;
    }
    const contentType = String(req.headers?.["content-type"] || "");
    if (contentType !== LISTENER_JSON_CONTENT_TYPE) {
      writeSanitized(res, 415);
      return;
    }

    if (urlPath === bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH) {
      await handleRequestRoute(req, res, capturedGeneration);
      return;
    }
    await handleCompleteRoute(req, res, capturedGeneration);
  }

  async function preparePresentation(input = {}) {
    if (phase !== LISTENER_PHASES.UNBOUND && phase !== LISTENER_PHASES.CLOSED) {
      throw new RecoveryTransportError("ROLE1_LISTENER_ALREADY_BOUND");
    }
    const nextSessionId = input.sessionId;
    if (typeof nextSessionId !== "string" || !/^0x[0-9a-fA-F]{64}$/u.test(nextSessionId)) {
      throw new RecoveryTransportError("ROLE1_SESSION_ID_INVALID");
    }
    const issuedAtMs = Number(input.issuedAtMs);
    const expiresAt = Number(input.expiresAt);
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAt)) {
      throw new RecoveryTransportError("ROLE1_SESSION_TIMES_INVALID");
    }
    if (!(expiresAt > issuedAtMs) || expiresAt - issuedAtMs > SESSION_TTL_MS + 1000) {
      throw new RecoveryTransportError("ROLE1_SESSION_TIMES_INVALID");
    }

    const hostAddress = resolveBindAddress(bindAddressProvider);
    generation += 1;
    const capturedGeneration = generation;
    phase = LISTENER_PHASES.UNBOUND;
    closedReason = null;
    clearExpiryTimer();
    clearAckFallbackTimer();
    sessionId = nextSessionId;
    expiresAtMs = expiresAt;
    adapterPhoneKeyLock = null;
    fetchAttemptsReserved = 0;
    successfulDeliveries = 0;
    completionConsumed = false;
    pendingComplete = null;
    completedEncryptedResponse = null;
    requestDeliveryCapability = null;
    seenDeliveryNonces = new Set();
    waiters = [];
    boundHost = null;
    boundPort = null;
    completionEndpoint = null;
    requestEndpoint = null;
    sockets.clear();

    let nextServer;
    try {
      nextServer = createHttpServer({ ...defaultHttpServerOptions });
      if (!nextServer || typeof nextServer.listen !== "function") {
        throw new RecoveryTransportError("ROLE1_LISTENER_SERVER_INVALID");
      }
      server = nextServer;
      if (typeof server.on === "function") {
        server.on("connection", (socket) => {
          if (!assertGeneration(capturedGeneration)) {
            try {
              socket.destroy();
            } catch {
              // ignore
            }
            return;
          }
          sockets.add(socket);
          if (typeof socket.setTimeout === "function") {
            socket.setTimeout(LISTENER_IDLE_MS);
          }
          if (typeof socket.on === "function") {
            socket.on("timeout", () => {
              if (!assertGeneration(capturedGeneration)) return;
              try {
                socket.destroy();
              } catch {
                // ignore
              }
            });
            socket.on("close", () => {
              sockets.delete(socket);
            });
          }
        });
        server.on("clientError", (error, socket) => {
          if (!assertGeneration(capturedGeneration)) {
            try {
              socket.destroy();
            } catch {
              // ignore
            }
            return;
          }
          const code = error && error.code;
          if (
            code === "HPE_HEADER_OVERFLOW"
            && socket
            && socket.writable !== false
            && typeof socket.end === "function"
          ) {
            try {
              socket.end(
                "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
              );
              return;
            } catch {
              // fall through to destroy
            }
          }
          try {
            if (socket && typeof socket.destroy === "function") socket.destroy();
          } catch {
            // ignore
          }
        });
        server.on("request", (req, res) => {
          Promise.resolve()
            .then(() => onRequest(req, res, capturedGeneration))
            .catch(() => {
              writeSanitized(res, 500);
            });
        });
      }

      await new Promise((resolve, reject) => {
        let settled = false;
        const onListenError = () => {
          if (settled) return;
          settled = true;
          if (typeof server.removeListener === "function") {
            server.removeListener("error", onListenError);
          }
          reject(new RecoveryTransportError("ROLE1_LISTENER_BIND_FAILED"));
        };
        if (typeof server.once === "function") {
          server.once("error", onListenError);
        } else if (typeof server.on === "function") {
          server.on("error", onListenError);
        }
        try {
          server.listen(0, hostAddress, () => {
            if (settled) return;
            settled = true;
            if (typeof server.removeListener === "function") {
              server.removeListener("error", onListenError);
            }
            if (typeof server.on === "function") {
              server.on("error", () => {
                if (!assertGeneration(capturedGeneration)) return;
                terminate("SERVER_ERROR", 410);
              });
            }
            resolve();
          });
        } catch {
          if (settled) return;
          settled = true;
          if (typeof server.removeListener === "function") {
            server.removeListener("error", onListenError);
          }
          reject(new RecoveryTransportError("ROLE1_LISTENER_BIND_FAILED"));
        }
      });

      const address = typeof server.address === "function" ? server.address() : null;
      if (!address || typeof address !== "object") {
        throw new RecoveryTransportError("ROLE1_BIND_PORT_INVALID");
      }
      if (typeof address.address !== "string") {
        throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
      }
      if (!isIpv4Family(address.family)) {
        throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
      }
      if (
        address.address === "0.0.0.0"
        || address.address === "::"
        || address.address !== hostAddress
      ) {
        throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
      }
      const verifiedHost = requireCanonicalRfc1918Ipv4(address.address);
      if (verifiedHost !== hostAddress) {
        throw new RecoveryTransportError("ROLE1_BIND_ADDRESS_INVALID");
      }
      const port = requireListenerPort(Number(address.port));
      boundHost = verifiedHost;
      boundPort = port;
      completionEndpoint =
        `http://${boundHost}:${boundPort}${bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH}`;
      requestEndpoint =
        `http://${boundHost}:${boundPort}${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`;
      if (!transport.isRfc1918RecoveryApprovalEndpoint(completionEndpoint)) {
        throw new RecoveryTransportError("ROLE1_ENDPOINT_INVALID");
      }
      phase = LISTENER_PHASES.BOUND_INACTIVE;
      armExpiryTimer(capturedGeneration);
      return {
        endpoint: completionEndpoint,
        completionEndpoint,
        requestEndpoint,
        host: boundHost,
        port: boundPort
      };
    } catch (error) {
      closeServerAndSockets();
      clearGenerationState();
      phase = LISTENER_PHASES.CLOSED;
      if (error instanceof RecoveryTransportError) throw error;
      throw new RecoveryTransportError("ROLE1_LISTENER_BIND_FAILED");
    }
  }

  async function startSession(sessionPresentation = {}) {
    if (phase !== LISTENER_PHASES.BOUND_INACTIVE) {
      throw new RecoveryTransportError("ROLE1_LISTENER_NOT_BOUND");
    }
    const nextSessionId = sessionPresentation.sessionId
      || sessionPresentation.request?.sessionId;
    if (!nextSessionId || nextSessionId !== sessionId) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_SESSION_MISMATCH");
    }
    if (typeof sessionPresentation.requestDeliveryCapability !== "function") {
      throw new RecoveryTransportError("ROLE1_REQUEST_DELIVERY_CAPABILITY_REQUIRED");
    }
    // Never retain private ECDH / AES / decrypted material from presentation.
    requestDeliveryCapability = sessionPresentation.requestDeliveryCapability;
    phase = LISTENER_PHASES.SESSION_ACTIVE;
  }

  async function waitForResponse({
    sessionId: expectedSessionId,
    timeoutMs,
    captureSessionId,
    cancelledSignal
  } = {}) {
    if (phase === LISTENER_PHASES.CLOSED) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED");
    }
    if (
      phase !== LISTENER_PHASES.SESSION_ACTIVE
      && phase !== LISTENER_PHASES.COMPLETION_PENDING
    ) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_NOT_STARTED");
    }
    if (cancelledSignal?.cancelled === true) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED");
    }
    if (
      (expectedSessionId && expectedSessionId !== sessionId)
      || (captureSessionId && captureSessionId !== sessionId)
    ) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_SESSION_MISMATCH");
    }
    if (
      completedEncryptedResponse
      && phase === LISTENER_PHASES.COMPLETION_PENDING
    ) {
      return completedEncryptedResponse;
    }

    const capturedGeneration = generation;
    return new Promise((resolve, reject) => {
      let settled = false;
      const waiter = {
        resolve: (value) => {
          if (settled) return;
          settled = true;
          clearTimeoutFn(timer);
          if (!assertGeneration(capturedGeneration)) {
            reject(new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED"));
            return;
          }
          resolve(value);
        },
        reject: (error) => {
          if (settled) return;
          settled = true;
          clearTimeoutFn(timer);
          reject(error);
        }
      };
      waiters.push(waiter);
      const waitMs = Math.max(1, Number(timeoutMs) || 1);
      const timer = setTimeoutFn(() => {
        if (settled) return;
        if (!assertGeneration(capturedGeneration)) {
          waiter.reject(new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED"));
          return;
        }
        terminate("TIMEOUT", 410, "ROLE1_TRANSPORT_TIMEOUT");
      }, waitMs);
    });
  }

  async function sendAcknowledgement(encryptedAck, ackOptions = {}) {
    if (phase === LISTENER_PHASES.CLOSED) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_CANCELLED");
    }
    if (phase !== LISTENER_PHASES.COMPLETION_PENDING || !pendingComplete) {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_COMPLETION_NOT_PENDING");
    }
    if (ackOptions.sessionId && ackOptions.sessionId !== sessionId) {
      throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
    }
    let validatedAck;
    try {
      validatedAck = transport.validateEncryptedRecoveryAcknowledgement(encryptedAck);
    } catch {
      terminate("ACK_INVALID", 410);
      throw new RecoveryTransportError("ROLE1_ACK_INVALID");
    }
    if (validatedAck.sessionId !== sessionId) {
      terminate("ACK_SESSION_MISMATCH", 410);
      throw new RecoveryTransportError("ROLE1_ACK_SESSION_MISMATCH");
    }

    const pending = pendingComplete;
    pendingComplete = null;
    const { req, res, generation: ackGeneration } = pending;
    const ackSocket = req?.socket || res?.socket || null;

    // Write already-encrypted ack verbatim (do not re-encrypt).
    writeJson(res, 200, encryptedAck);

    // Stop accepting new connections without destroying the ACK socket yet.
    if (server) {
      try {
        server.close();
      } catch {
        // ignore
      }
    }
    for (const socket of [...sockets]) {
      if (ackSocket && socket === ackSocket) continue;
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      sockets.delete(socket);
    }

    await new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        clearAckFallbackTimer();
        resolve();
      };
      clearAckFallbackTimer();
      ackFallbackTimer = setTimeoutFn(() => {
        ackFallbackTimer = null;
        if (generation !== ackGeneration && phase === LISTENER_PHASES.CLOSED) {
          done();
          return;
        }
        try {
          // Prefer destroying the response so deferred-finish harnesses and
          // real sockets both observe a terminal force-close.
          if (res && typeof res.destroy === "function") {
            res.destroy();
          } else if (ackSocket && typeof ackSocket.destroy === "function") {
            ackSocket.destroy();
          }
        } catch {
          // ignore
        }
        done();
      }, LISTENER_IDLE_MS);

      if (res && typeof res.on === "function") {
        res.on("finish", done);
        res.on("close", done);
        res.on("error", done);
      }
      // Only treat as already complete when the response has fully finished.
      // writableEnded alone is insufficient: deferred-finish harnesses set it
      // before the flush/close signal.
      if (
        !res
        || res.writableFinished === true
        || res.finished === true
      ) {
        done();
      }
    });

    if (phase === LISTENER_PHASES.CLOSED) {
      return;
    }
    if (generation !== ackGeneration) {
      return;
    }
    phase = LISTENER_PHASES.CLOSED;
    closedReason = "ACK_SENT";
    generation += 1;
    closeServerAndSockets();
    clearGenerationState();
  }

  function cancel(_reason) {
    if (phase === LISTENER_PHASES.CLOSED && closedReason) {
      return;
    }
    terminate(_reason || "CANCELLED", 410);
  }

  return Object.freeze({
    testOnly: false,
    preparePresentation,
    startSession,
    waitForResponse,
    sendAcknowledgement,
    cancel,
    getPhase: () => phase,
    getBoundAddress: () => boundHost,
    getBoundPort: () => boundPort,
    getPublicStatus: () => publicStatus()
  });
}

function createUnavailableRole1TransportAdapter() {
  return Object.freeze({
    unavailable: true,
    testOnly: false,
    async preparePresentation() {
      throw new RecoveryTransportError("ROLE1_TRANSPORT_NOT_CONFIGURED");
    },
    cancel() {}
  });
}

function createRecoveryTransportHost(options = {}) {
  const trustedConfigProvider = requireFunction(
    options.trustedConfigProvider,
    "TRUSTED_CONFIG_PROVIDER"
  );
  const role2FactorProvider = requireFunction(
    options.role2FactorProvider,
    "ROLE2_FACTOR_PROVIDER"
  );
  const localStaticVerifier = requireFunction(
    options.localStaticVerifier,
    "LOCAL_STATIC_VERIFIER"
  );
  const role1TransportAdapter = requireObject(
    options.role1TransportAdapter,
    "ROLE1_TRANSPORT_ADAPTER"
  );
  const assertionVerifier = requireObject(
    options.assertionVerifier,
    "ASSERTION_VERIFIER"
  );
  if (typeof assertionVerifier.verifyAssertion !== "function") {
    throw new RecoveryTransportError("ASSERTION_VERIFIER_INVALID");
  }
  const expectedOrigin = options.expectedOrigin || RECOVERY_ORIGIN;
  const expectedRpId = options.expectedRpId || RECOVERY_RP_ID;
  const now = typeof options.now === "function" ? options.now : () => Date.now();
  const randomBytes = typeof options.randomBytes === "function"
    ? options.randomBytes
    : (n) => crypto.randomBytes(n);
  const encodeRole0Evidence = typeof options.encodeRole0Evidence === "function"
    ? options.encodeRole0Evidence
    : defaultEncodeRole0Evidence;

  let state = STATES.NOT_STARTED;
  let session = null;

  function publicStatus() {
    const base = { state };
    if (!session) return Object.freeze(base);
    const collectedRoles = [...session.factors.keys()].sort((a, b) => a - b);
    const status = {
      state,
      sessionId: session.sessionId,
      bitmap: session.bitmap,
      expiresAt: session.expiresAt,
      roles: Object.freeze([...session.roles]),
      collectedRoles: Object.freeze(collectedRoles)
    };
    if (session.result) status.result = session.result;
    if (
      session.role1PublicPresentation
      && !session.terminal
      && state !== STATES.SESSION_CANCELLED
      && state !== STATES.LOCAL_DRILL_PASSED
      && now() < session.expiresAt
    ) {
      // Detached snapshot: never return the mutable internal presentation object.
      status.role1Presentation = cloneJsonSafePublicSnapshot(
        session.role1PublicPresentation
      );
    }
    return Object.freeze(status);
  }

  function clearSessionSecrets(target) {
    if (!target) return;
    if (target.factors instanceof Map) {
      for (const factor of target.factors.values()) {
        if (factor?.evidence instanceof SecretValue) factor.evidence.clear();
        if (factor && typeof factor === "object") {
          factor.evidence = null;
        }
      }
      target.factors.clear();
    }
    if (target.envelope instanceof SecretValue) {
      target.envelope.clear();
    }
    target.envelope = null;
    if (target.decryptedPayload instanceof SecretValue) {
      target.decryptedPayload.clear();
    }
    target.decryptedPayload = null;
    clearEcdh(target.ecdh);
    target.ecdh = null;
    clearAesKey(target.aesKey);
    target.aesKey = null;
    clearBuffer(target.sharedSecret);
    target.sharedSecret = null;
    clearBuffer(target.transcript);
    target.transcript = null;
    clearBuffer(target.transcriptHash);
    target.transcriptHash = null;
    target.encryptedResponse = null;
    target.acknowledgement = null;
    target.role1Request = null;
    target.endpoint = null;
    target.requestEndpoint = null;
    target.bootstrapUri = null;
    target.requestHash = null;
    clearBuffer(target.canonicalRequestBytes);
    target.canonicalRequestBytes = null;
    target.lockedPhoneEphemeralPublicKey = null;
    target.role1PublicPresentation = null;
    target.role1CollectInFlight = false;
  }

  function markCancelled(target) {
    clearSessionSecrets(target);
    if (
      role1TransportAdapter
      && typeof role1TransportAdapter.cancel === "function"
    ) {
      try {
        role1TransportAdapter.cancel();
      } catch {
        // Adapter cancel is best-effort and must not block host cancel.
      }
    }
  }

  function isCapturedCurrent(captured) {
    return Boolean(
      captured
      && session === captured
      && session.generation === captured.generation
      && !captured.terminal
    );
  }

  function failCaptured(captured, code) {
    if (
      captured
      && session
      && (session === captured || session.generation === captured.generation)
    ) {
      markCancelled(captured);
      captured.terminal = true;
      state = STATES.SESSION_CANCELLED;
      throw new RecoveryTransportError(code);
    }
    throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
  }

  function assertCapturedFresh(captured) {
    if (
      session !== captured
      || !captured
      || captured.terminal
      || session?.generation !== captured.generation
    ) {
      throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
    }
    if (now() >= captured.expiresAt) {
      failCaptured(captured, "SESSION_EXPIRED");
    }
  }

  function assertNotTerminal() {
    if (
      state === STATES.SESSION_CANCELLED
      || state === STATES.LOCAL_DRILL_PASSED
      || session?.terminal
    ) {
      throw new RecoveryTransportError("SESSION_NOT_RESUMABLE");
    }
  }

  function assertCollecting(captured) {
    assertNotTerminal();
    if (!session || !COLLECTING_STATES.has(state)) {
      throw new RecoveryTransportError("SESSION_NOT_COLLECTING");
    }
    assertCapturedFresh(captured);
  }

  function storeFactor(captured, role, evidenceHex) {
    assertCapturedFresh(captured);
    if (!bitmapIncludesRole(captured.bitmap, role)) {
      failCaptured(captured, "ROLE_NOT_SELECTED");
    }
    if (captured.factors.has(role)) {
      failCaptured(captured, "ROLE_DUPLICATE_OR_REPLAY");
    }
    if (captured.factors.size >= 2) {
      failCaptured(captured, "THIRD_FACTOR_REJECTED");
    }
    captured.factors.set(role, {
      role,
      evidence: new SecretValue(evidenceHex)
    });
    if (captured.factors.size === 1) {
      state = STATES.AWAITING_SECOND_FACTOR;
    }
  }

  function createProvisionalSession(bitmap) {
    const roles = rolesSelected(bitmap);
    const issuedAtMs = now();
    const expiresAt = issuedAtMs + SESSION_TTL_MS;
    const sessionId = asBytes32Hex(randomBytes(32));
    let sessionChallenge = asBytes32Hex(randomBytes(32));
    for (
      let attempt = 0;
      sessionChallenge === sessionId && attempt < 8;
      attempt += 1
    ) {
      sessionChallenge = asBytes32Hex(randomBytes(32));
    }
    if (sessionChallenge === sessionId) {
      const distinct = Buffer.from(getBytes(sessionId));
      distinct[0] ^= 0x01;
      sessionChallenge = asBytes32Hex(distinct);
    }
    return {
      generation: Symbol("recovery-transport-session"),
      sessionId,
      sessionChallenge,
      bitmap,
      roles,
      config: null,
      context: null,
      digest: null,
      contextHash: null,
      expiresAt,
      issuedAtMs,
      factors: new Map(),
      ecdh: null,
      aesKey: null,
      sharedSecret: null,
      role1Request: null,
      transcript: null,
      transcriptHash: null,
      decryptedPayload: null,
      encryptedResponse: null,
      acknowledgement: null,
      endpoint: null,
      requestEndpoint: null,
      bootstrapUri: null,
      requestHash: null,
      canonicalRequestBytes: null,
      lockedPhoneEphemeralPublicKey: null,
      role1PublicPresentation: null,
      envelope: null,
      result: null,
      terminal: false,
      provisional: true,
      role1Collected: false,
      role2Collected: false,
      role0Collected: false,
      role1CollectInFlight: false,
      role1FactorCommitment: null
    };
  }

  async function maybeAssembleAndVerify(captured) {
    assertCapturedFresh(captured);
    if (captured.factors.size !== 2) return publicStatus();

    state = STATES.ENVELOPE_ASSEMBLED;
    const verifiedFactors = [...captured.factors.values()].map((factor) => ({
      role: factor.role,
      evidence: factor.evidence.peek()
    }));

    let envelope;
    try {
      envelope = transport.assemblePhilCoreRecoveryEnvelopeFromVerifiedFactors({
        request: {
          actionType: captured.config.actionType,
          account: captured.config.account,
          chainId: captured.config.chainId,
          entryPoint: captured.config.entryPoint,
          authorizedIntentHash: captured.config.authorizedIntentHash,
          userOpHash: captured.config.userOpHash,
          requestId: captured.config.requestId,
          recoveryConfigHash: captured.config.recoveryConfigHash,
          validatorEpoch: captured.config.validatorEpoch,
          recoveryEpoch: captured.config.recoveryEpoch,
          validAfter: captured.config.validAfter,
          validUntil: captured.config.validUntil,
          proposedValidatorCommitment:
            captured.config.proposedValidatorCommitment,
          proposedRecoveryConfigHash:
            captured.config.proposedRecoveryConfigHash,
          proposedRecoveryEpoch: captured.config.proposedRecoveryEpoch
        },
        commitments: captured.config.commitments,
        bitmap: captured.bitmap,
        verifiedFactors
      });
    } catch {
      failCaptured(captured, "ENVELOPE_ASSEMBLY_FAILED");
    }

    assertCapturedFresh(captured);
    captured.envelope = new SecretValue(envelope);

    assertCapturedFresh(captured);
    let magic;
    try {
      const commitments = captured.config.commitments;
      magic = await localStaticVerifier({
        request: {
          actionType: captured.config.actionType,
          account: captured.config.account,
          chainId: captured.config.chainId,
          entryPoint: captured.config.entryPoint,
          accountVersionId: captured.config.accountVersionId,
          securityModelId: captured.config.securityModelId,
          authorizedIntentHash: captured.config.authorizedIntentHash,
          userOpHash: captured.config.userOpHash,
          validator: captured.config.validator,
          validatorKeyIdBinding: captured.config.validatorKeyIdBinding,
          requestId: captured.config.requestId,
          recoveryConfigHash: captured.config.recoveryConfigHash,
          validatorEpoch: captured.config.validatorEpoch,
          recoveryEpoch: captured.config.recoveryEpoch,
          validAfter: captured.config.validAfter,
          validUntil: captured.config.validUntil,
          proposedValidatorCommitment:
            captured.config.proposedValidatorCommitment,
          proposedRecoveryConfigHash:
            captured.config.proposedRecoveryConfigHash,
          proposedRecoveryEpoch: captured.config.proposedRecoveryEpoch,
          primaryDeviceCommitment: commitments[0],
          hardwareSecurityKeyCommitment: commitments[1],
          recoveryFactorCommitment: commitments[2]
        },
        envelope
      });
    } catch {
      failCaptured(captured, "LOCAL_STATIC_VERIFIER_FAILED");
    }

    assertCapturedFresh(captured);
    if (!isSuccessMagic(magic)) {
      failCaptured(captured, "LOCAL_STATIC_VERIFIER_MAGIC_MISMATCH");
    }

    const result = Object.freeze({
      state: STATES.LOCAL_DRILL_PASSED,
      sessionId: captured.sessionId,
      bitmap: captured.bitmap,
      contextHash: captured.contextHash,
      digest: captured.digest,
      envelopeHash: keccak256(envelope)
    });

    clearSessionSecrets(captured);
    captured.terminal = true;
    captured.result = result;
    state = STATES.LOCAL_DRILL_PASSED;
    return publicStatus();
  }

  async function beginDrill(input = {}) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw new RecoveryTransportError("BEGIN_DRILL_PAYLOAD_INVALID");
    }
    const keys = Object.keys(input);
    if (keys.length !== 1 || keys[0] !== "bitmap") {
      throw new RecoveryTransportError("BEGIN_DRILL_UNEXPECTED_FIELD");
    }
    const bitmap = Number(input.bitmap);
    if (!ALLOWED_BITMAPS.has(bitmap)) {
      throw new RecoveryTransportError("BITMAP_INVALID");
    }

    if (session) {
      markCancelled(session);
      session.terminal = true;
    }

    const provisional = createProvisionalSession(bitmap);
    session = provisional;
    const captured = provisional;
    state = STATES.REQUEST_CONSTRUCTED;

    let config;
    try {
      config = await trustedConfigProvider();
    } catch (error) {
      if (!isCapturedCurrent(captured)) {
        throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
      }
      if (error instanceof RecoveryTransportError) {
        failCaptured(captured, error.code);
      }
      failCaptured(captured, "TRUSTED_CONFIG_PROVIDER_FAILED");
    }
    assertCapturedFresh(captured);

    if (!config || typeof config !== "object") {
      failCaptured(captured, "TRUSTED_CONFIG_INVALID");
    }
    if (Number(config.actionType) !== 8) {
      failCaptured(captured, "TRUSTED_ACTION_TYPE_INVALID");
    }

    const context = buildEvidenceContext(config, bitmap);
    let digest;
    let contextHash;
    try {
      digest = recomputeDigest(config, bitmap);
      contextHash = computePhilCoreV2ConsumerRecoveryEvidenceContextHash(context);
    } catch {
      failCaptured(captured, "TRUSTED_CONTEXT_RECOMPUTE_FAILED");
    }

    assertCapturedFresh(captured);
    captured.config = config;
    captured.context = context;
    captured.digest = digest;
    captured.contextHash = contextHash;
    captured.provisional = false;

    if (bitmapIncludesRole(bitmap, 1)) {
      if (
        !role1TransportAdapter
        || role1TransportAdapter.unavailable === true
        || typeof role1TransportAdapter.preparePresentation !== "function"
      ) {
        failCaptured(captured, "ROLE1_TRANSPORT_NOT_CONFIGURED");
      }
      if (
        typeof role1TransportAdapter.startSession !== "function"
        || typeof role1TransportAdapter.waitForResponse !== "function"
      ) {
        failCaptured(captured, "ROLE1_TRANSPORT_ADAPTER_INVALID");
      }
      if (!config.role1) {
        failCaptured(captured, "TRUSTED_ROLE1_CONFIG_REQUIRED");
      }

      // 1) Create/retain Desktop ECDH in host before binding the listener.
      const ecdh = crypto.createECDH("prime256v1");
      const desktopPublic = ecdh.generateKeys();
      captured.ecdh = ecdh;

      let presentation;
      try {
        presentation = await role1TransportAdapter.preparePresentation({
          sessionId: captured.sessionId,
          issuedAtMs: captured.issuedAtMs,
          expiresAt: captured.expiresAt,
          path: transport.PHILCORE_RECOVERY_APPROVAL_ENDPOINT_PATH
        });
      } catch (error) {
        if (!isCapturedCurrent(captured)) {
          throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
        }
        if (error instanceof RecoveryTransportError) {
          failCaptured(captured, error.code);
        }
        failCaptured(captured, "ROLE1_TRANSPORT_NOT_CONFIGURED");
      }
      assertCapturedFresh(captured);

      const completionEndpoint = presentation?.completionEndpoint
        || presentation?.endpoint;
      if (
        typeof completionEndpoint !== "string"
        || !transport.isRfc1918RecoveryApprovalEndpoint(completionEndpoint)
        || !completionEndpoint.includes(
          bootstrap.PHILCORE_RECOVERY_COMPLETION_ENDPOINT_PATH
        )
      ) {
        failCaptured(captured, "ROLE1_ENDPOINT_INVALID");
      }

      let endpointAuthority;
      try {
        endpointAuthority = parseCompletionEndpointAuthority(completionEndpoint);
      } catch (error) {
        if (error instanceof RecoveryTransportError) {
          failCaptured(captured, error.code);
        }
        failCaptured(captured, "ROLE1_ENDPOINT_INVALID");
      }

      const requestEndpoint = typeof presentation?.requestEndpoint === "string"
        && presentation.requestEndpoint.length > 0
        ? presentation.requestEndpoint
        : `http://${endpointAuthority.host}:${endpointAuthority.port}${bootstrap.PHILCORE_RECOVERY_REQUEST_ENDPOINT_PATH}`;
      captured.endpoint = completionEndpoint;
      captured.requestEndpoint = requestEndpoint;

      const approvalRequest = {
        protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
        context,
        claimedContextHash: contextHash,
        claimedRecoveryFactorDigest: digest,
        accountVersionId: config.accountVersionId,
        securityModelId: config.securityModelId,
        nativeRecoveryDomainId: config.nativeRecoveryDomainId,
        applicationIdentity: config.applicationIdentity,
        localApprovalPolicy: config.localApprovalPolicy,
        selectedRole1CredentialIdentifierCommitment:
          config.role1.credentialIdentifierCommitment,
        selectedRole1CredentialGeneration: config.role1.credentialGeneration,
        trustedRole1Descriptor: config.role1.descriptor,
        trustedRole1PublicKey: {
          qx: config.role1.publicKey.qx,
          qy: config.role1.publicKey.qy
        },
        sessionId: captured.sessionId,
        sessionChallenge: captured.sessionChallenge,
        desktopEphemeralPublicKey: encodeBase64url(desktopPublic),
        issuedAt: String(captured.issuedAtMs),
        expiresAt: String(captured.expiresAt),
        endpoint: completionEndpoint,
        now: String(captured.issuedAtMs)
      };

      let validated;
      try {
        validated = transport.validatePhilCoreRecoveryApprovalRequest(
          approvalRequest
        );
      } catch {
        failCaptured(captured, "ROLE1_REQUEST_VALIDATION_FAILED");
      }
      if (validated.digest !== digest || validated.contextHash !== contextHash) {
        failCaptured(captured, "ROLE1_REQUEST_DIGEST_MISMATCH");
      }

      let requestHash;
      let canonicalRequestBytes;
      try {
        canonicalRequestBytes =
          bootstrap.serializeCanonicalRecoveryRequest(approvalRequest);
        requestHash = bootstrap.computePhilCoreRecoveryRequestHash(
          canonicalRequestBytes
        );
      } catch {
        failCaptured(captured, "ROLE1_REQUEST_HASH_FAILED");
      }
      captured.requestHash = requestHash;
      captured.canonicalRequestBytes = canonicalRequestBytes;

      let bootstrapUri;
      try {
        const expiresAtSeconds = Math.floor(Number(captured.expiresAt) / 1000);
        const ticketBytes = bootstrap.encodePrb1Ticket({
          sessionId: Buffer.from(getBytes(captured.sessionId)),
          expiresAt: expiresAtSeconds,
          ipv4: endpointAuthority.host,
          port: endpointAuthority.port,
          desktopEphemeralPublicKey: desktopPublic,
          requestHash
        });
        if (
          ticketBytes.length !== bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_TICKET_BYTES
        ) {
          failCaptured(captured, "ROLE1_BOOTSTRAP_TICKET_INVALID");
        }
        const decodedTicket = bootstrap.decodePrb1Ticket(ticketBytes);
        bootstrap.validatePrb1TicketPolicy({
          ticket: decodedTicket,
          nowSeconds: Math.floor(Number(captured.issuedAtMs) / 1000),
          boundRequestExpiresAtMs: captured.expiresAt
        });
        const derivedRequestEndpoint =
          bootstrap.buildRequestEndpointFromTicket(decodedTicket);
        if (derivedRequestEndpoint !== requestEndpoint) {
          failCaptured(captured, "ROLE1_REQUEST_ENDPOINT_MISMATCH");
        }
        bootstrapUri = bootstrap.formatPrb1Uri(ticketBytes);
        if (
          Buffer.byteLength(bootstrapUri, "ascii")
          !== bootstrap.PHILCORE_RECOVERY_BOOTSTRAP_URI_BYTES
        ) {
          failCaptured(captured, "ROLE1_BOOTSTRAP_URI_INVALID");
        }
      } catch (error) {
        if (error instanceof RecoveryTransportError) {
          failCaptured(captured, error.code);
        }
        failCaptured(captured, "ROLE1_BOOTSTRAP_TICKET_INVALID");
      }

      const transcript = transport.buildPhilCoreNativeRecoveryApprovalTranscript(
        approvalRequest
      );
      const transcriptHash =
        transport.hashPhilCoreNativeRecoveryApprovalTranscript(transcript);
      const comparisonFingerprint =
        transport.displayPhilCoreRecoveryComparisonFingerprint(transcriptHash);
      captured.role1Request = approvalRequest;
      captured.transcript = transcript;
      captured.transcriptHash = transcriptHash;
      captured.role1FactorCommitment = validated.role1FactorCommitment;
      const pendingRole1PublicPresentation = buildRole1PublicPresentation({
        approvalRequest,
        validated,
        transcriptHash,
        bootstrapUri
      });

      const requestDeliveryCapability = async (fetchInitInput) => {
        assertCapturedFresh(captured);
        let fetchInit;
        try {
          fetchInit = bootstrap.validateFetchInit(fetchInitInput);
        } catch {
          failCaptured(captured, "ROLE1_FETCH_INIT_INVALID");
        }
        if (fetchInit.sessionId !== captured.sessionId) {
          failCaptured(captured, "ROLE1_FETCH_SESSION_MISMATCH");
        }
        if (!captured.lockedPhoneEphemeralPublicKey) {
          captured.lockedPhoneEphemeralPublicKey = fetchInit.phoneEphemeralPublicKey;
        } else if (
          captured.lockedPhoneEphemeralPublicKey
          !== fetchInit.phoneEphemeralPublicKey
        ) {
          failCaptured(captured, "ROLE1_PHONE_KEY_MISMATCH");
        }
        if (!captured.ecdh || !captured.requestHash || !captured.canonicalRequestBytes) {
          failCaptured(captured, "ROLE1_REQUEST_NOT_READY");
        }

        let phonePublic;
        let sharedSecret;
        let aesKey;
        try {
          phonePublic = transport.validateUncompressedP256PublicKey(
            fetchInit.phoneEphemeralPublicKey,
            "phone_ephemeral"
          );
          sharedSecret = captured.ecdh.computeSecret(phonePublic);
          if (sharedSecret.length !== 32) {
            failCaptured(captured, "ROLE1_REQUEST_SHARED_SECRET_INVALID");
          }
          aesKey = bootstrap.deriveRecoveryRequestAesKey(
            sharedSecret,
            captured.requestHash
          );
          return bootstrap.encryptRecoveryRequestDelivery({
            plaintext: captured.canonicalRequestBytes,
            sessionId: captured.sessionId,
            key: aesKey,
            requestHash: captured.requestHash,
            phoneEphemeralPublicKey: fetchInit.phoneEphemeralPublicKey,
            fetchChallenge: fetchInit.fetchChallenge
          });
        } catch (error) {
          if (error instanceof RecoveryTransportError) throw error;
          failCaptured(captured, "ROLE1_REQUEST_DELIVERY_FAILED");
        } finally {
          clearBuffer(sharedSecret);
          clearAesKey(aesKey);
        }
      };

      try {
        const startPayload = {
          sessionId: captured.sessionId,
          request: approvalRequest,
          transcriptHash: asBytes32Hex(transcriptHash),
          transcriptHashBytes: transcriptHash,
          comparisonFingerprint,
          desktopEcdhPublicKey: approvalRequest.desktopEphemeralPublicKey,
          completionEndpoint,
          requestEndpoint,
          bootstrapUri
        };
        if (
          role1TransportAdapter
          && role1TransportAdapter.testOnly !== true
          && typeof role1TransportAdapter.startSession === "function"
        ) {
          startPayload.requestDeliveryCapability = requestDeliveryCapability;
        } else if (
          typeof role1TransportAdapter.startSession === "function"
          && role1TransportAdapter.preparePresentation
        ) {
          // In-memory / hybrid adapters may optionally accept the capability.
          startPayload.requestDeliveryCapability = requestDeliveryCapability;
        }
        await role1TransportAdapter.startSession(startPayload);
      } catch (error) {
        if (!isCapturedCurrent(captured)) {
          throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
        }
        if (error instanceof RecoveryTransportError) {
          failCaptured(captured, error.code);
        }
        failCaptured(captured, "ROLE1_TRANSPORT_START_FAILED");
      }
      assertCapturedFresh(captured);
      if (
        typeof role1TransportAdapter.getPhase === "function"
        && role1TransportAdapter.getPhase() !== LISTENER_PHASES.SESSION_ACTIVE
        && role1TransportAdapter.testOnly !== true
      ) {
        failCaptured(captured, "ROLE1_TRANSPORT_START_FAILED");
      }
      captured.bootstrapUri = bootstrapUri;
      captured.role1PublicPresentation = pendingRole1PublicPresentation;
    }

    assertCapturedFresh(captured);
    state = STATES.AWAITING_FIRST_FACTOR;
    return publicStatus();
  }

  function beginRole0Assertion() {
    const captured = session;
    assertCollecting(captured);
    if (!bitmapIncludesRole(captured.bitmap, 0)) {
      throw new RecoveryTransportError("ROLE_NOT_SELECTED");
    }
    if (captured.factors.has(0) || captured.role0Collected) {
      throw new RecoveryTransportError("ROLE_DUPLICATE_OR_REPLAY");
    }
    const role0 = captured.config.role0;
    if (!role0?.credentialId) {
      throw new RecoveryTransportError("TRUSTED_ROLE0_CONFIG_REQUIRED");
    }
    const challenge = encodeBase64url(getBytes(captured.digest));
    return Object.freeze({
      challenge,
      timeout: 60_000,
      rpId: expectedRpId,
      userVerification: "required",
      allowCredentials: Object.freeze([
        Object.freeze({
          type: "public-key",
          id: role0.credentialId,
          transports: Object.freeze(["internal"])
        })
      ])
    });
  }

  async function submitRole0Assertion(input = {}) {
    const captured = session;
    assertCollecting(captured);
    if (!bitmapIncludesRole(captured.bitmap, 0)) {
      failCaptured(captured, "ROLE_NOT_SELECTED");
    }
    if (captured.factors.has(0) || captured.role0Collected) {
      failCaptured(captured, "ROLE_DUPLICATE_OR_REPLAY");
    }
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      failCaptured(captured, "ROLE0_ASSERTION_PAYLOAD_INVALID");
    }
    const keys = Object.keys(input);
    if (keys.length !== 1 || keys[0] !== "assertion") {
      failCaptured(captured, "ROLE0_ASSERTION_UNEXPECTED_FIELD");
    }
    const assertion = input.assertion;
    const role0 = captured.config.role0;
    if (!role0) failCaptured(captured, "TRUSTED_ROLE0_CONFIG_REQUIRED");

    const expectedChallenge = encodeBase64url(getBytes(captured.digest));
    let verification;
    try {
      verification = await assertionVerifier.verifyAssertion({
        assertion,
        credential: {
          credentialId: role0.credentialId,
          publicKey: role0.publicKey,
          publicKeyAlgorithm: role0.publicKeyAlgorithm ?? -7
        },
        expectedChallenge,
        expectedOrigin,
        expectedRpId,
        expectedUserVerification: "required",
        storedSignCount: role0.storedSignCount ?? 0
      });
    } catch {
      failCaptured(captured, "ROLE0_ASSERTION_VERIFICATION_FAILED");
    }
    assertCapturedFresh(captured);

    if (!verification?.verified || !verification?.productionVerified) {
      failCaptured(captured, "ROLE0_ASSERTION_VERIFICATION_FAILED");
    }

    let flags;
    try {
      flags = parseWebAuthnAuthenticatorData(assertion.response.authenticatorData);
    } catch {
      failCaptured(captured, "ROLE0_ASSERTION_POLICY_REJECTED");
    }
    if (
      !flags.userPresent
      || !flags.userVerified
      || flags.backupEligible
      || flags.backupState
    ) {
      failCaptured(captured, "ROLE0_ASSERTION_POLICY_REJECTED");
    }

    try {
      parseAndValidateRole0ClientData(assertion, expectedChallenge);
    } catch (error) {
      if (error instanceof RecoveryTransportError) {
        failCaptured(captured, error.code);
      }
      failCaptured(captured, "ROLE0_CLIENT_DATA_INVALID");
    }

    let evidence;
    try {
      evidence = await encodeRole0Evidence({
        assertion,
        role0,
        digest: captured.digest,
        verification
      });
    } catch (error) {
      if (!isCapturedCurrent(captured)) {
        throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
      }
      if (error instanceof RecoveryTransportError) {
        failCaptured(captured, error.code);
      }
      failCaptured(captured, "ROLE0_EVIDENCE_ENCODE_FAILED");
    }
    assertCapturedFresh(captured);

    captured.role0Collected = true;
    storeFactor(captured, 0, evidence);
    return maybeAssembleAndVerify(captured);
  }

  async function collectRole1() {
    const captured = session;
    assertCollecting(captured);
    if (captured.role1CollectInFlight) {
      throw new RecoveryTransportError("ROLE1_COLLECTION_IN_FLIGHT");
    }
    captured.role1CollectInFlight = true;
    try {
      if (!bitmapIncludesRole(captured.bitmap, 1)) {
        failCaptured(captured, "ROLE_NOT_SELECTED");
      }
      if (captured.factors.has(1) || captured.role1Collected) {
        failCaptured(captured, "ROLE_DUPLICATE_OR_REPLAY");
      }
      if (!captured.role1Request || !captured.ecdh || !captured.transcriptHash) {
        failCaptured(captured, "ROLE1_REQUEST_NOT_READY");
      }

      const timeoutMs = Math.max(1, captured.expiresAt - now());
      let encryptedMessage;
      try {
        encryptedMessage = await role1TransportAdapter.waitForResponse({
          sessionId: captured.sessionId,
          timeoutMs,
          captureSessionId: captured.sessionId
        });
      } catch (error) {
        if (!isCapturedCurrent(captured)) {
          throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
        }
        if (error instanceof RecoveryTransportError) {
          if (error.code === "ROLE1_TRANSPORT_TIMEOUT") {
            failCaptured(captured, "ROLE1_TRANSPORT_TIMEOUT");
          }
          throw error;
        }
        failCaptured(captured, "ROLE1_TRANSPORT_WAIT_FAILED");
      }
      assertCapturedFresh(captured);

    let validatedMessage;
    try {
      validatedMessage = transport.validateEncryptedNativeRecoveryResponse(
        encryptedMessage
      );
    } catch {
      failCaptured(captured, "ROLE1_RESPONSE_SCHEMA_INVALID");
    }
    if (validatedMessage.sessionId !== captured.sessionId) {
      failCaptured(captured, "ROLE1_RESPONSE_SESSION_MISMATCH");
    }
    if (
      captured.lockedPhoneEphemeralPublicKey
      && validatedMessage.phoneEphemeralPublicKey
        !== captured.lockedPhoneEphemeralPublicKey
    ) {
      failCaptured(captured, "ROLE1_PHONE_KEY_MISMATCH");
    }

    let phonePublic;
    let sharedSecret;
    let aesKey;
    try {
      phonePublic = transport.validateUncompressedP256PublicKey(
        validatedMessage.phoneEphemeralPublicKey,
        "phone_ephemeral"
      );
      sharedSecret = captured.ecdh.computeSecret(phonePublic);
      if (sharedSecret.length !== 32) {
        failCaptured(captured, "ROLE1_SHARED_SECRET_INVALID");
      }
      aesKey = transport.deriveRecoveryApprovalAesKey(
        sharedSecret,
        captured.transcriptHash
      );
    } catch (error) {
      clearBuffer(sharedSecret);
      clearAesKey(aesKey);
      if (error instanceof RecoveryTransportError) throw error;
      failCaptured(captured, "ROLE1_ECDH_FAILED");
    }

    assertCapturedFresh(captured);
    captured.sharedSecret = sharedSecret;
    captured.aesKey = aesKey;
    clearEcdh(captured.ecdh);
    captured.ecdh = null;

    let plaintext;
    try {
      plaintext = transport.decryptRecoveryApprovalMessage({
        message: validatedMessage,
        key: aesKey,
        direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_PHONE_TO_DESKTOP
      });
    } catch {
      failCaptured(captured, "ROLE1_RESPONSE_DECRYPT_FAILED");
    }
    assertCapturedFresh(captured);

    let payloadObject;
    try {
      payloadObject = JSON.parse(plaintext.toString("utf8"));
    } catch {
      clearBuffer(plaintext);
      failCaptured(captured, "ROLE1_RESPONSE_PAYLOAD_INVALID");
    }
    captured.decryptedPayload = new SecretValue(plaintext);
    captured.encryptedResponse = encryptedMessage;

    let validatedPayload;
    try {
      validatedPayload = transport.validateNativeRecoveryResponsePayload(
        payloadObject,
        {
          sessionId: captured.sessionId,
          transcriptHash: captured.transcriptHash,
          role1FactorCommitment: captured.role1FactorCommitment,
          credentialIdentifierCommitment:
            captured.config.role1.credentialIdentifierCommitment,
          credentialGeneration: Number(
            captured.config.role1.credentialGeneration
          )
        }
      );
    } catch {
      failCaptured(captured, "ROLE1_RESPONSE_BINDING_INVALID");
    }

    let evidence;
    try {
      evidence = transport.encodeNativeRecoveryEvidenceFromDer({
        descriptor: captured.config.role1.descriptor,
        factorCommitment: captured.role1FactorCommitment,
        qx: captured.config.role1.publicKey.qx,
        qy: captured.config.role1.publicKey.qy,
        derSignature: decodeBase64url(validatedPayload.derRecoverySignature),
        digest: captured.digest
      });
    } catch {
      failCaptured(captured, "ROLE1_EVIDENCE_ENCODE_FAILED");
    }
    assertCapturedFresh(captured);

    let acknowledgement;
    try {
      acknowledgement = transport.encryptRecoveryApprovalMessage({
        value: {
          protocolVersion: transport.PHILCORE_RECOVERY_APPROVAL_PROTOCOL_VERSION,
          sessionId: captured.sessionId,
          transcriptHash: asBytes32Hex(captured.transcriptHash),
          status: "ACCEPTED"
        },
        sessionId: captured.sessionId,
        key: aesKey,
        direction: transport.PHILCORE_NATIVE_RECOVERY_APPROVAL_AAD_DESKTOP_TO_PHONE,
        phoneEphemeralPublicKey: null
      });
      transport.assertDistinctRecoveryApprovalNonces(
        validatedMessage,
        acknowledgement
      );
    } catch (error) {
      if (error instanceof RecoveryTransportError) throw error;
      failCaptured(captured, "ROLE1_ACK_FAILED");
    }

    assertCapturedFresh(captured);
    captured.acknowledgement = acknowledgement;
    if (typeof role1TransportAdapter.sendAcknowledgement === "function") {
      try {
        await role1TransportAdapter.sendAcknowledgement(acknowledgement, {
          sessionId: captured.sessionId
        });
      } catch (error) {
        if (!isCapturedCurrent(captured)) {
          throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
        }
        if (error instanceof RecoveryTransportError) throw error;
        failCaptured(captured, "ROLE1_ACK_FAILED");
      }
      assertCapturedFresh(captured);
    }

    clearBuffer(plaintext);
    if (captured.decryptedPayload instanceof SecretValue) {
      captured.decryptedPayload.clear();
    }
    captured.decryptedPayload = null;
    clearAesKey(captured.aesKey);
    captured.aesKey = null;
    clearBuffer(captured.sharedSecret);
    captured.sharedSecret = null;
    captured.encryptedResponse = null;
    captured.acknowledgement = null;

      captured.role1Collected = true;
      storeFactor(captured, 1, evidence);
      return maybeAssembleAndVerify(captured);
    } finally {
      captured.role1CollectInFlight = false;
    }
  }

  async function collectRole2() {
    const captured = session;
    assertCollecting(captured);
    if (!bitmapIncludesRole(captured.bitmap, 2)) {
      failCaptured(captured, "ROLE_NOT_SELECTED");
    }
    if (captured.factors.has(2) || captured.role2Collected) {
      failCaptured(captured, "ROLE_DUPLICATE_OR_REPLAY");
    }

    let contribution;
    try {
      contribution = await role2FactorProvider({
        digest: captured.digest,
        sessionId: captured.sessionId,
        config: captured.config
      });
    } catch (error) {
      if (!isCapturedCurrent(captured)) {
        throw new RecoveryTransportError("SESSION_REPLACED_OR_CANCELLED");
      }
      if (error instanceof RecoveryTransportError) throw error;
      failCaptured(captured, "ROLE2_PROVIDER_FAILED");
    }
    assertCapturedFresh(captured);

    if (!contribution || Number(contribution.role) !== 2) {
      failCaptured(captured, "ROLE2_PROVIDER_ROLE_INVALID");
    }
    if (
      typeof contribution.evidence !== "string"
      || !/^0x[0-9a-fA-F]+$/u.test(contribution.evidence)
    ) {
      failCaptured(captured, "ROLE2_EVIDENCE_INVALID");
    }

    captured.role2Collected = true;
    storeFactor(captured, 2, contribution.evidence.toLowerCase());
    return maybeAssembleAndVerify(captured);
  }

  async function awaitRole1Approval() {
    return collectRole1();
  }

  async function runAutomatedCollection() {
    const captured = session;
    assertCollecting(captured);
    for (const role of captured.roles) {
      assertCapturedFresh(captured);
      if (captured.factors.has(role)) continue;
      if (role === 0) {
        throw new RecoveryTransportError("ROLE0_REQUIRES_ASSERTION");
      }
      if (role === 1) await collectRole1();
      if (role === 2) await collectRole2();
    }
    return publicStatus();
  }

  function cancel() {
    if (state === STATES.LOCAL_DRILL_PASSED) {
      if (session) {
        markCancelled(session);
        session.terminal = true;
      }
      return publicStatus();
    }
    if (state === STATES.NOT_STARTED && !session) {
      return publicStatus();
    }
    markCancelled(session);
    if (session) session.terminal = true;
    state = STATES.SESSION_CANCELLED;
    return publicStatus();
  }

  function status() {
    if (session && !session.terminal && COLLECTING_STATES.has(state)) {
      if (now() >= session.expiresAt) {
        markCancelled(session);
        session.terminal = true;
        state = STATES.SESSION_CANCELLED;
      }
    }
    return publicStatus();
  }

  return Object.freeze({
    status,
    beginDrill,
    beginRole0Assertion,
    submitRole0Assertion,
    collectRole1,
    awaitRole1Approval,
    collectRole2,
    cancel,
    runAutomatedCollection
  });
}

module.exports = {
  STATES,
  SESSION_TTL_MS,
  SUCCESS_MAGIC,
  RecoveryTransportError,
  safeError,
  createRecoveryTransportHost,
  createInMemoryRole1TransportAdapter,
  createProductionRole1TransportListenerAdapter,
  createUnavailableRole1TransportAdapter,
  cloneJsonSafePublicSnapshot
};
