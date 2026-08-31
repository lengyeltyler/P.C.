"use strict";

const http = require("node:http");
const { createECDH, randomBytes } = require("node:crypto");

require("tsx/cjs");

const authorization = require("../../../phil-device-sdk/src/routineAuthorizationV1.ts");
const journal = require("../../../phil-device-sdk/src/runtime/routineAuthorizationJournalV1.ts");
const transport = require("../../../phil-device-sdk/src/routineAuthorizationTransportV1.ts");

class RoutineAuthorizationHostError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "RoutineAuthorizationHostError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new RoutineAuthorizationHostError(code, message);
}

function exactOwnKeys(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) {
    fail(code, "object schema is not exact");
  }
}

function normalizeHeaders(headers) {
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) {
    fail("ROUTINE_HTTP_HEADERS_INVALID");
  }
  const normalized = Object.create(null);
  for (const [rawName, rawValue] of Object.entries(headers)) {
    const name = String(rawName).toLowerCase();
    if (Object.hasOwn(normalized, name) || Array.isArray(rawValue)) {
      fail("ROUTINE_HTTP_HEADERS_INVALID");
    }
    normalized[name] = String(rawValue);
  }
  return normalized;
}

function sanitizeError(error) {
  if (error instanceof RoutineAuthorizationHostError) return error.code;
  if (error && typeof error.code === "string" && /^[A-Z0-9_]+$/.test(error.code)) return error.code;
  return "ROUTINE_AUTHORIZATION_FAILED";
}

function defaultResponse(status, headers = {}, body = Buffer.alloc(0)) {
  return Object.freeze({ status, headers: Object.freeze({ ...headers }), body: Buffer.from(body) });
}

function validateHttpEnvelope(input, session, expectedContentType) {
  exactOwnKeys(input, ["requestId", "method", "path", "headers", "body"], "ROUTINE_HTTP_ENVELOPE_INVALID");
  if (input.method !== "POST") fail("ROUTINE_HTTP_METHOD_INVALID");
  const headers = normalizeHeaders(input.headers);
  const body = Buffer.from(input.body || []);
  if (body.length > transport.PHIL_ROUTINE_TRANSPORT_V1.maximumHttpBodyBytes) {
    fail("ROUTINE_HTTP_BODY_TOO_LARGE");
  }
  if (headers["content-type"] !== expectedContentType
    || Object.hasOwn(headers, "content-encoding")
    || Object.hasOwn(headers, "transfer-encoding")
  ) {
    fail("ROUTINE_HTTP_CONTENT_TYPE_INVALID");
  }
  if (headers.host !== `${session.ipv4}:${session.port}`
    || headers["content-length"] !== String(body.length)
    || headers["cache-control"] !== "no-store"
    || Object.hasOwn(headers, "cookie")
    || Object.hasOwn(headers, "authorization")
    || Object.hasOwn(headers, "proxy-authorization")) {
    fail("ROUTINE_HTTP_HEADERS_INVALID");
  }
  return body;
}

function destroySessionTransport(session) {
  if (Buffer.isBuffer(session.privateKey)) session.privateKey.fill(0);
  session.cipher?.destroy();session.cipher = null;
}

function createRoutineAuthorizationHost(options) {
  exactOwnKeys(options, [
    "disposableProfileId", "ipv4", "requestFactory", "readTrustedState", "simulate", "execute",
    "reconcile", "protectedKeyStore", "journalStore", "requestStore", "now",
    ...(Object.hasOwn(options,"readCurrentNonce") ? ["readCurrentNonce"] : [])
  ], "ROUTINE_HOST_OPTIONS_INVALID");
  if (typeof options.requestFactory !== "function" || typeof options.readTrustedState !== "function"
    || typeof options.simulate !== "function" || typeof options.execute !== "function"
    || typeof options.reconcile !== "function" || typeof options.now !== "function") {
    fail("ROUTINE_HOST_DEPENDENCY_INVALID");
  }
  for (const method of ["create", "load", "delete"]) {
    if (typeof options.protectedKeyStore?.[method] !== "function") fail("ROUTINE_KEY_STORE_INVALID");
  }
  for (const method of ["append", "read", "list", "delete"]) {
    if (typeof options.journalStore?.[method] !== "function") fail("ROUTINE_JOURNAL_STORE_INVALID");
  }
  for (const method of ["save", "load", "list", "delete"]) {
    if (typeof options.requestStore?.[method] !== "function") fail("ROUTINE_REQUEST_STORE_INVALID");
  }

  const sessions = new Map();
  let journalKey;
  try { journalKey = Buffer.from(options.protectedKeyStore.load(options.disposableProfileId)); }
  catch { journalKey = Buffer.from(options.protectedKeyStore.create(options.disposableProfileId, randomBytes(32))); }
  if (journalKey.length !== 32) fail("ROUTINE_JOURNAL_KEY_INVALID");
  const journalCipher = new journal.PhilRoutineJournalFrameCipherV1({
    key: journalKey,
    disposableProfileId: options.disposableProfileId
  });
  const coordinator = new journal.PhilRoutineAuthorizationSyntheticCoordinatorV1({
    now: options.now,
    flush: async (record) => {
      const encrypted = journalCipher.encryptRecord(record);
      await options.journalStore.append(record.requestId, record.generation, encrypted);
    },
    readTrustedState: options.readTrustedState,
    simulate: async (request) => options.simulate(request,sessions.get(request.requestId)?.response),
    execute: options.execute,
    reconcile: options.reconcile
  });
  let listener = null;
  let activeLifecycleOperations = 0;
  let deletingProfile = false;

  let operationTail = Promise.resolve();
  function exclusive(operation) {
    const result = operationTail.then(operation);
    operationTail = result.catch(() => {});
    return result;
  }
  async function expireSession(session) {
    if (["terminal", "cancelled", "expired", "transport_failed"].includes(session.state)) return;
    if (BigInt(options.now()) < BigInt(session.request.authorizationCore.expiresAt)) return;
    const outcome = await coordinator.expireRoutineAuthorization(session.request.requestId);
    if (outcome === "expired") { session.state = "expired"; destroySessionTransport(session); }
    // A committed/unknown outcome remains protected; elapsed time cannot cancel it.
  }

  function hasUnresolvedOutcome() {
    return [...sessions.values()].some(session => [6,7,8,24,25].includes(
      coordinator.getRoutineAuthorizationStatus(session.request.requestId).state));
  }

  async function beginRoutineAuthorization(typedApplicationIntent, input = {}) {
    if (deletingProfile) fail("ROUTINE_PROFILE_DELETION_ACTIVE");
    activeLifecycleOperations += 1;
    try {
    if (Object.keys(input).some((key) => !["port"].includes(key))) fail("ROUTINE_BEGIN_OPTIONS_INVALID");
    for (const session of sessions.values()) await expireSession(session);
    if (hasUnresolvedOutcome()) fail("ROUTINE_UNRESOLVED_SUBMISSION_EXISTS");
    if ([...sessions.values()].some((entry) => entry.state !== "terminal" && entry.state !== "cancelled" && entry.state !== "expired" && entry.state !== "transport_failed")) {
      fail("ROUTINE_ACTIVE_SESSION_EXISTS");
    }
    const request = authorization.validatePhilRoutineAuthorizationRequestV1(
      await options.requestFactory(typedApplicationIntent)
    );
    const canonicalRequestJson = authorization.serializePhilRoutineAuthorizationRequestJsonV1(request);
    await options.requestStore.save(request.requestId, canonicalRequestJson);
    try { await coordinator.beginRoutineAuthorization(request); }
    catch (error) { await options.requestStore.delete(request.requestId);throw error; }
    const ecdh = createECDH("prime256v1");
    ecdh.generateKeys();
    const port = input.port || listener?.address()?.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) fail("ROUTINE_LISTENER_PORT_INVALID");
    const bootstrap = Object.freeze({
      sessionId: request.authorizationCore.sessionId,
      ipv4: options.ipv4,
      port,
      desktopPublicKeyX963: `0x${ecdh.getPublicKey(undefined, "uncompressed").toString("hex")}`,
      requestId: request.requestId,
      expiresAt: request.authorizationCore.expiresAt
    });
    const session = {
      request,
      bootstrap,
      privateKey: Buffer.from(ecdh.getPrivateKey()),
      state: "transport_waiting",
      phoneKeyAccepted: false,
      completeAccepted: false,
      fingerprint: null,
      cipher: null
    };
    sessions.set(request.requestId, session);
    return Object.freeze({
      requestId: request.requestId,
      qrPayload: transport.encodePhilRoutineTransportBootstrapV1(bootstrap),
      expiresAt: request.authorizationCore.expiresAt,
      status: "transport_waiting"
    });
    } finally { activeLifecycleOperations -= 1; }
  }

  async function publicStatus(requestId) {
    const session = sessions.get(String(requestId).toLowerCase());
    if (!session) fail("ROUTINE_REQUEST_UNKNOWN");
    await expireSession(session);
    const status = coordinator.getRoutineAuthorizationStatus(session.request.requestId);
    return Object.freeze({
      requestId: status.requestId,
      state: status.state,
      terminalReason: status.terminalReason,
      comparisonFingerprint: session.fingerprint,
      expiresAt: session.request.authorizationCore.expiresAt
    });
  }

  async function acceptanceBaseline() {
    for (const session of sessions.values()) await expireSession(session);
    const states=[...sessions.values()].map(session=>coordinator.getRoutineAuthorizationStatus(session.request.requestId));
    const active=states.filter(status=>status.state<9 || [24,25].includes(status.state));
    if(typeof options.readCurrentNonce!=="function") fail("ROUTINE_BASELINE_NONCE_UNAVAILABLE");
    return Object.freeze({schemaVersion:1,observedAt:String(options.now()),pendingRequestCount:active.length,
      activeRequestId:active.length===1 ? active[0].requestId : null,
      unresolvedSubmissionCount:states.filter(status=>[6,7,8,24,25].includes(status.state)).length,
      expectedNonce:await options.readCurrentNonce()});
  }

  async function handleBegin(input, session) {
    if (session.phoneKeyAccepted) fail("ROUTINE_BEGIN_REPLAY");
    const body = validateHttpEnvelope(input, session.bootstrap, "application/json");
    const begin = transport.parsePhilRoutineTransportBeginJsonV1(body);
    if (begin.sessionId !== session.bootstrap.sessionId || begin.requestId !== session.bootstrap.requestId) {
      fail("ROUTINE_BEGIN_BINDING_INVALID");
    }
    const transcriptHash = transport.derivePhilRoutineTransportTranscriptHashV1({
      bootstrap: session.bootstrap,
      iphonePublicKeyX963: begin.iphonePublicKey
    });
    const key = transport.derivePhilRoutineTransportKeyV1({
      privateKey: session.privateKey,
      peerPublicKeyX963: begin.iphonePublicKey,
      transcriptHash
    });
    session.cipher = new transport.PhilRoutineTransportCipherV1({ key });
    session.phoneKeyAccepted = true;
    session.fingerprint = transport.formatPhilRoutineTransportFingerprintV1(transcriptHash);
    session.state = "fingerprint_confirmation_required";
    session.privateKey.fill(0);
    const aad = transport.derivePhilRoutineTransportAadV1({
      direction: "request",
      sessionId: session.bootstrap.sessionId,
      requestId: session.bootstrap.requestId
    });
    const plaintext = authorization.serializePhilRoutineAuthorizationRequestJsonV1(session.request);
    const encrypted = session.cipher.encrypt({ plaintext, aad });
    return defaultResponse(200, {
      "content-type": "application/octet-stream",
      "content-length": String(encrypted.length),
      "cache-control": "no-store",
      connection: "close"
    }, encrypted);
  }

  async function handleComplete(input, session) {
    if (!session.phoneKeyAccepted || !session.cipher) fail("ROUTINE_COMPLETE_OUT_OF_ORDER");
    if (session.completeAccepted) fail("ROUTINE_COMPLETE_REPLAY");
    const body = validateHttpEnvelope(input, session.bootstrap, "application/octet-stream");
    const aad = transport.derivePhilRoutineTransportAadV1({
      direction: "response",
      sessionId: session.bootstrap.sessionId,
      requestId: session.bootstrap.requestId
    });
    const plaintext = session.cipher.decrypt({ frame: body, aad });
    const response = authorization.parsePhilRoutineAuthorizationResponseJsonV1({
      request: session.request,
      json: plaintext
    });
    session.response = response;
    destroySessionTransport(session);
    session.completeAccepted = true;
    await coordinator.acceptRoutineDeviceResponse({ requestId: session.request.requestId, response });
    await coordinator.simulateApprovedRoutineAuthorization(session.request.requestId);
    try {
      await coordinator.commitAndExecuteSimulatedRoutineAuthorization(session.request.requestId);
      await coordinator.reconcileRoutineAuthorization(session.request.requestId);
    }
    finally { session.state = "terminal"; }
    if (coordinator.getRoutineAuthorizationStatus(session.request.requestId).state !== 9) {
      fail("ROUTINE_EXECUTION_OUTCOME_NOT_SUCCESSFUL");
    }
    return defaultResponse(204, {
      "content-length": "0",
      "cache-control": "no-store",
      connection: "close"
    });
  }

  async function handleTerminal(input, session) {
    if (!session.phoneKeyAccepted || !session.cipher || session.completeAccepted) fail("ROUTINE_TERMINAL_OUT_OF_ORDER");
    const body = validateHttpEnvelope(input, session.bootstrap, "application/octet-stream");
    const aad = (direction) => transport.derivePhilRoutineTransportAadV1({direction,
      sessionId:session.bootstrap.sessionId, requestId:session.bootstrap.requestId});
    const terminal = transport.parsePhilRoutineTerminalV1(session.cipher.decrypt({frame:body, aad:aad("terminal")}));
    if (terminal.sessionId !== session.bootstrap.sessionId || terminal.requestId !== session.bootstrap.requestId) {
      fail("ROUTINE_TERMINAL_BINDING_INVALID");
    }
    const result = terminal.outcome === "rejected"
      ? await coordinator.rejectRoutineAuthorization(session.request.requestId)
      : await coordinator.cancelRoutineAuthorization(session.request.requestId);
    if (result !== terminal.outcome) fail("ROUTINE_TERMINAL_OUT_OF_ORDER");
    const acknowledgement = session.cipher.encrypt({plaintext:JSON.stringify({...terminal,purpose:"PHIL_ROUTINE_TERMINAL_ACK_V1"}),aad:aad("terminalAck")});
    session.state = "cancelled"; destroySessionTransport(session);
    return defaultResponse(200, {"content-type":"application/octet-stream","content-length":String(acknowledgement.length),
      "cache-control":"no-store",connection:"close"}, acknowledgement);
  }

  function dispatchHttp(input) { return exclusive(() => dispatchHttpUnlocked(input)); }
  async function dispatchHttpUnlocked(input) {
    if (deletingProfile) return defaultResponse(409);
    activeLifecycleOperations += 1;
    try {
    const requestId = input?.requestId;
    if (typeof requestId !== "string") return defaultResponse(404);
    const session = sessions.get(requestId.toLowerCase());
    if (!session) return defaultResponse(404);
    await expireSession(session);
    if (session.state === "expired") return defaultResponse(410);
    if (["terminal", "cancelled", "transport_failed"].includes(session.state)) return defaultResponse(409);
    try {
      if (input.path === transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath) return await handleBegin(input, session);
      if (input.path === transport.PHIL_ROUTINE_TRANSPORT_V1.terminalPath) return await handleTerminal(input, session);
      if (input.path === transport.PHIL_ROUTINE_TRANSPORT_V1.completePath) return await handleComplete(input, session);
      return defaultResponse(404);
    } catch (error) {
      const code = sanitizeError(error);
      const status = code.includes("TOO_LARGE") ? 413
        : code.includes("CONTENT_TYPE") ? 415
          : code.includes("REPLAY") || code.includes("OUT_OF_ORDER") ? 409
            : 400;
      if (status !== 409) {
        await coordinator.failRoutineTransport(session.request.requestId);
        session.state = "transport_failed";destroySessionTransport(session);
      }
      return defaultResponse(status, { "content-length": "0", "cache-control": "no-store", connection: "close" });
    }
    } finally { activeLifecycleOperations -= 1; }
  }

  async function cancelRoutineAuthorization(requestId) {
    if (deletingProfile) fail("ROUTINE_PROFILE_DELETION_ACTIVE");
    activeLifecycleOperations += 1;
    try {
    const session = sessions.get(String(requestId).toLowerCase());
    if (!session) fail("ROUTINE_REQUEST_UNKNOWN");
    const result = await coordinator.cancelRoutineAuthorization(session.request.requestId);
    if (result === "cancelled") {
      session.state = "cancelled";
      destroySessionTransport(session);
    }
    return result;
    } finally { activeLifecycleOperations -= 1; }
  }

  async function reconcileRoutineAuthorization(requestId) {
    if (deletingProfile) fail("ROUTINE_PROFILE_DELETION_ACTIVE");
    activeLifecycleOperations += 1;
    try { return await coordinator.reconcileRoutineAuthorization(requestId); }
    finally { activeLifecycleOperations -= 1; }
  }

  async function restoreRoutineAuthorization(input) {
    if (deletingProfile) fail("ROUTINE_PROFILE_DELETION_ACTIVE");
    activeLifecycleOperations += 1;
    try {
    exactOwnKeys(input, ["requestId"], "ROUTINE_RESTORE_INPUT_INVALID");
    const requestId = String(input.requestId).toLowerCase();
    const request = authorization.parsePhilRoutineAuthorizationRequestJsonV1(
      await options.requestStore.load(requestId)
    );
    if (request.requestId !== requestId) fail("ROUTINE_RESTORE_REQUEST_ID_MISMATCH");
    if (sessions.has(request.requestId)) fail("ROUTINE_RESTORE_REPLAY");
    const key = Buffer.from(options.protectedKeyStore.load(options.disposableProfileId));
    if (key.length !== 32) fail("ROUTINE_JOURNAL_KEY_INVALID");
    const cipher = new journal.PhilRoutineJournalFrameCipherV1({ key, disposableProfileId: options.disposableProfileId });
    const frames = await options.journalStore.read(request.requestId);
    coordinator.restoreEncryptedRoutineAuthorization({
      request,
      frameCipher: cipher,
      journalFrameJsonChain: frames
    });
    sessions.set(request.requestId, {
      request, bootstrap: null, privateKey: Buffer.alloc(0), state: "restoring",
      phoneKeyAccepted: false, completeAccepted: false, fingerprint: null, cipher: null
    });
    try { return await coordinator.reconcileRoutineAuthorization(request.requestId); }
    finally { sessions.get(request.requestId).state = "terminal";cipher.destroy();key.fill(0); }
    } finally { activeLifecycleOperations -= 1; }
  }

  async function restoreAllRoutineAuthorizations() {
    const results = [];
    for (const requestId of await options.requestStore.list()) {
      results.push(Object.freeze({ requestId, result: await restoreRoutineAuthorization({ requestId }) }));
    }
    return Object.freeze(results);
  }

  function assertDisposableProfileDeletionSafe() {
    if (deletingProfile || activeLifecycleOperations > 0 || hasUnresolvedOutcome()
      || [...sessions.values()].some((entry) => !["terminal","cancelled","expired","transport_failed"].includes(entry.state))) {
      fail("ROUTINE_PROFILE_DELETE_TOO_EARLY");
    }
    return true;
  }

  function disposeForDeviceReplacement() {
    assertDisposableProfileDeletionSafe();
    for (const session of sessions.values()) destroySessionTransport(session);
    sessions.clear();journalCipher.destroy();journalKey.fill(0);
  }

  function disposeAfterDurableDeletion() { disposeForDeviceReplacement(); }

  async function deleteDisposableProfile() {
    assertDisposableProfileDeletionSafe();
    deletingProfile = true;
    try {
    for (const session of sessions.values()) {
      destroySessionTransport(session);
    }
    const requestIds = new Set([
      ...await options.journalStore.list(),
      ...await options.requestStore.list()
    ]);
    for (const requestId of requestIds) {
      await options.journalStore.delete(requestId);
      await options.requestStore.delete(requestId);
    }
    sessions.clear();
    journalCipher.destroy();
    journalKey.fill(0);
    await options.protectedKeyStore.delete(options.disposableProfileId);
    return Object.freeze({ status: "deleted", identityOrRecoveryStateTouched: false });
    } finally { deletingProfile = false; }
  }

  async function startListener() {
    if (listener) fail("ROUTINE_LISTENER_ALREADY_STARTED");
    listener = http.createServer(async (request, response) => {
      request.socket.setKeepAlive(false);
      const headerNames = request.rawHeaders.filter((_value,index) => index % 2 === 0).map((name) => name.toLowerCase());
      if (request.httpVersion !== "1.1" || new Set(headerNames).size !== headerNames.length) {
        response.writeHead(400, { "content-length": "0", "cache-control": "no-store", connection: "close" });response.end();return;
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > 65536) { response.writeHead(413, { "content-length": "0", connection: "close" });response.end();return; }
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks);
      let requestId = null;
      try {
        if (request.url === transport.PHIL_ROUTINE_TRANSPORT_V1.beginPath) {
          requestId = transport.parsePhilRoutineTransportBeginJsonV1(body).requestId;
        } else {
          // Route to an explicit request, never whichever request is currently active.
          // The header grants no authority: AEAD still binds session and request.
          const routed = request.headers["x-philcore-routine-request"];
          requestId = typeof routed === "string" && /^0x[0-9a-f]{64}$/.test(routed) ? routed : null;
        }
      } catch {}
      const result = await dispatchHttp({ requestId, method: request.method, path: request.url, headers: request.headers, body });
      response.writeHead(result.status, result.headers);response.end(result.body);
    });
    await new Promise((resolve, reject) => {
      listener.once("error", reject);
      listener.listen({ host: options.ipv4, port: 0, exclusive: true }, resolve);
    });
    return Object.freeze({ ipv4: options.ipv4, port: listener.address().port });
  }

  async function stopListener() {
    if (!listener) return;
    const current = listener;listener = null;
    await new Promise((resolve, reject) => current.close((error) => error ? reject(error) : resolve()));
  }

  return Object.freeze({
    beginRoutineAuthorization: (...args) => exclusive(() => beginRoutineAuthorization(...args)),
    getRoutineAuthorizationStatus: (...args) => exclusive(() => publicStatus(...args)),
    cancelRoutineAuthorization: (...args) => exclusive(() => cancelRoutineAuthorization(...args)),
    reconcileRoutineAuthorization,
    restoreRoutineAuthorization,
    restoreAllRoutineAuthorizations,
    dispatchHttp,
    acceptanceBaseline: () => exclusive(acceptanceBaseline),
    startListener,
    stopListener,
    assertDisposableProfileDeletionSafe,
    disposeForDeviceReplacement,
    disposeAfterDurableDeletion,
    deleteDisposableProfile
  });
}

module.exports = {
  RoutineAuthorizationHostError,
  createRoutineAuthorizationHost
};
