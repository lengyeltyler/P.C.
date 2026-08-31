const crypto = require("node:crypto");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");

const PROTOCOL_VERSION = 1;
const SESSION_TTL_MS = 5 * 60 * 1000;
const MAX_BODY_BYTES = 96 * 1024;
const APPLICATION_IDENTITY =
  "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha";
const LOCAL_APPROVAL_POLICY =
  "PHILCORE_LOCAL_APPROVAL_V1|DEVICE_OWNER_AUTHENTICATION|FOREGROUND_ONLY|EXACT_DIGEST";
const ACCOUNT_VERSION_ID =
  "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f";
const SECURITY_MODEL_ID =
  "0xbfded32375d70119930c009b80e9a3774335bb0ae2fc4d3b7133fd8713753f44";

class NativePairingError extends Error {
  constructor(code) {
    super(code);
    this.name = "NativePairingError";
    this.code = /^[A-Z0-9_]{3,96}$/u.test(code)
      ? code
      : "NATIVE_PAIRING_INTERNAL_ERROR";
  }
}

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64url(value, exactLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,4096}$/u.test(value)) {
    throw new NativePairingError("PAIRING_BASE64URL_INVALID");
  }
  const decoded = Buffer.from(value, "base64url");
  if (exactLength !== undefined && decoded.length !== exactLength) {
    throw new NativePairingError("PAIRING_VALUE_LENGTH_INVALID");
  }
  return decoded;
}

function sha256(...parts) {
  const hash = crypto.createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function canonicalTranscript(request) {
  return Buffer.from([
    "PHILCORE_NATIVE_PAIRING_V1",
    String(request.protocolVersion),
    request.sessionId,
    request.expiresAt,
    request.endpoint,
    request.desktopEphemeralPublicKey,
    request.challenge,
    request.philCoreIdentityCommitment,
    request.accountVersionId,
    request.securityModelId,
    String(request.recoveryEpoch),
    String(request.requestedGeneration),
    request.applicationIdentity
  ].join("\n"), "utf8");
}

function displayFingerprint(value) {
  const hex = sha256(value).toString("hex").toUpperCase().slice(0, 24);
  return hex.match(/.{4}/gu).join(" ");
}

function privateIPv4(address) {
  const octets = String(address).split(".").map(Number);
  if (octets.length !== 4 || octets.some((value) =>
    !Number.isInteger(value) || value < 0 || value > 255
  )) return false;
  return octets[0] === 10
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168);
}

function listPrivateInterfaces(networkInterfaces = os.networkInterfaces()) {
  const entries = [];
  for (const [name, values] of Object.entries(networkInterfaces)) {
    for (const value of values || []) {
      if (
        value.family === "IPv4"
        && value.internal !== true
        && privateIPv4(value.address)
      ) entries.push(Object.freeze({ name, address: value.address }));
    }
  }
  return Object.freeze(entries.sort((a, b) =>
    `${a.name}:${a.address}`.localeCompare(`${b.name}:${b.address}`)
  ));
}

function parseMacHardwarePorts(value) {
  if (typeof value !== "string" || value.length > 64 * 1024) return Object.freeze([]);
  const names = [];
  let hardwarePort = null;
  for (const line of value.split(/\r?\n/u)) {
    const port = /^Hardware Port: (.+)$/u.exec(line);
    if (port) {
      hardwarePort = port[1];
      continue;
    }
    const device = /^Device: ([a-z][a-z0-9]{0,15})$/u.exec(line);
    if (device && (hardwarePort === "Wi-Fi" || hardwarePort === "AirPort")) names.push(device[1]);
  }
  return Object.freeze([...new Set(names)]);
}

function selectIPhonePrivateInterface(options = {}) {
  const candidates = listPrivateInterfaces(options.networkInterfaces || os.networkInterfaces());
  if (!candidates.length) return null;
  let hardwarePortsText = options.hardwarePortsText;
  if (hardwarePortsText === undefined && process.platform === "darwin") {
    try {
      hardwarePortsText = (options.execFileSync || childProcess.execFileSync)(
        "/usr/sbin/networksetup",
        ["-listallhardwareports"],
        { encoding: "utf8", timeout: 2_000, maxBuffer: 64 * 1024 }
      );
    } catch {
      hardwarePortsText = "";
    }
  }
  const wifiNames = parseMacHardwarePorts(hardwarePortsText || "");
  return wifiNames.map((name) => candidates.find((candidate) => candidate.name === name)).find(Boolean)
    || candidates.find((candidate) => candidate.name === "en0")
    || candidates[0];
}

function keyFromSharedSecret(secret, transcriptHash) {
  return Buffer.from(crypto.hkdfSync(
    "sha256",
    secret,
    transcriptHash,
    Buffer.from("PHILCORE_NATIVE_PAIRING_AES256_GCM_V1", "utf8"),
    32
  ));
}

function decryptMessage(message, key, direction) {
  if (
    message?.version !== 1
    || typeof message.sessionId !== "string"
    || typeof message.nonce !== "string"
    || typeof message.ciphertext !== "string"
    || typeof message.tag !== "string"
  ) throw new NativePairingError("PAIRING_MESSAGE_SCHEMA_INVALID");
  const nonce = decodeBase64url(message.nonce, 12);
  const ciphertext = decodeBase64url(message.ciphertext);
  const tag = decodeBase64url(message.tag, 16);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(Buffer.from(`${direction}|${message.sessionId}`, "utf8"));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new NativePairingError("PAIRING_MESSAGE_AUTHENTICATION_FAILED");
  }
}

function encryptMessage(value, sessionId, key, direction) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(`${direction}|${sessionId}`, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final()
  ]);
  return Object.freeze({
    version: 1,
    sessionId,
    phoneEphemeralPublicKey: null,
    nonce: base64url(nonce),
    ciphertext: base64url(ciphertext),
    tag: base64url(cipher.getAuthTag())
  });
}

function p256PublicKey(raw) {
  if (raw.length !== 65 || raw[0] !== 4) {
    throw new NativePairingError("PAIRING_CREDENTIAL_PUBLIC_KEY_INVALID");
  }
  return crypto.createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: base64url(raw.subarray(1, 33)),
      y: base64url(raw.subarray(33, 65))
    },
    format: "jwk"
  });
}

function validateResponse(payload, session, { allowSimulator }) {
  if (
    payload?.protocolVersion !== PROTOCOL_VERSION
    || payload.sessionId !== session.request.sessionId
    || payload.applicationIdentity !== APPLICATION_IDENTITY
    || payload.generation !== session.request.requestedGeneration
    || typeof payload.credentialFingerprint !== "string"
    || payload.credentialFingerprint.length > 64
  ) throw new NativePairingError("PAIRING_RESPONSE_BINDING_INVALID");
  const transcript = canonicalTranscript(session.request);
  const transcriptHash = sha256(transcript);
  if (!crypto.timingSafeEqual(
    decodeBase64url(payload.transcriptHash, 32),
    transcriptHash
  )) throw new NativePairingError("PAIRING_TRANSCRIPT_SUBSTITUTION");

  const publicKey = decodeBase64url(payload.credentialPublicKey, 65);
  if (payload.credentialFingerprint !== displayFingerprint(publicKey)) {
    throw new NativePairingError("PAIRING_PUBLIC_FINGERPRINT_INVALID");
  }
  const expectedCredentialId = sha256(
    Buffer.from("PHILCORE_NATIVE_CREDENTIAL_ID_V1", "utf8"),
    publicKey
  );
  const generation = Buffer.alloc(8);
  generation.writeBigUInt64BE(BigInt(payload.generation));
  const expectedCustody = sha256(
    Buffer.from("PHILCORE_NATIVE_DEVICE_CUSTODY_V1", "utf8"),
    publicKey,
    generation
  );
  const exact = [
    [payload.credentialIdentifierCommitment, expectedCredentialId],
    [payload.applicationIdentityHash, sha256(Buffer.from(APPLICATION_IDENTITY, "utf8"))],
    [payload.deviceCustodyCommitment, expectedCustody],
    [payload.localApprovalPolicyHash, sha256(Buffer.from(LOCAL_APPROVAL_POLICY, "utf8"))]
  ];
  for (const [encoded, expected] of exact) {
    if (!crypto.timingSafeEqual(decodeBase64url(encoded, 32), expected)) {
      throw new NativePairingError("PAIRING_DESCRIPTOR_COMMITMENT_INVALID");
    }
  }
  if (allowSimulator) {
    if (payload.simulatorOnly !== true || payload.secureEnclaveBacked !== false) {
      throw new NativePairingError("PAIRING_DISPOSABLE_CLASS_INVALID");
    }
  } else if (
    payload.simulatorOnly !== false
    || payload.secureEnclaveBacked !== true
  ) {
    throw new NativePairingError("PAIRING_SECURE_ENCLAVE_REQUIRED");
  }
  const signature = decodeBase64url(payload.enrollmentSignatureDER);
  if (!crypto.verify("sha256", transcript, p256PublicKey(publicKey), signature)) {
    throw new NativePairingError("PAIRING_ENROLLMENT_SIGNATURE_INVALID");
  }
  return Object.freeze({
    verifierKind: 4,
    descriptorVersion: 1,
    role: 1,
    publicKeyX963: base64url(publicKey),
    qx: `0x${publicKey.subarray(1, 33).toString("hex")}`,
    qy: `0x${publicKey.subarray(33, 65).toString("hex")}`,
    publicFingerprint: displayFingerprint(publicKey),
    credentialIdentifierCommitment:
      `0x${expectedCredentialId.toString("hex")}`,
    applicationIdentity: APPLICATION_IDENTITY,
    applicationIdentityHash:
      `0x${sha256(Buffer.from(APPLICATION_IDENTITY, "utf8")).toString("hex")}`,
    deviceCustodyCommitment: `0x${expectedCustody.toString("hex")}`,
    localApprovalPolicyHash:
      `0x${sha256(Buffer.from(LOCAL_APPROVAL_POLICY, "utf8")).toString("hex")}`,
    generation: payload.generation,
    secureEnclaveRequired: !allowSimulator,
    simulatorCredential: allowSimulator,
    appAttest: "DEFERRED_OPTIONAL_ENROLLMENT_ATTESTATION",
    enrollmentTranscriptHash: `0x${transcriptHash.toString("hex")}`
  });
}

function createNativeRole1DescriptorStore({ storageRoot, encryptionAdapter }) {
  const root = path.resolve(storageRoot);
  if (root === path.parse(root).root) {
    throw new NativePairingError("NATIVE_DESCRIPTOR_STORAGE_ROOT_INVALID");
  }
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") fs.chmodSync(root, 0o700);
  const filePath = path.join(root, "native-role1-descriptor.v1.json");
  const rootBinding = sha256(Buffer.from(root, "utf8")).toString("hex");

  function assertAdapter() {
    if (!encryptionAdapter?.isAvailable?.()) {
      throw new NativePairingError("NATIVE_DESCRIPTOR_PROTECTED_STORAGE_UNAVAILABLE");
    }
  }

  function read() {
    assertAdapter();
    if (!fs.existsSync(filePath)) return null;
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new NativePairingError("NATIVE_DESCRIPTOR_PATH_INVALID");
    }
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
      throw new NativePairingError("NATIVE_DESCRIPTOR_PERMISSIONS_INVALID");
    }
    try {
      const envelope = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (
        envelope.version !== 1
        || envelope.rootBinding !== rootBinding
        || typeof envelope.ciphertext !== "string"
      ) throw new NativePairingError("NATIVE_DESCRIPTOR_ENVELOPE_INVALID");
      const encrypted = Buffer.from(envelope.ciphertext, "base64");
      if (
        sha256(encrypted).toString("hex")
        !== envelope.ciphertextSha256
      ) throw new NativePairingError("NATIVE_DESCRIPTOR_CIPHERTEXT_CORRUPTED");
      const record = JSON.parse(encryptionAdapter.decrypt(encrypted));
      if (
        record.version !== 1
        || record.applicationIdentity !== APPLICATION_IDENTITY
        || record.descriptor?.role !== 1
        || record.descriptor?.verifierKind !== 4
      ) throw new NativePairingError("NATIVE_DESCRIPTOR_RECORD_INVALID");
      return record;
    } catch (error) {
      if (error instanceof NativePairingError) throw error;
      throw new NativePairingError("NATIVE_DESCRIPTOR_DECRYPTION_FAILED");
    }
  }

  function write(descriptor) {
    assertAdapter();
    if (
      descriptor?.role !== 1
      || descriptor?.verifierKind !== 4
      || descriptor?.applicationIdentity !== APPLICATION_IDENTITY
      || !Number.isSafeInteger(descriptor.generation)
      || descriptor.generation < 1
    ) throw new NativePairingError("NATIVE_DESCRIPTOR_INVALID");
    const existing = read();
    if (existing && descriptor.generation !== existing.descriptor.generation + 1) {
      throw new NativePairingError("NATIVE_DESCRIPTOR_GENERATION_INVALID");
    }
    const record = {
      version: 1,
      applicationIdentity: APPLICATION_IDENTITY,
      descriptor,
      enrolledAt: new Date().toISOString(),
      lostDevice: false,
      containsPrivateKey: false
    };
    persistRecord(record);
    return publicStatus();
  }

  function persistRecord(record) {
    const encrypted = Buffer.from(encryptionAdapter.encrypt(JSON.stringify(record)));
    const envelope = {
      version: 1,
      rootBinding,
      ciphertextSha256: sha256(encrypted).toString("hex"),
      ciphertext: encrypted.toString("base64")
    };
    const temporary = path.join(root, `.native-role1.${process.pid}.${base64url(crypto.randomBytes(8))}.tmp`);
    fs.writeFileSync(temporary, `${JSON.stringify(envelope, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx"
    });
    fs.renameSync(temporary, filePath);
    if (process.platform !== "win32") fs.chmodSync(filePath, 0o600);
  }

  function markLost() {
    const existing = read();
    if (!existing) return Object.freeze({ enrolled: false, lostDevice: true });
    const record = { ...existing, lostDevice: true, invalidatedAt: new Date().toISOString() };
    persistRecord(record);
    return publicStatus();
  }

  function publicStatus() {
    const record = read();
    return Object.freeze({
      enrolled: Boolean(record),
      lostDevice: record?.lostDevice === true,
      generation: record?.descriptor?.generation || null,
      publicFingerprint: record?.descriptor?.publicFingerprint || null,
      applicationIdentity: record?.applicationIdentity || APPLICATION_IDENTITY,
      simulatorCredential: record?.descriptor?.simulatorCredential ?? null,
      containsPrivateKey: false
    });
  }

  return Object.freeze({ read, write, markLost, publicStatus, filePath });
}

function createNativeIPhonePairingHost({
  interfaceAddress,
  interfaceName = null,
  port = 0,
  now = () => Date.now(),
  randomBytes = crypto.randomBytes,
  onVerified = () => {},
  allowSimulator = false
} = {}) {
  if (!privateIPv4(interfaceAddress)) {
    throw new NativePairingError("PAIRING_PRIVATE_INTERFACE_REQUIRED");
  }
  const sessions = new Map();
  let server = null;
  let listeningPort = null;
  let completedDescriptor = null;

  async function start() {
    if (server) return status();
    server = http.createServer(async (request, response) => {
      response.setHeader("cache-control", "no-store");
      response.setHeader("content-security-policy", "default-src 'none'");
      if (
        request.method !== "POST"
        || request.url !== "/philcore/pair/v1/complete"
        || request.headers["content-type"]?.split(";")[0] !== "application/json"
      ) {
        response.writeHead(404).end();
        return;
      }
      let size = 0;
      const chunks = [];
      request.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) request.destroy();
        else chunks.push(chunk);
      });
      request.on("end", async () => {
        try {
          const message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          const session = sessions.get(message.sessionId);
          if (!session || session.used || now() >= session.expiresAtMs) {
            throw new NativePairingError("PAIRING_SESSION_EXPIRED_OR_USED");
          }
          const phonePublic = decodeBase64url(message.phoneEphemeralPublicKey, 65);
          const secret = session.ecdh.computeSecret(phonePublic);
          const transcriptHash = sha256(canonicalTranscript(session.request));
          const key = keyFromSharedSecret(secret, transcriptHash);
          const plaintext = decryptMessage(message, key, "PHONE_TO_DESKTOP");
          const payload = JSON.parse(plaintext.toString("utf8"));
          const descriptor = validateResponse(payload, session, { allowSimulator });
          session.used = true;
          session.state = "VERIFIED";
          completedDescriptor = descriptor;
          await onVerified(descriptor);
          const acknowledgement = encryptMessage(
            {
              status: "VERIFIED",
              sessionId: message.sessionId,
              descriptorFingerprint: descriptor.publicFingerprint
            },
            message.sessionId,
            key,
            "DESKTOP_TO_PHONE"
          );
          response.writeHead(200, { "content-type": "application/json" });
          response.end(JSON.stringify(acknowledgement));
        } catch (error) {
          response.writeHead(400, { "content-type": "application/json" });
          response.end(JSON.stringify({
            status: "REJECTED",
            reason: error instanceof NativePairingError
              ? error.code
              : "NATIVE_PAIRING_INTERNAL_ERROR"
          }));
        }
      });
    });
    server.on("clientError", (_error, socket) => socket.destroy());
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: interfaceAddress, port, exclusive: true }, resolve);
    });
    listeningPort = server.address().port;
    return status();
  }

  function beginPairing(input) {
    if (!server || !listeningPort) {
      throw new NativePairingError("PAIRING_HOST_NOT_STARTED");
    }
    if (
      typeof input?.philCoreIdentityCommitment !== "string"
      || !/^(0x)?[a-fA-F0-9]{64}$/u.test(input.philCoreIdentityCommitment)
      || !Number.isSafeInteger(input.recoveryEpoch)
      || input.recoveryEpoch < 1
      || !Number.isSafeInteger(input.requestedGeneration)
      || input.requestedGeneration < 1
    ) throw new NativePairingError("PAIRING_REQUEST_INPUT_INVALID");
    for (const session of sessions.values()) {
      if (!session.used) {
        session.used = true;
        session.state = "CANCELLED_BY_REPLACEMENT";
      }
    }
    const ecdh = crypto.createECDH("prime256v1");
    const publicKey = ecdh.generateKeys();
    const sessionId = base64url(randomBytes(32));
    const expiresAtMs = now() + SESSION_TTL_MS;
    const request = Object.freeze({
      protocolVersion: PROTOCOL_VERSION,
      sessionId,
      expiresAt: new Date(expiresAtMs).toISOString(),
      endpoint:
        `http://${interfaceAddress}:${listeningPort}/philcore/pair/v1/complete`,
      desktopEphemeralPublicKey: base64url(publicKey),
      challenge: base64url(randomBytes(32)),
      philCoreIdentityCommitment:
        input.philCoreIdentityCommitment.replace(/^0x/u, "").toLowerCase(),
      accountVersionId: ACCOUNT_VERSION_ID,
      securityModelId: SECURITY_MODEL_ID,
      recoveryEpoch: input.recoveryEpoch,
      requestedGeneration: input.requestedGeneration,
      applicationIdentity: APPLICATION_IDENTITY
    });
    const encoded = base64url(Buffer.from(JSON.stringify(request), "utf8"));
    const session = {
      request,
      ecdh,
      expiresAtMs,
      used: false,
      state: "AWAITING_IPHONE"
    };
    sessions.set(sessionId, session);
    return Object.freeze({
      status: "AWAITING_IPHONE",
      protocolVersion: PROTOCOL_VERSION,
      expiresAt: request.expiresAt,
      encodedRequest: `philcore://pair/v1?request=${encoded}`,
      comparisonFingerprint: displayFingerprint(canonicalTranscript(request)),
      interface: Object.freeze({ name: interfaceName, address: interfaceAddress }),
      containsPrivateAuthority: false,
      containsLongLivedBearerToken: false,
      simulatorTestOnly: allowSimulator
    });
  }

  function cancel() {
    for (const session of sessions.values()) {
      if (!session.used) {
        session.used = true;
        session.state = "CANCELLED";
      }
    }
    return Object.freeze({ status: "CANCELLED" });
  }

  function status() {
    const active = [...sessions.values()].find((session) => !session.used);
    return Object.freeze({
      status: active?.state || (completedDescriptor ? "VERIFIED" : "READY"),
      interface: Object.freeze({ name: interfaceName, address: interfaceAddress }),
      port: listeningPort,
      activeExpiresAt: active?.request.expiresAt || null,
      completedDescriptor,
      publicNetworkExposure: false,
      tlsReliedUpon: false,
      applicationEncryption: "P-256 ECDH / HKDF-SHA256 / AES-256-GCM",
      policyMode: allowSimulator ? "SIMULATOR_TEST" : "PRODUCTION",
      applicationIdentity: APPLICATION_IDENTITY,
      localApprovalPolicy: LOCAL_APPROVAL_POLICY,
      accountVersionId: ACCOUNT_VERSION_ID,
      securityModelId: SECURITY_MODEL_ID,
      verifierKind: 4,
      simulatorCredentialsAllowed: allowSimulator === true,
      secureEnclaveRequired: allowSimulator !== true
    });
  }

  async function stop() {
    cancel();
    if (!server) return;
    const current = server;
    server = null;
    listeningPort = null;
    await new Promise((resolve) => current.close(resolve));
  }

  return Object.freeze({ start, beginPairing, cancel, status, stop });
}

/**
 * Desktop-side capability signals for recovery preflight.
 * These are NOT physical iPhone verification and do not require
 * nativeRole1DescriptorStore.enrolled.
 * Policy readiness is derived solely from immutable host.status() metadata.
 */
function evaluateDesktopIPhoneReadiness(host) {
  if (!host || typeof host.status !== "function") {
    return Object.freeze({
      pairingTransportReady: false,
      nativeRole1PolicyReady: false
    });
  }
  let status;
  try {
    status = host.status();
  } catch {
    return Object.freeze({
      pairingTransportReady: false,
      nativeRole1PolicyReady: false
    });
  }
  if (!status || typeof status !== "object") {
    return Object.freeze({
      pairingTransportReady: false,
      nativeRole1PolicyReady: false
    });
  }
  const listeningPort = status.port;
  const address = status.interface?.address;
  // Desktop pairing transport readiness: host running, valid listening port,
  // RFC1918 private IPv4, and no public network exposure claim.
  const pairingTransportReady = Number.isInteger(listeningPort)
    && listeningPort > 0
    && listeningPort <= 65535
    && privateIPv4(address)
    && status.publicNetworkExposure === false;
  // Desktop Role 1 policy readiness: transport ready AND host-owned production
  // policy metadata matches pinned constants exactly. This is still not
  // physical iPhone verification.
  const nativeRole1PolicyReady = pairingTransportReady
    && status.policyMode === "PRODUCTION"
    && status.applicationIdentity === APPLICATION_IDENTITY
    && status.localApprovalPolicy === LOCAL_APPROVAL_POLICY
    && status.accountVersionId === ACCOUNT_VERSION_ID
    && status.securityModelId === SECURITY_MODEL_ID
    && status.verifierKind === 4
    && status.simulatorCredentialsAllowed === false
    && status.secureEnclaveRequired === true;
  return Object.freeze({
    pairingTransportReady,
    nativeRole1PolicyReady
  });
}

module.exports = {
  ACCOUNT_VERSION_ID,
  APPLICATION_IDENTITY,
  LOCAL_APPROVAL_POLICY,
  SECURITY_MODEL_ID,
  NativePairingError,
  canonicalTranscript,
  createNativeRole1DescriptorStore,
  createNativeIPhonePairingHost,
  displayFingerprint,
  encryptMessage,
  evaluateDesktopIPhoneReadiness,
  keyFromSharedSecret,
  listPrivateInterfaces,
  parseMacHardwarePorts,
  privateIPv4,
  selectIPhonePrivateInterface,
  sha256,
  validateResponse
};
