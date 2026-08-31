const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
require("tsx/cjs");
const {
  SigningKey,
  computeAddress,
  getBytes,
  id,
  keccak256,
  toBeHex
} = require("ethers");
const {
  CONSUMER_PLATFORM_POLICY_V1,
  EXTERNAL_HARDWARE_POLICY_V1,
  classifyRegistrationPolicy
} = require("./recovery-attestation-policy.cjs");
const {
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require("./recovery-secure-origin.cjs");
const {
  createWebAuthnAssertionVerifier,
  parseWebAuthnAuthenticatorData,
  verifyWebAuthnRegistration
} = require("../../../phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  evaluateRecoveryPreflightV3
} = require("./recovery-preflight-v3.cjs");

const RECORD_SCHEMA_VERSION = 1;
const ENCRYPTION_ENVELOPE_VERSION = 1;
const PAIRING_PROTOCOL_VERSION = 1;
const PAIRING_TTL_MS = 5 * 60 * 1000;
const DISPOSABLE_DIAGNOSTIC_TTL_MS = PAIRING_TTL_MS;
const DISPOSABLE_TEST_LABEL = "O42_1_DISPOSABLE_PLATFORM_WEBAUTHN_TEST_ONLY";
const assertionVerifier = createWebAuthnAssertionVerifier();
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const OFFLINE_DERIVATION_DOMAIN = id("PHILCORE_OFFLINE_RECOVERY_FACTOR_V1");
const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const STATES = Object.freeze({
  NOT_STARTED: "NOT_STARTED",
  PREFLIGHT_RUNNING: "PREFLIGHT_RUNNING",
  PREFLIGHT_BLOCKED: "PREFLIGHT_BLOCKED",
  PRIMARY_PENDING: "PRIMARY_PENDING",
  PRIMARY_COMPLETE: "PRIMARY_COMPLETE",
  SECONDARY_PENDING: "SECONDARY_PENDING",
  SECONDARY_COMPLETE: "SECONDARY_COMPLETE",
  OFFLINE_PENDING: "OFFLINE_PENDING",
  OFFLINE_EXPORT_CONFIRMED: "OFFLINE_EXPORT_CONFIRMED",
  OFFLINE_DRILL_COMPLETE: "OFFLINE_DRILL_COMPLETE",
  INDEPENDENCE_REVIEW: "INDEPENDENCE_REVIEW",
  READY_FOR_COMMITMENT_APPROVAL: "READY_FOR_COMMITMENT_APPROVAL",
  COMPLETE: "COMPLETE",
  CANCELLED: "CANCELLED",
  INVALIDATED: "INVALIDATED"
});

class RecoveryEnrollmentError extends Error {
  constructor(code) {
    const safeCode = /^[A-Z0-9_]{3,96}$/u.test(String(code))
      ? String(code)
      : "RECOVERY_ENROLLMENT_INTERNAL_ERROR";
    super(safeCode);
    this.name = "RecoveryEnrollmentError";
    this.code = safeCode;
  }

  toJSON() {
    return { name: this.name, code: this.code };
  }
}

class SecretValue {
  #value;
  constructor(value) {
    this.#value = String(value);
  }
  consume(callback) {
    if (this.#value === null) throw new RecoveryEnrollmentError("SECRET_ALREADY_CLEARED");
    return callback(this.#value);
  }
  clear() {
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
    errorCode: error instanceof RecoveryEnrollmentError
      ? error.code
      : "RECOVERY_ENROLLMENT_INTERNAL_ERROR"
  });
}

function redactForLog(value) {
  if (value instanceof SecretValue) return "[REDACTED_SECRET]";
  if (Array.isArray(value)) return value.map(redactForLog);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const [key, nested] of Object.entries(value)) {
    if (/(credential.?id|private|secret|recovery.?code|pairing.?key|ciphertext|restoration)/iu.test(key)) {
      result[key] = "[REDACTED_SECRET]";
    } else {
      result[key] = redactForLog(nested);
    }
  }
  return result;
}

function ensurePrivateDirectory(directory) {
  const resolved = path.resolve(directory);
  if (resolved === path.parse(resolved).root) throw new RecoveryEnrollmentError("UNSAFE_STORAGE_ROOT");
  fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new RecoveryEnrollmentError("STORAGE_ROOT_INVALID");
  }
  if (process.platform !== "win32") {
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      throw new RecoveryEnrollmentError("STORAGE_OWNER_INVALID");
    }
    if ((stat.mode & 0o077) !== 0) fs.chmodSync(resolved, 0o700);
  }
  return resolved;
}

function atomicPrivateWrite(filePath, contents) {
  const directory = ensurePrivateDirectory(path.dirname(filePath));
  if (fs.existsSync(filePath) && fs.lstatSync(filePath).isSymbolicLink()) {
    throw new RecoveryEnrollmentError("STORAGE_SYMLINK_REJECTED");
  }
  const temporary = path.join(
    directory,
    `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`
  );
  const descriptor = fs.openSync(
    temporary,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
    0o600
  );
  try {
    fs.writeFileSync(descriptor, contents, { encoding: "utf8" });
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, filePath);
  if (process.platform !== "win32") fs.chmodSync(filePath, 0o600);
}

function hashObject(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function createEncryptedRecoveryCredentialStore({ storageRoot, encryptionAdapter, now = () => Date.now() }) {
  const root = ensurePrivateDirectory(storageRoot);
  const rootBinding = crypto.createHash("sha256").update(root).digest("hex");

  function assertAvailable() {
    if (!encryptionAdapter?.isAvailable?.()) {
      throw new RecoveryEnrollmentError("RECOVERY_SAFE_STORAGE_UNAVAILABLE");
    }
  }

  function recordPath(reference) {
    if (!/^recovery_credential_[a-f0-9]{32}$/u.test(reference)) {
      throw new RecoveryEnrollmentError("CREDENTIAL_REFERENCE_INVALID");
    }
    return path.join(root, `${reference}.v1.json`);
  }

  function inspectPath(filePath) {
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new RecoveryEnrollmentError("CREDENTIAL_RECORD_PATH_INVALID");
    }
    if (process.platform !== "win32") {
      if ((stat.mode & 0o077) !== 0) {
        throw new RecoveryEnrollmentError("CREDENTIAL_RECORD_PERMISSIONS_INVALID");
      }
      if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
        throw new RecoveryEnrollmentError("CREDENTIAL_RECORD_OWNER_INVALID");
      }
    }
  }

  function publicRecord(record) {
    return Object.freeze({
      reference: record.reference,
      publicKey: record.publicKey,
      publicKeyHash: record.publicKeyHash,
      descriptorMetadata: record.descriptorMetadata,
      role: record.role,
      generation: record.generation,
      custodyDomainCommitment: record.custodyDomainCommitment,
      rpId: record.rpId,
      origin: record.origin,
      backupEligible: record.backupEligible,
      backupState: record.backupState,
      enrolledAt: record.enrolledAt,
      policyId: record.policyId,
      policyVersion: record.policyVersion,
      policyCommitment: record.policyCommitment,
      safePublicFingerprint: record.safePublicFingerprint,
      rotatedFrom: record.rotatedFrom || null
    });
  }

  function write(input) {
    assertAvailable();
    if (![0, 1].includes(input.role)) throw new RecoveryEnrollmentError("CREDENTIAL_ROLE_INVALID");
    if (
      typeof input.rawCredentialId !== "string"
      || input.rawCredentialId.length < 16
      || input.rawCredentialId.length > 2048
    ) throw new RecoveryEnrollmentError("RAW_CREDENTIAL_ID_INVALID");
    const policyResult = classifyRegistrationPolicy(input.registrationPolicy);
    if (!policyResult.accepted) {
      throw new RecoveryEnrollmentError(
        input.registrationPolicy?.requestedProfile === "ENHANCED_HARDWARE"
          ? "ENHANCED_ATTESTATION_UNAVAILABLE"
          : "CONSUMER_ATTESTATION_POLICY_REJECTED"
      );
    }
    const duplicateHash = crypto.createHash("sha256").update(input.rawCredentialId).digest("hex");
    for (const existing of list()) {
      if (existing.safePublicFingerprint === duplicateHash) {
        throw new RecoveryEnrollmentError("DUPLICATE_RECOVERY_CREDENTIAL");
      }
    }
    const reference = `recovery_credential_${crypto.randomBytes(16).toString("hex")}`;
    const record = {
      schemaVersion: RECORD_SCHEMA_VERSION,
      storageRootBinding: rootBinding,
      ownerUid: typeof process.getuid === "function" ? process.getuid() : null,
      reference,
      rawCredentialId: input.rawCredentialId,
      publicKey: input.publicKey,
      publicKeyHash: hashObject(input.publicKey),
      descriptorMetadata: input.descriptorMetadata || {},
      role: input.role,
      generation: input.generation,
      custodyDomainCommitment: input.custodyDomainCommitment,
      rpId: RECOVERY_RP_ID,
      origin: RECOVERY_ORIGIN,
      backupEligible: false,
      backupState: false,
      enrolledAt: new Date(now()).toISOString(),
      policyId: policyResult.policy.id,
      policyVersion: policyResult.policy.version,
      policyCommitment: policyResult.policy.policyCommitment,
      safePublicFingerprint: duplicateHash,
      rotatedFrom: input.rotatedFrom || null
    };
    const plaintext = JSON.stringify(record);
    const encrypted = encryptionAdapter.encrypt(plaintext);
    const envelope = {
      envelopeVersion: ENCRYPTION_ENVELOPE_VERSION,
      reference,
      ciphertextSha256: crypto.createHash("sha256").update(encrypted).digest("hex"),
      ciphertext: encrypted.toString("base64")
    };
    atomicPrivateWrite(recordPath(reference), `${JSON.stringify(envelope, null, 2)}\n`);
    return publicRecord(record);
  }

  function read(reference) {
    assertAvailable();
    const filePath = recordPath(reference);
    if (!fs.existsSync(filePath)) throw new RecoveryEnrollmentError("CREDENTIAL_RECORD_NOT_FOUND");
    inspectPath(filePath);
    try {
      const envelope = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (
        envelope.envelopeVersion !== ENCRYPTION_ENVELOPE_VERSION
        || envelope.reference !== reference
        || typeof envelope.ciphertext !== "string"
      ) throw new RecoveryEnrollmentError("CREDENTIAL_ENVELOPE_SCHEMA_INVALID");
      const encrypted = Buffer.from(envelope.ciphertext, "base64");
      const actualHash = crypto.createHash("sha256").update(encrypted).digest("hex");
      if (actualHash !== envelope.ciphertextSha256) {
        throw new RecoveryEnrollmentError("CREDENTIAL_CIPHERTEXT_CORRUPTED");
      }
      const record = JSON.parse(encryptionAdapter.decrypt(encrypted));
      if (
        record.schemaVersion !== RECORD_SCHEMA_VERSION
        || record.reference !== reference
        || record.storageRootBinding !== rootBinding
        || record.ownerUid !== (typeof process.getuid === "function" ? process.getuid() : null)
        || record.rpId !== RECOVERY_RP_ID
        || record.origin !== RECOVERY_ORIGIN
      ) throw new RecoveryEnrollmentError("CREDENTIAL_RECORD_BINDING_INVALID");
      return record;
    } catch (error) {
      if (error instanceof RecoveryEnrollmentError) throw error;
      throw new RecoveryEnrollmentError("CREDENTIAL_RECORD_DECRYPTION_FAILED");
    }
  }

  function list() {
    assertAvailable();
    ensurePrivateDirectory(root);
    return Object.freeze(
      fs.readdirSync(root)
        .filter((name) => /^recovery_credential_[a-f0-9]{32}\.v1\.json$/u.test(name))
        .sort()
        .map((name) => publicRecord(read(name.slice(0, -8))))
    );
  }

  function remove(reference) {
    const filePath = recordPath(reference);
    if (!fs.existsSync(filePath)) return false;
    inspectPath(filePath);
    fs.rmSync(filePath);
    return true;
  }

  function rotate(reference, next) {
    const previous = publicRecord(read(reference));
    const replacement = write({ ...next, role: previous.role, rotatedFrom: previous.reference });
    remove(reference);
    return replacement;
  }

  function writeOfflinePublicMetadata(metadata) {
    const record = {
      schemaVersion: 1,
      role: 2,
      formatVersion: "PHIL39-V1",
      signer: metadata.signer,
      safePublicFingerprint: metadata.safePublicFingerprint,
      confirmationStatus: metadata.confirmationStatus,
      restorationDrillStatus: metadata.restorationDrillStatus,
      secretRetained: false,
      updatedAt: new Date(now()).toISOString()
    };
    atomicPrivateWrite(
      path.join(root, "offline-factor-public.v1.json"),
      `${JSON.stringify({ ...record, recordSha256: hashObject(record) }, null, 2)}\n`
    );
    return Object.freeze(record);
  }

  function readOfflinePublicMetadata() {
    const filePath = path.join(root, "offline-factor-public.v1.json");
    if (!fs.existsSync(filePath)) return null;
    inspectPath(filePath);
    try {
      const stored = JSON.parse(fs.readFileSync(filePath, "utf8"));
      const { recordSha256, ...record } = stored;
      if (
        record.schemaVersion !== 1
        || record.role !== 2
        || record.secretRetained !== false
        || recordSha256 !== hashObject(record)
      ) throw new RecoveryEnrollmentError("OFFLINE_PUBLIC_METADATA_CORRUPTED");
      return Object.freeze(record);
    } catch (error) {
      if (error instanceof RecoveryEnrollmentError) throw error;
      throw new RecoveryEnrollmentError("OFFLINE_PUBLIC_METADATA_INVALID");
    }
  }

  return Object.freeze({
    root,
    write,
    read,
    list,
    remove,
    rotate,
    writeOfflinePublicMetadata,
    readOfflinePublicMetadata
  });
}

function encodeTransfer(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodeTransfer(value, expectedKind) {
  try {
    if (typeof value !== "string" || value.length > 24_000) throw new Error();
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (parsed.kind !== expectedKind || parsed.version !== PAIRING_PROTOCOL_VERSION) throw new Error();
    const expectedKeys = expectedKind === "PHILCORE_O41_PAIRING_REQUEST"
      ? [
          "kind", "version", "sessionId", "challenge", "createdAt", "expiresAt",
          "rpId", "origin", "policyId", "primaryPublicKey",
          "userConfirmationRequiredOnBothDevices"
        ]
      : [
          "kind", "version", "sessionId", "requestHash", "secondaryPublicKey",
          "nonce", "ciphertext", "authTag", "confirmedOnSecondary"
        ];
    if (
      Object.keys(parsed).length !== expectedKeys.length
      || expectedKeys.some((key, index) => Object.keys(parsed)[index] !== key)
      || encodeTransfer(parsed) !== value
    ) throw new Error();
    return parsed;
  } catch {
    throw new RecoveryEnrollmentError("PAIRING_TRANSFER_INVALID");
  }
}

function derivePairingKey(privateKey, otherPublicKey, sessionId) {
  const shared = crypto.diffieHellman({
    privateKey,
    publicKey: crypto.createPublicKey({
      key: Buffer.from(otherPublicKey, "base64url"),
      format: "der",
      type: "spki"
    })
  });
  return crypto.hkdfSync(
    "sha256",
    shared,
    Buffer.from(sessionId, "hex"),
    Buffer.from("PHILCORE_O41_SECONDARY_HANDOFF_V1"),
    32
  );
}

function publicKeyDer(keyPair) {
  return keyPair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
}

function createSecondaryPairingResponse({
  encodedRequest,
  credential,
  now = Date.now(),
  randomBytes = crypto.randomBytes
}) {
  const request = decodeTransfer(encodedRequest, "PHILCORE_O41_PAIRING_REQUEST");
  if (request.origin !== RECOVERY_ORIGIN || request.rpId !== RECOVERY_RP_ID) {
    throw new RecoveryEnrollmentError("PAIRING_ORIGIN_BINDING_INVALID");
  }
  if (now > request.expiresAt) throw new RecoveryEnrollmentError("PAIRING_REQUEST_EXPIRED");
  if (credential.challenge !== request.challenge) {
    throw new RecoveryEnrollmentError("PAIRING_CHALLENGE_MISMATCH");
  }
  const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const key = derivePairingKey(keyPair.privateKey, request.primaryPublicKey, request.sessionId);
  const nonce = randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const aad = Buffer.from(hashObject(request), "hex");
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(credential), "utf8"),
    cipher.final()
  ]);
  return encodeTransfer({
    kind: "PHILCORE_O41_PAIRING_RESPONSE",
    version: PAIRING_PROTOCOL_VERSION,
    sessionId: request.sessionId,
    requestHash: hashObject(request),
    secondaryPublicKey: publicKeyDer(keyPair),
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    authTag: cipher.getAuthTag().toString("base64url"),
    confirmedOnSecondary: true
  });
}

function encodeBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value) {
  let bits = 0;
  let buffer = 0;
  const output = [];
  for (const character of value) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new RecoveryEnrollmentError("OFFLINE_CODE_INVALID_BASE32");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function offlineChecksum(entropy) {
  return encodeBase32(Buffer.from(getBytes(keccak256(entropy))).subarray(0, 5));
}

function formatOfflineCode(entropy) {
  const groups = encodeBase32(entropy).match(/.{1,4}/gu) || [];
  return `PHIL39-V1-${groups.join("-")}-${offlineChecksum(entropy)}`;
}

function inspectOfflineCode(code) {
  const normalized = String(code).trim().toUpperCase();
  if (!normalized.startsWith("PHIL39-V1-")) {
    throw new RecoveryEnrollmentError("OFFLINE_CODE_VERSION_INVALID");
  }
  const segments = normalized.slice("PHIL39-V1-".length).split("-");
  const checksum = segments.pop();
  const entropy = decodeBase32(segments.join(""));
  if (entropy.length !== 32 || checksum !== offlineChecksum(entropy)) {
    throw new RecoveryEnrollmentError("OFFLINE_CODE_CHECKSUM_INVALID");
  }
  const digest = BigInt(keccak256(Buffer.concat([
    Buffer.from(getBytes(OFFLINE_DERIVATION_DOMAIN)),
    entropy
  ])));
  const privateKey = toBeHex((digest % (SECP256K1_ORDER - 1n)) + 1n, 32);
  const signer = computeAddress(new SigningKey(privateKey).publicKey);
  return Object.freeze({
    signer,
    publicVerificationMaterialHash: id(`PHILCORE_OFFLINE_PUBLIC_V1|${signer.toLowerCase()}`)
  });
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function createRecoveryEnrollmentHost({
  credentialStore,
  originStatus,
  secureDisplay,
  platformWebAuthnStartup = null,
  desktopCapabilityEvidenceProvider = null,
  disposableAwaitGate = null,
  now = () => Date.now(),
  randomBytes = crypto.randomBytes
}) {
  let state = STATES.NOT_STARTED;
  let profile = null;
  let pairing = null;
  let offline = null;
  let primaryChallenge = null;
  let secondaryChallenge = null;
  let lastPlatformAuthenticatorAvailable = false;
  let disposableDiagnostic = null;
  let disposableVerifiedUntil = 0;
  let disposableSessionToken = 0;
  const consumedPairingSessions = new Set();
  const publicFactors = new Map();
  for (const record of credentialStore.list()) publicFactors.set(record.role, record);
  const retainedOffline = credentialStore.readOfflinePublicMetadata();
  if (retainedOffline?.restorationDrillStatus === "matched") {
    publicFactors.set(2, retainedOffline);
  }

  function requireState(...allowed) {
    if (!allowed.includes(state)) throw new RecoveryEnrollmentError("ENROLLMENT_STATE_TRANSITION_REJECTED");
  }

  function clearDisposableDiagnosticSession() {
    if (disposableDiagnostic) {
      disposableDiagnostic.registrationChallenge = null;
      disposableDiagnostic.assertionChallenge = null;
      disposableDiagnostic.credentialId = null;
      disposableDiagnostic.publicKey = null;
      disposableDiagnostic.algorithm = null;
      disposableDiagnostic.signCount = null;
    }
    disposableDiagnostic = null;
  }

  function invalidateDisposableDiagnostic() {
    clearDisposableDiagnosticSession();
    disposableVerifiedUntil = 0;
  }

  function invalidateDisposableSession(session) {
    if (disposableDiagnostic === session) {
      invalidateDisposableDiagnostic();
      return;
    }
    if (!session || typeof session !== "object") return;
    session.registrationChallenge = null;
    session.assertionChallenge = null;
    session.credentialId = null;
    session.publicKey = null;
    session.algorithm = null;
    session.signCount = null;
    session.stage = "invalid";
  }

  function disposableCreationAssertionReady() {
    return Number.isFinite(disposableVerifiedUntil) && now() < disposableVerifiedUntil;
  }

  function hasDisposableAuthority() {
    return Boolean(disposableDiagnostic) || disposableCreationAssertionReady();
  }

  function resolveDesktopCapabilityEvidence() {
    if (typeof desktopCapabilityEvidenceProvider !== "function") return null;
    try {
      const value = desktopCapabilityEvidenceProvider();
      if (!isPlainObject(value)) return null;
      return value;
    } catch {
      return null;
    }
  }

  async function invokeDisposableAwaitGate() {
    if (typeof disposableAwaitGate !== "function") return;
    await disposableAwaitGate();
  }

  function assertDisposableSessionCurrent(session, stage) {
    if (disposableDiagnostic !== session) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED");
    }
    if (now() >= session.expiresAt) {
      invalidateDisposableDiagnostic();
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_EXPIRED");
    }
    if (session.stage !== stage) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_STAGE_REJECTED");
    }
  }

  function packagedIdentityConfigured() {
    return Boolean(
      platformWebAuthnStartup
      && platformWebAuthnStartup.result === "SUPPORTED_AND_CONFIGURED"
      && platformWebAuthnStartup.configuredAfterReady === true
      && platformWebAuthnStartup.packaged === true
      && platformWebAuthnStartup.bundleIdentifier === "com.philcore.desktop.localalpha"
      && platformWebAuthnStartup.teamIdentifier === "B342738S82"
      && platformWebAuthnStartup.keychainAccessGroup
        === "B342738S82.com.philcore.desktop.localalpha.webauthn"
    );
  }

  function assertDisposableBeginPrerequisites() {
    const origin = originStatus();
    const evidence = resolveDesktopCapabilityEvidence();
    if (
      !packagedIdentityConfigured()
      || !origin?.ready
      || origin.origin !== RECOVERY_ORIGIN
      || origin.rpId !== RECOVERY_RP_ID
      || !evidence
      || evidence.certificatePersistence !== true
      || evidence.safeStoragePersistence !== true
      || evidence.packagedBuild !== true
      || lastPlatformAuthenticatorAvailable !== true
    ) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_PREREQUISITES_UNMET");
    }
  }

  function requireActiveDisposableStage(stage) {
    if (!disposableDiagnostic) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_SESSION_MISSING");
    }
    if (now() >= disposableDiagnostic.expiresAt) {
      invalidateDisposableDiagnostic();
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_EXPIRED");
    }
    if (disposableDiagnostic.stage !== stage) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_STAGE_REJECTED");
    }
  }

  function status() {
    return Object.freeze({
      state,
      profile,
      rpId: RECOVERY_RP_ID,
      origin: RECOVERY_ORIGIN,
      factors: Object.freeze([...publicFactors.values()]),
      exactThreshold: "2-of-3",
      totpAuthority: false,
      ephemeralOfflineSecretPresent: Boolean(offline?.secret),
      activePairing: pairing ? Object.freeze({
        sessionId: pairing.request.sessionId,
        expiresAt: pairing.request.expiresAt,
        requestFingerprint: pairing.requestHash
      }) : null
    });
  }

  function preflight(input = {}) {
    requireState(STATES.NOT_STARTED, STATES.PREFLIGHT_BLOCKED);
    state = STATES.PREFLIGHT_RUNNING;
    profile = input.profile === "ENHANCED" ? "ENHANCED" : "STANDARD";
    lastPlatformAuthenticatorAvailable = input.platformAuthenticatorAvailable === true;
    const origin = originStatus();
    const baseChecks = {
      secureOrigin: origin.ready && origin.origin === RECOVERY_ORIGIN && origin.rpId === RECOVERY_RP_ID,
      encryptedStorage: Boolean(credentialStore),
      webAuthnApi: input.webAuthnApiAvailable === true,
      platformAuthenticator: lastPlatformAuthenticatorAvailable,
      loggingCrashExclusion: true,
      offlineRevealRestore: typeof secureDisplay === "function",
      packagedEnvironment: input.packagedEnvironmentReady !== false,
      dependencyAdvisoryGate: input.dependencyAdvisoryGateReady !== false
    };
    const enhancedReady = EXTERNAL_HARDWARE_POLICY_V1.readiness !== "BLOCKED";
    const desktopEvidence = resolveDesktopCapabilityEvidence();
    const desktopEvidenceReady = Boolean(desktopEvidence);
    const disposableCreationAssertion = disposableCreationAssertionReady();
    const preflightV3 = platformWebAuthnStartup
      ? evaluateRecoveryPreflightV3({
          electronRuntimeCapability:
            platformWebAuthnStartup.result === "SUPPORTED_AND_CONFIGURED",
          startupWebAuthnConfiguration:
            platformWebAuthnStartup.result === "SUPPORTED_AND_CONFIGURED"
            && platformWebAuthnStartup.configuredAfterReady === true,
          bundleIdentity:
            platformWebAuthnStartup.packaged === true
            && platformWebAuthnStartup.bundleIdentifier === "com.philcore.desktop.localalpha"
            && platformWebAuthnStartup.teamIdentifier === "B342738S82",
          keychainAccessGroup:
            platformWebAuthnStartup.keychainAccessGroup
              === "B342738S82.com.philcore.desktop.localalpha.webauthn",
          secureOrigin: baseChecks.secureOrigin,
          certificatePersistence:
            desktopEvidenceReady && desktopEvidence.certificatePersistence === true,
          safeStoragePersistence:
            desktopEvidenceReady && desktopEvidence.safeStoragePersistence === true,
          platformAuthenticator: baseChecks.platformAuthenticator,
          disposableCreationAssertion,
          packagedBuild: desktopEvidenceReady && desktopEvidence.packagedBuild === true,
          iphoneCompanionConnectivity:
            desktopEvidenceReady && desktopEvidence.iphoneCompanionConnectivity === true,
          iphoneRole1CredentialPolicy:
            desktopEvidenceReady && desktopEvidence.iphoneRole1CredentialPolicy === true,
          loggingCrashExclusion: true,
          noStaleCeremonyState: publicFactors.size === 0,
          noProductionSecretContamination: desktopEvidenceReady
            ? desktopEvidence.noProductionSecretContamination !== false
            : false
        })
      : null;
    const blocked = Object.entries(baseChecks).filter(([, passed]) => !passed).map(([id]) => id);
    if (preflightV3) {
      blocked.push(...preflightV3.completeStandardCeremony.blockers);
    }
    if (profile === "ENHANCED" && !enhancedReady) blocked.push("directAttestationTrustRoots");
    const uniqueBlocked = [...new Set(blocked)];
    state = uniqueBlocked.length
      ? STATES.PREFLIGHT_BLOCKED
      : publicFactors.has(0) && publicFactors.has(1) && publicFactors.has(2)
        ? STATES.OFFLINE_DRILL_COMPLETE
      : publicFactors.has(1)
        ? STATES.SECONDARY_COMPLETE
        : publicFactors.has(0)
          ? STATES.PRIMARY_COMPLETE
          : STATES.PRIMARY_PENDING;
    return Object.freeze({
      standard: uniqueBlocked.filter((id) => id !== "directAttestationTrustRoots").length
        ? "BLOCKED"
        : "READY_WITH_WARNINGS",
      enhanced: enhancedReady && uniqueBlocked.length === 0 ? "READY_WITH_WARNINGS" : "BLOCKED",
      selectedProfile: profile,
      blockers: Object.freeze(uniqueBlocked),
      warnings: Object.freeze([
        "Custody-domain independence requires explicit user review.",
        "Synthetic tests do not replace a later interactive credential ceremony."
      ]),
      checks: Object.freeze(baseChecks),
      preflightV3,
      platformWebAuthnStartup: platformWebAuthnStartup
        ? Object.freeze({
            result: platformWebAuthnStartup.result,
            electronVersion: platformWebAuthnStartup.electronVersion,
            packaged: platformWebAuthnStartup.packaged,
            bundleIdentifier: platformWebAuthnStartup.bundleIdentifier,
            teamIdentifier: platformWebAuthnStartup.teamIdentifier,
            keychainAccessGroup: platformWebAuthnStartup.keychainAccessGroup,
            configuredBeforeReady: platformWebAuthnStartup.configuredBeforeReady,
            configuredAfterReady: platformWebAuthnStartup.configuredAfterReady,
            chromiumFlagsUsed: platformWebAuthnStartup.chromiumFlagsUsed
          })
        : null,
      state
    });
  }

  function beginCredential() {
    requireState(STATES.PRIMARY_PENDING);
    if (!disposableCreationAssertionReady()) {
      invalidateDisposableDiagnostic();
      primaryChallenge = null;
      state = STATES.PREFLIGHT_BLOCKED;
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_REQUIRED_OR_EXPIRED");
    }
    invalidateDisposableDiagnostic();
    primaryChallenge = randomBytes(32).toString("base64url");
    return Object.freeze({
      challenge: primaryChallenge,
      rp: Object.freeze({ id: RECOVERY_RP_ID, name: "PhilCore Recovery" }),
      userVerification: "required",
      residentKey: "required",
      authenticatorAttachment: "platform",
      attestation: "none",
      algorithms: Object.freeze([-7]),
      timeoutMs: 60_000,
      policyId: CONSUMER_PLATFORM_POLICY_V1.id
    });
  }

  function beginDisposableDiagnostic() {
    requireState(STATES.PREFLIGHT_BLOCKED, STATES.PRIMARY_PENDING);
    assertDisposableBeginPrerequisites();
    invalidateDisposableDiagnostic();
    primaryChallenge = null;
    state = STATES.PREFLIGHT_BLOCKED;
    const registrationChallenge = randomBytes(32).toString("base64url");
    disposableSessionToken += 1;
    disposableDiagnostic = {
      token: disposableSessionToken,
      stage: "registration",
      registrationChallenge,
      assertionChallenge: null,
      credentialId: null,
      publicKey: null,
      algorithm: null,
      signCount: null,
      expiresAt: now() + DISPOSABLE_DIAGNOSTIC_TTL_MS,
      registrationConsumed: false,
      assertionConsumed: false
    };
    return Object.freeze({
      challenge: registrationChallenge,
      rp: Object.freeze({ id: RECOVERY_RP_ID, name: "PhilCore Recovery" }),
      userVerification: "required",
      residentKey: "required",
      authenticatorAttachment: "platform",
      attestation: "none",
      algorithms: Object.freeze([-7]),
      timeoutMs: 60_000,
      testLabel: DISPOSABLE_TEST_LABEL
    });
  }

  function cancelDisposableDiagnostic() {
    if (!hasDisposableAuthority()) {
      return status();
    }
    invalidateDisposableDiagnostic();
    primaryChallenge = null;
    if (
      state === STATES.PRIMARY_PENDING
      || state === STATES.PREFLIGHT_BLOCKED
      || state === STATES.PREFLIGHT_RUNNING
    ) {
      state = STATES.PREFLIGHT_BLOCKED;
    }
    return status();
  }

  async function verifyDisposableRegistration(registration) {
    requireState(STATES.PREFLIGHT_BLOCKED, STATES.PRIMARY_PENDING);
    requireActiveDisposableStage("registration");
    if (registration?.policyAccepted === true && !registration?.response) {
      throw new RecoveryEnrollmentError("DISPOSABLE_POLICY_ACCEPTED_HAS_NO_AUTHORITY");
    }
    const session = disposableDiagnostic;
    if (session.registrationConsumed) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_REPLAY_REJECTED");
    }
    session.registrationConsumed = true;
    const expectedChallenge = session.registrationChallenge;
    let verification;
    try {
      await invokeDisposableAwaitGate();
      assertDisposableSessionCurrent(session, "registration");
      verification = await verifyRegistration(registration, expectedChallenge);
      assertDisposableSessionCurrent(session, "registration");
    } catch (error) {
      if (
        error instanceof RecoveryEnrollmentError
        && error.code === "DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED"
      ) {
        throw error;
      }
      if (disposableDiagnostic === session) {
        invalidateDisposableSession(session);
      }
      throw error;
    }
    const assertionChallenge = randomBytes(32).toString("base64url");
    if (assertionChallenge === expectedChallenge) {
      if (disposableDiagnostic === session) {
        invalidateDisposableSession(session);
      }
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_INTERNAL_ERROR");
    }
    if (disposableDiagnostic !== session) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED");
    }
    session.stage = "assertion";
    session.assertionChallenge = assertionChallenge;
    session.credentialId = verification.credentialId;
    session.publicKey = verification.credentialPublicKey;
    session.algorithm = verification.algorithm;
    session.signCount = verification.signCount;
    session.registrationChallenge = null;
    return Object.freeze({
      verified: true,
      assertionChallenge,
      label: DISPOSABLE_TEST_LABEL,
      productionAuthorityCreated: false,
      rawCredentialIdReturned: false
    });
  }

  async function verifyDisposableAssertion(assertion) {
    requireState(STATES.PREFLIGHT_BLOCKED, STATES.PRIMARY_PENDING);
    requireActiveDisposableStage("assertion");
    if (assertion?.policyAccepted === true && !assertion?.response) {
      throw new RecoveryEnrollmentError("DISPOSABLE_POLICY_ACCEPTED_HAS_NO_AUTHORITY");
    }
    const session = disposableDiagnostic;
    if (session.assertionConsumed) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_REPLAY_REJECTED");
    }
    if (
      !session.credentialId
      || !session.publicKey
      || session.algorithm !== -7
      || !session.assertionChallenge
    ) {
      invalidateDisposableSession(session);
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_SESSION_INVALID");
    }
    session.assertionConsumed = true;
    const expectedChallenge = session.assertionChallenge;
    const credentialId = session.credentialId;
    const publicKey = session.publicKey;
    const algorithm = session.algorithm;
    const storedSignCount = session.signCount ?? 0;
    let verification;
    try {
      await invokeDisposableAwaitGate();
      assertDisposableSessionCurrent(session, "assertion");
      verification = await assertionVerifier.verifyAssertion({
        assertion,
        credential: {
          credentialId,
          publicKey,
          publicKeyAlgorithm: algorithm
        },
        expectedChallenge,
        expectedOrigin: RECOVERY_ORIGIN,
        expectedRpId: RECOVERY_RP_ID,
        expectedUserVerification: "required",
        storedSignCount
      });
      assertDisposableSessionCurrent(session, "assertion");
    } catch (error) {
      if (
        error instanceof RecoveryEnrollmentError
        && error.code === "DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED"
      ) {
        throw error;
      }
      if (disposableDiagnostic === session) {
        invalidateDisposableSession(session);
      }
      throw error;
    }
    if (!verification.verified || !verification.productionVerified) {
      if (disposableDiagnostic === session) {
        invalidateDisposableSession(session);
      }
      throw new RecoveryEnrollmentError("WEBAUTHN_ASSERTION_VERIFICATION_FAILED");
    }
    let authenticatorFlags;
    try {
      authenticatorFlags = parseWebAuthnAuthenticatorData(assertion.response.authenticatorData);
    } catch {
      if (disposableDiagnostic === session) {
        invalidateDisposableSession(session);
      }
      throw new RecoveryEnrollmentError("WEBAUTHN_ASSERTION_POLICY_REJECTED");
    }
    if (
      !authenticatorFlags.userPresent
      || !authenticatorFlags.userVerified
      || authenticatorFlags.backupEligible
      || authenticatorFlags.backupState
    ) {
      if (disposableDiagnostic === session) {
        invalidateDisposableSession(session);
      }
      throw new RecoveryEnrollmentError("WEBAUTHN_ASSERTION_POLICY_REJECTED");
    }
    if (disposableDiagnostic !== session) {
      throw new RecoveryEnrollmentError("DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED");
    }
    if (disposableDiagnostic === session) {
      clearDisposableDiagnosticSession();
      disposableVerifiedUntil = now() + DISPOSABLE_DIAGNOSTIC_TTL_MS;
    }
    return Object.freeze({
      verified: true,
      label: DISPOSABLE_TEST_LABEL,
      disposableCreationAssertion: true,
      productionAuthorityCreated: false,
      rawCredentialIdReturned: false,
      cleanup: "OS_CREDENTIAL_DELETION_API_UNAVAILABLE_PRODUCTION_UNREFERENCED"
    });
  }

  function beginHardwareCredentialFallback() {
    requireState(STATES.PRIMARY_COMPLETE);
    secondaryChallenge = randomBytes(32).toString("base64url");
    state = STATES.SECONDARY_PENDING;
    return Object.freeze({
      challenge: secondaryChallenge,
      rp: Object.freeze({ id: RECOVERY_RP_ID, name: "PhilCore Recovery" }),
      userVerification: "required",
      residentKey: "required",
      authenticatorAttachment: "cross-platform",
      attestation: "none",
      algorithms: Object.freeze([-7]),
      timeoutMs: 60_000,
      policyId: CONSUMER_PLATFORM_POLICY_V1.id,
      classification: "CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION",
      enhancedAssurance: false
    });
  }

  async function verifyRegistration(registration, expectedChallenge) {
    const verification = await verifyWebAuthnRegistration({
      registration,
      expectedChallenge,
      expectedOrigin: RECOVERY_ORIGIN,
      expectedRpId: RECOVERY_RP_ID,
      expectedUserVerification: "required",
      expectedAlgorithms: [-7],
      attestationPolicy: { mode: "none" }
    });
    if (!verification.verified || !verification.productionVerified) {
      throw new RecoveryEnrollmentError("WEBAUTHN_REGISTRATION_VERIFICATION_FAILED");
    }
    if (
      !verification.userPresent
      || !verification.userVerified
      || !verification.attestedCredentialDataIncluded
      || verification.backupEligible
      || verification.backupState
      || verification.algorithm !== -7
      || !verification.credentialPublicKey
    ) throw new RecoveryEnrollmentError("WEBAUTHN_REGISTRATION_POLICY_REJECTED");
    return verification;
  }

  async function storeCredential(input) {
    if (input.role === 0) {
      requireState(STATES.PRIMARY_PENDING);
      invalidateDisposableDiagnostic();
    } else if (input.role === 1) requireState(STATES.SECONDARY_PENDING);
    else throw new RecoveryEnrollmentError("CREDENTIAL_ROLE_INVALID");
    const challenge = input.role === 0 ? primaryChallenge : secondaryChallenge;
    if (!challenge) {
      throw new RecoveryEnrollmentError("WEBAUTHN_REGISTRATION_CHALLENGE_MISSING");
    }
    const verification = await verifyRegistration(input.registration, challenge);
    const stored = credentialStore.write({
      role: input.role,
      rawCredentialId: verification.credentialId,
      publicKey: {
        spki: verification.credentialPublicKey,
        algorithm: verification.algorithm
      },
      descriptorMetadata: input.descriptorMetadata,
      generation: input.generation,
      custodyDomainCommitment: input.custodyDomainCommitment,
      registrationPolicy: {
        requestedProfile: "STANDARD",
        attestationConveyance: "none",
        algorithm: "ES256",
        userVerified: verification.userVerified,
        attestedCredentialDataPresent: verification.attestedCredentialDataIncluded,
        backupEligible: verification.backupEligible,
        backupState: verification.backupState
      }
    });
    if (input.role === 0) primaryChallenge = null;
    else secondaryChallenge = null;
    publicFactors.set(input.role, stored);
    state = input.role === 0 ? STATES.PRIMARY_COMPLETE : STATES.SECONDARY_COMPLETE;
    return stored;
  }

  function beginPairing() {
    requireState(STATES.PRIMARY_COMPLETE);
    const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const request = {
      kind: "PHILCORE_O41_PAIRING_REQUEST",
      version: PAIRING_PROTOCOL_VERSION,
      sessionId: randomBytes(32).toString("hex"),
      challenge: randomBytes(32).toString("base64url"),
      createdAt: now(),
      expiresAt: now() + PAIRING_TTL_MS,
      rpId: RECOVERY_RP_ID,
      origin: RECOVERY_ORIGIN,
      policyId: CONSUMER_PLATFORM_POLICY_V1.id,
      primaryPublicKey: publicKeyDer(keyPair),
      userConfirmationRequiredOnBothDevices: true
    };
    pairing = { request, requestHash: hashObject(request), privateKey: keyPair.privateKey };
    state = STATES.SECONDARY_PENDING;
    return Object.freeze({
      encodedRequest: encodeTransfer(request),
      expiresAt: request.expiresAt,
      requestFingerprint: pairing.requestHash
    });
  }

  function beginNativeIPhonePairing() {
    requireState(STATES.PRIMARY_COMPLETE);
    pairing = null;
    secondaryChallenge = null;
    state = STATES.SECONDARY_PENDING;
    return Object.freeze({
      state,
      role: 1,
      verifierKind: 4,
      transport: "NATIVE_IPHONE_LOCAL_NETWORK_V1"
    });
  }

  function completeNativeIPhonePairing(descriptor) {
    requireState(STATES.SECONDARY_PENDING);
    if (
      descriptor?.role !== 1
      || descriptor?.verifierKind !== 4
      || descriptor?.descriptorVersion !== 1
      || typeof descriptor.publicFingerprint !== "string"
      || typeof descriptor.deviceCustodyCommitment !== "string"
      || !Number.isSafeInteger(descriptor.generation)
      || descriptor.generation < 1
    ) throw new RecoveryEnrollmentError("NATIVE_IPHONE_DESCRIPTOR_INVALID");
    const primary = publicFactors.get(0);
    if (
      primary?.safePublicFingerprint === descriptor.publicFingerprint
      || primary?.custodyDomainCommitment === descriptor.deviceCustodyCommitment
    ) throw new RecoveryEnrollmentError("NATIVE_IPHONE_INDEPENDENCE_ALIAS_REJECTED");
    const publicFactor = Object.freeze({
      role: 1,
      verifierKind: 4,
      descriptorVersion: 1,
      generation: descriptor.generation,
      safePublicFingerprint: descriptor.publicFingerprint,
      custodyDomainCommitment: descriptor.deviceCustodyCommitment,
      applicationIdentityHash: descriptor.applicationIdentityHash,
      simulatorCredential: descriptor.simulatorCredential,
      policyId: "PHILCORE_NATIVE_IOS_ROLE1_V1"
    });
    publicFactors.set(1, publicFactor);
    state = STATES.SECONDARY_COMPLETE;
    return publicFactor;
  }

  function cancelNativeIPhonePairing() {
    if (state === STATES.SECONDARY_PENDING) state = STATES.PRIMARY_COMPLETE;
    return status();
  }

  async function completePairing(encodedResponse, expectedCustodyDomainCommitment) {
    requireState(STATES.SECONDARY_PENDING);
    if (!pairing) throw new RecoveryEnrollmentError("PAIRING_SESSION_MISSING");
    if (now() > pairing.request.expiresAt) throw new RecoveryEnrollmentError("PAIRING_REQUEST_EXPIRED");
    if (consumedPairingSessions.has(pairing.request.sessionId)) {
      throw new RecoveryEnrollmentError("PAIRING_REPLAY_REJECTED");
    }
    const response = decodeTransfer(encodedResponse, "PHILCORE_O41_PAIRING_RESPONSE");
    if (
      response.sessionId !== pairing.request.sessionId
      || response.requestHash !== pairing.requestHash
      || response.confirmedOnSecondary !== true
    ) throw new RecoveryEnrollmentError("PAIRING_TRANSCRIPT_MISMATCH");
    try {
      const key = derivePairingKey(
        pairing.privateKey,
        response.secondaryPublicKey,
        pairing.request.sessionId
      );
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(response.nonce, "base64url")
      );
      decipher.setAAD(Buffer.from(pairing.requestHash, "hex"));
      decipher.setAuthTag(Buffer.from(response.authTag, "base64url"));
      const credential = JSON.parse(Buffer.concat([
        decipher.update(Buffer.from(response.ciphertext, "base64url")),
        decipher.final()
      ]).toString("utf8"));
      if (credential.custodyDomainCommitment !== expectedCustodyDomainCommitment) {
        throw new RecoveryEnrollmentError("PAIRING_CREDENTIAL_BINDING_MISMATCH");
      }
      const verification = await verifyRegistration(
        credential.registration,
        pairing.request.challenge
      );
      const stored = credentialStore.write({
        role: 1,
        rawCredentialId: verification.credentialId,
        publicKey: {
          spki: verification.credentialPublicKey,
          algorithm: verification.algorithm
        },
        descriptorMetadata: credential.descriptorMetadata,
        generation: credential.generation,
        custodyDomainCommitment: credential.custodyDomainCommitment,
        registrationPolicy: {
          requestedProfile: "STANDARD",
          attestationConveyance: "none",
          algorithm: "ES256",
          userVerified: verification.userVerified,
          attestedCredentialDataPresent: verification.attestedCredentialDataIncluded,
          backupEligible: verification.backupEligible,
          backupState: verification.backupState
        }
      });
      consumedPairingSessions.add(pairing.request.sessionId);
      publicFactors.set(1, stored);
      pairing = null;
      state = STATES.SECONDARY_COMPLETE;
      return stored;
    } catch (error) {
      if (error instanceof RecoveryEnrollmentError) throw error;
      throw new RecoveryEnrollmentError("PAIRING_TRANSCRIPT_DECRYPTION_FAILED");
    }
  }

  function generateOffline() {
    requireState(STATES.SECONDARY_COMPLETE);
    const entropy = randomBytes(32);
    if (entropy.length !== 32 || entropy.every((byte) => byte === 0)) {
      throw new RecoveryEnrollmentError("OFFLINE_ENTROPY_INVALID");
    }
    const recoveryCode = formatOfflineCode(entropy);
    const inspected = inspectOfflineCode(recoveryCode);
    offline = {
      secret: new SecretValue(recoveryCode),
      signer: inspected.signer,
      publicVerificationMaterialHash: inspected.publicVerificationMaterialHash,
      revealed: false
    };
    publicFactors.set(2, Object.freeze({
      role: 2,
      generation: 1,
      formatVersion: "PHIL39-V1",
      signer: offline.signer,
      safePublicFingerprint: offline.publicVerificationMaterialHash,
      persistence: "public_metadata_only"
    }));
    state = STATES.OFFLINE_PENDING;
    return Object.freeze({
      role: 2,
      formatVersion: "PHIL39-V1",
      signer: offline.signer,
      safePublicFingerprint: offline.publicVerificationMaterialHash
    });
  }

  function revealOffline() {
    requireState(STATES.OFFLINE_PENDING, STATES.OFFLINE_EXPORT_CONFIRMED);
    if (!offline?.secret) throw new RecoveryEnrollmentError("OFFLINE_SECRET_UNAVAILABLE");
    offline.secret.consume((secret) => secureDisplay(new SecretValue(secret)));
    offline.revealed = true;
    return Object.freeze({ revealedInProtectedView: true, secretReturned: false });
  }

  function confirmOfflineExport() {
    requireState(STATES.OFFLINE_PENDING);
    if (!offline?.revealed) throw new RecoveryEnrollmentError("OFFLINE_REVEAL_REQUIRED");
    state = STATES.OFFLINE_EXPORT_CONFIRMED;
    return status();
  }

  function restoreOffline(restorationInput) {
    requireState(STATES.OFFLINE_EXPORT_CONFIRMED);
    const candidate = new SecretValue(restorationInput);
    try {
      const inspected = candidate.consume(inspectOfflineCode);
      if (inspected.publicVerificationMaterialHash !== offline.publicVerificationMaterialHash) {
        state = STATES.INVALIDATED;
        offline.secret?.clear();
        offline = null;
        throw new RecoveryEnrollmentError("OFFLINE_RESTORATION_MISMATCH_INVALIDATED");
      }
      offline.secret?.clear();
      offline.secret = null;
      credentialStore.writeOfflinePublicMetadata({
        signer: inspected.signer,
        safePublicFingerprint: inspected.publicVerificationMaterialHash,
        confirmationStatus: "stored_by_user",
        restorationDrillStatus: "matched"
      });
      state = STATES.OFFLINE_DRILL_COMPLETE;
      return Object.freeze({
        matched: true,
        safePublicFingerprint: inspected.publicVerificationMaterialHash,
        secretRetained: false
      });
    } finally {
      candidate.clear();
    }
  }

  function reviewIndependence({ acknowledged, primaryAndSecondaryIndependent }) {
    requireState(STATES.OFFLINE_DRILL_COMPLETE);
    state = STATES.INDEPENDENCE_REVIEW;
    if (!acknowledged || !primaryAndSecondaryIndependent) {
      state = STATES.INVALIDATED;
      throw new RecoveryEnrollmentError("INDEPENDENCE_REVIEW_FAILED");
    }
    state = STATES.READY_FOR_COMMITMENT_APPROVAL;
    return status();
  }

  function complete() {
    requireState(STATES.READY_FOR_COMMITMENT_APPROVAL);
    if ([0, 1, 2].some((role) => !publicFactors.has(role))) {
      throw new RecoveryEnrollmentError("RECOVERY_FACTOR_SET_INCOMPLETE");
    }
    state = STATES.COMPLETE;
    return status();
  }

  function cancel() {
    pairing = null;
    primaryChallenge = null;
    secondaryChallenge = null;
    invalidateDisposableDiagnostic();
    offline?.secret?.clear();
    offline = null;
    state = STATES.CANCELLED;
    return status();
  }

  function deleteFactor(reference) {
    const removed = credentialStore.remove(reference);
    for (const [role, factor] of publicFactors) {
      if (factor.reference === reference) publicFactors.delete(role);
    }
    state = STATES.INVALIDATED;
    return Object.freeze({ removed, state });
  }

  function rotateFactor(reference, next) {
    if (state !== STATES.COMPLETE) throw new RecoveryEnrollmentError("ROTATION_REQUIRES_COMPLETE_ENROLLMENT");
    const replacement = credentialStore.rotate(reference, next);
    publicFactors.set(replacement.role, replacement);
    state = STATES.INVALIDATED;
    return replacement;
  }

  return Object.freeze({
    preflight,
    status,
    beginCredential,
    beginDisposableDiagnostic,
    cancelDisposableDiagnostic,
    verifyDisposableRegistration,
    verifyDisposableAssertion,
    beginHardwareCredentialFallback,
    storeCredential,
    beginPairing,
    completePairing,
    beginNativeIPhonePairing,
    completeNativeIPhonePairing,
    cancelNativeIPhonePairing,
    generateOffline,
    revealOffline,
    confirmOfflineExport,
    restoreOffline,
    reviewIndependence,
    complete,
    cancel,
    deleteFactor,
    rotateFactor
  });
}

module.exports = {
  RECORD_SCHEMA_VERSION,
  ENCRYPTION_ENVELOPE_VERSION,
  PAIRING_PROTOCOL_VERSION,
  PAIRING_TTL_MS,
  DISPOSABLE_DIAGNOSTIC_TTL_MS,
  DISPOSABLE_TEST_LABEL,
  STATES,
  RecoveryEnrollmentError,
  SecretValue,
  safeError,
  redactForLog,
  createEncryptedRecoveryCredentialStore,
  createSecondaryPairingResponse,
  formatOfflineCode,
  inspectOfflineCode,
  createRecoveryEnrollmentHost
};
