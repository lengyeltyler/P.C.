const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
require("tsx/cjs");
const {
  AbiCoder,
  Wallet,
  getBytes,
  hexlify,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");
const {
  APP_MODE,
  CHANNELS,
  containsForbiddenKey,
  validateBridgePayload
} = require("../shared/bridge-contract.cjs");
function realLocalAuthorizationWorkflow() {
  return require("./real-local-authorization-workflow.cjs");
}
function auditCurrentDesktopDemoStages(...args) {
  return realLocalAuthorizationWorkflow().auditCurrentDesktopDemoStages(...args);
}
function completeDesktopRealLocalAuthorizationWorkflow(...args) {
  return realLocalAuthorizationWorkflow().completeDesktopRealLocalAuthorizationWorkflow(...args);
}
function sanitizeWorkflow(...args) {
  return realLocalAuthorizationWorkflow().sanitizeWorkflow(...args);
}
function startDesktopRealLocalAuthorizationWorkflow(...args) {
  return realLocalAuthorizationWorkflow().startDesktopRealLocalAuthorizationWorkflow(...args);
}
function sepoliaUserOperationPreparationWorkflow() {
  return require("./sepolia-user-operation-preparation-workflow.cjs");
}
function loadDesktopSepoliaPreparationConfiguration(...args) {
  return sepoliaUserOperationPreparationWorkflow()
    .loadDesktopSepoliaPreparationConfiguration(...args);
}
function startDesktopSepoliaUserOperationPreparation(...args) {
  return sepoliaUserOperationPreparationWorkflow()
    .startDesktopSepoliaUserOperationPreparation(...args);
}
function validateConfigurationBinding(...args) {
  return sepoliaUserOperationPreparationWorkflow()
    .validateConfigurationBinding(...args);
}
function sepoliaMintComposedWorkflow() {
  return require("./sepolia-mint-composed-workflow.cjs");
}
const {
  completeDesktopSepoliaUserOperationSigning
} = require("./sepolia-user-operation-signing-workflow.cjs");
const {
  createMacOsUserPresenceEvidence,
  createUnsupportedMacOsUserPresenceProvider
} = require("./macos-user-presence.cjs");
const {
  controlledBetaReleaseState
} = require("./controlled-beta-release-state.cjs");

const abiCoder = AbiCoder.defaultAbiCoder();

const DEFAULT_SETTINGS = Object.freeze({
  appearance: "system",
  sessionTimeoutMinutes: 15,
  autoLockEnabled: true,
  developerModeVisible: true,
  auditDetailLevel: "standard",
  presentationMode: "user",
  introCompleted: false
});

const INDEX_FORMAT = "philcore-desktop-local-identity-index-v1";
const INDEX_VERSION = 1;
const IDENTITY_ENVELOPE_FORMAT = "philcore-desktop-private-identity-envelope-v1";
const REGISTRY_ENVELOPE_FORMAT = "phil-device-identity-registry-encrypted";
const REGISTRY_PLAINTEXT_FORMAT = "phil-device-identity-registry";
const VALIDATOR_ENVELOPE_FORMAT = "philcore-desktop-device-vault-validator-envelope-v1";
const RECOVERY_ENVELOPE_FORMAT = "philcore-desktop-device-vault-recovery-authority-envelope-v1";
const PLATFORM_PROTECTION_FORMAT = "philcore-desktop-platform-protection-v1";
const PLATFORM_PASSPHRASE_WRAP_FORMAT = "philcore-desktop-wrapping-key-passphrase-envelope-v1";
const STORAGE_VERSION = 1;
const PLATFORM_PROTECTION_VERSION = 1;
const PHIL_SECRET_FIELD_MASK = (1n << 251n) - 1n;
const SCRYPT = Object.freeze({ N: 32768, r: 8, p: 1, keyLength: 32 });
const SCRYPT_MAXMEM = 128 * 1024 * 1024;
const WRAPPING_KEY_PROVIDER_KIND = "desktop-vault-wrapping-key-v1";
const PLATFORM_UNLOCK_POLICY = Object.freeze({
  platformUnlockEnabled: true,
  platformUnlockRequired: false,
  passphraseFallbackAllowed: true,
  fallbackDisabled: false,
  userPresenceRequired: false,
  biometricPreferred: false,
  keychainOnly: true,
  nativeUserPresenceSupported: true,
  releaseCandidateRequiresNativeUserPresence: true,
  externalKeyAllowed: false,
  sessionTimeoutMinutes: DEFAULT_SETTINGS.sessionTimeoutMinutes,
  reauthenticationRequiredForSigning: true,
  reauthenticationRequiredForRecovery: true,
  lockOnSleep: true,
  lockOnScreenLock: true,
  lockOnUserSwitch: true
});
const PRESENTATION_TTL_MS = 5 * 60_000;
const APPROVAL_TTL_MS = 2 * 60_000;
const FRESH_AUTH_TTL_MS = 2 * 60_000;
const MAX_PENDING_PRESENTATIONS = 8;
const CRITICAL_PRESENTATION_KINDS = Object.freeze([
  "ethereum_sepolia_user_operation_signing",
  "recovery_complete",
  "execution_owner_rotation",
  "recovery_authority_rotation",
  "local_identity_reset"
]);
const FRESH_AUTH_REQUIRED_KINDS = Object.freeze([
  "ethereum_sepolia_user_operation_signing",
  "user_operation_signing",
  "recovery_request",
  "recovery_complete",
  "execution_owner_rotation",
  "recovery_authority_rotation",
  "recovery_signing_session",
  "validator_signing_session",
  "platform_unlock_disablement",
  "local_identity_reset"
]);
const DOMAIN_HASHES = Object.freeze({
  identityRoot: keccak256(toUtf8Bytes("PHIL_IDENTITY_ROOT_V1")),
  canonicalOwnerCommitment: keccak256(toUtf8Bytes("PHIL_OWNER_COMMITMENT_CANONICAL_V1"))
});

function shortRef(value) {
  const text = String(value || "");
  if (text.length <= 18) return text;
  return `${text.slice(0, 10)}...${text.slice(-6)}`;
}

function makeId(prefix) {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}

function nowIso() {
  return new Date().toISOString();
}

function frozen(value) {
  return Object.freeze(JSON.parse(JSON.stringify(value)));
}

function stableJson(value) {
  return JSON.stringify(value, (_key, candidate) => {
    if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
      return Object.fromEntries(
        Object.entries(candidate).sort(([left], [right]) => left.localeCompare(right))
      );
    }
    return candidate;
  });
}

function normalizeHex32(value) {
  return zeroPadValue(hexlify(value), 32).toLowerCase();
}

function hashAbiEncoded(types, values) {
  return keccak256(abiCoder.encode(types, values));
}

function identityRootFromPhilSecret(philSecret) {
  return hashAbiEncoded(
    ["bytes32", "bytes32"],
    [DOMAIN_HASHES.identityRoot, normalizeHex32(philSecret)]
  );
}

function ownerCommitmentFromIdentityRoot(identityRoot) {
  return hashAbiEncoded(
    ["bytes32", "bytes32"],
    [DOMAIN_HASHES.canonicalOwnerCommitment, normalizeHex32(identityRoot)]
  );
}

function generatePhilSecret() {
  for (;;) {
    const numeric = BigInt(`0x${crypto.randomBytes(32).toString("hex")}`) & PHIL_SECRET_FIELD_MASK;
    if (numeric !== 0n) return zeroPadValue(toBeHex(numeric), 32).toLowerCase();
  }
}

function createPhilIdentityPrivate() {
  const philSecret = generatePhilSecret();
  const identityRoot = identityRootFromPhilSecret(philSecret);
  const ownerCommitment = ownerCommitmentFromIdentityRoot(identityRoot);
  return Object.freeze({ philSecret, identityRoot, ownerCommitment });
}

function createSafeWallet() {
  for (;;) {
    try {
      return new Wallet(`0x${crypto.randomBytes(32).toString("hex")}`);
    } catch {
      // Try fresh entropy if secp256k1 rejects the scalar.
    }
  }
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dirPath, 0o700);
  } catch {
    // Best-effort on platforms that do not honor POSIX modes.
  }
}

function assertSafeStoragePath(root, targetPath) {
  const relative = path.relative(root, targetPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("desktop_storage_path_escape_rejected");
  }
}

function atomicWriteFile(filePath, contents) {
  const dir = path.dirname(filePath);
  ensureDir(dir);
  assertSafeStoragePath(path.dirname(path.dirname(dir)), filePath);
  if (fs.existsSync(filePath)) {
    const stat = fs.lstatSync(filePath);
    if (stat.isSymbolicLink()) throw new Error("desktop_storage_symlink_rejected");
  }
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`);
  fs.writeFileSync(tmpPath, contents, { encoding: "utf8", mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
  try {
    fs.chmodSync(filePath, 0o600);
  } catch {
    // Best-effort on platforms that do not honor POSIX modes.
  }
}

function readJsonFile(filePath) {
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink()) throw new Error("desktop_storage_symlink_rejected");
  if (stat.size > 2_000_000) throw new Error("desktop_storage_file_too_large");
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function deriveKey(passphrase, ownerCommitment, salt) {
  if (typeof passphrase !== "string" || passphrase.length < 8) {
    throw new Error("local_alpha_passphrase_too_short");
  }
  return crypto.scryptSync(
    passphrase,
    Buffer.concat([Buffer.from(salt), Buffer.from(ownerCommitment.slice(2), "hex")]),
    SCRYPT.keyLength,
    { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: SCRYPT_MAXMEM }
  );
}

function envelopeAad(envelope) {
  return stableJson({
    format: envelope.format,
    version: envelope.version,
    identityId: envelope.identityId,
    ownerCommitment: envelope.ownerCommitment,
    payloadFormat: envelope.payloadFormat
  });
}

function encryptPayload({ format, identityId, ownerCommitment, payload, passphrase }) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, ownerCommitment, salt);
  const envelope = {
    format,
    version: STORAGE_VERSION,
    identityId,
    ownerCommitment,
    payloadFormat: payload.format,
    encryption: {
      algorithm: "aes-256-gcm",
      kdf: {
        providerKind: "local-alpha-passphrase-scrypt-device-registry-key-test-only-v1",
        unsafeForProduction: true,
        salt: salt.toString("base64url"),
        scrypt: SCRYPT
      },
      iv: iv.toString("base64url"),
      tag: ""
    },
    ciphertext: ""
  };
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(envelopeAad(envelope), "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(stableJson(payload), "utf8")),
    cipher.final()
  ]);
  envelope.encryption.tag = cipher.getAuthTag().toString("base64url");
  envelope.ciphertext = ciphertext.toString("base64url");
  key.fill(0);
  return stableJson(envelope);
}

function encryptPayloadWithRawKey({ format, identityId, ownerCommitment, payload, rawKey }) {
  if (!Buffer.isBuffer(rawKey) || rawKey.length !== 32) throw new Error("wrapping_key_invalid");
  const iv = crypto.randomBytes(12);
  const envelope = {
    format,
    version: STORAGE_VERSION,
    identityId,
    ownerCommitment,
    payloadFormat: payload.format,
    encryption: {
      algorithm: "aes-256-gcm",
      kdf: {
        providerKind: WRAPPING_KEY_PROVIDER_KIND,
        keyLength: 32
      },
      iv: iv.toString("base64url"),
      tag: ""
    },
    ciphertext: ""
  };
  const cipher = crypto.createCipheriv("aes-256-gcm", rawKey, iv);
  cipher.setAAD(Buffer.from(envelopeAad(envelope), "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(stableJson(payload), "utf8")),
    cipher.final()
  ]);
  envelope.encryption.tag = cipher.getAuthTag().toString("base64url");
  envelope.ciphertext = ciphertext.toString("base64url");
  return stableJson(envelope);
}

function decryptPayload({ serialized, passphrase, expectedIdentityId, expectedOwnerCommitment }) {
  let envelope;
  try {
    envelope = JSON.parse(serialized);
  } catch {
    throw new Error("encrypted_envelope_corrupted");
  }
  if (!envelope || typeof envelope !== "object" || envelope.version !== STORAGE_VERSION) {
    throw new Error("encrypted_envelope_unsupported");
  }
  if (envelope.identityId !== expectedIdentityId) throw new Error("identity_binding_mismatch");
  if (envelope.ownerCommitment !== expectedOwnerCommitment) throw new Error("owner_commitment_mismatch");
  if (envelope.encryption?.algorithm !== "aes-256-gcm") throw new Error("encryption_algorithm_unsupported");
  const salt = Buffer.from(envelope.encryption.kdf.salt, "base64url");
  const iv = Buffer.from(envelope.encryption.iv, "base64url");
  const tag = Buffer.from(envelope.encryption.tag, "base64url");
  const key = deriveKey(passphrase, envelope.ownerCommitment, salt);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAAD(Buffer.from(envelopeAad(envelope), "utf8"));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
      decipher.final()
    ]);
    return { envelope, payload: JSON.parse(plaintext.toString("utf8")), key };
  } catch {
    key.fill(0);
    throw new Error("encrypted_envelope_authentication_failed");
  }
}

function decryptPayloadWithRawKey({ serialized, rawKey, expectedIdentityId, expectedOwnerCommitment }) {
  if (!Buffer.isBuffer(rawKey) || rawKey.length !== 32) throw new Error("wrapping_key_invalid");
  let envelope;
  try {
    envelope = JSON.parse(serialized);
  } catch {
    throw new Error("encrypted_envelope_corrupted");
  }
  if (!envelope || typeof envelope !== "object" || envelope.version !== STORAGE_VERSION) {
    throw new Error("encrypted_envelope_unsupported");
  }
  if (envelope.identityId !== expectedIdentityId) throw new Error("identity_binding_mismatch");
  if (envelope.ownerCommitment !== expectedOwnerCommitment) throw new Error("owner_commitment_mismatch");
  if (envelope.encryption?.algorithm !== "aes-256-gcm") throw new Error("encryption_algorithm_unsupported");
  if (envelope.encryption?.kdf?.providerKind !== WRAPPING_KEY_PROVIDER_KIND) {
    throw new Error("encryption_key_provider_mismatch");
  }
  const iv = Buffer.from(envelope.encryption.iv, "base64url");
  const tag = Buffer.from(envelope.encryption.tag, "base64url");
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", rawKey, iv);
    decipher.setAAD(Buffer.from(envelopeAad(envelope), "utf8"));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
      decipher.final()
    ]);
    return { envelope, payload: JSON.parse(plaintext.toString("utf8")) };
  } catch {
    throw new Error("encrypted_envelope_authentication_failed");
  }
}

function encryptWrappingKeyForPassphrase({ identityId, ownerCommitment, wrappingKey, passphrase }) {
  const payload = {
    format: "philcore-desktop-vault-wrapping-key-payload-v1",
    identityId,
    ownerCommitment,
    wrappingKey: wrappingKey.toString("base64url"),
    privateMaterialReturned: false
  };
  return JSON.parse(encryptPayload({
    format: PLATFORM_PASSPHRASE_WRAP_FORMAT,
    identityId,
    ownerCommitment,
    payload,
    passphrase
  }));
}

function decryptWrappingKeyFromPassphrase({ envelope, identityId, ownerCommitment, passphrase }) {
  const result = decryptPayload({
    serialized: JSON.stringify(envelope),
    passphrase,
    expectedIdentityId: identityId,
    expectedOwnerCommitment: ownerCommitment
  });
  try {
    const wrappingKey = Buffer.from(result.payload.wrappingKey, "base64url");
    if (wrappingKey.length !== 32) throw new Error("wrapping_key_invalid");
    return wrappingKey;
  } finally {
    result.key.fill(0);
  }
}

function createUnsupportedPlatformKeyAdapter(platform = process.platform) {
  return Object.freeze({
    kind: "unsupported_platform_key_adapter",
    getAvailability: () => ({
      status: "unsupported_platform",
      available: false,
      platform,
      backend: "none",
      protectionType: "unsupported",
      keychainAvailable: false,
      userPresenceGuaranteed: false,
      biometricAvailable: false,
      reason: platform === "darwin" ? "keychain_adapter_not_configured" : "unsupported_platform"
    }),
    protectWrappingKey: () => ({ status: "unsupported_platform" }),
    retrieveWrappingKey: () => ({ status: "unsupported_platform" }),
    deleteWrappingKey: () => ({ status: "unsupported_platform" })
  });
}

function createFixturePlatformKeyAdapter(options = {}) {
  const masterKey = Buffer.isBuffer(options.masterKey)
    ? Buffer.from(options.masterKey)
    : crypto.createHash("sha256").update(String(options.masterKey || "philcore-desktop-fixture-platform-key")).digest();
  let nextReadOutcome = null;
  const adapter = {
    kind: "fixture_platform_key_adapter",
    setNextReadOutcome(outcome) {
      nextReadOutcome = outcome;
    },
    getAvailability() {
      return {
        status: options.available === false ? "platform_authentication_unavailable" : "available",
        available: options.available !== false,
        platform: "fixture",
        backend: "isolated_fixture_keychain",
        protectionType: "fixture_keychain_for_tests",
        keychainAvailable: options.available !== false,
        userPresenceGuaranteed: false,
        biometricAvailable: false,
        productionCandidate: false,
        reason: options.available === false ? "fixture_disabled" : "fixture_available"
      };
    },
    protectWrappingKey({ identityId, ownerCommitment, wrappingKey }) {
      if (options.available === false) return { status: "platform_authentication_unavailable" };
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, iv);
      cipher.setAAD(Buffer.from(`${identityId}:${ownerCommitment}`, "utf8"));
      const ciphertext = Buffer.concat([cipher.update(wrappingKey), cipher.final()]);
      return {
        status: "stored",
        keychainReference: {
          provider: "fixture_keychain",
          service: "philcore.desktop.fixture",
          account: identityId,
          purpose: "desktop_vault_wrapping_key",
          storageVersion: PLATFORM_PROTECTION_VERSION
        },
        protectedKeyBlob: Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url"),
        protectionType: "fixture_keychain_for_tests"
      };
    },
    retrieveWrappingKey({ identityId, ownerCommitment, protectedKeyBlob }) {
      if (nextReadOutcome) {
        const outcome = nextReadOutcome;
        nextReadOutcome = null;
        return { status: outcome };
      }
      if (options.available === false) return { status: "platform_authentication_unavailable" };
      try {
        const blob = Buffer.from(protectedKeyBlob, "base64url");
        if (blob.length < 60) return { status: "wrapping_key_invalid" };
        const iv = blob.subarray(0, 12);
        const tag = blob.subarray(12, 28);
        const ciphertext = blob.subarray(28);
        const decipher = crypto.createDecipheriv("aes-256-gcm", masterKey, iv);
        decipher.setAAD(Buffer.from(`${identityId}:${ownerCommitment}`, "utf8"));
        decipher.setAuthTag(tag);
        const wrappingKey = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
        if (wrappingKey.length !== 32) return { status: "wrapping_key_invalid" };
        return { status: "retrieved", wrappingKey };
      } catch {
        return { status: "wrapping_key_invalid" };
      }
    },
    deleteWrappingKey() {
      return { status: "deleted" };
    }
  };
  return Object.freeze(adapter);
}

function createElectronSafeStoragePlatformKeyAdapter({ safeStorage, platform = process.platform } = {}) {
  return Object.freeze({
    kind: "electron_safe_storage_platform_key_adapter",
    getAvailability() {
      const safeStorageAvailable = Boolean(safeStorage?.isEncryptionAvailable?.());
      const macos = platform === "darwin";
      return {
        status: macos && safeStorageAvailable ? "available" : "unsupported_platform",
        available: macos && safeStorageAvailable,
        platform,
        backend: macos ? "electron_safe_storage_macos_keychain" : "electron_safe_storage_non_macos_unsupported",
        protectionType: macos ? "macos_keychain_safe_storage" : "unsupported",
        keychainAvailable: macos && safeStorageAvailable,
        userPresenceGuaranteed: false,
        biometricAvailable: false,
        productionCandidate: macos && safeStorageAvailable,
        reason: macos
          ? (safeStorageAvailable ? "macos_keychain_available" : "electron_safe_storage_unavailable")
          : "macos_only_boundary"
      };
    },
    protectWrappingKey({ identityId, wrappingKey }) {
      const availability = this.getAvailability();
      if (!availability.available) return { status: availability.status };
      try {
        const protectedBuffer = safeStorage.encryptString(wrappingKey.toString("base64url"));
        return {
          status: "stored",
          keychainReference: {
            provider: "electron_safe_storage",
            service: "philcore.desktop",
            account: identityId,
            purpose: "desktop_vault_wrapping_key",
            storageVersion: PLATFORM_PROTECTION_VERSION
          },
          protectedKeyBlob: protectedBuffer.toString("base64url"),
          protectionType: "macos_keychain_safe_storage"
        };
      } catch {
        return { status: "keychain_access_denied" };
      }
    },
    retrieveWrappingKey({ protectedKeyBlob }) {
      const availability = this.getAvailability();
      if (!availability.available) return { status: availability.status };
      try {
        const decrypted = safeStorage.decryptString(Buffer.from(protectedKeyBlob, "base64url"));
        const wrappingKey = Buffer.from(decrypted, "base64url");
        if (wrappingKey.length !== 32) return { status: "wrapping_key_invalid" };
        return { status: "retrieved", wrappingKey };
      } catch {
        return { status: "keychain_access_denied" };
      }
    },
    deleteWrappingKey() {
      return { status: "deleted_reference_only" };
    }
  });
}

function createDesktopRuntimeHost(options = {}) {
  const preferencesPath = options.preferencesPath;
  const storageRoot = path.resolve(
    options.identityStorageRoot
      || path.join(path.dirname(preferencesPath || process.cwd()), "philcore-local-identities")
  );
  ensureDir(storageRoot);

  let settings = loadSettings(preferencesPath);
  let auditEvents = [];
  let selectedIdentityId = null;
  let lifecycle = createLifecycle("locked");
  let pendingUnlock = null;
  let unlockedVault = null;
  let protectedRuntimeMaterial = null;
  let activeAuthorizationWorkflow = null;
  const preparedSepoliaProofDigests = new Set();
  const preparedSepoliaNullifiers = new Set();
  let cachedSepoliaPreparationConfiguration = null;
  let lockTimer = null;
  const presentations = new Map();
  const approvals = new Map();
  const freshAuthEvidence = new Map();
  let approvalHistory = [];
  const platformKeyAdapter = options.platformKeyAdapter || createUnsupportedPlatformKeyAdapter();
  const userPresenceProvider = options.userPresenceProvider || createUnsupportedMacOsUserPresenceProvider();
  const protectedActionMarkerPath = path.join(storageRoot, "active-protected-action.json");
  const localNullifierLedgerPath = path.join(storageRoot, "local-nullifier-ledger.json");
  let localNullifierLedgerError = null;
  let localNullifierLedger = { format: "philcore-local-nullifier-ledger", version: 1, entries: [] };
  try {
    if (fs.existsSync(localNullifierLedgerPath)) {
      const parsed = readJsonFile(localNullifierLedgerPath);
      if (parsed?.format !== localNullifierLedger.format
        || parsed?.version !== localNullifierLedger.version
        || !Array.isArray(parsed.entries)
        || parsed.entries.length > 10_000
        || parsed.entries.some((entry) =>
          !/^0x[0-9a-f]{64}$/u.test(entry?.nullifier || "")
          || !["reserved", "consumed"].includes(entry?.state)
          || typeof entry?.workflowId !== "string"
          || typeof entry?.recordedAt !== "string")) {
        throw new Error("local_nullifier_ledger_invalid");
      }
      if (new Set(parsed.entries.map((entry) => entry.nullifier)).size !== parsed.entries.length) {
        throw new Error("local_nullifier_ledger_duplicate");
      }
      localNullifierLedger = parsed;
    }
  } catch (error) {
    localNullifierLedgerError = error instanceof Error ? error.message : "local_nullifier_ledger_unavailable";
  }

  function persistLocalNullifierLedger() {
    if (localNullifierLedgerError) throw new Error(localNullifierLedgerError);
    atomicWriteFile(localNullifierLedgerPath, `${stableJson(localNullifierLedger)}\n`);
  }

  function reserveLocalNullifier(nullifier, workflowId) {
    if (localNullifierLedgerError) throw new Error("local_nullifier_ledger_unavailable");
    if (!/^0x[0-9a-f]{64}$/u.test(nullifier || "")) throw new Error("local_nullifier_invalid");
    if (localNullifierLedger.entries.some((entry) => entry.nullifier === nullifier)) {
      throw new Error("durable_local_nullifier_replay_rejected");
    }
    localNullifierLedger = {
      ...localNullifierLedger,
      entries: [...localNullifierLedger.entries, {
        nullifier,
        state: "reserved",
        workflowId,
        recordedAt: nowIso()
      }]
    };
    persistLocalNullifierLedger();
  }

  function markLocalNullifierConsumed(nullifier, workflowId) {
    const index = localNullifierLedger.entries.findIndex((entry) =>
      entry.nullifier === nullifier && entry.workflowId === workflowId);
    if (index < 0) throw new Error("local_nullifier_reservation_missing");
    const entries = [...localNullifierLedger.entries];
    entries[index] = { ...entries[index], state: "consumed", consumedAt: nowIso() };
    localNullifierLedger = { ...localNullifierLedger, entries };
    persistLocalNullifierLedger();
  }
  let startupInterruptedAction = null;
  try {
    if (fs.existsSync(protectedActionMarkerPath)) {
      startupInterruptedAction = readJsonFile(protectedActionMarkerPath);
      fs.rmSync(protectedActionMarkerPath, { force: true });
    }
  } catch {
    startupInterruptedAction = { workflowId: "unknown", status: "interrupted" };
  }
  const requireNativeUserPresence = Boolean(
    options.requireNativeUserPresence
      || process.env.PHILCORE_DESKTOP_REQUIRE_NATIVE_USER_PRESENCE === "1"
      || process.env.PHILCORE_DESKTOP_RELEASE_PROFILE === "release_candidate_signed"
      || process.env.PHILCORE_DESKTOP_RELEASE_PROFILE === "release_candidate_notarized"
  );

  function indexPath() {
    return path.join(storageRoot, "identity-index.json");
  }

  function identityDir(identityId) {
    if (!/^identity_[a-f0-9]{12}_[a-f0-9]{8}$/u.test(identityId)) {
      throw new Error("invalid_identity_id");
    }
    const dir = path.join(storageRoot, identityId);
    assertSafeStoragePath(storageRoot, dir);
    return dir;
  }

  function pathsFor(identityId) {
    const dir = identityDir(identityId);
    return {
      dir,
      identity: path.join(dir, "identity.encrypted.json"),
      registry: path.join(dir, "registry.encrypted.json"),
      validator: path.join(dir, "validator.encrypted.json"),
      recovery: path.join(dir, "recovery-authority.encrypted.json"),
      platformProtection: path.join(dir, "platform-protection.json")
    };
  }

  function loadIndex() {
    if (!fs.existsSync(indexPath())) {
      return { format: INDEX_FORMAT, version: INDEX_VERSION, identities: [] };
    }
    const parsed = readJsonFile(indexPath());
    if (parsed.format !== INDEX_FORMAT || parsed.version !== INDEX_VERSION || !Array.isArray(parsed.identities)) {
      throw new Error("identity_index_unsupported_or_corrupted");
    }
    return parsed;
  }

  function saveIndex(index) {
    atomicWriteFile(indexPath(), `${stableJson(index)}\n`);
  }

  function updateIndexEntry(identityId, updater) {
    const index = loadIndex();
    const identities = index.identities.map((entry) => entry.identityId === identityId ? updater(entry) : entry);
    saveIndex({ ...index, identities });
  }

  function getSelectedEntry() {
    if (!selectedIdentityId) return undefined;
    return loadIndex().identities.find((entry) => entry.identityId === selectedIdentityId);
  }

  function addAudit(category, action, result, details = {}) {
    const safeDetails = sanitizeDetails(details);
    const event = {
      auditEventId: makeId("audit"),
      timestamp: nowIso(),
      category,
      applicationId: "philcore_desktop",
      sessionId: lifecycle.sessionId,
      action,
      result,
      correlationRef: makeId("corr"),
      evidenceClass: selectedIdentityId ? "desktop_local_encrypted_identity" : "desktop_process_local",
      publicNetworkMutation: false,
      details: safeDetails
    };
    auditEvents.unshift(event);
    return event;
  }

  if (startupInterruptedAction) {
    addAudit("authorization", "protected_action_interrupted", "interrupted", {
      workflowId: startupInterruptedAction.workflowId,
      previousStatus: startupInterruptedAction.status,
      reason: "application_restarted_before_action_completed",
      publicNetworkMutation: false
    });
  }

  function workflowIsTerminal(status) {
    return [
      "completed",
      "prepared_unsigned",
      "signed_unsubmitted",
      "rejected",
      "cancelled",
      "failed",
      "timed_out",
      "interrupted"
    ].includes(status);
  }

  function writeProtectedActionMarker(workflowId, status, auditCorrelationId) {
    atomicWriteFile(protectedActionMarkerPath, `${stableJson({
      format: "philcore-desktop-active-protected-action-v1",
      workflowId,
      status,
      identityId: selectedIdentityId,
      auditCorrelationId,
      startedAt: nowIso(),
      containsSecrets: false,
      publicNetworkMutation: false
    })}\n`);
  }

  function clearProtectedActionMarker() {
    fs.rmSync(protectedActionMarkerPath, { force: true });
  }

  function terminalizeActiveWorkflow(status, reason, auditAction = "real_local_workflow_stopped") {
    if (!activeAuthorizationWorkflow || workflowIsTerminal(activeAuthorizationWorkflow.status)) {
      return sanitizedActiveWorkflow();
    }
    activeAuthorizationWorkflow = {
      ...sanitizeWorkflow(activeAuthorizationWorkflow),
      status,
      updatedAt: nowIso(),
      pendingSigningPresentation: undefined,
      privateState: undefined,
      error: reason
    };
    clearProtectedActionMarker();
    addAudit("authorization", auditAction, status, {
      workflowId: activeAuthorizationWorkflow.workflowId,
      reason,
      auditCorrelationId: activeAuthorizationWorkflow.correlation?.auditCorrelationId,
      publicNetworkMutation: false
    });
    return sanitizedActiveWorkflow();
  }

  function persistRegistryAudit(action, result, details = {}) {
    if (!unlockedVault) return;
    const event = {
      eventId: keccak256(toUtf8Bytes(stableJson({
        ownerCommitment: unlockedVault.ownerCommitment,
        action,
        occurredAt: nowIso(),
        sequence: unlockedVault.registry.auditTrail.length
      }))),
      eventType: action,
      ownerCommitment: unlockedVault.ownerCommitment,
      occurredAt: nowIso(),
      details: sanitizeDetails(details)
    };
    unlockedVault.registry.auditTrail.push(event);
    saveUnlockedRegistry();
  }

  function expireProcessLocalAuthority() {
    const now = Date.now();
    for (const [id, presentation] of presentations.entries()) {
      if (Date.parse(presentation.expiresAt) <= now) {
        presentations.delete(id);
        recordApprovalHistory(presentation, "expired", "presentation_expired");
        addAudit("approval", "presentation_expired", "expired", {
          presentationId: id,
          actionKind: presentation.kind,
          digestRef: presentation.digestShort
        });
      }
    }
    for (const [id, approval] of approvals.entries()) {
      if (Date.parse(approval.expiresAt) <= now) approvals.delete(id);
    }
    for (const [id, evidence] of freshAuthEvidence.entries()) {
      if (Date.parse(evidence.expiresAt) <= now) freshAuthEvidence.delete(id);
    }
  }

  function clearPendingApprovalAuthority(reason) {
    for (const presentation of presentations.values()) {
      recordApprovalHistory(presentation, "cancelled", reason);
    }
    presentations.clear();
    approvals.clear();
    freshAuthEvidence.clear();
  }

  function canonicalPresentationDigest(canonical) {
    return keccak256(toUtf8Bytes(stableJson(canonical)));
  }

  function field(label, value, category = "summary") {
    return { label, value: value ?? "not available", category };
  }

  function riskForKind(kind) {
    if (kind === "local_identity_reset" || kind === "recovery_complete") return "critical_local";
    if (kind === "recovery_request" || kind === "execution_owner_rotation" || kind === "recovery_authority_rotation") return "critical_local";
    if (kind.includes("signing") || kind.startsWith("platform_unlock")) return "sensitive";
    if (
      kind === "local_authorization_execution"
      || kind === "ethereum_sepolia_unsigned_preparation"
    ) return "sensitive";
    return "low";
  }

  function kindLabel(kind) {
    return kind.split("_").map((part) => part[0].toUpperCase() + part.slice(1)).join(" ");
  }

  function currentOperationFixture(kind, scenario = "") {
    const entry = getSelectedEntry();
    const validator = validatorStatus();
    const recovery = recoveryStatus();
    if (kind === "ethereum_sepolia_user_operation_signing") {
      const workflow = activeAuthorizationWorkflow;
      const artifact = workflow?.privateState?.unsignedArtifact;
      if (
        workflow?.workflowKind !== "ethereum_sepolia_unsigned_preparation"
        || workflow?.status !== "prepared_unsigned"
        || !artifact
      ) {
        throw new Error("sepolia_unsigned_artifact_not_available");
      }
      return {
        proofInputHash: artifact.proofInputHash,
        proofDigest: artifact.proofArtifactDigest,
        publicNullifier: artifact.publicNullifier,
        authorizationDigest: artifact.authorizationDigest,
        calldataHash: keccak256(artifact.userOperation.callData),
        userOperationHash: artifact.userOperationHash,
        nonce: artifact.userOperation.nonce,
        gasLimit: artifact.userOperation.accountGasLimits,
        feeLimit: artifact.userOperation.gasFees,
        prefundStatus: "not_funded",
        account: artifact.smartAccountAddress,
        entryPoint: artifact.entryPointAddress,
        target: artifact.targetAddress,
        value: "0",
        method: "executeLocalProofAuthorization(bytes32,bytes32,uint64)",
        validatorAddress: artifact.identityBinding.validatorAddress,
        validatorKeyId: artifact.identityBinding.validatorKeyId,
        chainId: artifact.chainId,
        expiry: artifact.expiry,
        securityModel: artifact.securityModel,
        signingPurpose: "ethereum_sepolia_local_proof_gated_v1_signing"
      };
    }
    if (kind === "ethereum_sepolia_unsigned_preparation") {
      const configuration = getSepoliaPreparationConfiguration();
      return {
        proofInputHash: "generated_after_approval",
        factHigh: "not_published",
        factLow: "not_published",
        publicNullifier: "generated_once_in_protected_runtime",
        calldataHash: "generated_after_runtime_authorization",
        userOperationHash: "generated_after_runtime_authorization",
        nonce: "0_counterfactual",
        gasLimit: "bounded_preparation_policy",
        feeLimit: "fresh_read_only_sepolia_fee_cap",
        prefundStatus: "not_funded",
        account: configuration.proposal.accountAddress,
        entryPoint: configuration.network.entryPointAddress,
        actionGate: "not_used_by_local-proof-gated-v1",
        consumer: configuration.proposal.targetAddress,
        target: configuration.proposal.targetAddress,
        value: "0",
        method: "executeLocalProofAuthorization(bytes32,bytes32,uint64)",
        validatorAddress: validator.publicOwnerAddress || "not_created",
        recoveryAddress: recovery.publicAddress || "not_created",
        chainId: configuration.network.chainId
      };
    }
    const proofInputHash = `0x${crypto.createHash("sha256").update(stableJson({
      kind,
      scenario,
      identityId: entry?.identityId,
      sessionId: lifecycle.sessionId,
      ownerCommitment: entry?.ownerCommitment,
      fixture: "desktop-o4"
    })).digest("hex")}`;
    const calldataHash = keccak256(toUtf8Bytes(stableJson({ kind, scenario, proofInputHash })));
    const userOperationHash = keccak256(toUtf8Bytes(stableJson({
      kind,
      scenario,
      account: "local_fixture_counterfactual_account",
      nonce: lifecycle.sequence,
      calldataHash
    })));
    return {
      proofInputHash,
      factHigh: `0x${proofInputHash.slice(2, 34)}`,
      factLow: `0x${proofInputHash.slice(34, 66)}`,
      publicNullifier: `0x${crypto.createHash("sha256").update(`${proofInputHash}:nullifier`).digest("hex")}`,
      calldataHash,
      userOperationHash,
      nonce: lifecycle.sequence,
      gasLimit: "local_fixture_350000",
      feeLimit: "local_fixture_fee_cap",
      prefundStatus: "fixture_prefund_not_public",
      account: "local_fixture_counterfactual_account",
      entryPoint: "ERC-4337 v0.7 local fixture",
      actionGate: "local_fixture_action_gate",
      consumer: "local_fixture_consumer",
      target: "local_fixture_action_gate.verifyAndConsume",
      value: "0",
      method: scenario || kind,
      validatorAddress: validator.publicOwnerAddress || "not_created",
      recoveryAddress: recovery.publicAddress || "not_created"
    };
  }

  function buildPresentationFields(kind, scenario, operation) {
    const entry = getSelectedEntry();
    const base = [
      field("Requesting application", "PhilCore Desktop"),
      field("Action", kindLabel(kind)),
      field("Risk", riskForKind(kind)),
      field("Local only", true),
      field("Public network mutation", false),
      field("Identity", entry?.label),
      field("Owner commitment", shortRef(entry?.ownerCommitment)),
      field("Session", lifecycle.sessionId),
      field("Expiry", new Date(Date.now() + PRESENTATION_TTL_MS).toISOString())
    ];
    if (kind === "ethereum_sepolia_unsigned_preparation") {
      return [
        ...base,
        field("Network", "Ethereum Sepolia", "network"),
        field("Chain ID", operation.chainId, "network"),
        field("Smart account", operation.account, "account"),
        field("EntryPoint", operation.entryPoint, "account"),
        field("Confirmation target", operation.target, "operation"),
        field("Method", operation.method, "operation"),
        field("Value", operation.value, "operation"),
        field("Execution validator", operation.validatorAddress, "authorization"),
        field("Proof type", "phil-noir-ultra-keccak-zk-honk-garaga-v1", "proof"),
        field("Proof generation", "after this one-time approval", "proof"),
        field("STARK verification", "local Runtime only", "proof"),
        field("Ethereum STARK verification", false, "proof"),
        field("Signature", "not created", "authorization"),
        field("Submission", "not allowed in O.21.1", "authorization"),
        field("Account deployment", "not performed", "account"),
        field("Account funding", "not performed", "account"),
        field("Paymaster", "disabled", "gas")
      ];
    }
    if (kind === "ethereum_sepolia_user_operation_signing") {
      return [
        ...base,
        field("Action", "Create Ethereum test account", "operation"),
        field("Network", "Ethereum Sepolia", "network"),
        field("Chain ID", operation.chainId, "network"),
        field("Security", "Verified locally by PhilCore", "proof"),
        field("Smart account", operation.account, "account"),
        field("EntryPoint", operation.entryPoint, "account"),
        field("Target", operation.target, "operation"),
        field("Method", operation.method, "operation"),
        field("Value", operation.value, "operation"),
        field("Nonce", operation.nonce, "gas"),
        field("Gas limits", operation.gasLimit, "gas"),
        field("Fee values", operation.feeLimit, "gas"),
        field("Expiry", new Date(Number(operation.expiry) * 1000).toISOString(), "authorization"),
        field("Authorization digest", shortRef(operation.authorizationDigest), "authorization"),
        field("UserOperation hash", shortRef(operation.userOperationHash), "authorization"),
        field("Execution validator", operation.validatorAddress, "authorization"),
        field("Validator key ID", shortRef(operation.validatorKeyId), "authorization"),
        field("Proof digest", shortRef(operation.proofDigest), "proof"),
        field("proofInputHash", shortRef(operation.proofInputHash), "proof"),
        field("Signing purpose", operation.signingPurpose, "authorization"),
        field("What happens", "Your device will authorize this action.", "summary"),
        field("Submission", "Nothing has been sent to Ethereum.", "summary")
      ];
    }
    if (kind === "local_authorization_execution" || kind === "user_operation_signing" || kind === "validator_signing_session") {
      return [
        ...base,
        field("Network mode", "local fixture only", "network"),
        field("Smart account", operation.account, "account"),
        field("EntryPoint", operation.entryPoint, "account"),
        field("ActionGate", operation.actionGate, "account"),
        field("Consumer", operation.consumer, "account"),
        field("Method", operation.method, "operation"),
        field("Target", operation.target, "operation"),
        field("Value", operation.value, "operation"),
        field("Capability scope", "local_fixture_authorization_demo", "authorization"),
        field("Capability Grant", "local_fixture_active_only_after_approval", "authorization"),
        field("Execution validator", operation.validatorAddress, "authorization"),
        field("Proof type", "phil-noir-ultra-keccak-zk-honk-garaga-v1", "proof"),
        field("proofInputHash", shortRef(operation.proofInputHash), "proof"),
        field("Public nullifier", shortRef(operation.publicNullifier), "proof"),
        field("Operation nonce", operation.nonce, "gas"),
        field("Gas limit", operation.gasLimit, "gas"),
        field("Fee limit", operation.feeLimit, "gas"),
        field("Prefund", operation.prefundStatus, "gas"),
        field("Paymaster", "disabled", "gas"),
        field("Account state", "counterfactual_not_deployed_local_fixture", "account"),
        field("UserOperation hash", shortRef(operation.userOperationHash), "technical"),
        field("Calldata hash", shortRef(operation.calldataHash), "technical")
      ];
    }
    if (kind.startsWith("recovery") || kind === "execution_owner_rotation") {
      return [
        ...base,
        field("Scenario", scenario || kind, "recovery"),
        field("Account", operation.account, "recovery"),
        field("Current execution owner", operation.validatorAddress, "recovery"),
        field("Proposed execution owner", scenario === "complete" || kind === "execution_owner_rotation" ? "local_fixture_new_owner" : "unchanged", "recovery"),
        field("Current recovery authority", operation.recoveryAddress, "recovery"),
        field("Proposed recovery authority", kind === "recovery_authority_rotation" ? "local_fixture_new_recovery_authority" : "unchanged", "recovery"),
        field("Recovery request ID", shortRef(operation.userOperationHash), "recovery"),
        field("Challenge start", nowIso(), "recovery"),
        field("Executable after", "local_fixture_after_challenge", "recovery"),
        field("Freeze effect", kind === "recovery_cancel" ? "unfreeze_if_pending" : "account_frozen_during_pending_recovery", "recovery"),
        field("Cancellation authority", "current_owner", "recovery"),
        field("Completion authority", "recovery_authority_after_delay", "recovery"),
        field("Maintenance selector", scenario || kind, "technical"),
        field("Calldata hash", shortRef(operation.calldataHash), "technical"),
        field("UserOperation hash", shortRef(operation.userOperationHash), "technical")
      ];
    }
    if (kind.startsWith("platform_unlock")) {
      return [
        ...base,
        field("Current protection", platformStatus().status, "platform"),
        field("Protection type", platformStatus().protectionType, "platform"),
        field("Fallback status", platformStatus().passphraseFallbackAllowed ? "passphrase fallback preserved" : "fallback disabled", "platform"),
        field("Device-specific limitation", "Keychain/safeStorage access may not migrate to another Mac", "platform"),
        field("Keychain loss warning", "passphrase fallback or future backup required", "platform")
      ];
    }
    if (kind === "local_identity_reset") {
      return [
        ...base,
        field("Local identity label", entry?.label, "reset"),
        field("Encrypted records deleted", "identity, registry, validator, recovery-authority, platform-protection", "reset"),
        field("Execution-validator status", validatorStatus().status, "reset"),
        field("Recovery-authority status", recoveryStatus().status, "reset"),
        field("Irreversibility", "local encrypted identity files are deleted; private-key export is not offered", "reset")
      ];
    }
    return base;
  }

  function createApprovalPresentation({ kind, scenario = "", confirmationTarget = "" }) {
    expireProcessLocalAuthority();
    const entry = getSelectedEntry();
    if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
    if (kind !== "local_identity_reset" && lifecycle.state !== "unlocked") {
      return frozen({ status: "failed", reason: "identity_must_be_unlocked", snapshot: snapshot() });
    }
    if (CRITICAL_PRESENTATION_KINDS.includes(kind)) {
      for (const presentation of presentations.values()) {
        if (CRITICAL_PRESENTATION_KINDS.includes(presentation.kind)) {
          return frozen({ status: "failed", reason: "critical_approval_already_pending", snapshot: snapshot() });
        }
      }
    }
    if (presentations.size >= MAX_PENDING_PRESENTATIONS) {
      return frozen({ status: "failed", reason: "too_many_pending_presentations", snapshot: snapshot() });
    }
    const operation = currentOperationFixture(kind, scenario);
    const issuedAt = nowIso();
    const expiresAt = new Date(Date.now() + PRESENTATION_TTL_MS).toISOString();
    const canonical = {
      format: "philcore-desktop-sensitive-action-presentation-v1",
      version: 1,
      kind,
      scenario,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      sessionId: lifecycle.sessionId,
      lifecycleSequence: lifecycle.sequence,
      operation,
      issuedAt,
      expiresAt,
      requiresFreshAuthentication: FRESH_AUTH_REQUIRED_KINDS.includes(kind),
      confirmationTarget,
      localOnly: true,
      publicNetworkMutation: false
    };
    const digest = canonicalPresentationDigest(canonical);
    const presentation = {
      presentationId: makeId("presentation"),
      status: "pending",
      kind,
      actionName: kindLabel(kind),
      scenario,
      risk: riskForKind(kind),
      issuedAt,
      expiresAt,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      ownerCommitmentShort: shortRef(entry.ownerCommitment),
      sessionId: lifecycle.sessionId,
      requiresFreshAuthentication: canonical.requiresFreshAuthentication,
      requiredAuthenticationMethods: canonical.requiresFreshAuthentication
        ? ["safe_storage_keychain_access", "passphrase_reauthentication", "developer_fixture"]
        : ["unlocked_session_or_passphrase_confirmation"],
      digest,
      digestShort: shortRef(digest),
      digestAlgorithm: "keccak256(stable-json-runtime-canonical-presentation)",
      fields: buildPresentationFields(kind, scenario, operation),
      limitations: [
        kind === "ethereum_sepolia_unsigned_preparation"
          ? "Ethereum Sepolia read-only checks and local preparation only"
          : "local fixture only",
        "approval is one-time and expires",
        "renderer cannot modify canonical fields",
        "public network mutation disabled",
        "biometric user verification is not guaranteed"
      ],
      confirmationTarget,
      canonical,
      rendererMayModify: false,
      publicNetworkMutation: false
    };
    presentations.set(presentation.presentationId, presentation);
    addAudit("approval", "presentation_created", "created", {
      presentationId: presentation.presentationId,
      actionKind: kind,
      digestRef: presentation.digestShort,
      risk: presentation.risk
    });
    return frozen({ status: "presentation_created", presentation: sanitizePresentation(presentation), snapshot: snapshot() });
  }

  function sanitizePresentation(presentation) {
    if (!presentation) return undefined;
    return {
      presentationId: presentation.presentationId,
      status: presentation.status,
      kind: presentation.kind,
      actionName: presentation.actionName,
      scenario: presentation.scenario,
      risk: presentation.risk,
      issuedAt: presentation.issuedAt,
      expiresAt: presentation.expiresAt,
      identityId: presentation.identityId,
      ownerCommitmentShort: presentation.ownerCommitmentShort,
      sessionId: presentation.sessionId,
      requiresFreshAuthentication: presentation.requiresFreshAuthentication,
      requiredAuthenticationMethods: presentation.requiredAuthenticationMethods,
      digest: presentation.digest,
      digestShort: presentation.digestShort,
      digestAlgorithm: presentation.digestAlgorithm,
      fields: presentation.fields,
      limitations: presentation.limitations,
      rendererMayModify: false,
      publicNetworkMutation: false
    };
  }

  function getApprovalPresentation(presentationId) {
    expireProcessLocalAuthority();
    const presentation = presentations.get(presentationId);
    if (!presentation) return frozen({ status: "not_found", reason: "presentation_not_found", snapshot: snapshot() });
    addAudit("approval", "presentation_viewed", "viewed", {
      presentationId,
      digestRef: presentation.digestShort,
      actionKind: presentation.kind
    });
    return frozen({ status: "presentation_found", presentation: sanitizePresentation(presentation), snapshot: snapshot() });
  }

  function recordApprovalHistory(presentation, decision, outcome, artifact) {
    if (!presentation) return;
    approvalHistory.unshift({
      historyId: makeId("approval_history"),
      timestamp: nowIso(),
      actionKind: presentation.kind,
      actionName: presentation.actionName,
      decision,
      outcome,
      digestShort: presentation.digestShort,
      identityId: presentation.identityId,
      sessionId: presentation.sessionId,
      authenticationMethod: artifact?.authenticationMethod || "not_required_or_not_supplied",
      localOnly: true,
      reusableAuthority: false
    });
    if (approvalHistory.length > 80) approvalHistory.pop();
  }

  function respondApproval({ presentationId, decision, typedConfirmation = "" }) {
    expireProcessLocalAuthority();
    const presentation = presentations.get(presentationId);
    if (!presentation) return frozen({ status: "failed", reason: "presentation_not_found", snapshot: snapshot() });
    if (Date.parse(presentation.expiresAt) <= Date.now()) {
      presentations.delete(presentationId);
      recordApprovalHistory(presentation, "expired", "presentation_expired");
      return frozen({ status: "expired", reason: "presentation_expired", snapshot: snapshot() });
    }
    if (decision !== "approve") {
      presentations.delete(presentationId);
      recordApprovalHistory(presentation, decision, `approval_${decision}`);
      addAudit("approval", `approval_${decision}`, decision, {
        presentationId,
        actionKind: presentation.kind,
        digestRef: presentation.digestShort
      });
      return frozen({ status: decision, decision, snapshot: snapshot() });
    }
    if (presentation.kind === "local_identity_reset" && typedConfirmation !== presentation.confirmationTarget) {
      addAudit("approval", "approval_rejected", "failed", {
        presentationId,
        actionKind: presentation.kind,
        reason: "typed_confirmation_mismatch"
      });
      return frozen({ status: "failed", reason: "typed_confirmation_mismatch", snapshot: snapshot() });
    }
    const artifact = {
      approvalArtifactId: makeId("approval"),
      status: "approved",
      decision: "approve",
      source: "desktop_renderer_user_action",
      presentationId,
      kind: presentation.kind,
      presentationDigest: presentation.digest,
      identityId: presentation.identityId,
      ownerCommitment: presentation.ownerCommitment,
      sessionId: presentation.sessionId,
      actionKind: presentation.kind,
      issuedAt: nowIso(),
      expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
      used: false,
      oneTimeUse: true,
      localOnly: true,
      reusableAuthority: false,
      publicNetworkMutation: false
    };
    approvals.set(artifact.approvalArtifactId, artifact);
    presentation.status = "approved";
    recordApprovalHistory(presentation, "approve", "approval_approved", artifact);
    addAudit("approval", "approval_approved", "approved", {
      presentationId,
      actionKind: presentation.kind,
      digestRef: presentation.digestShort,
      approvalArtifactId: artifact.approvalArtifactId
    });
    return frozen({
      status: "approved",
      approvalArtifact: sanitizeApprovalArtifact(artifact),
      presentation: sanitizePresentation(presentation),
      snapshot: snapshot()
    });
  }

  function sanitizeApprovalArtifact(artifact) {
    if (!artifact) return undefined;
    return {
      approvalArtifactId: artifact.approvalArtifactId,
      status: artifact.status,
      decision: artifact.decision,
      source: artifact.source,
      presentationId: artifact.presentationId,
      kind: artifact.kind,
      presentationDigest: artifact.presentationDigest,
      digestShort: shortRef(artifact.presentationDigest),
      identityId: artifact.identityId,
      sessionId: artifact.sessionId,
      issuedAt: artifact.issuedAt,
      expiresAt: artifact.expiresAt,
      oneTimeUse: true,
      localOnly: true,
      reusableAuthority: false,
      publicNetworkMutation: false
    };
  }

  function cancelApprovalPresentation(presentationId) {
    const presentation = presentations.get(presentationId);
    if (!presentation) return frozen({ status: "not_found", reason: "presentation_not_found", snapshot: snapshot() });
    presentations.delete(presentationId);
    recordApprovalHistory(presentation, "cancel", "approval_cancelled");
    addAudit("approval", "approval_cancelled", "cancelled", {
      presentationId,
      actionKind: presentation.kind,
      digestRef: presentation.digestShort
    });
    return frozen({ status: "cancelled", snapshot: snapshot() });
  }

  function consumeApprovalArtifact({ approvalArtifactId, kind, presentationDigest, freshAuthenticationEvidenceId = "" }) {
    expireProcessLocalAuthority();
    const artifact = approvals.get(approvalArtifactId);
    if (!artifact) return { ok: false, reason: "approval_not_found_or_consumed" };
    const presentation = presentations.get(artifact.presentationId);
    if (!presentation) return { ok: false, reason: "presentation_not_found" };
    if (artifact.used) return { ok: false, reason: "approval_replay_rejected" };
    if (artifact.kind !== kind) return { ok: false, reason: "approval_action_kind_mismatch" };
    if (artifact.identityId !== selectedIdentityId) return { ok: false, reason: "approval_identity_mismatch" };
    if (artifact.sessionId !== lifecycle.sessionId) return { ok: false, reason: "approval_session_mismatch" };
    if (Date.parse(artifact.expiresAt) <= Date.now() || Date.parse(presentation.expiresAt) <= Date.now()) {
      approvals.delete(approvalArtifactId);
      presentations.delete(artifact.presentationId);
      return { ok: false, reason: "approval_expired" };
    }
    const currentDigest = canonicalPresentationDigest(presentation.canonical);
    if (currentDigest !== artifact.presentationDigest || (presentationDigest && presentationDigest !== artifact.presentationDigest)) {
      return { ok: false, reason: "presentation_changed" };
    }
    if (FRESH_AUTH_REQUIRED_KINDS.includes(kind)) {
      const evidence = freshAuthEvidence.get(freshAuthenticationEvidenceId);
      if (!evidence) return { ok: false, reason: "fresh_authentication_required" };
      if (Date.parse(evidence.expiresAt) <= Date.now()) return { ok: false, reason: "fresh_authentication_expired" };
      if (evidence.identityId !== artifact.identityId || evidence.sessionId !== artifact.sessionId) {
        return { ok: false, reason: "fresh_authentication_mismatch" };
      }
      if (evidence.presentationDigest && evidence.presentationDigest !== artifact.presentationDigest) {
        return { ok: false, reason: "fresh_authentication_digest_mismatch" };
      }
    }
    artifact.used = true;
    artifact.consumedAt = nowIso();
    artifact.status = "consumed";
    presentations.delete(artifact.presentationId);
    approvals.delete(approvalArtifactId);
    addAudit("approval", "approval_consumed", "consumed", {
      actionKind: kind,
      digestRef: shortRef(artifact.presentationDigest),
      approvalArtifactId
    });
    return { ok: true, artifact, presentation };
  }

  function listApprovalHistory() {
    expireProcessLocalAuthority();
    return frozen({
      status: "history",
      pendingCount: presentations.size,
      approvalCount: approvals.size,
      events: approvalHistory
    });
  }

  function saveUnlockedRegistry() {
    if (!unlockedVault) return;
    const p = pathsFor(unlockedVault.identityId);
    atomicWriteFile(p.registry, `${encryptRecordForCurrentUnlock({
      format: REGISTRY_ENVELOPE_FORMAT,
      identityId: unlockedVault.identityId,
      ownerCommitment: unlockedVault.ownerCommitment,
      payload: unlockedVault.registry,
      passphrase: unlockedVault.passphrase,
      wrappingKey: unlockedVault.wrappingKey,
      unlockMethod: unlockedVault.unlockMethod
    })}\n`);
  }

  function encryptRecordForCurrentUnlock({ format, identityId, ownerCommitment, payload, passphrase, wrappingKey, unlockMethod }) {
    if (unlockMethod === "platform_keychain"
      || unlockMethod === "passphrase_fallback_platform_wrapping_key"
      || unlockMethod === "platform_enrolled_passphrase_session") {
      return encryptPayloadWithRawKey({ format, identityId, ownerCommitment, payload, rawKey: wrappingKey });
    }
    return encryptPayload({ format, identityId, ownerCommitment, payload, passphrase });
  }

  function loadPlatformProtection(entry) {
    const p = pathsFor(entry.identityId);
    if (!fs.existsSync(p.platformProtection)) return null;
    const parsed = readJsonFile(p.platformProtection);
    if (parsed.format !== PLATFORM_PROTECTION_FORMAT || parsed.version !== PLATFORM_PROTECTION_VERSION) {
      throw new Error("platform_protection_unsupported");
    }
    if (parsed.identityId !== entry.identityId || parsed.ownerCommitment !== entry.ownerCommitment) {
      throw new Error("platform_protection_identity_mismatch");
    }
    return parsed;
  }

  function writePlatformProtection(entry, protection) {
    const p = pathsFor(entry.identityId);
    atomicWriteFile(p.platformProtection, `${stableJson(protection)}\n`);
  }

  function platformStatus(entry = getSelectedEntry()) {
    if (!entry) {
      return {
        status: "no_identity_selected",
        enabled: false,
        protectionType: "none",
        passphraseFallbackAllowed: true
      };
    }
    let protection = null;
    try {
      protection = loadPlatformProtection(entry);
    } catch (error) {
      return {
        status: "malformed",
        enabled: false,
        reason: error.message,
        protectionType: "unknown",
        passphraseFallbackAllowed: true
      };
    }
    const availability = platformKeyAdapter.getAvailability();
    const userPresenceAvailability = userPresenceProvider.getAvailability();
    return {
      status: protection?.enabled ? "enabled" : "not_enrolled",
      enabled: Boolean(protection?.enabled),
      protectionType: protection?.protectionType || "none",
      backend: protection?.backend || availability.backend,
      availability: availability.status,
      keychainAvailable: availability.keychainAvailable,
      userPresenceGuaranteed: availability.userPresenceGuaranteed,
      biometricAvailable: availability.biometricAvailable,
      nativeUserPresence: {
        status: userPresenceAvailability.status,
        available: Boolean(userPresenceAvailability.available),
        provider: userPresenceAvailability.provider,
        requiredForReleaseCandidate: requireNativeUserPresence,
        biometricClaimSupported: Boolean(userPresenceAvailability.biometricClaimSupported)
      },
      passphraseFallbackAllowed: protection?.policy?.passphraseFallbackAllowed ?? true,
      fallbackDisabled: protection?.policy?.fallbackDisabled ?? false,
      migrationVersion: protection?.version || 0,
      enrolledAt: protection?.createdAt,
      lastSuccessfulUnlockMethod: entry.lastSuccessfulUnlockMethod || "none",
      identityBound: true,
      keychainReferenceExposed: false,
      productionApproved: false
    };
  }

  function setLifecycle(state, metadata = {}) {
    const now = nowIso();
    lifecycle = {
      lifecycleId: lifecycle.lifecycleId || makeId("lifecycle"),
      sessionId: lifecycle.sessionId || makeId("session"),
      state,
      sequence: lifecycle.sequence + 1,
      version: 1,
      createdAt: lifecycle.createdAt || now,
      updatedAt: now,
      metadata: {
        ...lifecycle.metadata,
        ...metadata,
        deviceVaultUnlocked: state === "unlocked",
        protectedStateAvailable: state === "unlocked",
        persisted: false
      },
      persisted: false,
      ownsSecrets: false,
      authenticatesUser: false,
      unlocksVault: state === "unlocked",
      grantsAuthority: false
    };
  }

  function scheduleAutoLock() {
    if (lockTimer) clearTimeout(lockTimer);
    lockTimer = null;
    if (!settings.autoLockEnabled || lifecycle.state !== "unlocked") return;
    const ttl = options.sessionTtlMs ?? settings.sessionTimeoutMinutes * 60_000;
    lockTimer = setTimeout(() => {
      try {
        lock("auto_lock_timeout");
      } catch {
        // Do not leak lock errors through a timer callback.
      }
    }, ttl);
    if (typeof lockTimer.unref === "function") lockTimer.unref();
  }

  function clearProcessLocalSecrets(reason = "process_local_authority_cleared") {
    if (pendingUnlock?.vaultKey) pendingUnlock.vaultKey.fill(0);
    if (unlockedVault?.vaultKey) unlockedVault.vaultKey.fill(0);
    pendingUnlock = null;
    unlockedVault = null;
    protectedRuntimeMaterial = null;
    if (
      activeAuthorizationWorkflow
      && (
        !workflowIsTerminal(activeAuthorizationWorkflow.status)
        || activeAuthorizationWorkflow.privateState
      )
    ) {
      activeAuthorizationWorkflow = {
        ...sanitizeWorkflow(activeAuthorizationWorkflow),
        status: "interrupted",
        updatedAt: nowIso(),
        privateState: undefined
      };
      clearProtectedActionMarker();
      addAudit("authorization", "protected_action_interrupted", "interrupted", {
        workflowId: activeAuthorizationWorkflow.workflowId,
        reason,
        publicNetworkMutation: false
      });
    }
  }

  function lock(reason = "manual_lock") {
    persistRegistryAudit("registry-saved", "locked", { reason });
    clearPendingApprovalAuthority(reason);
    clearProcessLocalSecrets(reason);
    setLifecycle("locked", {
      vaultUnlockedAt: undefined,
      lockReason: reason
    });
    addAudit("session", "lock", "locked", { reason });
    return snapshot();
  }

  function snapshot() {
    const entry = getSelectedEntry();
    const index = safeIndex();
    const protectedViewsAvailable = lifecycle.state === "unlocked" && Boolean(unlockedVault);
    return frozen({
      app: {
        name: "PhilCore Desktop",
        mode: APP_MODE.LOCAL_ALPHA,
        localOnly: true,
        desktopStack: "electron_static_renderer",
        storageModel: "main_process_file_backend_encrypted_registry",
        publicNetworkMutationEnabled: false,
        publicSubmittersRegistered: false,
        paymasterEnabled: false
      },
      publicTestnetMode: APP_MODE.PUBLIC_TESTNET_DISABLED,
      mainnetMode: APP_MODE.MAINNET_DISABLED,
      localIdentities: index,
      session: {
        sessionId: lifecycle.sessionId,
        lockState: lifecycle.state,
        authentication: pendingUnlock || unlockedVault
          ? (unlockedVault?.unlockMethod || pendingUnlock?.unlockMethod || "local_alpha_passphrase_scrypt_verified")
          : "none",
        vaultState: protectedViewsAvailable ? "unlocked" : "locked",
        recoveryState: recoveryStatus().state,
        pendingApprovals: presentations.size,
        activeCapabilityCount: protectedViewsAvailable && demoCompleted() ? 1 : 0,
        activeApplicationId: "ethereum_net",
        expiresAt: lifecycle.metadata?.lockTimeoutAt,
        failedUnlockAttempts: entry?.failedUnlockAttempts ?? 0
      },
      identity: identitySummary(entry),
      trust: trustSummary(),
      ethereum: ethereumSummary(),
      protectedAction: protectedActionStatus(),
      sepoliaPreparation: sepoliaPreparationStatus(),
      proof: currentProofState(),
      demo: currentDemoState(),
      platformAuth: platformStatus(entry),
      controlledBeta: controlledBetaReleaseState(),
      release: releaseStatus(),
      securityGate: {
        acp0002: "Proposed",
        baseSepoliaBeta: "blocked",
        externalAudit: "missing",
        productionApproved: false,
        meaningfulAssetsAllowed: false
      },
      vault: vaultStatus(),
      audit: {
        count: auditEvents.length + (unlockedVault?.registry.auditTrail.length ?? 0),
        recent: [...auditEvents, ...registryAuditEvents()].slice(0, 40),
        history: [...auditEvents, ...registryAuditEvents()]
      },
      approvals: {
        pendingCount: presentations.size,
        approvalArtifactCount: approvals.size,
        history: approvalHistory.slice(0, 12)
      },
      settings
    });
  }

  function releaseStatus() {
    function readFirstJson(candidates) {
      for (const candidate of candidates) {
        try {
          if (fs.existsSync(candidate)) return JSON.parse(fs.readFileSync(candidate, "utf8"));
        } catch {
          // Try the next candidate; release status should never block app startup.
        }
      }
      return null;
    }
    const releaseRoots = [
      process.cwd(),
      path.join(__dirname, "..", "..", "..", ".."),
      path.join(__dirname, "..", "..", "..")
    ];
    const candidates = [
      ...releaseRoots.map((root) => path.join(root, "config", "release", "philcore-desktop-local-alpha.json")),
      path.join(__dirname, "..", "..", "config", "release", "philcore-desktop-local-alpha.json")
    ];
    const o9Evidence = readFirstJson([
      ...releaseRoots.map((root) => path.join(root, "config", "release", "philcore-desktop-o9-release-evidence.json")),
      path.join(__dirname, "..", "..", "config", "release", "philcore-desktop-o9-release-evidence.json")
    ]);
    for (const candidate of candidates) {
      try {
        if (!fs.existsSync(candidate)) continue;
        const parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
        const liveTrust = o9Evidence?.liveTrustChecks || {};
        const signed = parsed.signing?.codeSigned || liveTrust.strictSignatureVerifiedWorkingApp === true;
        const notarized = parsed.signing?.notarized || liveTrust.notarizationAccepted === true;
        const gatekeeperAccepted = parsed.signing?.gatekeeperAccepted
          || liveTrust.gatekeeperAcceptedWorkingApp === true
          || liveTrust.gatekeeperAcceptedExtractedApp === true;
        return {
          version: parsed.version || "0.1.0",
          channel: parsed.releaseChannel || "local-alpha",
          sourceCommit: parsed.sourceCommit || "unavailable",
          sourceTreeHash: parsed.sourceTreeHash || "unavailable",
          sourceTreeClean: parsed.sourceTree?.checked === true && parsed.sourceTree?.dirty === false,
          bundleIdentifier: parsed.bundleIdentifier || "com.philcore.desktop.localalpha",
          packageProfile: notarized ? "trusted_tester_release_candidate" : parsed.packageProfile || parsed.releaseChannel || "local_alpha_unsigned",
          signingStatus: signed ? "signed" : "unsigned",
          signingIdentitySummary: parsed.signing?.identitySummary || "not_configured",
          notarizationStatus: notarized ? "notarized" : "not_notarized",
          gatekeeperStatus: gatekeeperAccepted ? "accepted" : "not_accepted_or_not_checked",
          nativeUserPresenceStatus: parsed.userPresence?.nativeUserPresenceStatus || "not_available_or_not_checked",
          publicNetworkMode: "disabled",
          packageTool: parsed.packageTool?.selected || "custom_macos_packager",
          productionApproved: parsed.securityStatus?.productionApproved === true,
          developerSurfacesAllowed: options.developerSurfacesAllowed === true
        };
      } catch {
        break;
      }
    }
    return {
      version: "0.1.0",
      channel: "local-alpha",
      sourceCommit: "unavailable",
      sourceTreeHash: "unavailable",
      sourceTreeClean: false,
      bundleIdentifier: "com.philcore.desktop.localalpha",
      packageProfile: "local_alpha_unsigned",
      signingStatus: "unsigned",
      signingIdentitySummary: "not_configured",
      notarizationStatus: "not_notarized",
      gatekeeperStatus: "not_accepted_or_not_checked",
      nativeUserPresenceStatus: "not_available_or_not_checked",
      publicNetworkMode: "disabled",
      packageTool: "custom_macos_packager",
      productionApproved: false,
      developerSurfacesAllowed: options.developerSurfacesAllowed === true
    };
  }

  function safeIndex() {
    try {
      return loadIndex().identities.map(sanitizeIndexEntry);
    } catch (error) {
      addAudit("storage", "identity_index_load", "failed", { reason: error.message });
      return [];
    }
  }

  function sanitizeIndexEntry(entry) {
    return {
      identityId: entry.identityId,
      label: entry.label,
      ownerCommitmentShort: shortRef(entry.ownerCommitment),
      createdAt: entry.createdAt,
      lastOpenedAt: entry.lastOpenedAt,
      storageFormatVersion: entry.storageFormatVersion,
      status: entry.status,
      validatorStatus: entry.validatorStatus,
      recoveryStatus: entry.recoveryStatus,
      platformProtectionStatus: entry.platformProtectionStatus || "not_enrolled",
      platformUnlockEnabled: Boolean(entry.platformUnlockEnabled),
      platformProtectionType: entry.platformProtectionType || "none",
      philPreview: entry.philPreview || {
        selectionId: "local-philenator-00",
        sequence: 0,
        traits: {
          bgColor: "bgColor-pending",
          bgNebula: "bgNebula-pending",
          bgStars: "bgStars-pending",
          bgSpiral: "bgSpiral-pending",
          bgDust: "bgDust-pending",
          bgOverlay: "bgOverlay-pending",
          bodyBase: "bodyBase-pending",
          body: "body-pending",
          spikes: "spikes-pending",
          teeth: "teeth-pending",
          jawNose: "jawNose-pending",
          eyes: "eyes-pending",
          top: "top-pending"
        },
        source: "philenator-local",
        artworkSource: "philenator-local",
        generatorRevision: "f174dedda16a354c592e3252d9b0b5805bab59c4",
        mintStatus: "not-minted",
        publicToken: null
      }
    };
  }

  function identitySummary(entry = getSelectedEntry()) {
    if (!entry) return null;
    return {
      identityId: entry.identityId,
      label: entry.label,
      localIdentityState: lifecycle.state === "unlocked" ? "opened_unlocked" : "locked",
      identityRootReference: lifecycle.state === "unlocked" ? "available_in_protected_boundary" : "locked",
      ownerCommitment: entry.ownerCommitment,
      ownerCommitmentShort: shortRef(entry.ownerCommitment),
      activeDevice: "desktop_local_alpha_main_process",
      canonicalActivationStatus: "local_identity_created",
      worldIdStatus: "not_integrated",
      publicAccountDeployment: "not_deployed",
      meaningfulAssets: "prohibited",
      storageStatus: entry.status,
      storageVersion: entry.storageFormatVersion,
      platformUnlock: platformStatus(entry).status,
      philPreview: sanitizeIndexEntry(entry).philPreview
    };
  }

  function trustSummary() {
    const credentials = publicCredentials();
    const workflow = sanitizeWorkflow(activeAuthorizationWorkflow);
    return {
      lastEvaluation: workflow?.status ? workflow.status : (lifecycle.state === "unlocked" ? "not_run_real_policy" : "locked"),
      evidenceClass: workflow?.evidenceLabels?.trustAndPolicy || "desktop_local_alpha_public_metadata",
      publicMetadataSufficient: lifecycle.state === "unlocked",
      devices: credentials.map((credential) => ({
        deviceId: credential.deviceReference,
        providerType: credential.providerType,
        lifecycleStatus: credential.lifecycleStatus,
        ordinaryUseEligible: credential.ordinaryUseEligible,
        recoveryOnly: credential.recoveryOnly,
        productionEvidence: false
      })),
      credentials
    };
  }

  function ethereumSummary() {
    const validator = validatorStatus();
    const recovery = recoveryStatus();
    const workflow = sanitizeWorkflow(activeAuthorizationWorkflow);
    const execution = workflow?.execution;
    return {
      networkLabel: "Local fixture network",
      fundsLabel: "No real funds",
      publicTransactionLabel: "No public transaction",
      entryPointVersion: "ERC-4337 v0.7",
      smartAccountStatus: execution?.account ? "deployed_local_fixture" : (validator.status === "available" ? "counterfactual_not_deployed" : "not_configured"),
      smartAccountAddress: execution?.account || "not_deployed",
      approvedActionGate: execution?.actionGate || "not_connected",
      executionOwnerAddress: validator.publicOwnerAddress || "not_created",
      recoveryAuthorityAddress: recovery.publicAddress || "not_created",
      frozen: false,
      latestUserOperation: execution?.userOperationHash || (demoCompleted() ? "local_fixture_user_operation_included" : "none"),
      nullifierState: execution?.nullifierConsumed ? "consumed_local_fixture" : (execution?.nullifier ? "available_or_pending_local_fixture" : (demoCompleted() ? "consumed_local_fixture" : "not_consumed")),
      lastConsumerExecution: execution?.consumerExecuted ? "verified_local_fixture" : (execution?.consumerResult || (demoCompleted() ? "verified_local_fixture" : "none")),
      validator,
      recovery
    };
  }

  function vaultStatus() {
    return {
      status: lifecycle.state === "unlocked" ? "unlocked" : "locked",
      handleReference: unlockedVault ? "process_local_main_only" : undefined,
      expiresAt: lifecycle.metadata?.lockTimeoutAt,
      protectedStateAvailable: lifecycle.state === "unlocked" && Boolean(unlockedVault),
      executionValidatorAvailable: validatorStatus().status === "available",
      recoveryAuthorityAvailable: recoveryStatus().status === "available",
      handleExposedToRenderer: false,
      registryPlaintextExposedToRenderer: false
    };
  }

  function validatorStatus() {
    const record = unlockedVault?.validator;
    if (!record) {
      const entry = getSelectedEntry();
      return {
        status: entry?.validatorStatus || "locked_or_not_created",
        lifecycleState: "locked",
        publicOwnerAddress: entry?.validatorPublicAddress,
        keyReferenceId: entry?.validatorKeyReferenceId,
        accountBinding: "local_alpha_counterfactual",
        deployedStatus: "not_deployed",
        localOnly: true,
        privateMaterialReturned: false
      };
    }
    return {
      status: "available",
      lifecycleState: record.lifecycleState,
      publicOwnerAddress: record.publicOwnerAddress,
      keyReferenceId: record.keyReferenceId,
      accountBinding: "local_alpha_counterfactual",
      deployedStatus: "not_deployed",
      localOnly: true,
      privateMaterialReturned: false
    };
  }

  function recoveryStatus() {
    const record = unlockedVault?.recovery;
    if (!record) {
      const entry = getSelectedEntry();
      return {
        status: entry?.recoveryStatus || "not_created",
        state: entry?.recoveryStatus === "available" ? "configured_locked" : "incomplete",
        publicAddress: entry?.recoveryPublicAddress,
        custodyType: entry?.recoveryCustodyType || "not_configured",
        sameDeviceWarning: entry?.recoveryStatus === "available",
        rotationCapability: "local_alpha_supported_not_beta_approved",
        privateMaterialReturned: false
      };
    }
    return {
      status: "available",
      state: "configured",
      publicAddress: record.publicRecoveryAddress,
      custodyType: record.custodyType,
      sameDeviceWarning: record.custodyType === "device_vault_separate_ecdsa_key",
      rotationCapability: "local_alpha_supported_not_beta_approved",
      privateMaterialReturned: false
    };
  }

  function publicCredentials() {
    if (lifecycle.state !== "unlocked" || !unlockedVault) return [];
    return [
      {
        credentialId: unlockedVault.validator.keyReferenceId,
        providerType: "device_vault_ecdsa_local_alpha",
        lifecycleStatus: unlockedVault.validator.lifecycleState,
        ordinaryUseEligible: true,
        recoveryOnly: false,
        publicOwnerAddress: unlockedVault.validator.publicOwnerAddress,
        deviceReference: "desktop_local_alpha_main_process",
        productionEvidence: false
      },
      ...(unlockedVault.recovery ? [{
        credentialId: unlockedVault.recovery.authorityId,
        providerType: "device_vault_ecdsa_recovery_local_alpha",
        lifecycleStatus: unlockedVault.recovery.lifecycleState,
        ordinaryUseEligible: false,
        recoveryOnly: true,
        publicOwnerAddress: unlockedVault.recovery.publicRecoveryAddress,
        deviceReference: "desktop_local_alpha_main_process",
        productionEvidence: false
      }] : [])
    ];
  }

  function protectedView(viewType = "runtime_summary") {
    if (lifecycle.state !== "unlocked" || !unlockedVault) {
      return { status: "locked", reason: "protected_state_unavailable" };
    }
    const registrySummary = {
      registryVersion: unlockedVault.registry.version,
      ownerCommitment: unlockedVault.ownerCommitment,
      credentialCount: publicCredentials().length,
      auditEventCount: unlockedVault.registry.auditTrail.length,
      warningCount: unlockedVault.registry.warnings.length
    };
    const views = {
      identity_summary: identitySummary(),
      credential_summary: {
        totalCredentials: publicCredentials().length,
        credentialsByStatus: countBy(publicCredentials(), "lifecycleStatus")
      },
      device_summary: {
        devicesByType: { desktop: 1 },
        hardwareBackedDeviceCount: 0,
        providerKindCount: publicCredentials().length
      },
      recovery_summary: recoveryStatus(),
      audit_summary: {
        auditEventCount: unlockedVault.registry.auditTrail.length,
        firstAuditEventAt: unlockedVault.registry.auditTrail.at(-1)?.occurredAt,
        latestAuditEventAt: unlockedVault.registry.auditTrail[0]?.occurredAt
      },
      registry_summary: registrySummary,
      key_lifecycle_summary: {
        keyLifecycleProvided: true,
        storageKeyCount: 1,
        backupKeyCount: 0,
        activeStorageKeyCount: 1
      },
      runtime_summary: {
        sessionId: lifecycle.sessionId,
        lifecycleState: lifecycle.state,
        deviceVaultUnlocked: true,
        protectedStateAvailable: true,
        activeCapabilityCreated: false,
        authorizationCreated: false,
        persisted: false
      }
    };
    return {
      status: "view_created",
      viewType,
      summary: views[viewType] || views.runtime_summary,
      containsSecrets: false,
      containsPrivateKeys: false,
      containsVaultKeys: false,
      registryPlaintextReturned: false
    };
  }

  function registryAuditEvents() {
    return (unlockedVault?.registry.auditTrail ?? []).map((event) => ({
      auditEventId: event.eventId,
      timestamp: event.occurredAt,
      category: "registry",
      action: event.eventType,
      result: "recorded_encrypted_registry",
      evidenceClass: "encrypted_registry",
      correlationRef: shortRef(event.eventId),
      publicNetworkMutation: false,
      details: event.details
    }));
  }

  function demoCompleted() {
    return activeAuthorizationWorkflow?.status === "completed" || demoState.status === "completed";
  }

  function currentProofState() {
    const workflow = sanitizeWorkflow(activeAuthorizationWorkflow);
    if (!workflow?.proof) return proofState;
    return {
      proofType: workflow.proof.proofType,
      proofInputHash: shortRef(workflow.proof.proofInputHash),
      factHigh: shortRef(workflow.proof.factHigh),
      factLow: shortRef(workflow.proof.factLow),
      generationState: workflow.proof.proofDigest ? "generated_real_local" : "not_started",
      verificationState: workflow.proof.proofInputHash ? "verified_real_local" : "not_started",
      crossDomainRoute: "local_fixture_fact_availability_public_route_not_executed",
      witnessExposed: false,
      proofBytesDisplayed: false,
      proofDigest: shortRef(workflow.proof.proofDigest),
      generationDurationMs: workflow.proof.generationDurationMs,
      verificationDurationMs: workflow.proof.verificationDurationMs
    };
  }

  function currentDemoState() {
    const workflow = sanitizeWorkflow(activeAuthorizationWorkflow);
    if (!workflow) return demoState;
    return {
      status: workflow.status,
      workflowId: workflow.workflowId,
      workflowKind: workflow.workflowKind,
      stages: workflow.stages,
      selectedAction: workflow.selectedAction,
      evidenceLabels: workflow.evidenceLabels,
      timings: workflow.timings,
      preparation: workflow.preparation,
      proof: workflow.proof,
      pendingSigningPresentation: workflow.pendingSigningPresentation,
      completed: workflow.status === "completed" || workflow.status === "prepared_unsigned",
      publicNetworkMutation: false,
      includesSecrets: false
    };
  }

  function protectedActionStatus() {
    if (!getSelectedEntry()) {
      return {
        status: "unavailable",
        eligible: false,
        reason: "no_identity",
        explanation: "Create or open a local identity before testing a protected action."
      };
    }
    if (lifecycle.state !== "unlocked" || !unlockedVault || !protectedRuntimeMaterial) {
      return {
        status: "unavailable",
        eligible: false,
        reason: "identity_locked",
        explanation: "Unlock the identity before PhilCore can prepare a protected local action."
      };
    }
    if (activeAuthorizationWorkflow && !workflowIsTerminal(activeAuthorizationWorkflow.status)) {
      return {
        status: "busy",
        eligible: false,
        reason: "protected_action_already_active",
        explanation: "Finish or cancel the active protected action before starting another one.",
        workflowId: activeAuthorizationWorkflow.workflowId,
        workflowStatus: activeAuthorizationWorkflow.status
      };
    }
    if (validatorStatus().status !== "available") {
      return {
        status: "unavailable",
        eligible: false,
        reason: "device_vault_signer_unavailable",
        explanation: "The local Device Vault signing key is required for this Alpha action."
      };
    }
    const platform = platformStatus();
    if (!platform.enabled) {
      return {
        status: "preflight_required",
        eligible: true,
        ready: false,
        reason: "platform_unlock_not_enrolled",
        explanation: "Protected Mac unlock is not set up yet. Enable it in Settings, then try again.",
        canonicalOperation: "startRealLocalAuthorizationWorkflow",
        localOnly: true,
        publicNetworkMutation: false,
        realFundsUsed: false
      };
    }
    if (platform.nativeUserPresence.requiredForReleaseCandidate && !platform.nativeUserPresence.available) {
      return {
        status: "unavailable",
        eligible: true,
        ready: false,
        reason: "native_user_presence_unavailable",
        explanation: "This Mac cannot confirm user presence right now. Check the protected Mac unlock setup, then try again.",
        canonicalOperation: "startRealLocalAuthorizationWorkflow",
        localOnly: true,
        publicNetworkMutation: false,
        realFundsUsed: false
      };
    }
    return {
      status: "available",
      eligible: true,
      ready: true,
      reason: "ready",
      explanation: "PhilCore can prepare a local-only protected action with trust, policy, approval, proof, signing, and fixture execution.",
      canonicalOperation: "startRealLocalAuthorizationWorkflow",
      localOnly: true,
      publicNetworkMutation: false,
      realFundsUsed: false
    };
  }

  function getSepoliaPreparationConfiguration() {
    if (options.sepoliaPreparationConfiguration) {
      return options.sepoliaPreparationConfiguration;
    }
    if (!cachedSepoliaPreparationConfiguration) {
      cachedSepoliaPreparationConfiguration =
        loadDesktopSepoliaPreparationConfiguration({
          root: options.repositoryRoot,
          indexPath: indexPath()
        });
    }
    return cachedSepoliaPreparationConfiguration;
  }

  function sepoliaPreparationStatus() {
    const entry = getSelectedEntry();
    if (!entry) {
      return {
        status: "unavailable",
        eligible: false,
        ready: false,
        reason: "no_identity",
        explanation:
          "Create or open the configured PhilCore identity before preparing an Ethereum test action."
      };
    }
    if (lifecycle.state !== "unlocked" || !unlockedVault || !protectedRuntimeMaterial) {
      return {
        status: "unavailable",
        eligible: false,
        ready: false,
        reason: "identity_locked",
        explanation:
          "Unlock the configured PhilCore identity before preparing an Ethereum test action."
      };
    }
    if (activeAuthorizationWorkflow && !workflowIsTerminal(activeAuthorizationWorkflow.status)) {
      return {
        status: "busy",
        eligible: false,
        ready: false,
        reason: "protected_action_already_active",
        explanation:
          "Finish or cancel the active protected action before starting another one."
      };
    }
    try {
      const configuration = getSepoliaPreparationConfiguration();
      const binding = validateConfigurationBinding(
        configuration,
        protectedRuntimeMaterial
      );
      if (!binding.valid) {
        return {
          status: "unavailable",
          eligible: false,
          ready: false,
          reason: binding.errors[0] || "sepolia_identity_binding_invalid",
          explanation:
            "The unlocked identity does not match the approved local Sepolia preparation profile."
        };
      }
      return {
        status: "available",
        eligible: true,
        ready: true,
        reason: "ready",
        explanation:
          "PhilCore can generate and verify a fresh local proof, then prepare one unsigned Ethereum Sepolia test action.",
        network: "Ethereum Sepolia",
        chainId: configuration.network.chainId,
        smartAccountAddress: configuration.proposal.accountAddress,
        targetAddress: configuration.proposal.targetAddress,
        securityModel: "local-proof-gated-v1",
        signingEnabled: false,
        submissionEnabled: false,
        publicNetworkMutation: false
      };
    } catch (error) {
      return {
        status: "unavailable",
        eligible: false,
        ready: false,
        reason: error instanceof Error ? error.message : "sepolia_configuration_invalid",
        explanation:
          "The local Sepolia preparation profile is unavailable or does not match this identity."
      };
    }
  }

  const proofState = {
    proofType: "phil-noir-ultra-keccak-zk-honk-garaga-v1",
    proofInputHash: "not_generated",
    factHigh: "not_generated",
    factLow: "not_generated",
    generationState: "not_started",
    verificationState: "not_started",
    crossDomainRoute: "noir_native_verified_then_local_fixture",
    witnessExposed: false,
    proofBytesDisplayed: false
  };

  const demoState = {
    status: "not_started",
    stages: []
  };

  function decryptIdentityAndRegistryWithPassphrase(entry, passphrase) {
    const protection = loadPlatformProtection(entry);
    if (protection?.enabled) {
      const wrappingKey = decryptWrappingKeyFromPassphrase({
        envelope: protection.passphraseFallbackWrappedKey,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        passphrase
      });
      try {
        const result = decryptIdentityAndRegistryWithWrappingKey(entry, wrappingKey);
        return {
          ...result,
          wrappingKey,
          unlockMethod: "passphrase_fallback_platform_wrapping_key"
        };
      } catch (error) {
        wrappingKey.fill(0);
        throw error;
      }
    }

    const p = pathsFor(entry.identityId);
    const identityResult = decryptPayload({
      serialized: fs.readFileSync(p.identity, "utf8"),
      passphrase,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    const registryResult = decryptPayload({
      serialized: fs.readFileSync(p.registry, "utf8"),
      passphrase,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    assertIdentityBinding(identityResult.payload, entry);
    assertRegistryBinding(registryResult.payload, entry);
    registryResult.key.fill(0);
    return {
      privateIdentity: identityResult.payload,
      registry: registryResult.payload,
      vaultKey: identityResult.key,
      passphrase,
      unlockMethod: "local_alpha_passphrase_scrypt_verified"
    };
  }

  function decryptIdentityAndRegistryWithWrappingKey(entry, wrappingKey) {
    const p = pathsFor(entry.identityId);
    const identityResult = decryptPayloadWithRawKey({
      serialized: fs.readFileSync(p.identity, "utf8"),
      rawKey: wrappingKey,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    const registryResult = decryptPayloadWithRawKey({
      serialized: fs.readFileSync(p.registry, "utf8"),
      rawKey: wrappingKey,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    assertIdentityBinding(identityResult.payload, entry);
    assertRegistryBinding(registryResult.payload, entry);
    return {
      privateIdentity: identityResult.payload,
      registry: registryResult.payload
    };
  }

  function decryptVaultRecordsForPendingUnlock() {
    const p = pathsFor(pendingUnlock.identityId);
    if (pendingUnlock.wrappingKey) {
      const validator = decryptPayloadWithRawKey({
        serialized: fs.readFileSync(p.validator, "utf8"),
        rawKey: pendingUnlock.wrappingKey,
        expectedIdentityId: pendingUnlock.identityId,
        expectedOwnerCommitment: pendingUnlock.ownerCommitment
      });
      let recovery = null;
      if (fs.existsSync(p.recovery)) {
        recovery = decryptPayloadWithRawKey({
          serialized: fs.readFileSync(p.recovery, "utf8"),
          rawKey: pendingUnlock.wrappingKey,
          expectedIdentityId: pendingUnlock.identityId,
          expectedOwnerCommitment: pendingUnlock.ownerCommitment
        });
      }
      return { validator, recovery };
    }
    const validator = decryptPayload({
      serialized: fs.readFileSync(p.validator, "utf8"),
      passphrase: pendingUnlock.passphrase,
      expectedIdentityId: pendingUnlock.identityId,
      expectedOwnerCommitment: pendingUnlock.ownerCommitment
    });
    let recovery = null;
    if (fs.existsSync(p.recovery)) {
      recovery = decryptPayload({
        serialized: fs.readFileSync(p.recovery, "utf8"),
        passphrase: pendingUnlock.passphrase,
        expectedIdentityId: pendingUnlock.identityId,
        expectedOwnerCommitment: pendingUnlock.ownerCommitment
      });
    }
    return { validator, recovery };
  }

  function completeVaultUnlock(unlockSource = "passphrase") {
    if (!pendingUnlock) return frozen({ status: "failed", reason: "authentication_required", snapshot: snapshot() });
    const entry = getSelectedEntry();
    const { validator, recovery } = decryptVaultRecordsForPendingUnlock();
    protectedRuntimeMaterial = {
      identityId: pendingUnlock.identityId,
      ownerCommitment: pendingUnlock.ownerCommitment,
      philSecret: pendingUnlock.privateIdentity.philSecret,
      validator: {
        recordId: validator.payload.recordId,
        keyReferenceId: validator.payload.keyReferenceId,
        publicOwnerAddress: validator.payload.publicOwnerAddress,
        privateKey: validator.payload.privateKey
      }
    };
    unlockedVault = {
      handleId: makeId("vault_handle"),
      identityId: pendingUnlock.identityId,
      ownerCommitment: pendingUnlock.ownerCommitment,
      privateIdentity: pendingUnlock.privateIdentity,
      registry: pendingUnlock.registry,
      passphrase: pendingUnlock.passphrase,
      wrappingKey: pendingUnlock.wrappingKey,
      vaultKey: pendingUnlock.vaultKey || pendingUnlock.wrappingKey,
      unlockMethod: pendingUnlock.unlockMethod,
      validator: sanitizeValidatorRecord(validator.payload),
      recovery: recovery ? sanitizeRecoveryRecord(recovery.payload) : null,
      unlockedAt: nowIso()
    };
    if (validator.key) validator.key.fill(0);
    if (recovery?.key) recovery.key.fill(0);
    pendingUnlock = null;
    const ttl = options.sessionTtlMs ?? settings.sessionTimeoutMinutes * 60_000;
    setLifecycle("unlocked", {
      vaultHandleReference: "process_local_main_only",
      vaultUnlockedAt: unlockedVault.unlockedAt,
      lockTimeoutAt: new Date(Date.now() + ttl).toISOString(),
      lastUnlockMethod: unlockSource
    });
    persistRegistryAudit("registry-loaded", "unlocked", {
      protectedStateAvailable: true,
      privateMaterialReturned: false,
      unlockSource
    });
    if (entry) {
      updateIndexEntry(entry.identityId, (current) => ({
        ...current,
        status: "locked",
        lastSuccessfulUnlockMethod: unlockSource
      }));
    }
    addAudit("vault", "unlock_device_vault", "unlocked", {
      unlockSource,
      handleExposedToRenderer: false,
      registryPlaintextExposedToRenderer: false
    });
    scheduleAutoLock();
    return frozen({ status: "unlocked", snapshot: snapshot() });
  }

  function readAllPlainRecordsWithPassphrase(entry, passphrase) {
    const p = pathsFor(entry.identityId);
    const identity = decryptPayload({
      serialized: fs.readFileSync(p.identity, "utf8"),
      passphrase,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    const registry = decryptPayload({
      serialized: fs.readFileSync(p.registry, "utf8"),
      passphrase,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    const validator = decryptPayload({
      serialized: fs.readFileSync(p.validator, "utf8"),
      passphrase,
      expectedIdentityId: entry.identityId,
      expectedOwnerCommitment: entry.ownerCommitment
    });
    let recovery = null;
    if (fs.existsSync(p.recovery)) {
      recovery = decryptPayload({
        serialized: fs.readFileSync(p.recovery, "utf8"),
        passphrase,
        expectedIdentityId: entry.identityId,
        expectedOwnerCommitment: entry.ownerCommitment
      });
    }
    try {
      assertIdentityBinding(identity.payload, entry);
      assertRegistryBinding(registry.payload, entry);
      return {
        identity: identity.payload,
        registry: registry.payload,
        validator: validator.payload,
        recovery: recovery?.payload
      };
    } finally {
      identity.key.fill(0);
      registry.key.fill(0);
      validator.key.fill(0);
      if (recovery?.key) recovery.key.fill(0);
    }
  }

  function rewriteRecordsWithWrappingKey(entry, records, wrappingKey) {
    const p = pathsFor(entry.identityId);
    atomicWriteFile(p.identity, `${encryptPayloadWithRawKey({
      format: IDENTITY_ENVELOPE_FORMAT,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      payload: records.identity,
      rawKey: wrappingKey
    })}\n`);
    atomicWriteFile(p.registry, `${encryptPayloadWithRawKey({
      format: REGISTRY_ENVELOPE_FORMAT,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      payload: records.registry,
      rawKey: wrappingKey
    })}\n`);
    atomicWriteFile(p.validator, `${encryptPayloadWithRawKey({
      format: VALIDATOR_ENVELOPE_FORMAT,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      payload: records.validator,
      rawKey: wrappingKey
    })}\n`);
    if (records.recovery) {
      atomicWriteFile(p.recovery, `${encryptPayloadWithRawKey({
        format: RECOVERY_ENVELOPE_FORMAT,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        payload: records.recovery,
        rawKey: wrappingKey
      })}\n`);
    }
  }

  function rewriteRecordsWithPassphrase(entry, records, passphrase) {
    const p = pathsFor(entry.identityId);
    atomicWriteFile(p.identity, `${encryptPayload({
      format: IDENTITY_ENVELOPE_FORMAT,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      payload: records.identity,
      passphrase
    })}\n`);
    atomicWriteFile(p.registry, `${encryptPayload({
      format: REGISTRY_ENVELOPE_FORMAT,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      payload: records.registry,
      passphrase
    })}\n`);
    atomicWriteFile(p.validator, `${encryptPayload({
      format: VALIDATOR_ENVELOPE_FORMAT,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      payload: records.validator,
      passphrase
    })}\n`);
    if (records.recovery) {
      atomicWriteFile(p.recovery, `${encryptPayload({
        format: RECOVERY_ENVELOPE_FORMAT,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        payload: records.recovery,
        passphrase
      })}\n`);
    }
  }

  function backupSerializedRecords(entry) {
    const p = pathsFor(entry.identityId);
    return {
      identity: fs.readFileSync(p.identity, "utf8"),
      registry: fs.readFileSync(p.registry, "utf8"),
      validator: fs.readFileSync(p.validator, "utf8"),
      recovery: fs.existsSync(p.recovery) ? fs.readFileSync(p.recovery, "utf8") : null,
      platformProtection: fs.existsSync(p.platformProtection) ? fs.readFileSync(p.platformProtection, "utf8") : null
    };
  }

  function restoreSerializedRecords(entry, backup) {
    const p = pathsFor(entry.identityId);
    atomicWriteFile(p.identity, backup.identity);
    atomicWriteFile(p.registry, backup.registry);
    atomicWriteFile(p.validator, backup.validator);
    if (backup.recovery) atomicWriteFile(p.recovery, backup.recovery);
    if (backup.platformProtection) {
      atomicWriteFile(p.platformProtection, backup.platformProtection);
    } else if (fs.existsSync(p.platformProtection)) {
      fs.rmSync(p.platformProtection, { force: true });
    }
  }

  function enrollPlatformProtection(passphrase, approvalArtifactId = "") {
    const entry = getSelectedEntry();
    if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
    if (lifecycle.state !== "unlocked" || !unlockedVault) {
      return frozen({ status: "failed", reason: "identity_must_be_unlocked", snapshot: snapshot() });
    }
    const approval = consumeApprovalArtifact({
      approvalArtifactId,
      kind: "platform_unlock_enrollment"
    });
    if (!approval.ok) {
      addAudit("approval", "platform_unlock_enrollment_blocked", "blocked", { reason: approval.reason });
      return frozen({ status: "approval_required", reason: approval.reason, snapshot: snapshot() });
    }
    const availability = platformKeyAdapter.getAvailability();
    if (!availability.available) {
      addAudit("platform_auth", "platform_protection_enrollment", "failed", { reason: availability.status });
      return frozen({ status: "failed", reason: availability.status, availability, snapshot: snapshot() });
    }
    addAudit("platform_auth", "platform_protection_enrollment_started", "started", {
      backend: availability.backend,
      userPresenceGuaranteed: availability.userPresenceGuaranteed
    });

    const backup = backupSerializedRecords(entry);
    const wrappingKey = crypto.randomBytes(32);
    try {
      const records = readAllPlainRecordsWithPassphrase(entry, passphrase);
      const protectedResult = platformKeyAdapter.protectWrappingKey({
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        wrappingKey
      });
      if (protectedResult.status !== "stored") throw new Error(protectedResult.status || "keychain_access_denied");
      const protection = {
        format: PLATFORM_PROTECTION_FORMAT,
        version: PLATFORM_PROTECTION_VERSION,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        createdAt: nowIso(),
        updatedAt: nowIso(),
        enabled: true,
        storageEnvelopeProvider: WRAPPING_KEY_PROVIDER_KIND,
        protectionType: protectedResult.protectionType,
        backend: availability.backend,
        keychainReference: protectedResult.keychainReference,
        protectedKeyBlob: protectedResult.protectedKeyBlob,
        passphraseFallbackWrappedKey: encryptWrappingKeyForPassphrase({
          identityId: entry.identityId,
          ownerCommitment: entry.ownerCommitment,
          wrappingKey,
          passphrase
        }),
        policy: {
          ...PLATFORM_UNLOCK_POLICY,
          userPresenceRequired: availability.userPresenceGuaranteed,
          biometricPreferred: availability.biometricAvailable,
          sessionTimeoutMinutes: settings.sessionTimeoutMinutes
        },
        limitations: {
          userPresenceGuaranteed: availability.userPresenceGuaranteed,
          biometricAuthenticationGuaranteed: false,
          deviceSpecific: true,
          secureEnclaveClaimed: false,
          productionApproved: false
        },
        privateMaterialReturned: false
      };
      rewriteRecordsWithWrappingKey(entry, records, wrappingKey);
      writePlatformProtection(entry, protection);
      const roundTrip = platformKeyAdapter.retrieveWrappingKey({
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        keychainReference: protectedResult.keychainReference,
        protectedKeyBlob: protectedResult.protectedKeyBlob
      });
      if (roundTrip.status !== "retrieved" || !roundTrip.wrappingKey.equals(wrappingKey)) {
        throw new Error(roundTrip.status || "wrapping_key_invalid");
      }
      roundTrip.wrappingKey.fill(0);
      updateIndexEntry(entry.identityId, (current) => ({
        ...current,
        platformProtectionStatus: "enabled",
        platformUnlockEnabled: true,
        platformProtectionType: protectedResult.protectionType,
        storageFormatVersion: STORAGE_VERSION
      }));
      if (unlockedVault) {
        if (unlockedVault.vaultKey) unlockedVault.vaultKey.fill(0);
        unlockedVault.wrappingKey = Buffer.from(wrappingKey);
        unlockedVault.vaultKey = unlockedVault.wrappingKey;
        unlockedVault.unlockMethod = "platform_enrolled_passphrase_session";
      }
      persistRegistryAudit("platform-protection-enrolled", "completed", {
        protectionType: protectedResult.protectionType,
        passphraseFallbackPreserved: true
      });
      addAudit("platform_auth", "platform_protection_enrollment_completed", "completed", {
        protectionType: protectedResult.protectionType,
        keychainValueReturned: false,
        wrappingKeyReturned: false
      });
      return frozen({ status: "enrolled", platform: platformStatus(entry), snapshot: snapshot() });
    } catch (error) {
      restoreSerializedRecords(entry, backup);
      addAudit("platform_auth", "platform_protection_enrollment_failed", "failed", { reason: error.message });
      return frozen({ status: "failed", reason: "platform_enrollment_failed", snapshot: snapshot() });
    } finally {
      wrappingKey.fill(0);
    }
  }

  function unlockWithPlatformProtection() {
    const entry = getSelectedEntry();
    if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
    let protection;
    try {
      protection = loadPlatformProtection(entry);
    } catch (error) {
      return frozen({ status: "failed", reason: error.message, snapshot: snapshot() });
    }
    if (!protection?.enabled) return frozen({ status: "failed", reason: "migration_required", snapshot: snapshot() });
    const availability = platformKeyAdapter.getAvailability();
    if (!availability.available) {
      addAudit("platform_auth", "platform_auth_requested", "failed", { reason: availability.status });
      return frozen({ status: "failed", reason: availability.status, availability, snapshot: snapshot() });
    }
    addAudit("platform_auth", "platform_auth_requested", "requested", {
      backend: availability.backend,
      userPresenceGuaranteed: availability.userPresenceGuaranteed
    });
    const retrieved = platformKeyAdapter.retrieveWrappingKey({
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      keychainReference: protection.keychainReference,
      protectedKeyBlob: protection.protectedKeyBlob
    });
    if (retrieved.status !== "retrieved") {
      addAudit("platform_auth", "keychain_retrieval", "failed", { reason: retrieved.status });
      return frozen({ status: "failed", reason: retrieved.status, snapshot: snapshot() });
    }
    try {
      const decrypted = decryptIdentityAndRegistryWithWrappingKey(entry, retrieved.wrappingKey);
      pendingUnlock = {
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        privateIdentity: decrypted.privateIdentity,
        registry: decrypted.registry,
        wrappingKey: retrieved.wrappingKey,
        unlockMethod: "platform_keychain"
      };
      setLifecycle("partially_unlocked", {
        selectedIdentityId: entry.identityId,
        platformAuthenticationEvidence: "keychain_retrieval_succeeded",
        lifecycleAuthenticationFactorVerified: true
      });
      updateIndexEntry(entry.identityId, (current) => ({ ...current, failedUnlockAttempts: 0 }));
      addAudit("platform_auth", "platform_unlock", "validated", {
        vaultIntegrityValidated: true,
        registryIntegrityValidated: true
      });
      return completeVaultUnlock("platform_keychain");
    } catch (error) {
      retrieved.wrappingKey.fill(0);
      clearProcessLocalSecrets();
      setLifecycle("locked", { lastUnlockFailure: "platform_failed_closed" });
      addAudit("platform_auth", "platform_unlock", "failed_closed", { reason: error.message });
      return frozen({ status: "failed", reason: "vault_integrity_failed", snapshot: snapshot() });
    }
  }

  function disablePlatformProtection(passphrase, approvalArtifactId = "", freshAuthenticationEvidenceId = "") {
    const entry = getSelectedEntry();
    if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
    if (lifecycle.state !== "unlocked" || !unlockedVault) {
      return frozen({ status: "failed", reason: "identity_must_be_unlocked", snapshot: snapshot() });
    }
    const approval = consumeApprovalArtifact({
      approvalArtifactId,
      kind: "platform_unlock_disablement",
      freshAuthenticationEvidenceId
    });
    if (!approval.ok) {
      addAudit("approval", "platform_unlock_disablement_blocked", "blocked", { reason: approval.reason });
      return frozen({ status: "approval_required", reason: approval.reason, snapshot: snapshot() });
    }
    const protection = loadPlatformProtection(entry);
    if (!protection?.enabled) return frozen({ status: "not_enrolled", snapshot: snapshot() });
    const wrappingKey = decryptWrappingKeyFromPassphrase({
      envelope: protection.passphraseFallbackWrappedKey,
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      passphrase
    });
    const backup = backupSerializedRecords(entry);
    try {
      const p = pathsFor(entry.identityId);
      const records = {
        identity: decryptPayloadWithRawKey({ serialized: fs.readFileSync(p.identity, "utf8"), rawKey: wrappingKey, expectedIdentityId: entry.identityId, expectedOwnerCommitment: entry.ownerCommitment }).payload,
        registry: decryptPayloadWithRawKey({ serialized: fs.readFileSync(p.registry, "utf8"), rawKey: wrappingKey, expectedIdentityId: entry.identityId, expectedOwnerCommitment: entry.ownerCommitment }).payload,
        validator: decryptPayloadWithRawKey({ serialized: fs.readFileSync(p.validator, "utf8"), rawKey: wrappingKey, expectedIdentityId: entry.identityId, expectedOwnerCommitment: entry.ownerCommitment }).payload,
        recovery: fs.existsSync(p.recovery)
          ? decryptPayloadWithRawKey({ serialized: fs.readFileSync(p.recovery, "utf8"), rawKey: wrappingKey, expectedIdentityId: entry.identityId, expectedOwnerCommitment: entry.ownerCommitment }).payload
          : null
      };
      rewriteRecordsWithPassphrase(entry, records, passphrase);
      platformKeyAdapter.deleteWrappingKey({
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        keychainReference: protection.keychainReference
      });
      fs.rmSync(p.platformProtection, { force: true });
      updateIndexEntry(entry.identityId, (current) => ({
        ...current,
        platformProtectionStatus: "not_enrolled",
        platformUnlockEnabled: false,
        platformProtectionType: "none"
      }));
      if (unlockedVault) {
        if (unlockedVault.wrappingKey) unlockedVault.wrappingKey.fill(0);
        unlockedVault.wrappingKey = undefined;
        unlockedVault.vaultKey = undefined;
        unlockedVault.passphrase = passphrase;
        unlockedVault.unlockMethod = "local_alpha_passphrase_scrypt_verified";
      }
      persistRegistryAudit("platform-protection-disabled", "completed", {
        passphraseFallbackVerified: true
      });
      addAudit("platform_auth", "platform_protection_disabled", "completed", {
        identityId: entry.identityId,
        keychainValueReturned: false
      });
      return frozen({ status: "disabled", platform: platformStatus(entry), snapshot: snapshot() });
    } catch (error) {
      restoreSerializedRecords(entry, backup);
      addAudit("platform_auth", "platform_protection_disable_failed", "failed", { reason: error.message });
      return frozen({ status: "failed", reason: "platform_disable_failed", snapshot: snapshot() });
    } finally {
      wrappingKey.fill(0);
    }
  }

  function requireFreshPlatformAuthentication(input = "sensitive_action") {
    const purpose = typeof input === "string" ? input : input.purpose || "sensitive_action";
    const presentationId = typeof input === "object" ? input.presentationId : "";
    const presentationDigest = typeof input === "object" ? input.presentationDigest : "";
    const entry = getSelectedEntry();
    if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
    const protection = loadPlatformProtection(entry);
    if (!protection?.enabled) return frozen({ status: "failed", reason: "platform_unlock_not_enrolled", snapshot: snapshot() });
    const retrieved = platformKeyAdapter.retrieveWrappingKey({
      identityId: entry.identityId,
      ownerCommitment: entry.ownerCommitment,
      keychainReference: protection.keychainReference,
      protectedKeyBlob: protection.protectedKeyBlob
    });
    if (retrieved.status !== "retrieved") {
      addAudit("platform_auth", "fresh_authentication", "failed", { purpose, reason: retrieved.status });
      return frozen({ status: "failed", reason: retrieved.status, snapshot: snapshot() });
    }
    retrieved.wrappingKey.fill(0);
    const userPresenceAvailability = userPresenceProvider.getAvailability();
    const shouldRequestUserPresence = Boolean(userPresenceAvailability.available || requireNativeUserPresence);
    let evidence;
    if (shouldRequestUserPresence) {
      if (!userPresenceAvailability.available) {
        addAudit("platform_auth", "native_user_presence", "failed", {
          purpose,
          reason: userPresenceAvailability.reason || userPresenceAvailability.status,
          required: requireNativeUserPresence
        });
        return frozen({
          status: "failed",
          reason: requireNativeUserPresence ? "native_user_presence_required" : userPresenceAvailability.status,
          snapshot: snapshot()
        });
      }
      const userPresence = userPresenceProvider.requestUserPresence({
        identityId: entry.identityId,
        sessionId: lifecycle.sessionId,
        presentationId,
        presentationDigest,
        actionKind: purpose,
        policy: "device_owner_authentication",
        reason: "Approve PhilCore local sensitive action"
      });
      if (!userPresence.userPresenceVerified) {
        addAudit("platform_auth", "native_user_presence", "failed", {
          purpose,
          reason: userPresence.outcome || userPresence.status,
          provider: userPresence.provider
        });
        return frozen({
          status: "failed",
          reason: userPresence.outcome || userPresence.status,
          snapshot: snapshot()
        });
      }
      evidence = createMacOsUserPresenceEvidence({
        purpose,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        sessionId: lifecycle.sessionId,
        presentationId,
        presentationDigest,
        actionKind: purpose,
        result: userPresence,
        ttlMs: FRESH_AUTH_TTL_MS
      });
    } else {
      evidence = {
        status: "fresh_authentication_satisfied",
        evidenceId: makeId("fresh_auth"),
        purpose,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        sessionId: lifecycle.sessionId,
        method: platformKeyAdapter.getAvailability().productionCandidate ? "safe_storage_keychain_access" : "developer_fixture",
        evidenceType: "platform_key_retrieval_without_key_return",
        presentationId,
        presentationDigest,
        userPresenceGuaranteed: platformKeyAdapter.getAvailability().userPresenceGuaranteed,
        issuedAt: nowIso(),
        expiresAt: new Date(Date.now() + FRESH_AUTH_TTL_MS).toISOString(),
        keychainValueReturned: false,
        wrappingKeyReturned: false
      };
    }
    freshAuthEvidence.set(evidence.evidenceId, evidence);
    addAudit("platform_auth", "fresh_authentication", "succeeded", {
      purpose,
      evidenceId: evidence.evidenceId,
      presentationDigest: shortRef(presentationDigest),
      method: evidence.method,
      userPresenceGuaranteed: evidence.userPresenceGuaranteed,
      nativeUserPresence: evidence.evidenceType === "macos_local_authentication_user_presence_without_secret"
    });
    return frozen({ status: "authenticated", evidence, snapshot: snapshot() });
  }

  function createPassphraseFreshAuthenticationEvidence({ passphrase, purpose, presentationId = "", presentationDigest = "" }) {
    const entry = getSelectedEntry();
    if (!entry) return { ok: false, reason: "no_identity_selected" };
    if (typeof passphrase !== "string" || passphrase.length < 8) {
      return { ok: false, reason: "passphrase_reauthentication_required" };
    }
    try {
      const decrypted = decryptIdentityAndRegistryWithPassphrase(entry, passphrase);
      if (decrypted.vaultKey) decrypted.vaultKey.fill(0);
      if (decrypted.wrappingKey) decrypted.wrappingKey.fill(0);
      const evidence = {
        status: "fresh_authentication_satisfied",
        evidenceId: makeId("fresh_auth"),
        purpose,
        identityId: entry.identityId,
        ownerCommitment: entry.ownerCommitment,
        sessionId: lifecycle.sessionId,
        method: "passphrase_reauthentication",
        evidenceType: "local_alpha_passphrase_reauthentication_without_unlock",
        presentationId,
        presentationDigest,
        userPresenceGuaranteed: false,
        issuedAt: nowIso(),
        expiresAt: new Date(Date.now() + FRESH_AUTH_TTL_MS).toISOString(),
        keychainValueReturned: false,
        wrappingKeyReturned: false
      };
      freshAuthEvidence.set(evidence.evidenceId, evidence);
      addAudit("platform_auth", "passphrase_fresh_authentication", "succeeded", {
        purpose,
        evidenceId: evidence.evidenceId,
        presentationDigest: shortRef(presentationDigest)
      });
      return { ok: true, evidence };
    } catch (error) {
      addAudit("platform_auth", "passphrase_fresh_authentication", "failed", {
        purpose,
        reason: error.message
      });
      return { ok: false, reason: "passphrase_reauthentication_failed" };
    }
  }

  function sanitizedActiveWorkflow() {
    return sanitizeWorkflow(activeAuthorizationWorkflow);
  }

  function workflowMatches(inputWorkflowId) {
    return !inputWorkflowId || activeAuthorizationWorkflow?.workflowId === inputWorkflowId;
  }

  function workflowStageAuditAction(stageId) {
    return {
      identity_unlocked: ["session", "identity_unlocked_for_preparation", "completed"],
      intent_created: ["authorization", "protected_action_requested", "requested"],
      trust_evaluated: ["trust", "trust_check_completed", "completed"],
      policy_decided: ["policy", "policy_approved", "approved"],
      approval_completed: ["approval", "action_approved", "approved"],
      capability_activated: ["authorization", "capability_activated", "completed"],
      authorization_candidate_created: ["authorization", "authorization_candidate_created", "completed"],
      package_draft_created: ["authorization", "authorization_package_created", "completed"],
      proof_generated: ["proof", "local_security_proof_generated", "generated"],
      proof_verified: ["proof", "local_security_proof_verified", "verified"],
      authorization_created: ["authorization", "runtime_authorization_created", "completed"],
      fact_available_local: ["proof", "local_fact_fixture_available", "completed"],
      base_execution_prepared: ["authorization", "local_ethereum_execution_prepared", "completed"],
      user_operation_prepared: ["authorization", "local_signing_approval_requested", "approval_required"],
      ready_for_review: ["authorization", "unsigned_user_operation_ready_for_review", "completed"],
      signing_approval_completed: ["approval", "local_signing_approved", "approved"],
      user_operation_signed: ["vault", "device_vault_signature_created", "signed"],
      user_operation_submitted_local: ["authorization", "local_ethereum_test_action_submitted", "submitted_local"],
      execution_verified: ["authorization", "local_ethereum_test_action_completed", "completed"],
      failed: ["authorization", "local_ethereum_test_action_failed", "failed"]
    }[stageId];
  }

  function recordWorkflowStageAudits(workflow, startIndex = 0) {
    if (!workflow?.stages?.length) return;
    for (const item of workflow.stages.slice(startIndex)) {
      const mapped = workflow.workflowKind === "ethereum_sepolia_unsigned_preparation"
        && item.id === "user_operation_prepared"
        ? ["authorization", "unsigned_user_operation_prepared", "completed"]
        : workflowStageAuditAction(item.id);
      if (!mapped) continue;
      const [category, action, result] = mapped;
      addAudit(category, action, result, {
        workflowId: workflow.workflowId,
        stageId: item.id,
        stageLabel: item.label,
        stageStatus: item.status,
        evidenceClass: item.evidenceClass,
        auditCorrelationId: workflow.correlation?.auditCorrelationId,
        proofInputHash: shortRef(workflow.proof?.proofInputHash),
        digestRef: shortRef(workflow.pendingSigningPresentation?.presentationDigest),
        userOperationHash: shortRef(workflow.execution?.userOperationHash),
        transactionHash: shortRef(workflow.execution?.transactionHash),
        publicNetworkMutation: false
      });
    }
  }

  async function startSepoliaUserOperationPreparation(input = {}) {
    if (lifecycle.state !== "unlocked" || !unlockedVault || !protectedRuntimeMaterial) {
      addAudit("authorization", "sepolia_unsigned_preparation", "blocked", {
        reason: "identity_locked"
      });
      return frozen({ status: "blocked", reason: "identity_locked", snapshot: snapshot() });
    }
    if (activeAuthorizationWorkflow && !workflowIsTerminal(activeAuthorizationWorkflow.status)) {
      return frozen({
        status: "busy",
        reason: "authorization_workflow_already_active",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    const readiness = sepoliaPreparationStatus();
    if (!readiness.ready) {
      addAudit("authorization", "sepolia_unsigned_preparation", "blocked", {
        reason: readiness.reason
      });
      return frozen({
        status: "blocked",
        reason: readiness.reason,
        preflight: readiness,
        snapshot: snapshot()
      });
    }
    const executionApproval = consumeApprovalArtifact({
      approvalArtifactId: input.approvalArtifactId,
      kind: "ethereum_sepolia_unsigned_preparation"
    });
    if (!executionApproval.ok) {
      addAudit("authorization", "sepolia_unsigned_preparation", "blocked", {
        reason: executionApproval.reason
      });
      return frozen({
        status: "approval_required",
        reason: executionApproval.reason,
        snapshot: snapshot()
      });
    }
    const workflowId = input.clientActionId || makeId("sepolia_preparation");
    const auditCorrelationId = makeId("audit_correlation");
    activeAuthorizationWorkflow = {
      workflowId,
      workflowKind: "ethereum_sepolia_unsigned_preparation",
      status: "preparing",
      correlation: {
        identityId: selectedIdentityId,
        sessionId: lifecycle.sessionId,
        auditCorrelationId
      },
      stages: [],
      createdAt: nowIso(),
      updatedAt: nowIso(),
      publicNetworkMutation: false
    };
    writeProtectedActionMarker(workflowId, "preparing", auditCorrelationId);
    const preparedWorkflow = await startDesktopSepoliaUserOperationPreparation({
      workflowId,
      sessionId: lifecycle.sessionId,
      vaultHandleId: unlockedVault.handleId,
      auditCorrelationId,
      protectedMaterial: protectedRuntimeMaterial,
      desktopApproval: {
        approvalArtifactId: executionApproval.artifact.approvalArtifactId,
        presentationId: executionApproval.artifact.presentationId,
        presentationDigest: executionApproval.artifact.presentationDigest,
        decidedAt: executionApproval.artifact.consumedAt || nowIso(),
        expiresAt: executionApproval.artifact.expiresAt
      },
      configuration: getSepoliaPreparationConfiguration(),
      storageRoot,
      usedProofDigests: preparedSepoliaProofDigests,
      usedNullifiers: preparedSepoliaNullifiers,
      proofTimeoutMs: input.proofTimeoutMs,
      dependencies: options.sepoliaPreparationDependencies
    });
    if (
      activeAuthorizationWorkflow?.workflowId !== workflowId
      || workflowIsTerminal(activeAuthorizationWorkflow.status)
    ) {
      return frozen({
        status: activeAuthorizationWorkflow?.status || "interrupted",
        reason: activeAuthorizationWorkflow?.error
          || "workflow_invalidated_during_preparation",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    activeAuthorizationWorkflow = preparedWorkflow;
    clearProtectedActionMarker();
    recordWorkflowStageAudits(activeAuthorizationWorkflow);
    addAudit(
      "authorization",
      "sepolia_unsigned_user_operation_prepared",
      activeAuthorizationWorkflow.status,
      {
        workflowId,
        auditCorrelationId,
        artifactId: activeAuthorizationWorkflow.preparation?.artifactId,
        proofInputHash: shortRef(activeAuthorizationWorkflow.proof?.proofInputHash),
        userOperationHash: shortRef(
          activeAuthorizationWorkflow.preparation?.userOperationHash
        ),
        starkVerificationLocation: "local",
        ethereumVerifiedProof: false,
        transactionSigned: false,
        userOperationSubmitted: false,
        publicNetworkMutation: false
      }
    );
    return frozen({
      status: activeAuthorizationWorkflow.status,
      workflow: sanitizedActiveWorkflow(),
      snapshot: snapshot()
    });
  }

  function getSepoliaUserOperationPreparation(input = {}) {
    if (!workflowMatches(input.workflowId)) {
      return frozen({
        status: "not_found",
        reason: "workflow_not_found",
        snapshot: snapshot()
      });
    }
    if (
      activeAuthorizationWorkflow
      && activeAuthorizationWorkflow.workflowKind
        !== "ethereum_sepolia_unsigned_preparation"
    ) {
      return frozen({
        status: "not_found",
        reason: "workflow_kind_mismatch",
        snapshot: snapshot()
      });
    }
    return frozen({
      status: activeAuthorizationWorkflow?.status || "not_started",
      workflow: sanitizedActiveWorkflow(),
      snapshot: snapshot()
    });
  }

  async function finalizeSepoliaSignedArtifact(input = {}) {
    if (
      !workflowMatches(input.workflowId)
      || !activeAuthorizationWorkflow
      || activeAuthorizationWorkflow.workflowKind
        !== "ethereum_sepolia_unsigned_preparation"
    ) {
      return frozen({
        status: "not_found",
        reason: "workflow_not_found",
        snapshot: snapshot()
      });
    }
    if (
      activeAuthorizationWorkflow.status !== "prepared_unsigned"
      || !activeAuthorizationWorkflow.privateState
    ) {
      return frozen({
        status: "blocked",
        reason: "process_local_signing_capability_unavailable",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    if (lifecycle.state !== "unlocked" || !unlockedVault || !protectedRuntimeMaterial) {
      return frozen({
        status: "blocked",
        reason: "identity_locked",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    const signingApproval = consumeApprovalArtifact({
      approvalArtifactId: input.approvalArtifactId,
      kind: "ethereum_sepolia_user_operation_signing",
      presentationDigest: input.presentationDigest,
      freshAuthenticationEvidenceId: input.freshAuthenticationEvidenceId
    });
    if (!signingApproval.ok) {
      addAudit("authorization", "sepolia_user_operation_signing", "blocked", {
        workflowId: input.workflowId,
        reason: signingApproval.reason
      });
      return frozen({
        status: "approval_required",
        reason: signingApproval.reason,
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    const freshAuthenticationEvidence = freshAuthEvidence.get(
      input.freshAuthenticationEvidenceId
    );
    if (!freshAuthenticationEvidence) {
      return frozen({
        status: "fresh_authentication_required",
        reason: "fresh_authentication_required",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    const previousStageCount = activeAuthorizationWorkflow.stages?.length || 0;
    try {
      const authorityMaterial = protectedRuntimeMaterial;
      const deviceVaultSigningAuthority = Object.freeze({
        checkAuthorityAvailable(expected) {
          return Boolean(
            lifecycle.state === "unlocked"
            && protectedRuntimeMaterial === authorityMaterial
            && unlockedVault?.handleId
            && expected.signingPurpose
              === "ethereum_sepolia_local_proof_gated_v1_signing"
            && authorityMaterial.validator.keyReferenceId
              === expected.keyReferenceId
            && authorityMaterial.validator.publicOwnerAddress.toLowerCase()
              === expected.ownerAddress.toLowerCase()
          );
        },
        async signBoundDigest(request) {
          if (
            request.signingPurpose
              !== "ethereum_sepolia_local_proof_gated_v1_signing"
            || protectedRuntimeMaterial !== authorityMaterial
            || lifecycle.state !== "unlocked"
          ) {
            throw new Error("device_vault_signing_authority_invalidated");
          }
          const wallet = new Wallet(authorityMaterial.validator.privateKey);
          return wallet.signMessage(getBytes(request.digest));
        },
        toJSON() {
          throw new Error(
            "Device Vault signing authority is process-local and non-serializable"
          );
        }
      });
      const signed = await completeDesktopSepoliaUserOperationSigning({
        workflow: activeAuthorizationWorkflow,
        signingIdentityMaterial: {
          identityId: protectedRuntimeMaterial.identityId,
          ownerCommitment: protectedRuntimeMaterial.ownerCommitment,
          validator: {
            recordId: protectedRuntimeMaterial.validator.recordId,
            keyReferenceId:
              protectedRuntimeMaterial.validator.keyReferenceId,
            publicOwnerAddress:
              protectedRuntimeMaterial.validator.publicOwnerAddress
          }
        },
        deviceVaultSigningAuthority,
        identityUnlocked: lifecycle.state === "unlocked",
        activeSession: Boolean(lifecycle.sessionId),
        sessionId: lifecycle.sessionId,
        vaultHandleId: unlockedVault.handleId,
        signingApproval: signingApproval.artifact,
        freshAuthenticationEvidence,
        storageRoot,
        proofTimeoutMs: input.proofTimeoutMs,
        dependencies: options.sepoliaPreparationDependencies
      });
      const signedAt = signed.signedArtifact.signedAt;
      activeAuthorizationWorkflow = {
        ...sanitizeWorkflow(activeAuthorizationWorkflow),
        status: "signed_unsubmitted",
        updatedAt: signedAt,
        stages: [
          ...(activeAuthorizationWorkflow.stages || []),
          {
            id: "signing_approval_completed",
            label: "Signing approved",
            evidenceClass: "real_local",
            status: "completed",
            at: signingApproval.artifact.consumedAt || signedAt,
            details: {
              presentationDigest: shortRef(
                signingApproval.artifact.presentationDigest
              ),
              oneTime: true
            }
          },
          {
            id: "proof_revalidated",
            label: "Proof revalidated locally",
            evidenceClass: "real_local",
            status: "completed",
            at: signedAt,
            details: {
              proofInputHash: shortRef(signed.signedArtifact.proofInputHash),
              ethereumVerifiedProof: false
            }
          },
          {
            id: "user_operation_signed",
            label: "Device authorized the action",
            evidenceClass: "real_local",
            status: "completed",
            at: signedAt,
            details: {
              userOperationHash: shortRef(
                signed.signedArtifact.userOperationHash
              ),
              purpose: signed.signedArtifact.signingPurpose,
              publicMutationOccurred: false
            }
          }
        ],
        signing: {
          artifactId: signed.signedArtifact.artifactId,
          artifactLocation: signed.artifactLocation,
          statusMessage:
            "Signed locally. Nothing has been sent to Ethereum.",
          signingPurpose: signed.signedArtifact.signingPurpose,
          validatorPublicAddress:
            signed.signedArtifact.validatorPublicAddress,
          userOperationHash: signed.signedArtifact.userOperationHash,
          authorizationDigest:
            signed.signedArtifact.authorizationDigest,
          proofDigest: signed.signedArtifact.proofArtifactDigest,
          proofInputHash: signed.signedArtifact.proofInputHash,
          chainId: signed.signedArtifact.chainId,
          ethereumVerifiedProof: false,
          starkVerificationLocation: "local",
          signaturePresent: true,
          publicMutationOccurred: false,
          userOperationSubmitted: false
        },
        evidenceLabels: {
          ...activeAuthorizationWorkflow.evidenceLabels,
          signing: "real_local",
          submission: "not_executed"
        },
        privateState: undefined,
        transactionSigned: false,
        userOperationSigned: true,
        userOperationSubmitted: false,
        publicNetworkMutation: false,
        productionApprovalGranted: false
      };
      clearProtectedActionMarker();
      recordWorkflowStageAudits(activeAuthorizationWorkflow, previousStageCount);
      addAudit("vault", "sepolia_signed_artifact_created", "signed_unsubmitted", {
        workflowId: input.workflowId,
        artifactId: signed.signedArtifact.artifactId,
        signingPurpose: signed.signedArtifact.signingPurpose,
        userOperationHash: shortRef(signed.signedArtifact.userOperationHash),
        authorizationDigest: shortRef(
          signed.signedArtifact.authorizationDigest
        ),
        proofDigest: shortRef(signed.signedArtifact.proofArtifactDigest),
        transactionSubmitted: false,
        userOperationSubmitted: false,
        publicNetworkMutation: false
      });
      freshAuthEvidence.delete(input.freshAuthenticationEvidenceId);
      return frozen({
        status: "signed_unsubmitted",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    } catch (error) {
      activeAuthorizationWorkflow = {
        ...sanitizeWorkflow(activeAuthorizationWorkflow),
        status: "failed",
        updatedAt: nowIso(),
        privateState: undefined,
        error: error instanceof Error ? error.message : "signing_failed",
        transactionSigned: false,
        userOperationSigned: false,
        userOperationSubmitted: false,
        publicNetworkMutation: false
      };
      clearProtectedActionMarker();
      addAudit("vault", "sepolia_user_operation_signing", "failed", {
        workflowId: input.workflowId,
        reason: activeAuthorizationWorkflow.error,
        publicNetworkMutation: false
      });
      freshAuthEvidence.delete(input.freshAuthenticationEvidenceId);
      return frozen({
        status: "failed",
        reason: activeAuthorizationWorkflow.error,
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
  }

  async function startRealLocalAuthorizationWorkflow(input = {}) {
    if (lifecycle.state !== "unlocked" || !unlockedVault || !protectedRuntimeMaterial) {
      addAudit("authorization", "real_local_workflow", "blocked", { reason: "session_locked" });
      return frozen({ status: "blocked", reason: "session_locked", snapshot: snapshot() });
    }
    if (activeAuthorizationWorkflow && !workflowIsTerminal(activeAuthorizationWorkflow.status)) {
      return frozen({
        status: "busy",
        reason: "authorization_workflow_already_active",
        workflow: sanitizedActiveWorkflow(),
        snapshot: snapshot()
      });
    }
    const executionApproval = consumeApprovalArtifact({
      approvalArtifactId: input.approvalArtifactId,
      kind: "local_authorization_execution"
    });
    if (!executionApproval.ok) {
      addAudit("authorization", "real_local_workflow", "blocked", { reason: executionApproval.reason });
      return frozen({ status: "approval_required", reason: executionApproval.reason, snapshot: snapshot() });
    }
    const preflight = protectedActionStatus();
    if (!preflight.ready) {
      addAudit("authorization", "protected_action_preflight", "blocked", {
        reason: preflight.reason,
        publicNetworkMutation: false
      });
      return frozen({ status: "blocked", reason: preflight.reason, preflight, snapshot: snapshot() });
    }
    const workflowId = input.clientActionId || makeId("desktop_workflow");
    const auditCorrelationId = makeId("audit_correlation");
    activeAuthorizationWorkflow = {
      workflowId,
      status: "preparing",
      correlation: {
        sessionId: lifecycle.sessionId,
        auditCorrelationId
      },
      stages: [],
      createdAt: nowIso(),
      updatedAt: nowIso(),
      publicNetworkMutation: false,
      privateState: undefined
    };
    writeProtectedActionMarker(workflowId, "preparing", auditCorrelationId);
    try {
      const preparedWorkflow = await startDesktopRealLocalAuthorizationWorkflow({
        workflowId,
        sessionId: lifecycle.sessionId,
        auditCorrelationId,
        protectedMaterial: protectedRuntimeMaterial,
        proofTimeoutMs: input.proofTimeoutMs,
        rootProofStack: options.rootProofStack,
        testOnlyHypotheticalWitnessHidingProofStack:
          options.testOnlyHypotheticalWitnessHidingProofStack,
        desktopApproval: {
          approvalArtifactId: executionApproval.artifact.approvalArtifactId,
          presentationId: executionApproval.artifact.presentationId,
          presentationDigest: executionApproval.artifact.presentationDigest,
          decidedAt: executionApproval.artifact.consumedAt || nowIso(),
          expiresAt: executionApproval.artifact.expiresAt
        }
      });
      if (activeAuthorizationWorkflow?.workflowId !== workflowId || workflowIsTerminal(activeAuthorizationWorkflow.status)) {
        return frozen({
          status: activeAuthorizationWorkflow?.status || "interrupted",
          reason: activeAuthorizationWorkflow?.error || "workflow_invalidated_during_preparation",
          workflow: sanitizedActiveWorkflow(),
          snapshot: snapshot()
        });
      }
      activeAuthorizationWorkflow = preparedWorkflow;
      if (!workflowIsTerminal(activeAuthorizationWorkflow.status)) {
        try {
          reserveLocalNullifier(
            activeAuthorizationWorkflow.execution?.nullifier,
            activeAuthorizationWorkflow.workflowId
          );
        } catch (error) {
          activeAuthorizationWorkflow = {
            ...sanitizeWorkflow(activeAuthorizationWorkflow),
            status: "failed",
            updatedAt: nowIso(),
            pendingSigningPresentation: undefined,
            privateState: undefined,
            error: error instanceof Error ? error.message : "local_nullifier_ledger_unavailable"
          };
        }
      }
    } catch (error) {
      clearProtectedActionMarker();
      throw error;
    }
    if (workflowIsTerminal(activeAuthorizationWorkflow.status)) clearProtectedActionMarker();
    else writeProtectedActionMarker(workflowId, activeAuthorizationWorkflow.status, auditCorrelationId);
    recordWorkflowStageAudits(activeAuthorizationWorkflow);
    addAudit("authorization", "real_local_workflow_started", activeAuthorizationWorkflow.status, {
      workflowId,
      auditCorrelationId,
      proofInputHash: shortRef(activeAuthorizationWorkflow.proof?.proofInputHash),
      publicNetworkMutation: false
    });
    return frozen({ status: activeAuthorizationWorkflow.status, workflow: sanitizedActiveWorkflow(), snapshot: snapshot() });
  }

  function getRealLocalAuthorizationWorkflow(input = {}) {
    if (!workflowMatches(input.workflowId)) {
      return frozen({ status: "not_found", reason: "workflow_not_found", snapshot: snapshot() });
    }
    return frozen({ status: activeAuthorizationWorkflow?.status || "not_started", workflow: sanitizedActiveWorkflow(), snapshot: snapshot() });
  }

  function requestRealLocalAuthorizationFreshAuth(input = {}) {
    if (!workflowMatches(input.workflowId) || !activeAuthorizationWorkflow) {
      return frozen({ status: "not_found", reason: "workflow_not_found", snapshot: snapshot() });
    }
    const digest = activeAuthorizationWorkflow.pendingSigningPresentation?.presentationDigest;
    if (!digest) return frozen({ status: "failed", reason: "signing_presentation_not_available", snapshot: snapshot() });
    const result = requireFreshPlatformAuthentication({
      purpose: "local_user_operation_signing",
      presentationId: activeAuthorizationWorkflow.workflowId,
      presentationDigest: digest
    });
    if (result.status === "authenticated") return result;
    const terminalStatus = result.reason === "helper_timeout"
      ? "timed_out"
      : result.reason === "user_cancelled" ? "cancelled" : "failed";
    const workflow = terminalizeActiveWorkflow(terminalStatus, result.reason, "fresh_authentication_stopped");
    return frozen({ ...result, status: terminalStatus, workflow, snapshot: snapshot() });
  }

  async function respondRealLocalAuthorizationApproval(input = {}) {
    if (!workflowMatches(input.workflowId) || !activeAuthorizationWorkflow) {
      return frozen({ status: "not_found", reason: "workflow_not_found", snapshot: snapshot() });
    }
    const digest = activeAuthorizationWorkflow.pendingSigningPresentation?.presentationDigest;
    if (!digest) return frozen({ status: "failed", reason: "signing_presentation_not_available", snapshot: snapshot() });
    if (input.presentationDigest !== digest) {
      addAudit("authorization", "real_local_workflow_signing", "blocked", { reason: "presentation_digest_mismatch" });
      return frozen({ status: "failed", reason: "presentation_digest_mismatch", workflow: sanitizedActiveWorkflow(), snapshot: snapshot() });
    }
    if (input.decision !== "approve") {
      activeAuthorizationWorkflow = {
        ...sanitizeWorkflow(activeAuthorizationWorkflow),
        status: input.decision === "deny" ? "failed" : "cancelled",
        updatedAt: nowIso(),
        pendingSigningPresentation: undefined,
        privateState: undefined,
        error: input.decision === "deny" ? "signing_denied" : "signing_cancelled"
      };
      addAudit("authorization", "real_local_workflow_signing", input.decision, {
        workflowId: activeAuthorizationWorkflow.workflowId
      });
      return frozen({ status: activeAuthorizationWorkflow.status, workflow: sanitizedActiveWorkflow(), snapshot: snapshot() });
    }
    const evidence = freshAuthEvidence.get(input.freshAuthenticationEvidenceId);
    if (!evidence) {
      return frozen({ status: "fresh_authentication_required", reason: "fresh_authentication_required", workflow: sanitizedActiveWorkflow(), snapshot: snapshot() });
    }
    const previousStageCount = activeAuthorizationWorkflow.stages?.length || 0;
    activeAuthorizationWorkflow = await completeDesktopRealLocalAuthorizationWorkflow(activeAuthorizationWorkflow, {
      signingApprovalId: makeId("signing_approval"),
      freshAuthenticationEvidence: evidence
    });
    if (activeAuthorizationWorkflow.status === "completed"
      && activeAuthorizationWorkflow.execution?.nullifierConsumed) {
      try {
        markLocalNullifierConsumed(
          activeAuthorizationWorkflow.execution.nullifier,
          activeAuthorizationWorkflow.workflowId
        );
      } catch (error) {
        addAudit("authorization", "local_nullifier_ledger", "failed", {
          reason: error instanceof Error ? error.message : "local_nullifier_ledger_update_failed",
          workflowId: activeAuthorizationWorkflow.workflowId,
          replaySafety: "reservation_remains_fail_closed"
        });
      }
    }
    if (workflowIsTerminal(activeAuthorizationWorkflow.status)) clearProtectedActionMarker();
    recordWorkflowStageAudits(activeAuthorizationWorkflow, previousStageCount);
    addAudit("authorization", "real_local_workflow_completed", activeAuthorizationWorkflow.status, {
      workflowId: activeAuthorizationWorkflow.workflowId,
      userOperationHash: shortRef(activeAuthorizationWorkflow.execution?.userOperationHash),
      transactionHash: shortRef(activeAuthorizationWorkflow.execution?.transactionHash),
      nullifierConsumed: Boolean(activeAuthorizationWorkflow.execution?.nullifierConsumed),
      consumerExecuted: Boolean(activeAuthorizationWorkflow.execution?.consumerExecuted),
      publicNetworkMutation: false
    });
    return frozen({ status: activeAuthorizationWorkflow.status, workflow: sanitizedActiveWorkflow(), snapshot: snapshot() });
  }

  function cancelRealLocalAuthorizationWorkflow(input = {}) {
    if (!workflowMatches(input.workflowId) || !activeAuthorizationWorkflow) {
      return frozen({ status: "not_found", reason: "workflow_not_found", snapshot: snapshot() });
    }
    const workflow = terminalizeActiveWorkflow(
      input.terminalStatus || "cancelled",
      input.reason || "user_cancelled",
      input.terminalStatus === "timed_out" ? "real_local_workflow_timed_out" : "real_local_workflow_cancelled"
    );
    return frozen({ status: workflow.status, reason: workflow.error, workflow, snapshot: snapshot() });
  }

  const handlers = {
    [CHANNELS.GET_SNAPSHOT]: () => snapshot(),
    [CHANNELS.PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW]: () => {
      const preflight = protectedActionStatus();
      if (!preflight.ready) {
        addAudit("authorization", "protected_action_preflight", "blocked", {
          reason: preflight.reason,
          publicNetworkMutation: false
        });
      }
      return frozen({ status: preflight.ready ? "ready" : "blocked", reason: preflight.reason, preflight, snapshot: snapshot() });
    },
    [CHANNELS.PREFLIGHT_SEPOLIA_USER_OPERATION_PREPARATION]: () => {
      const preflight = sepoliaPreparationStatus();
      if (!preflight.ready) {
        addAudit("authorization", "sepolia_preparation_preflight", "blocked", {
          reason: preflight.reason,
          publicNetworkMutation: false
        });
      }
      return frozen({
        status: preflight.ready ? "ready" : "blocked",
        reason: preflight.reason,
        preflight,
        snapshot: snapshot()
      });
    },
    [CHANNELS.LIST_LOCAL_IDENTITIES]: () => frozen({ identities: safeIndex() }),
    [CHANNELS.CREATE_LOCAL_IDENTITY]: (payload) => {
      const input = mustValidate(CHANNELS.CREATE_LOCAL_IDENTITY, payload);
      const createdAt = nowIso();
      const identity = createPhilIdentityPrivate();
      const identityId = `identity_${identity.ownerCommitment.slice(2, 14)}_${crypto.randomBytes(4).toString("hex")}`;
      const p = pathsFor(identityId);
      ensureDir(p.dir);
      const validatorWallet = createSafeWallet();
      const validator = {
        format: "philcore-desktop-validator-public-metadata-v1",
        version: STORAGE_VERSION,
        keyReferenceId: makeId("validator_key"),
        recordId: makeId("validator_record"),
        ownerCommitment: identity.ownerCommitment,
        publicOwnerAddress: validatorWallet.address,
        lifecycleState: "stored_encrypted",
        purpose: "erc4337_owner_validator_local_alpha",
        createdAt,
        updatedAt: createdAt,
        privateKey: validatorWallet.privateKey,
        privateMaterialReturned: false,
        storedEncrypted: true,
        localOnly: true
      };
      const recovery = input.createRecoveryAuthority
        ? createRecoveryRecord(identity.ownerCommitment, validator.publicOwnerAddress, createdAt)
        : null;
      const registry = createRegistry(identity, createdAt, validator, recovery, input.createRecoveryAuthority);
      const privateIdentityPayload = {
        format: "philcore-desktop-private-identity-v1",
        version: STORAGE_VERSION,
        identityId,
        philSecret: identity.philSecret,
        identityRoot: identity.identityRoot,
        ownerCommitment: identity.ownerCommitment,
        createdAt,
        privateMaterialExportable: false
      };
      atomicWriteFile(p.identity, `${encryptPayload({
        format: IDENTITY_ENVELOPE_FORMAT,
        identityId,
        ownerCommitment: identity.ownerCommitment,
        payload: privateIdentityPayload,
        passphrase: input.passphrase
      })}\n`);
      atomicWriteFile(p.registry, `${encryptPayload({
        format: REGISTRY_ENVELOPE_FORMAT,
        identityId,
        ownerCommitment: identity.ownerCommitment,
        payload: registry,
        passphrase: input.passphrase
      })}\n`);
      atomicWriteFile(p.validator, `${encryptPayload({
        format: VALIDATOR_ENVELOPE_FORMAT,
        identityId,
        ownerCommitment: identity.ownerCommitment,
        payload: validator,
        passphrase: input.passphrase
      })}\n`);
      if (recovery) {
        atomicWriteFile(p.recovery, `${encryptPayload({
          format: RECOVERY_ENVELOPE_FORMAT,
          identityId,
          ownerCommitment: identity.ownerCommitment,
          payload: recovery,
          passphrase: input.passphrase
        })}\n`);
      }
      const index = loadIndex();
      const entry = {
        identityId,
        label: input.label,
        ownerCommitment: identity.ownerCommitment,
        createdAt,
        lastOpenedAt: createdAt,
        storageFormatVersion: STORAGE_VERSION,
        encryptedRegistryPathRef: `${identityId}/registry.encrypted.json`,
        status: "locked",
        failedUnlockAttempts: 0,
        validatorStatus: "available",
        validatorPublicAddress: validator.publicOwnerAddress,
        validatorKeyReferenceId: validator.keyReferenceId,
        recoveryStatus: recovery ? "available" : "not_created",
        recoveryPublicAddress: recovery?.publicRecoveryAddress,
        recoveryCustodyType: recovery?.custodyType,
        platformProtectionStatus: "not_enrolled",
        platformUnlockEnabled: false,
        platformProtectionType: "none",
        lastSuccessfulUnlockMethod: "none",
        philPreview: input.philPreview
      };
      saveIndex({ ...index, identities: [...index.identities, entry] });
      selectedIdentityId = identityId;
      clearProcessLocalSecrets();
      setLifecycle("locked", { selectedIdentityId: identityId });
      addAudit("identity", "create_local_identity", "created_locked", {
        ownerCommitment: shortRef(identity.ownerCommitment),
        encryptedRegistryPersisted: true,
        privateMaterialReturned: false,
        localAlphaAuthentication: true
      });
      return snapshot();
    },
    [CHANNELS.OPEN_LOCAL_IDENTITY]: (payload) => {
      const input = mustValidate(CHANNELS.OPEN_LOCAL_IDENTITY, payload);
      const index = loadIndex();
      const entry = index.identities.find((candidate) => candidate.identityId === input.identityId);
      if (!entry) return frozen({ status: "failed", reason: "identity_not_found", snapshot: snapshot() });
      selectedIdentityId = entry.identityId;
      clearProcessLocalSecrets();
      setLifecycle("locked", { selectedIdentityId });
      updateIndexEntry(selectedIdentityId, (current) => ({ ...current, lastOpenedAt: nowIso(), status: "locked" }));
      addAudit("identity", "open_local_identity", "opened_locked", { identityId: selectedIdentityId });
      return snapshot();
    },
    [CHANNELS.RENAME_LOCAL_IDENTITY]: (payload) => {
      const input = mustValidate(CHANNELS.RENAME_LOCAL_IDENTITY, payload);
      const entry = getSelectedEntry();
      if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
      updateIndexEntry(entry.identityId, (current) => ({ ...current, label: input.label }));
      addAudit("identity", "rename_local_identity", "renamed", { identityId: entry.identityId });
      return frozen({ status: "renamed", identity: identitySummary(), snapshot: snapshot() });
    },
    [CHANNELS.GET_LOCKED_SUMMARY]: () => frozen({ selected: identitySummary(), vault: vaultStatus() }),
    [CHANNELS.GET_PLATFORM_AUTH_AVAILABILITY]: () => frozen(platformKeyAdapter.getAvailability()),
    [CHANNELS.GET_PLATFORM_AUTH_STATUS]: () => frozen(platformStatus()),
    [CHANNELS.GET_PLATFORM_AUTH_POLICY]: () => frozen({
      policy: {
        ...PLATFORM_UNLOCK_POLICY,
        sessionTimeoutMinutes: settings.sessionTimeoutMinutes
      },
      selected: platformStatus(),
      localOnly: true,
      productionApproved: false
    }),
    [CHANNELS.ENROLL_PLATFORM_AUTH]: (payload) => {
      const input = mustValidate(CHANNELS.ENROLL_PLATFORM_AUTH, payload);
      return enrollPlatformProtection(input.passphrase, input.approvalArtifactId);
    },
    [CHANNELS.PLATFORM_UNLOCK]: () => unlockWithPlatformProtection(),
    [CHANNELS.DISABLE_PLATFORM_AUTH]: (payload) => {
      const input = mustValidate(CHANNELS.DISABLE_PLATFORM_AUTH, payload);
      return disablePlatformProtection(input.passphrase, input.approvalArtifactId, input.freshAuthenticationEvidenceId);
    },
    [CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH]: (payload) => {
      const input = mustValidate(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, payload);
      return requireFreshPlatformAuthentication(input);
    },
    [CHANNELS.CREATE_APPROVAL_PRESENTATION]: (payload) => {
      const input = mustValidate(CHANNELS.CREATE_APPROVAL_PRESENTATION, payload);
      return createApprovalPresentation(input);
    },
    [CHANNELS.GET_APPROVAL_PRESENTATION]: (payload) => {
      const input = mustValidate(CHANNELS.GET_APPROVAL_PRESENTATION, payload);
      return getApprovalPresentation(input.presentationId);
    },
    [CHANNELS.RESPOND_APPROVAL]: (payload) => {
      const input = mustValidate(CHANNELS.RESPOND_APPROVAL, payload);
      return respondApproval(input);
    },
    [CHANNELS.CANCEL_APPROVAL]: (payload) => {
      const input = mustValidate(CHANNELS.CANCEL_APPROVAL, payload);
      return cancelApprovalPresentation(input.presentationId);
    },
    [CHANNELS.GET_APPROVAL_STATUS]: () => frozen({
      status: "ok",
      pendingCount: presentations.size,
      approvalArtifactCount: approvals.size,
      maxPendingPresentations: MAX_PENDING_PRESENTATIONS,
      oneCriticalAtATime: true
    }),
    [CHANNELS.CONSUME_APPROVAL]: (payload) => {
      const input = mustValidate(CHANNELS.CONSUME_APPROVAL, payload);
      const result = consumeApprovalArtifact(input);
      return frozen({ status: result.ok ? "consumed" : "failed", reason: result.reason, snapshot: snapshot() });
    },
    [CHANNELS.LIST_APPROVAL_HISTORY]: () => listApprovalHistory(),
    [CHANNELS.AUTHENTICATE_LOCAL]: (payload) => {
      const input = mustValidate(CHANNELS.AUTHENTICATE_LOCAL, payload);
      const entry = getSelectedEntry();
      if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
      try {
        const unlocked = decryptIdentityAndRegistryWithPassphrase(entry, input.passphrase);
        pendingUnlock = {
          identityId: entry.identityId,
          ownerCommitment: entry.ownerCommitment,
          privateIdentity: unlocked.privateIdentity,
          registry: unlocked.registry,
          passphrase: input.passphrase,
          vaultKey: unlocked.vaultKey,
          wrappingKey: unlocked.wrappingKey,
          unlockMethod: unlocked.unlockMethod
        };
        setLifecycle("partially_unlocked", {
          selectedIdentityId: entry.identityId,
          lifecycleAuthenticationFactorVerified: true
        });
        updateIndexEntry(entry.identityId, (current) => ({ ...current, failedUnlockAttempts: 0 }));
        addAudit("session", "authenticate_local_alpha_passphrase", "verified", {
          localAlphaOnly: true,
          productionAuthentication: false,
          platformProtectionEnabled: Boolean(unlocked.wrappingKey)
        });
        return frozen({ status: "authenticated", snapshot: snapshot() });
      } catch (error) {
        updateIndexEntry(entry.identityId, (current) => ({
          ...current,
          failedUnlockAttempts: (current.failedUnlockAttempts ?? 0) + 1,
          status: "locked"
        }));
        clearProcessLocalSecrets();
        setLifecycle("locked", { lastUnlockFailure: "failed_closed" });
        addAudit("session", "authenticate_local_alpha_passphrase", "failed_closed", {
          reason: error.message
        });
        return frozen({ status: "failed", reason: "authentication_failed_closed", snapshot: snapshot() });
      }
    },
    [CHANNELS.UNLOCK_VAULT]: () => completeVaultUnlock("passphrase_fallback"),
    [CHANNELS.AUTHENTICATE_LOCAL_FIXTURE]: () => frozen({
      status: "unsupported",
      reason: "fixture_identity_unlock_removed_from_normal_path",
      snapshot: snapshot()
    }),
    [CHANNELS.LOCK_SESSION]: () => lock("manual_lock"),
    [CHANNELS.GET_SESSION_STATE]: () => frozen({ lifecycle, session: snapshot().session }),
    [CHANNELS.GET_VAULT_STATUS]: () => frozen(vaultStatus()),
    [CHANNELS.GET_PROTECTED_VIEW]: (payload) => {
      const input = mustValidate(CHANNELS.GET_PROTECTED_VIEW, payload);
      return frozen(protectedView(input.viewType));
    },
    [CHANNELS.LIST_PUBLIC_CREDENTIALS]: () => frozen({ credentials: publicCredentials() }),
    [CHANNELS.GET_VALIDATOR_STATUS]: () => frozen(validatorStatus()),
    [CHANNELS.GET_RECOVERY_STATUS]: () => frozen(recoveryStatus()),
    [CHANNELS.RESET_LOCAL_IDENTITY]: (payload) => {
      const input = mustValidate(CHANNELS.RESET_LOCAL_IDENTITY, payload);
      const entry = getSelectedEntry();
      if (!entry) return frozen({ status: "failed", reason: "no_identity_selected", snapshot: snapshot() });
      if (lifecycle.state !== "locked") return frozen({ status: "failed", reason: "identity_must_be_locked", snapshot: snapshot() });
      let freshAuthenticationEvidenceId = input.freshAuthenticationEvidenceId;
      if (!freshAuthenticationEvidenceId && input.passphrase) {
        const artifact = approvals.get(input.approvalArtifactId);
        const passphraseEvidence = createPassphraseFreshAuthenticationEvidence({
          passphrase: input.passphrase,
          purpose: "local_identity_reset",
          presentationId: artifact?.presentationId || "",
          presentationDigest: artifact?.presentationDigest || ""
        });
        if (!passphraseEvidence.ok) {
          return frozen({ status: "fresh_authentication_required", reason: passphraseEvidence.reason, snapshot: snapshot() });
        }
        freshAuthenticationEvidenceId = passphraseEvidence.evidence.evidenceId;
      }
      const approval = consumeApprovalArtifact({
        approvalArtifactId: input.approvalArtifactId,
        kind: "local_identity_reset",
        freshAuthenticationEvidenceId
      });
      if (!approval.ok) return frozen({ status: "approval_required", reason: approval.reason, snapshot: snapshot() });
      if (input.confirmation !== `RESET ${entry.identityId}`) {
        return frozen({ status: "failed", reason: "confirmation_mismatch", snapshot: snapshot() });
      }
      try {
        const protection = loadPlatformProtection(entry);
        if (protection?.enabled) {
          platformKeyAdapter.deleteWrappingKey({
            identityId: entry.identityId,
            ownerCommitment: entry.ownerCommitment,
            keychainReference: protection.keychainReference
          });
        }
      } catch {
        // Reset still removes only the selected local identity files.
      }
      const dir = identityDir(entry.identityId);
      fs.rmSync(dir, { recursive: true, force: true });
      const index = loadIndex();
      saveIndex({ ...index, identities: index.identities.filter((candidate) => candidate.identityId !== entry.identityId) });
      addAudit("identity", "reset_local_identity", "deleted_local_only", { identityId: entry.identityId });
      selectedIdentityId = null;
      clearProcessLocalSecrets();
      setLifecycle("locked");
      return frozen({ status: "reset", snapshot: snapshot() });
    },
    [CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO]: (payload) => {
      const input = mustValidate(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, payload);
      return runLocalAuthorizationDemo(input);
    },
    [CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW]: async (payload) => {
      const input = mustValidate(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, payload);
      return startRealLocalAuthorizationWorkflow(input);
    },
    [CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION]: async (payload) => {
      const input = mustValidate(
        CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
        payload
      );
      return startSepoliaUserOperationPreparation(input);
    },
    [CHANNELS.GET_SEPOLIA_USER_OPERATION_PREPARATION]: (payload) => {
      const input = mustValidate(
        CHANNELS.GET_SEPOLIA_USER_OPERATION_PREPARATION,
        payload
      );
      return getSepoliaUserOperationPreparation(input);
    },
    [CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT]: async (payload) => {
      const input = mustValidate(
        CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT,
        payload
      );
      return finalizeSepoliaSignedArtifact(input);
    },
    [CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_WORKFLOW]: (payload) => {
      const input = mustValidate(CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_WORKFLOW, payload);
      return getRealLocalAuthorizationWorkflow(input);
    },
    [CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH]: (payload) => {
      const input = mustValidate(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, payload);
      return requestRealLocalAuthorizationFreshAuth(input);
    },
    [CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL]: async (payload) => {
      const input = mustValidate(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, payload);
      return respondRealLocalAuthorizationApproval(input);
    },
    [CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW]: (payload) => {
      const input = mustValidate(CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW, payload);
      return cancelRealLocalAuthorizationWorkflow(input);
    },
    [CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_RESULT]: (payload) => {
      const input = mustValidate(CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_RESULT, payload);
      return getRealLocalAuthorizationWorkflow(input);
    },
    [CHANNELS.RUN_RECOVERY_DEMO]: (payload) => {
      const input = mustValidate(CHANNELS.RUN_RECOVERY_DEMO, payload);
      const kindByScenario = {
        owner_rotation: "execution_owner_rotation",
        request: "recovery_request",
        cancel: "recovery_cancel",
        complete: "recovery_complete",
        authority_rotation_request: "recovery_authority_rotation",
        authority_rotation_cancel: "recovery_authority_rotation",
        authority_rotation_complete: "recovery_authority_rotation"
      };
      const approval = consumeApprovalArtifact({
        approvalArtifactId: input.approvalArtifactId,
        kind: kindByScenario[input.scenario],
        freshAuthenticationEvidenceId: input.freshAuthenticationEvidenceId
      });
      if (!approval.ok) {
        addAudit("recovery", input.scenario, "blocked", { reason: approval.reason });
        return frozen({ status: "approval_required", reason: approval.reason, snapshot: snapshot() });
      }
      addAudit("recovery", input.scenario, "local_fixture_recorded", {
        publicUserOperationSubmitted: false,
        productionAuthorityChanged: false
      });
      return snapshot();
    },
    [CHANNELS.LIST_AUDIT_EVENTS]: () => frozen({ events: snapshot().audit.history }),
    [CHANNELS.GET_SETTINGS]: () => frozen(settings),
    [CHANNELS.UPDATE_SETTINGS]: (payload) => {
      const input = mustValidate(CHANNELS.UPDATE_SETTINGS, payload);
      settings = { ...settings, ...input };
      saveSettings(preferencesPath, settings);
      addAudit("settings", "update_local_preferences", "updated", {});
      scheduleAutoLock();
      return frozen(settings);
    },
    [CHANNELS.EXPORT_SANITIZED_DIAGNOSTICS]: () => frozen({
      exportedAt: nowIso(),
      localOnly: true,
      includesSecrets: false,
      storageRoot: "app-data/philcore-local-identities",
      snapshot: snapshot()
    }),
    [CHANNELS.DIAGNOSE_STORAGE]: () => frozen(diagnoseStorage()),
    [CHANNELS.DIAGNOSE_IDENTITY]: () => frozen({
      status: selectedIdentityId ? "identity_selected" : "no_identity_selected",
      selected: identitySummary(),
      localIdentityCount: safeIndex().length,
      includesSecrets: false
    }),
    [CHANNELS.DIAGNOSE_VAULT]: () => frozen({
      status: vaultStatus().status,
      vault: vaultStatus(),
      includesSecrets: false
    }),
    [CHANNELS.DIAGNOSE_PLATFORM_AUTH]: () => frozen({
      diagnostic: "desktop_platform_auth",
      availability: platformKeyAdapter.getAvailability(),
      status: platformStatus(),
      policy: PLATFORM_UNLOCK_POLICY,
      includesSecrets: false,
      publicNetworkMutation: false
    }),
    [CHANNELS.DIAGNOSE_KEYCHAIN]: () => frozen({
      diagnostic: "desktop_keychain",
      availability: platformKeyAdapter.getAvailability(),
      selectedIdentity: identitySummary(),
      protection: platformStatus(),
      keychainValueReturned: false,
      wrappingKeyReturned: false,
      includesSecrets: false,
      publicNetworkMutation: false
    }),
    [CHANNELS.DIAGNOSE_FRESH_AUTH]: () => frozen({
      diagnostic: "desktop_fresh_auth",
      evidenceCount: freshAuthEvidence.size,
      pendingPresentations: presentations.size,
      approvalArtifacts: approvals.size,
      evidenceTtlMs: FRESH_AUTH_TTL_MS,
      includesSecrets: false,
      wrappingKeyReturned: false,
      publicNetworkMutation: false
    })
  };

  async function runLocalAuthorizationDemo(input = {}) {
    return startRealLocalAuthorizationWorkflow(input);
  }

  function diagnoseStorage() {
    let index;
    try {
      index = loadIndex();
    } catch (error) {
      return { status: "failed", reason: error.message, includesSecrets: false };
    }
    return {
      status: "ok",
      storageModel: "main_process_file_backend_encrypted_registry",
      indexVersion: index.version,
      identityCount: index.identities.length,
      rootLocation: "electron_app_data",
      filePermissionsBestEffort: true,
      includesSecrets: false
    };
  }

  function invoke(channel, payload = {}) {
    const validated = validateBridgePayload(channel, payload);
    if (!validated.ok) return frozen({ status: "failed", reason: validated.reason, snapshot: snapshot() });
    try {
      return handlers[channel](validated.value);
    } catch (error) {
      addAudit("runtime", "bridge_invoke", "failed_closed", { channel, reason: error.message });
      return frozen({ status: "failed", reason: "runtime_request_failed_closed", snapshot: snapshot() });
    }
  }

  function teardown(reason = "teardown") {
    lock(reason);
    if (lockTimer) clearTimeout(lockTimer);
  }

  async function createSepoliaMintComposedCapability(input = {}) {
    const allowedKeys = [
      "accountDeployed",
      "accountSalt",
      "bindingsInput",
      "dependencies",
      "enrollment",
      "epochs",
      "gas",
      "proofTimeoutMs",
      "replayStore",
      "repositoryRoot",
      "trustedStateFactory"
    ];
    if (!input || typeof input !== "object"
      || Object.keys(input).some((key) => !allowedKeys.includes(key))
      || typeof input.trustedStateFactory !== "function"
      || !input.replayStore) {
      throw new Error("phil_sepolia_mint_capability_input_invalid");
    }
    if (lifecycle.state !== "unlocked" || !unlockedVault || !protectedRuntimeMaterial) {
      throw new Error("phil_sepolia_mint_identity_locked");
    }
    const authorityMaterial = protectedRuntimeMaterial;
    const sessionId = lifecycle.sessionId;
    const prepared = await sepoliaMintComposedWorkflow()
      .preparePhilSepoliaMintComposedWorkflow({
        repositoryRoot: input.repositoryRoot,
        protectedMaterial: { philSecret: authorityMaterial.philSecret },
        bindingsInput: input.bindingsInput,
        epochs: input.epochs,
        enrollment: input.enrollment,
        executionOwner: authorityMaterial.validator.publicOwnerAddress,
        ownerCommitment: authorityMaterial.ownerCommitment,
        accountSalt: input.accountSalt,
        accountDeployed: input.accountDeployed,
        gas: input.gas,
        proofTimeoutMs: input.proofTimeoutMs,
        dependencies: input.dependencies
      });

    function assertAuthorityCurrent() {
      if (lifecycle.state !== "unlocked"
        || lifecycle.sessionId !== sessionId
        || protectedRuntimeMaterial !== authorityMaterial
        || unlockedVault?.identityId !== authorityMaterial.identityId) {
        throw new Error("phil_sepolia_mint_signing_authority_invalidated");
      }
    }

    async function onApproved({ request, response, context }) {
      assertAuthorityCurrent();
      const trustedState = await input.trustedStateFactory({ request, context });
      return sepoliaMintComposedWorkflow().completePhilSepoliaMintComposedWorkflow({
        repositoryRoot: input.repositoryRoot,
        context,
        request,
        response,
        enrollment: input.enrollment,
        replayStore: input.replayStore,
        trustedState,
        proofTimeoutMs: input.proofTimeoutMs,
        dependencies: input.dependencies,
        createDeviceVaultSigner: async ({ prepared: operation }) => {
          assertAuthorityCurrent();
          if (operation.executionOwner.toLowerCase()
            !== authorityMaterial.validator.publicOwnerAddress.toLowerCase()) {
            throw new Error("phil_sepolia_mint_execution_owner_mismatch");
          }
          const descriptor = Object.freeze({
            signerId: authorityMaterial.validator.recordId,
            mode: "device_vault_beta_ecdsa",
            ownerAddress: authorityMaterial.validator.publicOwnerAddress,
            keyReference: Object.freeze({
              keyReferenceId: authorityMaterial.validator.keyReferenceId,
              mode: "device_vault_beta_ecdsa",
              custody: "device_vault_encrypted",
              privateKeyExportable: false,
              derivedFromPhilSecret: false
            }),
            available: true,
            productionApproved: false,
            arbitraryMessageSigning: false,
            arbitraryTransactionSigning: false
          });
          return Object.freeze({
            describeSigner: async () => descriptor,
            checkAvailability: async () => {
              assertAuthorityCurrent();
              return descriptor;
            },
            getOwnerAddress: async () => {
              assertAuthorityCurrent();
              return authorityMaterial.validator.publicOwnerAddress;
            },
            signUserOperationHash: async (requestToSign) => {
              assertAuthorityCurrent();
              if (requestToSign.userOperationHash !== operation.userOperationHash
                || requestToSign.signingDigest !== operation.userOperationHash
                || requestToSign.smartAccountAddress.toLowerCase()
                  !== operation.smartAccount.toLowerCase()) {
                throw new Error("phil_sepolia_mint_signing_request_mismatch");
              }
              const wallet = new Wallet(authorityMaterial.validator.privateKey);
              return Object.freeze({
                status: "signed",
                signature: await wallet.signMessage(getBytes(requestToSign.userOperationHash)),
                signerDescriptor: descriptor,
                signedAt: nowIso()
              });
            },
            invalidateSigningSession: async () => undefined
          });
        }
      });
    }

    return Object.freeze({
      requestFactory: prepared.createDeviceRequest,
      onApproved,
      executionOwner: authorityMaterial.validator.publicOwnerAddress,
      ownerCommitment: authorityMaterial.ownerCommitment,
      sessionId,
      publicNetworkMutation: false
    });
  }

  return Object.freeze({
    invoke,
    snapshot,
    teardown,
    _storageRoot: storageRoot,
    _createSepoliaMintComposedCapability: createSepoliaMintComposedCapability
  });
}

function createLifecycle(state) {
  const now = nowIso();
  return {
    lifecycleId: makeId("lifecycle"),
    sessionId: makeId("session"),
    state,
    sequence: 0,
    version: 1,
    createdAt: now,
    updatedAt: now,
    metadata: { deviceVaultUnlocked: false, protectedStateAvailable: false, persisted: false },
    persisted: false,
    ownsSecrets: false,
    authenticatesUser: false,
    unlocksVault: false,
    grantsAuthority: false
  };
}

function createRegistry(identity, createdAt, validator, recovery, recoveryCreated) {
  const credentials = [
    {
      credentialId: validator.keyReferenceId,
      providerKind: "device_vault_ecdsa_local_alpha",
      algorithm: "secp256k1",
      label: "Local Alpha execution validator",
      createdAt,
      status: "active",
      deviceType: "local-dev",
      transport: { transports: ["electron-main-process"] },
      priority: 1,
      publicKeyHash: keccak256(toUtf8Bytes(validator.publicOwnerAddress))
    }
  ];
  if (recovery) {
    credentials.push({
      credentialId: recovery.authorityId,
      providerKind: "device_vault_ecdsa_recovery_local_alpha",
      algorithm: "secp256k1",
      label: "Local Alpha recovery authority",
      createdAt,
      status: "recovery-only",
      deviceType: "local-dev",
      transport: { transports: ["electron-main-process"] },
      priority: 2,
      publicKeyHash: keccak256(toUtf8Bytes(recovery.publicRecoveryAddress))
    });
  }
  return {
    format: REGISTRY_PLAINTEXT_FORMAT,
    version: "phil-device-credential-registry-v1",
    storageVersion: STORAGE_VERSION,
    philIdentity: {
      identityRoot: identity.identityRoot,
      ownerCommitment: identity.ownerCommitment
    },
    ownerCommitment: identity.ownerCommitment,
    credentials,
    recoveryPolicy: {
      state: recoveryCreated ? "normal" : "normal",
      mechanisms: recoveryCreated ? ["recovery-credential"] : [],
      requiresStrongerThanOrdinaryAuthentication: true
    },
    auditTrail: [{
      eventId: keccak256(toUtf8Bytes(stableJson({
        ownerCommitment: identity.ownerCommitment,
        eventType: "registry-created",
        occurredAt: createdAt
      }))),
      eventType: "registry-created",
      ownerCommitment: identity.ownerCommitment,
      occurredAt: createdAt,
      details: {
        encryptedAtRest: true,
        localAlpha: true,
        recoveryAuthorityCreated: recoveryCreated,
        privateMaterialReturned: false
      }
    }],
    warnings: [
      "Local Alpha passphrase unlock is not production authentication.",
      "Desktop local storage is encrypted at rest but not Secure Enclave or biometric-backed."
    ]
  };
}

function createRecoveryRecord(ownerCommitment, executionOwnerAddress, createdAt) {
  let wallet = createSafeWallet();
  while (wallet.address.toLowerCase() === executionOwnerAddress.toLowerCase()) {
    wallet = createSafeWallet();
  }
  return {
    format: "philcore-desktop-recovery-authority-v1",
    version: STORAGE_VERSION,
    authorityId: makeId("recovery_authority"),
    ownerCommitment,
    publicRecoveryAddress: wallet.address,
    custodyType: "device_vault_separate_ecdsa_key",
    purpose: "local_alpha_recovery_authority",
    lifecycleState: "active",
    rotationVersion: 1,
    chainId: 31337,
    networkProfile: "local_fixture",
    createdAt,
    updatedAt: createdAt,
    privateKey: wallet.privateKey,
    privateMaterialReturned: false,
    storedEncrypted: true,
    separateFromExecutionKey: true,
    ordinaryExecutionAuthority: false,
    publicSubmissionEnabled: false
  };
}

function assertIdentityBinding(identity, entry) {
  if (identity.format !== "philcore-desktop-private-identity-v1") throw new Error("identity_format_invalid");
  if (identity.ownerCommitment !== entry.ownerCommitment) throw new Error("identity_index_owner_mismatch");
  const expectedRoot = identityRootFromPhilSecret(identity.philSecret);
  const expectedOwner = ownerCommitmentFromIdentityRoot(expectedRoot);
  if (identity.identityRoot !== expectedRoot || identity.ownerCommitment !== expectedOwner) {
    throw new Error("identity_secret_derivation_mismatch");
  }
}

function assertRegistryBinding(registry, entry) {
  if (registry.format !== REGISTRY_PLAINTEXT_FORMAT) throw new Error("registry_format_invalid");
  if (registry.ownerCommitment !== entry.ownerCommitment) throw new Error("registry_owner_mismatch");
  if (registry.philIdentity?.ownerCommitment !== entry.ownerCommitment) throw new Error("registry_public_identity_mismatch");
}

function sanitizeValidatorRecord(record) {
  return {
    keyReferenceId: record.keyReferenceId,
    recordId: record.recordId,
    ownerCommitment: record.ownerCommitment,
    publicOwnerAddress: record.publicOwnerAddress,
    lifecycleState: record.lifecycleState,
    purpose: record.purpose,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    privateMaterialReturned: false,
    storedEncrypted: true,
    localOnly: true
  };
}

function sanitizeRecoveryRecord(record) {
  return {
    authorityId: record.authorityId,
    ownerCommitment: record.ownerCommitment,
    publicRecoveryAddress: record.publicRecoveryAddress,
    custodyType: record.custodyType,
    lifecycleState: record.lifecycleState,
    purpose: record.purpose,
    rotationVersion: record.rotationVersion,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    privateMaterialReturned: false,
    storedEncrypted: true,
    separateFromExecutionKey: true,
    ordinaryExecutionAuthority: false,
    publicSubmissionEnabled: false
  };
}

function mustValidate(channel, payload) {
  const validated = validateBridgePayload(channel, payload);
  if (!validated.ok) throw new Error(validated.reason);
  return validated.value;
}

function countBy(items, field) {
  return items.reduce((acc, item) => {
    const key = item[field] || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}

function stage(id, label, summary) {
  return {
    id,
    label,
    status: "completed",
    summary,
    publicNetworkMutation: false,
    secretsExposed: false
  };
}

function sanitizeDetails(details) {
  if (containsForbiddenKey(details)) return { redacted: true };
  return details;
}

function loadSettings(preferencesPath) {
  if (!preferencesPath || !fs.existsSync(preferencesPath)) return { ...DEFAULT_SETTINGS };
  try {
    const parsed = JSON.parse(fs.readFileSync(preferencesPath, "utf8"));
    return { ...DEFAULT_SETTINGS, ...parsed };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

function saveSettings(preferencesPath, settings) {
  if (!preferencesPath) return;
  fs.mkdirSync(path.dirname(preferencesPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(preferencesPath, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
}

module.exports = {
  createDesktopRuntimeHost,
  createElectronSafeStoragePlatformKeyAdapter,
  createFixturePlatformKeyAdapter,
  createUnsupportedPlatformKeyAdapter,
  DEFAULT_SETTINGS,
  shortRef
};
