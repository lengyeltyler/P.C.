const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const RECOVERY_RP_ID = "recovery.philcore.localhost";
const RECOVERY_HTTPS_PORT = 18443;
const RECOVERY_ORIGIN = `https://${RECOVERY_RP_ID}:${RECOVERY_HTTPS_PORT}`;
const AUTHORIZATION_HEADER = "x-philcore-local-service-authorization";
const CERTIFICATE_SCHEMA_VERSION = 2;
const CERTIFICATE_ROTATION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;
const STATIC_EXTENSIONS = new Set([
  ".cjs",
  ".css",
  ".html",
  ".js",
  ".png",
  ".svg",
  ".woff2"
]);

class RecoveryOriginError extends Error {
  constructor(code) {
    super(code);
    this.name = "RecoveryOriginError";
    this.code = code;
  }

  toJSON() {
    return { name: this.name, code: this.code };
  }
}

function assertSafeRoot(root) {
  const resolved = path.resolve(root);
  if (resolved === path.parse(resolved).root) throw new RecoveryOriginError("RECOVERY_ORIGIN_UNSAFE_ROOT");
  return resolved;
}

function ensurePrivateDirectory(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_STORAGE_NOT_DIRECTORY");
  }
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
    fs.chmodSync(directory, 0o700);
  }
}

function atomicPrivateWrite(filePath, contents) {
  const directory = path.dirname(filePath);
  ensurePrivateDirectory(directory);
  if (fs.existsSync(filePath) && fs.lstatSync(filePath).isSymbolicLink()) {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_SYMLINK_REJECTED");
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

function normalizeFingerprint(value) {
  return String(value || "").replaceAll(":", "").toLowerCase();
}

function certificateFingerprint(certificatePem) {
  return normalizeFingerprint(new crypto.X509Certificate(certificatePem).fingerprint256);
}

function canonicalApplicationIdentity(input = {}) {
  const identity = {
    bundleIdentifier: String(input.bundleIdentifier || "development.philcore.desktop"),
    teamIdentifier: String(input.teamIdentifier || "DEVELOPMENT_NO_TEAM"),
    keychainAccessGroup: String(
      input.keychainAccessGroup || "development.philcore.desktop.webauthn"
    )
  };
  for (const value of Object.values(identity)) {
    if (!/^[A-Za-z0-9._-]{3,160}$/u.test(value)) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_APPLICATION_IDENTITY_INVALID");
    }
  }
  return Object.freeze(identity);
}

function identityHash(identity) {
  return crypto.createHash("sha256")
    .update(JSON.stringify(canonicalApplicationIdentity(identity)))
    .digest("hex");
}

function createCertificateStore({
  storageRoot,
  encryptionAdapter,
  applicationIdentity,
  credentialRecordCount = () => 0,
  now = () => Date.now()
}) {
  const root = assertSafeRoot(storageRoot);
  const recordPath = path.join(root, "local-origin-certificate.v1.json");
  const currentIdentity = canonicalApplicationIdentity(applicationIdentity);
  const currentIdentityHash = identityHash(currentIdentity);
  let migrationStatus = "NOT_LOADED";

  function assertAdapter() {
    if (!encryptionAdapter?.isAvailable?.()) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_PROTECTED_STORAGE_UNAVAILABLE");
    }
  }

  function decryptRecord(record) {
    if (
      ![1, CERTIFICATE_SCHEMA_VERSION].includes(record?.schemaVersion)
      || record.rpId !== RECOVERY_RP_ID
      || record.origin !== RECOVERY_ORIGIN
      || typeof record.certificatePem !== "string"
      || typeof record.encryptedPrivateKey !== "string"
    ) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_CERTIFICATE_SCHEMA_INVALID");
    }
    if (
      record.schemaVersion === CERTIFICATE_SCHEMA_VERSION
      && (
        typeof record.applicationIdentityHash !== "string"
        || identityHash(record.applicationIdentity) !== record.applicationIdentityHash
      )
    ) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_APPLICATION_IDENTITY_RECORD_INVALID");
    }
    const privateKeyPem = encryptionAdapter.decrypt(
      Buffer.from(record.encryptedPrivateKey, "base64")
    );
    const certificate = new crypto.X509Certificate(record.certificatePem);
    if (certificateFingerprint(record.certificatePem) !== normalizeFingerprint(record.fingerprint256)) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_CERTIFICATE_FINGERPRINT_MISMATCH");
    }
    return {
      certificatePem: record.certificatePem,
      privateKeyPem,
      fingerprint256: certificateFingerprint(record.certificatePem),
      validTo: certificate.validTo,
      createdAt: record.createdAt,
      storedApplicationIdentityHash: record.applicationIdentityHash || null,
      identityMatches:
        record.schemaVersion === CERTIFICATE_SCHEMA_VERSION
        && record.applicationIdentityHash === currentIdentityHash
    };
  }

  function read() {
    assertAdapter();
    if (!fs.existsSync(recordPath)) return null;
    const stat = fs.lstatSync(recordPath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_CERTIFICATE_PATH_INVALID");
    }
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
      throw new RecoveryOriginError("RECOVERY_ORIGIN_CERTIFICATE_PERMISSIONS_INVALID");
    }
    try {
      return decryptRecord(JSON.parse(fs.readFileSync(recordPath, "utf8")));
    } catch (error) {
      if (error instanceof RecoveryOriginError) throw error;
      throw new RecoveryOriginError("RECOVERY_ORIGIN_CERTIFICATE_DECRYPTION_FAILED");
    }
  }

  function writeRecord({ certificatePem, privateKeyPem, fingerprint256, createdAt }) {
    const record = {
      schemaVersion: CERTIFICATE_SCHEMA_VERSION,
      rpId: RECOVERY_RP_ID,
      origin: RECOVERY_ORIGIN,
      applicationIdentity: currentIdentity,
      applicationIdentityHash: currentIdentityHash,
      certificatePem,
      encryptedPrivateKey: encryptionAdapter.encrypt(privateKeyPem).toString("base64"),
      fingerprint256,
      createdAt
    };
    atomicPrivateWrite(recordPath, `${JSON.stringify(record, null, 2)}\n`);
    return decryptRecord(record);
  }

  function generate() {
    assertAdapter();
    ensurePrivateDirectory(root);
    const temporaryRoot = fs.mkdtempSync(path.join(root, ".certificate-"));
    if (process.platform !== "win32") fs.chmodSync(temporaryRoot, 0o700);
    const keyPath = path.join(temporaryRoot, "private-key.pem");
    const certificatePath = path.join(temporaryRoot, "certificate.pem");
    try {
      const result = spawnSync(
        "/usr/bin/openssl",
        [
          "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
          "-days", "825",
          "-keyout", keyPath,
          "-out", certificatePath,
          "-subj", `/CN=${RECOVERY_RP_ID}`,
          "-addext", `subjectAltName=DNS:${RECOVERY_RP_ID}`,
          "-addext", "keyUsage=digitalSignature,keyEncipherment",
          "-addext", "extendedKeyUsage=serverAuth"
        ],
        { encoding: "utf8", stdio: ["ignore", "ignore", "ignore"], timeout: 30_000 }
      );
      if (result.status !== 0) {
        throw new RecoveryOriginError("RECOVERY_ORIGIN_CERTIFICATE_GENERATION_FAILED");
      }
      const certificatePem = fs.readFileSync(certificatePath, "utf8");
      const privateKeyPem = fs.readFileSync(keyPath, "utf8");
      migrationStatus = "FIRST_INSTALL_CREATED";
      return writeRecord({
        certificatePem,
        privateKeyPem,
        fingerprint256: certificateFingerprint(certificatePem),
        createdAt: new Date(now()).toISOString()
      });
    } finally {
      for (const candidate of [keyPath, certificatePath]) {
        if (fs.existsSync(candidate) && !fs.lstatSync(candidate).isSymbolicLink()) {
          fs.rmSync(candidate, { force: true });
        }
      }
      if (fs.existsSync(temporaryRoot)) fs.rmdirSync(temporaryRoot);
    }
  }

  function quarantineUnreadablePreEnrollmentRecord() {
    const timestamp = new Date(now()).toISOString().replaceAll(":", "-");
    const quarantinePath = path.join(
      root,
      `local-origin-certificate.v1.unreadable-pre-enrollment-${timestamp}-${crypto.randomBytes(4).toString("hex")}.json`
    );
    fs.renameSync(recordPath, quarantinePath);
    if (process.platform !== "win32") fs.chmodSync(quarantinePath, 0o600);
    return quarantinePath;
  }

  function loadOrCreate() {
    let existing;
    try {
      existing = read();
    } catch (error) {
      if (error?.code !== "RECOVERY_ORIGIN_CERTIFICATE_DECRYPTION_FAILED") throw error;
      const count = Number(credentialRecordCount());
      if (!Number.isSafeInteger(count) || count < 0) {
        throw new RecoveryOriginError("RECOVERY_ORIGIN_CREDENTIAL_COUNT_INVALID");
      }
      if (count > 0) throw error;
      quarantineUnreadablePreEnrollmentRecord();
      const replacement = generate();
      migrationStatus = "PRE_ENROLLMENT_UNREADABLE_CERTIFICATE_REPLACED";
      return replacement;
    }
    if (existing) {
      if (!existing.identityMatches) {
        const count = Number(credentialRecordCount());
        if (!Number.isSafeInteger(count) || count < 0) {
          throw new RecoveryOriginError("RECOVERY_ORIGIN_CREDENTIAL_COUNT_INVALID");
        }
        if (count > 0) {
          throw new RecoveryOriginError(
            "RECOVERY_ORIGIN_APPLICATION_IDENTITY_MISMATCH_WITH_CREDENTIALS"
          );
        }
        const rebound = writeRecord(existing);
        migrationStatus = existing.storedApplicationIdentityHash
          ? "PRE_ENROLLMENT_IDENTITY_REBOUND"
          : "LEGACY_PRE_ENROLLMENT_IDENTITY_BOUND";
        return rebound;
      }
      const expiresAt = Date.parse(existing.validTo);
      if (Number.isFinite(expiresAt) && expiresAt - now() > CERTIFICATE_ROTATION_WINDOW_MS) {
        migrationStatus = "EXACT_IDENTITY_REUSED";
        return existing;
      }
      if (Number(credentialRecordCount()) > 0) {
        throw new RecoveryOriginError(
          "RECOVERY_ORIGIN_CERTIFICATE_ROTATION_REQUIRES_REENROLLMENT"
        );
      }
    }
    return generate();
  }

  return Object.freeze({
    recordPath,
    applicationIdentityHash: currentIdentityHash,
    read,
    loadOrCreate,
    migrationStatus: () => migrationStatus
  });
}

function resolveRendererAsset(rendererRoot, requestUrl) {
  let parsed;
  try {
    parsed = new URL(requestUrl, RECOVERY_ORIGIN);
  } catch {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_REQUEST_INVALID");
  }
  if (parsed.origin !== RECOVERY_ORIGIN || parsed.search || parsed.hash) {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_REQUEST_INVALID");
  }
  const pathname = parsed.pathname === "/" ? "/index.html" : parsed.pathname;
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_REQUEST_INVALID");
  }
  if (decoded.includes("\0") || decoded.split("/").includes("..")) {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_PATH_REJECTED");
  }
  const root = path.resolve(rendererRoot);
  const resolved = path.resolve(root, `.${decoded}`);
  const relative = path.relative(root, resolved).split(path.sep).join("/");
  const philenatorManifest = relative === "assets/philenator/manifest.json";
  if (!resolved.startsWith(`${root}${path.sep}`) || (!STATIC_EXTENSIONS.has(path.extname(resolved)) && !philenatorManifest)) {
    throw new RecoveryOriginError("RECOVERY_ORIGIN_PATH_REJECTED");
  }
  return resolved;
}

function contentType(filePath) {
  return {
    ".cjs": "text/javascript; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2"
  }[path.extname(filePath)] || "application/octet-stream";
}

function createRecoverySecureOrigin({
  storageRoot,
  rendererRoot,
  encryptionAdapter,
  applicationIdentity,
  credentialRecordCount,
  authorization = crypto.randomBytes(32).toString("base64url"),
  now
}) {
  const certificateStore = createCertificateStore({
    storageRoot,
    encryptionAdapter,
    applicationIdentity,
    credentialRecordCount,
    now
  });
  let server = null;
  let certificate = null;

  function handleRequest(request, response) {
    const fail = (status) => {
      response.writeHead(status, {
        "cache-control": "no-store",
        "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff"
      });
      response.end();
    };
    if (!["GET", "HEAD"].includes(request.method)) return fail(405);
    if (request.headers.host !== `${RECOVERY_RP_ID}:${RECOVERY_HTTPS_PORT}`) return fail(421);
    const supplied = request.headers[AUTHORIZATION_HEADER];
    if (
      typeof supplied !== "string"
      || supplied.length !== authorization.length
      || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(authorization))
    ) return fail(403);
    if (request.headers.origin && request.headers.origin !== RECOVERY_ORIGIN) return fail(403);

    let asset;
    try {
      asset = resolveRendererAsset(rendererRoot, request.url);
      const stat = fs.lstatSync(asset);
      if (!stat.isFile() || stat.isSymbolicLink()) return fail(404);
    } catch {
      return fail(404);
    }
    response.writeHead(200, {
      "cache-control": "no-store",
      "content-type": contentType(asset),
      "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      "cross-origin-opener-policy": "same-origin",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff"
    });
    if (request.method === "HEAD") return response.end();
    return fs.createReadStream(asset).pipe(response);
  }

  async function start() {
    if (server) return publicStatus();
    certificate = certificateStore.loadOrCreate();
    server = https.createServer(
      { cert: certificate.certificatePem, key: certificate.privateKeyPem },
      handleRequest
    );
    server.on("clientError", (_error, socket) => socket.destroy());
    try {
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          server.off("listening", onListening);
          reject(error);
        };
        const onListening = () => {
          server.off("error", onError);
          resolve();
        };
        server.once("error", onError);
        server.once("listening", onListening);
        server.listen({ host: "127.0.0.1", port: RECOVERY_HTTPS_PORT, exclusive: true });
      });
    } catch {
      server?.close();
      server = null;
      throw new RecoveryOriginError("RECOVERY_ORIGIN_LOOPBACK_PORT_UNAVAILABLE");
    }
    return publicStatus();
  }

  async function stop() {
    if (!server) return;
    const active = server;
    server = null;
    await new Promise((resolve) => active.close(resolve));
  }

  function publicStatus() {
    return Object.freeze({
      ready: Boolean(server),
      rpId: RECOVERY_RP_ID,
      origin: RECOVERY_ORIGIN,
      loopbackAddress: "127.0.0.1",
      port: RECOVERY_HTTPS_PORT,
      certificateFingerprint256: certificate?.fingerprint256 || null,
      certificatePersistence: "encrypted_per_install",
      certificateMigrationStatus: certificateStore.migrationStatus(),
      applicationIdentityHash: certificateStore.applicationIdentityHash,
      tlsValidation: "exact_application_pin",
      developmentOrigin: RECOVERY_ORIGIN,
      packagedOrigin: RECOVERY_ORIGIN
    });
  }

  function installElectronGuards(electronApp, electronSession) {
    electronSession.webRequest.onBeforeSendHeaders(
      { urls: [`${RECOVERY_ORIGIN}/*`] },
      (details, callback) => {
        const requestHeaders = { ...details.requestHeaders, [AUTHORIZATION_HEADER]: authorization };
        callback({ cancel: false, requestHeaders });
      }
    );
    electronApp.on("certificate-error", (event, _contents, url, _error, cert, callback) => {
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        callback(false);
        return;
      }
      let presented = "";
      try {
        presented = cert?.data
          ? certificateFingerprint(cert.data)
          : normalizeFingerprint(cert?.fingerprint256 || cert?.fingerprint);
      } catch {
        presented = "";
      }
      const expected = normalizeFingerprint(certificate?.fingerprint256);
      if (
        parsed.origin === RECOVERY_ORIGIN
        && presented
        && expected
        && presented === expected
      ) {
        event.preventDefault();
        callback(true);
        return;
      }
      callback(false);
    });
  }

  return Object.freeze({
    rpId: RECOVERY_RP_ID,
    origin: RECOVERY_ORIGIN,
    start,
    stop,
    publicStatus,
    installElectronGuards
  });
}

module.exports = {
  RECOVERY_RP_ID,
  RECOVERY_HTTPS_PORT,
  RECOVERY_ORIGIN,
  AUTHORIZATION_HEADER,
  CERTIFICATE_SCHEMA_VERSION,
  RecoveryOriginError,
  canonicalApplicationIdentity,
  createCertificateStore,
  createRecoverySecureOrigin,
  identityHash,
  resolveRendererAsset,
  normalizeFingerprint
};
