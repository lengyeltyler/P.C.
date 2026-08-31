const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const {
  AUTHORIZATION_HEADER,
  RECOVERY_HTTPS_PORT,
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID,
  RecoveryOriginError,
  createCertificateStore,
  createRecoverySecureOrigin,
  resolveRendererAsset
} = require("../src/main/recovery-secure-origin.cjs");

function adapter(label = "default") {
  const key = crypto.createHash("sha256").update(`o41-origin-test-adapter:${label}`).digest();
  return {
    isAvailable: () => true,
    encrypt(value) {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
      const encrypted = Buffer.concat([
        cipher.update(String(value), "utf8"),
        cipher.final()
      ]);
      return Buffer.concat([
        nonce,
        cipher.getAuthTag(),
        encrypted
      ]);
    },
    decrypt(value) {
      const buffer = Buffer.from(value);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, buffer.subarray(0, 12));
      decipher.setAuthTag(buffer.subarray(12, 28));
      return Buffer.concat([
        decipher.update(buffer.subarray(28)),
        decipher.final()
      ]).toString("utf8");
    }
  };
}

function request({ authorization, host = `${RECOVERY_RP_ID}:${RECOVERY_HTTPS_PORT}`, pathname = "/" }) {
  return new Promise((resolve, reject) => {
    const call = https.request({
      host: "127.0.0.1",
      port: RECOVERY_HTTPS_PORT,
      path: pathname,
      method: "GET",
      servername: RECOVERY_RP_ID,
      rejectUnauthorized: false,
      headers: {
        host,
        [AUTHORIZATION_HEADER]: authorization
      }
    }, (response) => {
      const chunks = [];
      const certificate = response.socket.getPeerCertificate();
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
        headers: response.headers,
        certificate
      }));
    });
    call.on("error", reject);
    call.end();
  });
}

async function run() {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o41-origin-"));
  const rendererRoot = path.join(temporary, "renderer");
  const storageRoot = path.join(temporary, "storage");
  fs.mkdirSync(rendererRoot, { mode: 0o700 });
  fs.writeFileSync(path.join(rendererRoot, "index.html"), "<!doctype html><title>O41 origin fixture</title>", { mode: 0o600 });
  fs.writeFileSync(path.join(rendererRoot, "routine-ui.cjs"), "globalThis.philRoutineUiLoaded = true;", { mode: 0o600 });
  fs.writeFileSync(path.join(rendererRoot, "phil.png"), Buffer.from("89504e470d0a1a0a", "hex"), { mode: 0o600 });
  fs.writeFileSync(path.join(rendererRoot, "phil.woff2"), Buffer.from("wOF2", "ascii"), { mode: 0o600 });
  fs.writeFileSync(path.join(rendererRoot, "phil.jpg"), Buffer.from("ffd8", "hex"), { mode: 0o600 });
  fs.mkdirSync(path.join(rendererRoot, "assets", "philenator"), { recursive: true });
  fs.writeFileSync(path.join(rendererRoot, "assets", "philenator", "manifest.json"), "{}", { mode: 0o600 });
  const encryptionAdapter = adapter();

  assert.equal(RECOVERY_RP_ID, "recovery.philcore.localhost");
  assert.equal(RECOVERY_ORIGIN, "https://recovery.philcore.localhost:18443");
  assert.equal(
    resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/`),
    path.join(rendererRoot, "index.html")
  );
  assert.throws(
    () => resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/../package.json`),
    RecoveryOriginError
  );
  assert.throws(
    () => resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/index.html?secret=no`),
    RecoveryOriginError
  );
  assert.equal(
    resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/phil.png`),
    path.join(rendererRoot, "phil.png")
  );
  assert.equal(
    resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/phil.woff2`),
    path.join(rendererRoot, "phil.woff2")
  );
  assert.equal(
    resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/assets/philenator/manifest.json`),
    path.join(rendererRoot, "assets", "philenator", "manifest.json")
  );
  assert.throws(
    () => resolveRendererAsset(rendererRoot, `${RECOVERY_ORIGIN}/phil.jpg`),
    RecoveryOriginError
  );

  const store = createCertificateStore({ storageRoot, encryptionAdapter });
  const first = store.loadOrCreate();
  const second = store.loadOrCreate();
  assert.equal(first.fingerprint256, second.fingerprint256);
  assert.equal(first.privateKeyPem.includes("PRIVATE KEY"), true);
  assert.equal(fs.readFileSync(store.recordPath, "utf8").includes(first.privateKeyPem), false);
  assert.equal(store.migrationStatus(), "EXACT_IDENTITY_REUSED");
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(store.recordPath).mode & 0o777, 0o600);
  }

  const authorization = "o41-local-origin-test-authorization";
  const service = createRecoverySecureOrigin({
    storageRoot,
    rendererRoot,
    encryptionAdapter,
    authorization
  });
  const status = await service.start();
  assert.equal(status.ready, true);
  assert.equal(status.developmentOrigin, status.packagedOrigin);
  const accepted = await request({ authorization });
  assert.equal(accepted.status, 200);
  assert.match(accepted.body, /O41 origin fixture/);
  const commonJsAsset = await request({ authorization, pathname: "/routine-ui.cjs" });
  assert.equal(commonJsAsset.status, 200);
  assert.equal(commonJsAsset.headers["content-type"], "text/javascript; charset=utf-8");
  assert.match(commonJsAsset.body, /philRoutineUiLoaded/);
  const pngAsset = await request({ authorization, pathname: "/phil.png" });
  assert.equal(pngAsset.status, 200);
  assert.equal(pngAsset.headers["content-type"], "image/png");
  const fontAsset = await request({ authorization, pathname: "/phil.woff2" });
  assert.equal(fontAsset.status, 200);
  assert.equal(fontAsset.headers["content-type"], "font/woff2");
  assert.equal((await request({ authorization, pathname: "/phil.jpg" })).status, 404);
  assert.equal(
    accepted.certificate.fingerprint256.replaceAll(":", "").toLowerCase(),
    first.fingerprint256
  );
  assert.equal((await request({ authorization: "wrong-authorization" })).status, 403);
  assert.equal((await request({ authorization, host: `localhost:${RECOVERY_HTTPS_PORT}` })).status, 421);
  assert.equal((await request({ authorization, host: `${RECOVERY_RP_ID}:18444` })).status, 421);
  await service.stop();

  const blocker = net.createServer();
  await new Promise((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(RECOVERY_HTTPS_PORT, "127.0.0.1", resolve);
  });
  const impersonated = createRecoverySecureOrigin({
    storageRoot,
    rendererRoot,
    encryptionAdapter,
    authorization
  });
  await assert.rejects(
    () => impersonated.start(),
    /RECOVERY_ORIGIN_LOOPBACK_PORT_UNAVAILABLE/
  );
  await new Promise((resolve) => blocker.close(resolve));

  const record = JSON.parse(fs.readFileSync(store.recordPath, "utf8"));
  record.fingerprint256 = "00".repeat(32);
  fs.writeFileSync(store.recordPath, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  assert.throws(
    () => store.read(),
    /RECOVERY_ORIGIN_CERTIFICATE_FINGERPRINT_MISMATCH/
  );

  const migrationRoot = path.join(temporary, "migration");
  const originalIdentity = {
    bundleIdentifier: "com.philcore.desktop.legacy",
    teamIdentifier: "DEVELOPMENT_NO_TEAM",
    keychainAccessGroup: "development.philcore.desktop.webauthn"
  };
  const migratedIdentity = {
    bundleIdentifier: "com.philcore.desktop.localalpha",
    teamIdentifier: "B342738S82",
    keychainAccessGroup: "B342738S82.com.philcore.desktop.localalpha.webauthn"
  };
  const legacyStore = createCertificateStore({
    storageRoot: migrationRoot,
    encryptionAdapter,
    applicationIdentity: originalIdentity
  });
  const legacyCertificate = legacyStore.loadOrCreate();
  const migratedStore = createCertificateStore({
    storageRoot: migrationRoot,
    encryptionAdapter,
    applicationIdentity: migratedIdentity,
    credentialRecordCount: () => 0
  });
  const migratedCertificate = migratedStore.loadOrCreate();
  assert.equal(migratedCertificate.fingerprint256, legacyCertificate.fingerprint256);
  assert.equal(migratedStore.migrationStatus(), "PRE_ENROLLMENT_IDENTITY_REBOUND");
  assert.equal(migratedStore.loadOrCreate().fingerprint256, legacyCertificate.fingerprint256);
  assert.equal(migratedStore.migrationStatus(), "EXACT_IDENTITY_REUSED");

  const protectedStore = createCertificateStore({
    storageRoot: migrationRoot,
    encryptionAdapter,
    applicationIdentity: originalIdentity,
    credentialRecordCount: () => 1
  });
  assert.throws(
    () => protectedStore.loadOrCreate(),
    /RECOVERY_ORIGIN_APPLICATION_IDENTITY_MISMATCH_WITH_CREDENTIALS/
  );

  const unreadablePreEnrollmentRoot = path.join(temporary, "unreadable-pre-enrollment");
  const unreadableOriginalStore = createCertificateStore({
    storageRoot: unreadablePreEnrollmentRoot,
    encryptionAdapter: adapter("unreadable-original")
  });
  const unreadableOriginal = unreadableOriginalStore.loadOrCreate();
  const unreadableReplacementStore = createCertificateStore({
    storageRoot: unreadablePreEnrollmentRoot,
    encryptionAdapter: adapter("unreadable-replacement"),
    credentialRecordCount: () => 0
  });
  const unreadableReplacement = unreadableReplacementStore.loadOrCreate();
  assert.notEqual(unreadableReplacement.fingerprint256, unreadableOriginal.fingerprint256);
  assert.equal(
    unreadableReplacementStore.migrationStatus(),
    "PRE_ENROLLMENT_UNREADABLE_CERTIFICATE_REPLACED"
  );
  const unreadableFiles = fs.readdirSync(unreadablePreEnrollmentRoot);
  assert.equal(unreadableFiles.includes("local-origin-certificate.v1.json"), true);
  assert.equal(
    unreadableFiles.filter((name) => name.includes("unreadable-pre-enrollment")).length,
    1
  );

  const unreadableWithCredentialsRoot = path.join(temporary, "unreadable-with-credentials");
  createCertificateStore({
    storageRoot: unreadableWithCredentialsRoot,
    encryptionAdapter: adapter("protected-original")
  }).loadOrCreate();
  const unreadableWithCredentialsStore = createCertificateStore({
    storageRoot: unreadableWithCredentialsRoot,
    encryptionAdapter: adapter("protected-replacement"),
    credentialRecordCount: () => 1
  });
  assert.throws(
    () => unreadableWithCredentialsStore.loadOrCreate(),
    /RECOVERY_ORIGIN_CERTIFICATE_DECRYPTION_FAILED/
  );
  assert.deepEqual(
    fs.readdirSync(unreadableWithCredentialsRoot),
    ["local-origin-certificate.v1.json"]
  );

  fs.rmSync(temporary, { recursive: true, force: true });
  process.stdout.write("ok - O.41 canonical pinned loopback HTTPS origin\n");
}

run().catch((error) => {
  process.stderr.write(`not ok - O.41 canonical pinned loopback HTTPS origin: ${error.message}\n`);
  process.exitCode = 1;
});
