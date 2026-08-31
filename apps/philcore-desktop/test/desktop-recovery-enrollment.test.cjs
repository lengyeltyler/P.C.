const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  CONSUMER_PLATFORM_POLICY_V1,
  EXTERNAL_HARDWARE_POLICY_V1,
  classifyRegistrationPolicy
} = require("../src/main/recovery-attestation-policy.cjs");
const {
  DISPOSABLE_DIAGNOSTIC_TTL_MS,
  DISPOSABLE_TEST_LABEL,
  RecoveryEnrollmentError,
  SecretValue,
  STATES,
  createEncryptedRecoveryCredentialStore,
  createRecoveryEnrollmentHost,
  createSecondaryPairingResponse,
  inspectOfflineCode,
  redactForLog
} = require("../src/main/recovery-enrollment-host.cjs");
const {
  RECOVERY_ORIGIN,
  RECOVERY_RP_ID
} = require("../src/main/recovery-secure-origin.cjs");
const {
  evaluateDesktopIPhoneReadiness
} = require("../src/main/native-iphone-pairing-host.cjs");

function encryptionAdapter(available = true) {
  const key = crypto.createHash("sha256").update("o41-enrollment-test-adapter").digest();
  return {
    isAvailable: () => available,
    encrypt(value) {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
      const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
      return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
    },
    decrypt(value) {
      const buffer = Buffer.from(value);
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, buffer.subarray(0, 12));
      decipher.setAuthTag(buffer.subarray(12, 28));
      return Buffer.concat([decipher.update(buffer.subarray(28)), decipher.final()]).toString("utf8");
    }
  };
}

function cborUnsigned(value) {
  if (value < 24) return Buffer.from([value]);
  if (value < 256) return Buffer.from([0x18, value]);
  if (value < 65536) return Buffer.from([0x19, value >> 8, value & 0xff]);
  throw new Error("test CBOR integer too large");
}
function cborInt(value) {
  const encoded = cborUnsigned(value >= 0 ? value : -1 - value);
  if (value < 0) encoded[0] |= 0x20;
  return encoded;
}
function cborBytes(value) {
  const bytes = Buffer.from(value);
  const length = cborUnsigned(bytes.length);
  length[0] |= 0x40;
  return Buffer.concat([length, bytes]);
}
function cborText(value) {
  const bytes = Buffer.from(value, "utf8");
  const length = cborUnsigned(bytes.length);
  length[0] |= 0x60;
  return Buffer.concat([length, bytes]);
}
function cborMap(entries) {
  const length = cborUnsigned(entries.length);
  length[0] |= 0xa0;
  return Buffer.concat([length, ...entries.flatMap(([key, value]) => [cborAny(key), cborAny(value)])]);
}
function cborAny(value) {
  if (typeof value === "number") return cborInt(value);
  if (typeof value === "string") return cborText(value);
  if (Buffer.isBuffer(value)) return cborBytes(value);
  if (Array.isArray(value)) return cborMap(value);
  throw new Error("unsupported test CBOR value");
}
function base64url(value) {
  return Buffer.from(value).toString("base64url");
}
function p256Coordinates(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  return { x: Buffer.from(jwk.x, "base64url"), y: Buffer.from(jwk.y, "base64url") };
}
function registration({
  challenge,
  origin = RECOVERY_ORIGIN,
  rpId = RECOVERY_RP_ID,
  credentialByte = 17,
  flags = 0x45,
  fmt = "none",
  coseAlgorithm = -7,
  publicKeyAlgorithm = -7
} = {}) {
  const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const coordinates = p256Coordinates(keyPair.publicKey);
  const credentialId = Buffer.alloc(32, credentialByte);
  const cose = cborMap([[1, 2], [3, coseAlgorithm], [-1, 1], [-2, coordinates.x], [-3, coordinates.y]]);
  const header = Buffer.alloc(37);
  crypto.createHash("sha256").update(rpId).digest().copy(header);
  header[32] = flags;
  const credentialLength = Buffer.alloc(2);
  credentialLength.writeUInt16BE(credentialId.length);
  const authData = Buffer.concat([header, Buffer.alloc(16), credentialLength, credentialId, cose]);
  const attestation = cborMap([["fmt", fmt], ["authData", authData], ["attStmt", []]]);
  const spki = keyPair.publicKey.export({ type: "spki", format: "der" });
  return {
    id: `synthetic-o41-${credentialByte}`,
    rawId: base64url(credentialId),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      attestationObject: base64url(attestation),
      clientDataJSON: base64url(Buffer.from(JSON.stringify({
        type: "webauthn.create",
        challenge,
        origin
      }))),
      publicKey: base64url(spki),
      publicKeyAlgorithm,
      transports: ["internal"]
    },
    clientExtensionResults: {},
    keyPair
  };
}

function assertion({
  privateKey,
  challenge,
  origin = RECOVERY_ORIGIN,
  rpId = RECOVERY_RP_ID,
  credentialId,
  flags = 0x05,
  signCount = 1,
  invalidSignature = false
}) {
  const authenticatorData = Buffer.alloc(37);
  crypto.createHash("sha256").update(rpId).digest().copy(authenticatorData);
  authenticatorData[32] = flags;
  authenticatorData.writeUInt32BE(signCount >>> 0, 33);
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  const signedBytes = Buffer.concat([
    authenticatorData,
    crypto.createHash("sha256").update(clientDataJSON).digest()
  ]);
  const signer = crypto.createSign("SHA256");
  signer.update(signedBytes);
  signer.end();
  const signature = Buffer.from(signer.sign(privateKey));
  if (invalidSignature) signature[signature.length - 1] ^= 0x01;
  return {
    id: "synthetic-o41-assertion",
    rawId: credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: base64url(authenticatorData),
      clientDataJSON: base64url(clientDataJSON),
      signature: base64url(signature),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

function consumerRecord(role, rawCredentialId, custodyDomainCommitment) {
  return {
    role,
    rawCredentialId,
    publicKey: { spki: `synthetic-public-${role}`, algorithm: -7 },
    descriptorMetadata: { authenticatorClass: role === 0 ? "PRIMARY_PLATFORM_DEVICE" : "SECONDARY_PLATFORM_DEVICE" },
    generation: 1,
    custodyDomainCommitment,
    registrationPolicy: {
      requestedProfile: "STANDARD",
      attestationConveyance: "none",
      algorithm: "ES256",
      userVerified: true,
      attestedCredentialDataPresent: true,
      backupEligible: false,
      backupState: false
    }
  };
}

function decodeRequest(encoded) {
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
}

async function run() {
  require("../src/main/runtime-host.cjs");
  const loadedModules = Object.keys(require.cache).join("\n");
  for (const packageName of [
    "@nomicfoundation/hardhat-ethers",
    "adm-zip",
    "brace-expansion",
    "hardhat/internal",
    "immutable",
    "serialize-javascript",
    "node_modules/tmp/",
    "node_modules/undici/"
  ]) {
    assert.equal(
      loadedModules.includes(packageName),
      false,
      `${packageName} must not load on the desktop recovery startup path`
    );
  }
  assert.equal(CONSUMER_PLATFORM_POLICY_V1.attestation, "none");
  assert.equal(CONSUMER_PLATFORM_POLICY_V1.manufacturerProvenanceClaimed, false);
  assert.equal(EXTERNAL_HARDWARE_POLICY_V1.readiness, "BLOCKED");
  assert.equal(EXTERNAL_HARDWARE_POLICY_V1.trustRootBundleVersion, null);
  assert.equal(classifyRegistrationPolicy({
    requestedProfile: "ENHANCED_HARDWARE",
    allowConsumerPlatformFallback: true
  }).fallbackClassification, "CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION");
  assert.equal(classifyRegistrationPolicy({
    requestedProfile: "STANDARD",
    attestationConveyance: "direct",
    algorithm: "ES256",
    userVerified: true,
    attestedCredentialDataPresent: true,
    backupEligible: false,
    backupState: false
  }).accepted, false);

  const unavailableRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o41-unavailable-"));
  const unavailable = createEncryptedRecoveryCredentialStore({
    storageRoot: unavailableRoot,
    encryptionAdapter: encryptionAdapter(false)
  });
  assert.throws(() => unavailable.list(), /RECOVERY_SAFE_STORAGE_UNAVAILABLE/);
  fs.rmSync(unavailableRoot, { recursive: true, force: true });

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o41-enrollment-"));
  const store = createEncryptedRecoveryCredentialStore({
    storageRoot: path.join(root, "credentials"),
    encryptionAdapter: encryptionAdapter()
  });
  const primaryCustody = `0x${"11".repeat(32)}`;
  let displayedSecret = null;
  const ceremonyStartup = {
    result: "SUPPORTED_AND_CONFIGURED",
    electronVersion: "41.10.3",
    packaged: true,
    bundleIdentifier: "com.philcore.desktop.localalpha",
    teamIdentifier: "B342738S82",
    keychainAccessGroup: "B342738S82.com.philcore.desktop.localalpha.webauthn",
    chromiumFlagsUsed: false,
    configuredBeforeReady: false,
    configuredAfterReady: true
  };
  const host = createRecoveryEnrollmentHost({
    credentialStore: store,
    originStatus: () => ({ ready: true, origin: RECOVERY_ORIGIN, rpId: RECOVERY_RP_ID }),
    secureDisplay(secret) {
      assert.equal(JSON.stringify(secret), "\"[REDACTED_SECRET]\"");
      displayedSecret = secret.consume((value) => value);
      secret.clear();
    },
    platformWebAuthnStartup: ceremonyStartup,
    desktopCapabilityEvidenceProvider: () => ({
      certificatePersistence: true,
      safeStoragePersistence: true,
      packagedBuild: true,
      iphoneCompanionConnectivity: true,
      iphoneRole1CredentialPolicy: true,
      noProductionSecretContamination: true
    })
  });

  assert.throws(() => host.beginCredential(), /ENROLLMENT_STATE_TRANSITION_REJECTED/);
  const blockedPreflight = host.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true,
    packagedEnvironmentReady: true,
    dependencyAdvisoryGateReady: true
  });
  assert.equal(blockedPreflight.state, STATES.PREFLIGHT_BLOCKED);
  const ceremonyDisposableBegin = host.beginDisposableDiagnostic();
  const ceremonyDisposableReg = registration({
    challenge: ceremonyDisposableBegin.challenge,
    credentialByte: 16
  });
  const ceremonyDisposableVerifiedReg = await host.verifyDisposableRegistration(ceremonyDisposableReg);
  await host.verifyDisposableAssertion(assertion({
    privateKey: ceremonyDisposableReg.keyPair.privateKey,
    challenge: ceremonyDisposableVerifiedReg.assertionChallenge,
    credentialId: ceremonyDisposableReg.rawId,
    signCount: 1
  }));
  const preflight = host.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true,
    packagedEnvironmentReady: true,
    dependencyAdvisoryGateReady: true
  });
  assert.equal(preflight.standard, "READY_WITH_WARNINGS");
  assert.equal(preflight.enhanced, "BLOCKED");
  assert.equal(preflight.state, STATES.PRIMARY_PENDING);

  const primaryOptions = host.beginCredential();
  const wrongOrigin = registration({ challenge: primaryOptions.challenge, origin: "https://evil.example", credentialByte: 18 });
  await assert.rejects(
    () => host.storeCredential({
      role: 0,
      registration: wrongOrigin,
      descriptorMetadata: {},
      generation: 1,
      custodyDomainCommitment: primaryCustody
    }),
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );
  const primary = await host.storeCredential({
    role: 0,
    registration: registration({ challenge: primaryOptions.challenge, credentialByte: 19 }),
    descriptorMetadata: { authenticatorClass: "PRIMARY_PLATFORM_DEVICE" },
    generation: 1,
    custodyDomainCommitment: primaryCustody
  });
  assert.equal(primary.role, 0);
  assert.equal(Object.hasOwn(primary, "rawCredentialId"), false);
  assert.equal(store.list()[0].reference, primary.reference);
  const storedText = fs.readFileSync(path.join(store.root, `${primary.reference}.v1.json`), "utf8");
  assert.equal(storedText.includes(registration({ challenge: "unused", credentialByte: 19 }).rawId), false);
  assert.throws(
    () => store.write(consumerRecord(1, Buffer.alloc(32, 19).toString("base64url"), `0x${"22".repeat(32)}`)),
    /DUPLICATE_RECOVERY_CREDENTIAL/
  );

  const pairing = host.beginPairing();
  const request = decodeRequest(pairing.encodedRequest);
  const secondaryCustody = `0x${"22".repeat(32)}`;
  const secondaryRegistration = registration({ challenge: request.challenge, credentialByte: 20 });
  const response = createSecondaryPairingResponse({
    encodedRequest: pairing.encodedRequest,
    credential: {
      challenge: request.challenge,
      registration: secondaryRegistration,
      descriptorMetadata: { authenticatorClass: "SECONDARY_PLATFORM_DEVICE" },
      generation: 1,
      custodyDomainCommitment: secondaryCustody
    }
  });
  assert.equal(response.includes(secondaryRegistration.rawId), false);
  const secondary = await host.completePairing(response, secondaryCustody);
  assert.equal(secondary.role, 1);
  await assert.rejects(
    () => host.completePairing(response, secondaryCustody),
    /ENROLLMENT_STATE_TRANSITION_REJECTED/
  );

  const generated = host.generateOffline();
  assert.equal(generated.formatVersion, "PHIL39-V1");
  assert.equal(Object.hasOwn(generated, "recoveryCode"), false);
  assert.deepEqual(host.revealOffline(), { revealedInProtectedView: true, secretReturned: false });
  assert.match(displayedSecret, /^PHIL39-V1-/u);
  assert.deepEqual(inspectOfflineCode(displayedSecret), {
    signer: generated.signer,
    publicVerificationMaterialHash: generated.safePublicFingerprint
  });
  host.confirmOfflineExport();
  const restored = host.restoreOffline(displayedSecret);
  assert.equal(restored.matched, true);
  assert.equal(restored.secretRetained, false);
  assert.equal(JSON.stringify(host.status()).includes(displayedSecret), false);
  assert.equal(store.readOfflinePublicMetadata().secretRetained, false);
  const reviewed = host.reviewIndependence({
    acknowledged: true,
    primaryAndSecondaryIndependent: true
  });
  assert.equal(reviewed.state, STATES.READY_FOR_COMMITMENT_APPROVAL);
  assert.equal(host.complete().state, STATES.COMPLETE);

  const encryptedPath = path.join(store.root, `${primary.reference}.v1.json`);
  const encryptedRecord = JSON.parse(fs.readFileSync(encryptedPath, "utf8"));
  encryptedRecord.ciphertext = `${encryptedRecord.ciphertext.slice(0, -2)}AA`;
  fs.writeFileSync(encryptedPath, `${JSON.stringify(encryptedRecord)}\n`, { mode: 0o600 });
  assert.throws(() => store.read(primary.reference), /CREDENTIAL_CIPHERTEXT_CORRUPTED/);

  const boundaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o41-storage-boundary-"));
  const boundaryAdapter = encryptionAdapter();
  const boundaryStore = createEncryptedRecoveryCredentialStore({
    storageRoot: path.join(boundaryRoot, "a"),
    encryptionAdapter: boundaryAdapter
  });
  const boundaryRecord = boundaryStore.write(
    consumerRecord(0, Buffer.alloc(32, 81).toString("base64url"), primaryCustody)
  );
  const boundaryPath = path.join(boundaryStore.root, `${boundaryRecord.reference}.v1.json`);
  if (process.platform !== "win32") {
    fs.chmodSync(boundaryPath, 0o644);
    assert.throws(() => boundaryStore.read(boundaryRecord.reference), /CREDENTIAL_RECORD_PERMISSIONS_INVALID/);
    fs.chmodSync(boundaryPath, 0o600);
  }
  const movedStore = createEncryptedRecoveryCredentialStore({
    storageRoot: path.join(boundaryRoot, "b"),
    encryptionAdapter: boundaryAdapter
  });
  const movedPath = path.join(movedStore.root, `${boundaryRecord.reference}.v1.json`);
  fs.copyFileSync(boundaryPath, movedPath);
  fs.chmodSync(movedPath, 0o600);
  assert.throws(() => movedStore.read(boundaryRecord.reference), /CREDENTIAL_RECORD_BINDING_INVALID/);
  const symlinkReference = `recovery_credential_${"ab".repeat(16)}`;
  const symlinkPath = path.join(boundaryStore.root, `${symlinkReference}.v1.json`);
  fs.symlinkSync(boundaryPath, symlinkPath);
  assert.throws(() => boundaryStore.read(symlinkReference), /CREDENTIAL_RECORD_PATH_INVALID/);
  fs.rmSync(symlinkPath);
  const rotated = boundaryStore.rotate(boundaryRecord.reference, {
    ...consumerRecord(0, Buffer.alloc(32, 82).toString("base64url"), primaryCustody)
  });
  assert.equal(rotated.rotatedFrom, boundaryRecord.reference);
  assert.equal(fs.existsSync(boundaryPath), false);
  assert.equal(boundaryStore.remove(rotated.reference), true);
  assert.equal(boundaryStore.remove(rotated.reference), false);
  fs.rmSync(boundaryRoot, { recursive: true, force: true });

  const expiryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o41-pairing-expiry-"));
  const expiryStore = createEncryptedRecoveryCredentialStore({
    storageRoot: expiryRoot,
    encryptionAdapter: encryptionAdapter()
  });
  expiryStore.write(consumerRecord(0, Buffer.alloc(32, 91).toString("base64url"), primaryCustody));
  let clock = 10_000;
  const expiryHost = createRecoveryEnrollmentHost({
    credentialStore: expiryStore,
    originStatus: () => ({ ready: true, origin: RECOVERY_ORIGIN, rpId: RECOVERY_RP_ID }),
    secureDisplay() {},
    now: () => clock
  });
  expiryHost.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true
  });
  const expiringPairing = expiryHost.beginPairing();
  const expiringRequest = decodeRequest(expiringPairing.encodedRequest);
  assert.throws(
    () => createSecondaryPairingResponse({
      encodedRequest: expiringPairing.encodedRequest,
      credential: { challenge: "substituted" },
      now: clock
    }),
    /PAIRING_CHALLENGE_MISMATCH/
  );
  const expiringResponse = createSecondaryPairingResponse({
    encodedRequest: expiringPairing.encodedRequest,
    credential: {
      challenge: expiringRequest.challenge,
      registration: registration({ challenge: expiringRequest.challenge, credentialByte: 92 }),
      descriptorMetadata: {},
      generation: 1,
      custodyDomainCommitment: secondaryCustody
    },
    now: clock
  });
  clock = expiringRequest.expiresAt + 1;
  await assert.rejects(
    () => expiryHost.completePairing(expiringResponse, secondaryCustody),
    /PAIRING_REQUEST_EXPIRED/
  );
  assert.equal(expiryHost.cancel().state, STATES.CANCELLED);
  fs.rmSync(expiryRoot, { recursive: true, force: true });

  const secretCanary = "O41-CANARY-RECOVERY-CODE-DO-NOT-LOG";
  const wrapped = new SecretValue(secretCanary);
  assert.equal(String(wrapped), "[REDACTED_SECRET]");
  assert.equal(JSON.stringify(wrapped).includes(secretCanary), false);
  assert.equal(JSON.stringify(redactForLog({
    credentialId: secretCanary,
    recoveryCode: secretCanary,
    pairingSecret: secretCanary,
    privateScalar: secretCanary
  })).includes(secretCanary), false);
  const safeCrashContext = new RecoveryEnrollmentError(secretCanary).toJSON();
  assert.deepEqual(safeCrashContext, {
    name: "RecoveryEnrollmentError",
    code: "RECOVERY_ENROLLMENT_INTERNAL_ERROR"
  });
  let capturedStdout = "";
  let capturedStderr = "";
  const stdoutWrite = process.stdout.write;
  const stderrWrite = process.stderr.write;
  process.stdout.write = (value) => { capturedStdout += String(value); return true; };
  process.stderr.write = (value) => { capturedStderr += String(value); return true; };
  try {
    process.stdout.write(JSON.stringify(redactForLog({ recoveryCode: secretCanary })));
    process.stderr.write(JSON.stringify(safeCrashContext));
  } finally {
    process.stdout.write = stdoutWrite;
    process.stderr.write = stderrWrite;
  }
  assert.equal(capturedStdout.includes(secretCanary), false);
  assert.equal(capturedStderr.includes(secretCanary), false);
  wrapped.clear();

  const ui = [
    fs.readFileSync(path.resolve(__dirname, "../src/renderer/recovery-secret.html"), "utf8"),
    fs.readFileSync(path.resolve(__dirname, "../src/renderer/recovery-secret.js"), "utf8")
  ].join("\n");
  assert.match(ui, /Use system print dialog/);
  assert.match(ui, /Clipboard copying is intentionally unavailable/);
  assert.match(ui, /activeSecret = ""/);
  assert.doesNotMatch(ui, /navigator\.clipboard/);
  assert.doesNotMatch(ui, /localStorage|sessionStorage/);

  function preflightWithStartup(platformWebAuthnStartup) {
    const startupStore = createEncryptedRecoveryCredentialStore({
      storageRoot: path.join(root, `startup-${crypto.randomBytes(4).toString("hex")}`),
      encryptionAdapter: encryptionAdapter()
    });
    const startupHost = createRecoveryEnrollmentHost({
      credentialStore: startupStore,
      originStatus: () => ({ ready: true, origin: RECOVERY_ORIGIN, rpId: RECOVERY_RP_ID }),
      secureDisplay() {},
      platformWebAuthnStartup,
      desktopCapabilityEvidenceProvider: () => ({
        certificatePersistence: true,
        safeStoragePersistence: true,
        packagedBuild: true,
        iphoneCompanionConnectivity: true,
        iphoneRole1CredentialPolicy: true,
        noProductionSecretContamination: true
      })
    });
    return startupHost.preflight({
      profile: "STANDARD",
      webAuthnApiAvailable: true,
      platformAuthenticatorAvailable: true,
      packagedEnvironmentReady: true,
      dependencyAdvisoryGateReady: true
    });
  }

  const configuredBase = {
    result: "SUPPORTED_AND_CONFIGURED",
    electronVersion: "41.10.3",
    packaged: true,
    bundleIdentifier: "com.philcore.desktop.localalpha",
    teamIdentifier: "B342738S82",
    keychainAccessGroup: "B342738S82.com.philcore.desktop.localalpha.webauthn",
    chromiumFlagsUsed: false
  };
  const accepted = preflightWithStartup({
    ...configuredBase,
    configuredBeforeReady: false,
    configuredAfterReady: true
  });
  assert.equal(accepted.preflightV3.checks.startupWebAuthnConfiguration, true);
  assert.equal(
    accepted.preflightV3.completeStandardCeremony.blockers.includes("startupWebAuthnConfiguration"),
    false
  );
  assert.equal(accepted.platformWebAuthnStartup.configuredAfterReady, true);
  assert.equal(accepted.platformWebAuthnStartup.configuredBeforeReady, false);

  const missingAfterReady = preflightWithStartup({
    ...configuredBase,
    configuredBeforeReady: true
  });
  assert.equal(
    missingAfterReady.preflightV3.completeStandardCeremony.blockers.includes(
      "startupWebAuthnConfiguration"
    ),
    true
  );

  const falseAfterReady = preflightWithStartup({
    ...configuredBase,
    configuredBeforeReady: false,
    configuredAfterReady: false
  });
  assert.equal(
    falseAfterReady.preflightV3.completeStandardCeremony.blockers.includes(
      "startupWebAuthnConfiguration"
    ),
    true
  );

  const beforeReadyOnly = preflightWithStartup({
    ...configuredBase,
    configuredBeforeReady: true,
    configuredAfterReady: false
  });
  assert.equal(
    beforeReadyOnly.preflightV3.completeStandardCeremony.blockers.includes(
      "startupWebAuthnConfiguration"
    ),
    true
  );

  function createDisposableHost(overrides = {}) {
    const disposableStore = createEncryptedRecoveryCredentialStore({
      storageRoot: path.join(root, `disposable-${crypto.randomBytes(4).toString("hex")}`),
      encryptionAdapter: encryptionAdapter()
    });
    let clock = 1_700_000_000_000;
    const host = createRecoveryEnrollmentHost({
      credentialStore: disposableStore,
      originStatus: () => ({ ready: true, origin: RECOVERY_ORIGIN, rpId: RECOVERY_RP_ID }),
      secureDisplay() {},
      platformWebAuthnStartup: {
        ...configuredBase,
        configuredBeforeReady: false,
        configuredAfterReady: true
      },
      desktopCapabilityEvidenceProvider: () => ({
        certificatePersistence: true,
        safeStoragePersistence: true,
        packagedBuild: true,
        iphoneCompanionConnectivity: true,
        iphoneRole1CredentialPolicy: true,
        noProductionSecretContamination: true
      }),
      now: () => clock,
      ...overrides
    });
    return {
      host,
      store: disposableStore,
      advance(ms) {
        clock += ms;
      },
      setClock(value) {
        clock = value;
      }
    };
  }

  function runStandardPreflight(host) {
    return host.preflight({
      profile: "STANDARD",
      webAuthnApiAvailable: true,
      platformAuthenticatorAvailable: true,
      packagedEnvironmentReady: true,
      dependencyAdvisoryGateReady: true
    });
  }

  async function completeDisposableDiagnostic(fixture, credentialByte = 41) {
    if (
      fixture.host.status().state === STATES.NOT_STARTED
      || fixture.host.status().state === STATES.PREFLIGHT_BLOCKED
    ) {
      runStandardPreflight(fixture.host);
    }
    const begin = fixture.host.beginDisposableDiagnostic();
    assert.equal(typeof begin.challenge, "string");
    assert.equal(begin.challenge.length >= 43, true);
    assert.equal(begin.testLabel, DISPOSABLE_TEST_LABEL);
    const reg = registration({
      challenge: begin.challenge,
      credentialByte
    });
    const verifiedReg = await fixture.host.verifyDisposableRegistration(reg);
    assert.equal(verifiedReg.verified, true);
    assert.equal(typeof verifiedReg.assertionChallenge, "string");
    assert.notEqual(verifiedReg.assertionChallenge, begin.challenge);
    assert.equal(verifiedReg.rawCredentialIdReturned, false);
    assert.equal(Object.hasOwn(verifiedReg, "rawId"), false);
    const verifiedAssertion = await fixture.host.verifyDisposableAssertion(assertion({
      privateKey: reg.keyPair.privateKey,
      challenge: verifiedReg.assertionChallenge,
      credentialId: reg.rawId,
      signCount: 1
    }));
    assert.equal(verifiedAssertion.verified, true);
    assert.equal(verifiedAssertion.disposableCreationAssertion, true);
    assert.equal(verifiedAssertion.productionAuthorityCreated, false);
    assert.equal(verifiedAssertion.rawCredentialIdReturned, false);
    return { begin, reg, verifiedReg, verifiedAssertion };
  }

  const disposableFixture = createDisposableHost();
  const blockedBeforeDiagnostic = disposableFixture.host.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true,
    packagedEnvironmentReady: true,
    dependencyAdvisoryGateReady: true
  });
  assert.equal(blockedBeforeDiagnostic.state, STATES.PREFLIGHT_BLOCKED);
  assert.equal(
    blockedBeforeDiagnostic.preflightV3.completeStandardCeremony.blockers.includes(
      "disposableCreationAssertion"
    ),
    true
  );

  await assert.rejects(
    () => disposableFixture.host.verifyDisposableRegistration({ policyAccepted: true }),
    /DISPOSABLE_POLICY_ACCEPTED_HAS_NO_AUTHORITY|DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
  );

  const beginOptions = disposableFixture.host.beginDisposableDiagnostic();
  assert.equal(beginOptions.rp.id, RECOVERY_RP_ID);
  assert.equal(beginOptions.authenticatorAttachment, "platform");
  assert.equal(beginOptions.attestation, "none");
  assert.deepEqual([...beginOptions.algorithms], [-7]);

  await assert.rejects(
    () => disposableFixture.host.verifyDisposableRegistration({ policyAccepted: true }),
    /DISPOSABLE_POLICY_ACCEPTED_HAS_NO_AUTHORITY/
  );

  const staleChallenge = registration({
    challenge: crypto.randomBytes(32).toString("base64url"),
    credentialByte: 50
  });
  await assert.rejects(
    () => disposableFixture.host.verifyDisposableRegistration(staleChallenge),
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );
  await assert.rejects(
    () => disposableFixture.host.verifyDisposableRegistration(registration({
      challenge: beginOptions.challenge,
      credentialByte: 50
    })),
    /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
  );

  async function rejectDisposableRegistration(mutate, credentialByte, pattern) {
    const begin = disposableFixture.host.beginDisposableDiagnostic();
    await assert.rejects(
      () => disposableFixture.host.verifyDisposableRegistration(registration({
        challenge: begin.challenge,
        credentialByte,
        ...mutate
      })),
      pattern
    );
    await assert.rejects(
      () => disposableFixture.host.verifyDisposableRegistration(registration({
        challenge: begin.challenge,
        credentialByte: credentialByte + 100
      })),
      /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
    );
  }

  await rejectDisposableRegistration(
    { origin: "https://evil.example" },
    51,
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );
  await rejectDisposableRegistration(
    { rpId: "evil.philcore.localhost" },
    52,
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );
  await rejectDisposableRegistration(
    { flags: 0x40 },
    53,
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED|WEBAUTHN_REGISTRATION_POLICY_REJECTED/
  );
  await rejectDisposableRegistration(
    { flags: 0x41 },
    54,
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED|WEBAUTHN_REGISTRATION_POLICY_REJECTED/
  );
  await rejectDisposableRegistration(
    { flags: 0x4d },
    55,
    /WEBAUTHN_REGISTRATION_POLICY_REJECTED/
  );
  await rejectDisposableRegistration(
    { coseAlgorithm: -8, publicKeyAlgorithm: -8 },
    56,
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );

  async function rejectDisposableAssertion(mutate, credentialByte, pattern) {
    const begin = disposableFixture.host.beginDisposableDiagnostic();
    const reg = registration({
      challenge: begin.challenge,
      credentialByte
    });
    const verifiedReg = await disposableFixture.host.verifyDisposableRegistration(reg);
    await assert.rejects(
      () => disposableFixture.host.verifyDisposableAssertion(assertion({
        privateKey: reg.keyPair.privateKey,
        challenge: verifiedReg.assertionChallenge,
        credentialId: reg.rawId,
        ...mutate
      })),
      pattern
    );
    await assert.rejects(
      () => disposableFixture.host.verifyDisposableAssertion(assertion({
        privateKey: reg.keyPair.privateKey,
        challenge: verifiedReg.assertionChallenge,
        credentialId: reg.rawId,
        signCount: 1
      })),
      /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
    );
  }

  await rejectDisposableAssertion(
    { challenge: crypto.randomBytes(32).toString("base64url") },
    57,
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED/
  );
  await rejectDisposableAssertion(
    { credentialId: base64url(Buffer.alloc(32, 99)) },
    58,
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED/
  );
  await rejectDisposableAssertion(
    { invalidSignature: true },
    59,
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED/
  );
  await rejectDisposableAssertion(
    { flags: 0x01 },
    65,
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED|WEBAUTHN_ASSERTION_POLICY_REJECTED/
  );
  await rejectDisposableAssertion(
    { flags: 0x1d },
    66,
    /WEBAUTHN_ASSERTION_POLICY_REJECTED/
  );
  await rejectDisposableAssertion(
    { origin: "https://evil.example" },
    67,
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED/
  );
  await rejectDisposableAssertion(
    { rpId: "evil.philcore.localhost" },
    68,
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED/
  );

  const successBegin = disposableFixture.host.beginDisposableDiagnostic();
  const successReg = registration({
    challenge: successBegin.challenge,
    credentialByte: 69
  });
  const successVerifiedReg = await disposableFixture.host.verifyDisposableRegistration(successReg);
  assert.notEqual(successVerifiedReg.assertionChallenge, successBegin.challenge);
  const successAssertion = await disposableFixture.host.verifyDisposableAssertion(assertion({
    privateKey: successReg.keyPair.privateKey,
    challenge: successVerifiedReg.assertionChallenge,
    credentialId: successReg.rawId,
    signCount: 1
  }));
  assert.equal(successAssertion.disposableCreationAssertion, true);
  await assert.rejects(
    () => disposableFixture.host.verifyDisposableAssertion(assertion({
      privateKey: successReg.keyPair.privateKey,
      challenge: successVerifiedReg.assertionChallenge,
      credentialId: successReg.rawId,
      signCount: 2
    })),
    /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING|DISPOSABLE_DIAGNOSTIC_REPLAY_REJECTED/
  );
  assert.equal(disposableFixture.store.list().length, 0);

  const afterDiagnostic = disposableFixture.host.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true,
    packagedEnvironmentReady: true,
    dependencyAdvisoryGateReady: true
  });
  assert.equal(afterDiagnostic.state, STATES.PRIMARY_PENDING);
  assert.equal(afterDiagnostic.preflightV3.checks.disposableCreationAssertion, true);
  assert.equal(
    afterDiagnostic.preflightV3.completeStandardCeremony.blockers.includes(
      "disposableCreationAssertion"
    ),
    false
  );

  const expiryFixture = createDisposableHost();
  expiryFixture.host.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true
  });
  const expiryBegin = expiryFixture.host.beginDisposableDiagnostic();
  expiryFixture.advance(DISPOSABLE_DIAGNOSTIC_TTL_MS + 1);
  await assert.rejects(
    () => expiryFixture.host.verifyDisposableRegistration(registration({
      challenge: expiryBegin.challenge,
      credentialByte: 60
    })),
    /DISPOSABLE_DIAGNOSTIC_EXPIRED/
  );

  const replaceFixture = createDisposableHost();
  replaceFixture.host.preflight({
    profile: "STANDARD",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true
  });
  const replaced = replaceFixture.host.beginDisposableDiagnostic();
  const replacement = replaceFixture.host.beginDisposableDiagnostic();
  assert.notEqual(replaced.challenge, replacement.challenge);
  await assert.rejects(
    () => replaceFixture.host.verifyDisposableRegistration(registration({
      challenge: replaced.challenge,
      credentialByte: 61
    })),
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );

  const verifiedTtlFixture = createDisposableHost();
  await completeDisposableDiagnostic(verifiedTtlFixture, 62);
  verifiedTtlFixture.advance(DISPOSABLE_DIAGNOSTIC_TTL_MS + 1);
  const expiredVerified = runStandardPreflight(verifiedTtlFixture.host);
  assert.equal(expiredVerified.preflightV3.checks.disposableCreationAssertion, false);
  assert.equal(expiredVerified.state, STATES.PREFLIGHT_BLOCKED);

  const invalidateFixture = createDisposableHost();
  await completeDisposableDiagnostic(invalidateFixture, 63);
  const pendingAfterDiagnostic = runStandardPreflight(invalidateFixture.host);
  assert.equal(pendingAfterDiagnostic.state, STATES.PRIMARY_PENDING);
  assert.equal(pendingAfterDiagnostic.preflightV3.checks.disposableCreationAssertion, true);
  const beginAfterDisposable = invalidateFixture.host.beginCredential();
  assert.equal(typeof beginAfterDisposable.challenge, "string");
  assert.equal(invalidateFixture.store.list().length, 0);

  const freshHost = createDisposableHost();
  const freshPreflight = runStandardPreflight(freshHost.host);
  assert.equal(freshPreflight.preflightV3.checks.disposableCreationAssertion, false);
  assert.equal(freshHost.host.status().state, STATES.PREFLIGHT_BLOCKED);

  const providerFailClosed = createDisposableHost({
    desktopCapabilityEvidenceProvider: () => {
      throw new Error("provider_boom");
    }
  });
  const providerBlocked = runStandardPreflight(providerFailClosed.host);
  assert.equal(providerBlocked.state, STATES.PREFLIGHT_BLOCKED);
  assert.equal(providerBlocked.preflightV3.checks.certificatePersistence, false);
  assert.equal(providerBlocked.preflightV3.checks.iphoneCompanionConnectivity, false);
  assert.equal(providerBlocked.preflightV3.checks.disposableCreationAssertion, false);

  const cancelInvalidates = createDisposableHost();
  await completeDisposableDiagnostic(cancelInvalidates, 64);
  cancelInvalidates.host.cancel();
  const afterCancelHost = createDisposableHost();
  assert.equal(
    runStandardPreflight(afterCancelHost.host).preflightV3.checks.disposableCreationAssertion,
    false
  );

  // --- Defect 1: expired / consumed disposable proof must block beginCredential ---
  const expiredBeginFixture = createDisposableHost();
  await completeDisposableDiagnostic(expiredBeginFixture, 70);
  const pendingBeforeExpiry = runStandardPreflight(expiredBeginFixture.host);
  assert.equal(pendingBeforeExpiry.state, STATES.PRIMARY_PENDING);
  assert.equal(pendingBeforeExpiry.preflightV3.checks.disposableCreationAssertion, true);
  expiredBeginFixture.advance(DISPOSABLE_DIAGNOSTIC_TTL_MS);
  assert.throws(
    () => expiredBeginFixture.host.beginCredential(),
    (error) => {
      assert.equal(error instanceof RecoveryEnrollmentError, true);
      assert.equal(error.code, "DISPOSABLE_DIAGNOSTIC_REQUIRED_OR_EXPIRED");
      return true;
    }
  );
  assert.equal(expiredBeginFixture.host.status().state, STATES.PREFLIGHT_BLOCKED);
  assert.throws(
    () => expiredBeginFixture.host.beginCredential(),
    /ENROLLMENT_STATE_TRANSITION_REJECTED|DISPOSABLE_DIAGNOSTIC_REQUIRED_OR_EXPIRED/
  );

  const exactSessionExpiry = createDisposableHost();
  runStandardPreflight(exactSessionExpiry.host);
  const exactSessionBegin = exactSessionExpiry.host.beginDisposableDiagnostic();
  exactSessionExpiry.advance(DISPOSABLE_DIAGNOSTIC_TTL_MS);
  await assert.rejects(
    () => exactSessionExpiry.host.verifyDisposableRegistration(registration({
      challenge: exactSessionBegin.challenge,
      credentialByte: 76
    })),
    /DISPOSABLE_DIAGNOSTIC_EXPIRED/
  );

  const consumeProofFixture = createDisposableHost();
  await completeDisposableDiagnostic(consumeProofFixture, 71);
  runStandardPreflight(consumeProofFixture.host);
  const consumedBegin = consumeProofFixture.host.beginCredential();
  assert.equal(typeof consumedBegin.challenge, "string");
  assert.equal(consumedBegin.challenge.length >= 43, true);
  assert.throws(
    () => consumeProofFixture.host.beginCredential(),
    (error) => {
      assert.equal(error.code, "DISPOSABLE_DIAGNOSTIC_REQUIRED_OR_EXPIRED");
      return true;
    }
  );
  assert.equal(consumeProofFixture.host.status().state, STATES.PREFLIGHT_BLOCKED);

  // --- Defect 2: replacement must invalidate prior proof and Role 0 challenge ---
  const replaceProofFixture = createDisposableHost();
  await completeDisposableDiagnostic(replaceProofFixture, 72);
  const readyBeforeReplace = runStandardPreflight(replaceProofFixture.host);
  assert.equal(readyBeforeReplace.state, STATES.PRIMARY_PENDING);
  assert.equal(readyBeforeReplace.preflightV3.checks.disposableCreationAssertion, true);
  replaceProofFixture.host.beginDisposableDiagnostic();
  assert.equal(replaceProofFixture.host.status().state, STATES.PREFLIGHT_BLOCKED);
  const afterImmediateReplace = runStandardPreflight(replaceProofFixture.host);
  assert.equal(afterImmediateReplace.preflightV3.checks.disposableCreationAssertion, false);
  assert.equal(afterImmediateReplace.state, STATES.PREFLIGHT_BLOCKED);

  const failReplaceFixture = createDisposableHost();
  await completeDisposableDiagnostic(failReplaceFixture, 73);
  runStandardPreflight(failReplaceFixture.host);
  failReplaceFixture.host.beginDisposableDiagnostic();
  await assert.rejects(
    () => failReplaceFixture.host.verifyDisposableRegistration(registration({
      challenge: crypto.randomBytes(32).toString("base64url"),
      credentialByte: 77
    })),
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );
  const afterFailedReplace = runStandardPreflight(failReplaceFixture.host);
  assert.equal(afterFailedReplace.preflightV3.checks.disposableCreationAssertion, false);
  assert.equal(afterFailedReplace.state, STATES.PREFLIGHT_BLOCKED);
  assert.throws(
    () => failReplaceFixture.host.beginCredential(),
    /ENROLLMENT_STATE_TRANSITION_REJECTED|DISPOSABLE_DIAGNOSTIC_REQUIRED_OR_EXPIRED/
  );

  const clearRole0Fixture = createDisposableHost();
  await completeDisposableDiagnostic(clearRole0Fixture, 74);
  runStandardPreflight(clearRole0Fixture.host);
  const outstandingRole0 = clearRole0Fixture.host.beginCredential();
  assert.equal(typeof outstandingRole0.challenge, "string");
  assert.equal(clearRole0Fixture.host.status().state, STATES.PRIMARY_PENDING);
  clearRole0Fixture.host.beginDisposableDiagnostic();
  assert.equal(clearRole0Fixture.host.status().state, STATES.PREFLIGHT_BLOCKED);
  await assert.rejects(
    () => clearRole0Fixture.host.storeCredential({
      role: 0,
      registration: registration({
        challenge: outstandingRole0.challenge,
        credentialByte: 78
      }),
      descriptorMetadata: { authenticatorClass: "PRIMARY_PLATFORM_DEVICE" },
      generation: 1,
      custodyDomainCommitment: `0x${"ab".repeat(32)}`
    }),
    /ENROLLMENT_STATE_TRANSITION_REJECTED|WEBAUTHN_REGISTRATION_CHALLENGE_MISSING/
  );

  await completeDisposableDiagnostic(clearRole0Fixture, 79);
  const afterReplacementComplete = runStandardPreflight(clearRole0Fixture.host);
  assert.equal(afterReplacementComplete.state, STATES.PRIMARY_PENDING);
  assert.equal(afterReplacementComplete.preflightV3.checks.disposableCreationAssertion, true);

  // --- Defect 3: explicit cancelDisposableDiagnostic + crypto failure invalidation ---
  const cancelActive = createDisposableHost();
  runStandardPreflight(cancelActive.host);
  cancelActive.host.beginDisposableDiagnostic();
  const cancelledActive = cancelActive.host.cancelDisposableDiagnostic();
  assert.equal(cancelledActive.state, STATES.PREFLIGHT_BLOCKED);
  assert.equal(cancelActive.host.status().state, STATES.PREFLIGHT_BLOCKED);
  await assert.rejects(
    () => cancelActive.host.verifyDisposableRegistration(registration({
      challenge: crypto.randomBytes(32).toString("base64url"),
      credentialByte: 80
    })),
    /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
  );

  const cancelAfterProof = createDisposableHost();
  await completeDisposableDiagnostic(cancelAfterProof, 81);
  const readyBeforeCancel = runStandardPreflight(cancelAfterProof.host);
  assert.equal(readyBeforeCancel.preflightV3.checks.disposableCreationAssertion, true);
  cancelAfterProof.host.cancelDisposableDiagnostic();
  const afterCancelProof = runStandardPreflight(cancelAfterProof.host);
  assert.equal(afterCancelProof.preflightV3.checks.disposableCreationAssertion, false);
  assert.equal(afterCancelProof.state, STATES.PREFLIGHT_BLOCKED);

  const cancelIdempotent = createDisposableHost();
  runStandardPreflight(cancelIdempotent.host);
  // No disposable authority: cancel is a no-op and must leave PREFLIGHT_BLOCKED.
  assert.equal(
    cancelIdempotent.host.cancelDisposableDiagnostic().state,
    STATES.PREFLIGHT_BLOCKED
  );
  assert.equal(
    cancelIdempotent.host.cancelDisposableDiagnostic().state,
    STATES.PREFLIGHT_BLOCKED
  );

  const cancelAfterBeginCredential = createDisposableHost();
  await completeDisposableDiagnostic(cancelAfterBeginCredential, 85);
  runStandardPreflight(cancelAfterBeginCredential.host);
  const role0AfterProof = cancelAfterBeginCredential.host.beginCredential();
  assert.equal(typeof role0AfterProof.challenge, "string");
  assert.equal(cancelAfterBeginCredential.host.status().state, STATES.PRIMARY_PENDING);
  const afterCancelBegin = cancelAfterBeginCredential.host.cancelDisposableDiagnostic();
  assert.equal(afterCancelBegin.state, STATES.PRIMARY_PENDING);
  assert.equal(cancelAfterBeginCredential.host.status().state, STATES.PRIMARY_PENDING);
  const storedAfterCancelNoop = await cancelAfterBeginCredential.host.storeCredential({
    role: 0,
    registration: registration({
      challenge: role0AfterProof.challenge,
      credentialByte: 86
    }),
    descriptorMetadata: { authenticatorClass: "PRIMARY_PLATFORM_DEVICE" },
    generation: 1,
    custodyDomainCommitment: `0x${"cd".repeat(32)}`
  });
  assert.equal(storedAfterCancelNoop.role, 0);

  const regFailInvalidate = createDisposableHost();
  runStandardPreflight(regFailInvalidate.host);
  const badRegBegin = regFailInvalidate.host.beginDisposableDiagnostic();
  await assert.rejects(
    () => regFailInvalidate.host.verifyDisposableRegistration(registration({
      challenge: crypto.randomBytes(32).toString("base64url"),
      credentialByte: 82
    })),
    /WEBAUTHN_REGISTRATION_VERIFICATION_FAILED/
  );
  await assert.rejects(
    () => regFailInvalidate.host.verifyDisposableRegistration(registration({
      challenge: badRegBegin.challenge,
      credentialByte: 83
    })),
    /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
  );

  const assertionFailInvalidate = createDisposableHost();
  runStandardPreflight(assertionFailInvalidate.host);
  const assertBegin = assertionFailInvalidate.host.beginDisposableDiagnostic();
  const assertReg = registration({
    challenge: assertBegin.challenge,
    credentialByte: 84
  });
  const assertVerifiedReg = await assertionFailInvalidate.host.verifyDisposableRegistration(assertReg);
  await assert.rejects(
    () => assertionFailInvalidate.host.verifyDisposableAssertion(assertion({
      privateKey: assertReg.keyPair.privateKey,
      challenge: assertVerifiedReg.assertionChallenge,
      credentialId: assertReg.rawId,
      invalidSignature: true
    })),
    /WEBAUTHN_ASSERTION_VERIFICATION_FAILED/
  );
  await assert.rejects(
    () => assertionFailInvalidate.host.verifyDisposableAssertion(assertion({
      privateKey: assertReg.keyPair.privateKey,
      challenge: assertVerifiedReg.assertionChallenge,
      credentialId: assertReg.rawId,
      signCount: 1
    })),
    /DISPOSABLE_DIAGNOSTIC_SESSION_MISSING/
  );

  const enhancedBlocked = createDisposableHost().host.preflight({
    profile: "ENHANCED",
    webAuthnApiAvailable: true,
    platformAuthenticatorAvailable: true
  });
  assert.equal(enhancedBlocked.enhanced, "BLOCKED");
  assert.equal(enhancedBlocked.blockers.includes("directAttestationTrustRoots"), true);

  // --- Defect 5: async disposable-session TOCTOU isolation ---
  async function waitUntil(predicate, label) {
    for (let attempt = 0; attempt < 200; attempt += 1) {
      if (predicate()) return;
      await new Promise((resolve) => setImmediate(resolve));
    }
    throw new Error(`timed out waiting for ${label}`);
  }

  {
    let releaseGate;
    const gateOpen = new Promise((resolve) => { releaseGate = resolve; });
    let gateEntered = false;
    const race = createDisposableHost({
      disposableAwaitGate: async () => {
        gateEntered = true;
        await gateOpen;
      }
    });
    runStandardPreflight(race.host);
    const beginA = race.host.beginDisposableDiagnostic();
    const validRegA = registration({
      challenge: beginA.challenge,
      credentialByte: 90
    });
    const pending = race.host.verifyDisposableRegistration(validRegA);
    await waitUntil(() => gateEntered, "registration await gate");
    const beginB = race.host.beginDisposableDiagnostic();
    releaseGate();
    await assert.rejects(() => pending, /DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED/);
    const regB = registration({
      challenge: beginB.challenge,
      credentialByte: 91
    });
    const verifiedB = await race.host.verifyDisposableRegistration(regB);
    await race.host.verifyDisposableAssertion(assertion({
      privateKey: regB.keyPair.privateKey,
      challenge: verifiedB.assertionChallenge,
      credentialId: regB.rawId,
      signCount: 1
    }));
    assert.equal(
      runStandardPreflight(race.host).preflightV3.checks.disposableCreationAssertion,
      true
    );
  }

  {
    let releaseGate;
    const gateOpen = new Promise((resolve) => { releaseGate = resolve; });
    let gateCalls = 0;
    let assertionGateEntered = false;
    const race = createDisposableHost({
      disposableAwaitGate: async () => {
        gateCalls += 1;
        // Registration verification also hits the gate; only block assertion.
        if (gateCalls < 2) return;
        assertionGateEntered = true;
        await gateOpen;
      }
    });
    runStandardPreflight(race.host);
    const beginA = race.host.beginDisposableDiagnostic();
    const regA = registration({
      challenge: beginA.challenge,
      credentialByte: 92
    });
    const verifiedA = await race.host.verifyDisposableRegistration(regA);
    const pending = race.host.verifyDisposableAssertion(assertion({
      privateKey: regA.keyPair.privateKey,
      challenge: verifiedA.assertionChallenge,
      credentialId: regA.rawId,
      signCount: 1
    }));
    await waitUntil(() => assertionGateEntered, "assertion await gate");
    race.host.beginDisposableDiagnostic();
    releaseGate();
    await assert.rejects(() => pending, /DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED/);
    assert.equal(
      runStandardPreflight(race.host).preflightV3.checks.disposableCreationAssertion,
      false
    );
  }

  {
    let releaseGate;
    const gateOpen = new Promise((resolve) => { releaseGate = resolve; });
    let gateEntered = false;
    const race = createDisposableHost({
      disposableAwaitGate: async () => {
        gateEntered = true;
        await gateOpen;
      }
    });
    runStandardPreflight(race.host);
    const beginA = race.host.beginDisposableDiagnostic();
    const validRegA = registration({
      challenge: beginA.challenge,
      credentialByte: 93
    });
    const pending = race.host.verifyDisposableRegistration(validRegA);
    await waitUntil(() => gateEntered, "registration cancel gate");
    race.host.cancelDisposableDiagnostic();
    releaseGate();
    await assert.rejects(() => pending, /DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED/);
  }

  {
    let releaseFirst;
    const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
    let firstEntered = false;
    let secondEntered = false;
    const race = createDisposableHost({
      disposableAwaitGate: async () => {
        if (!firstEntered) {
          firstEntered = true;
          await firstGate;
          return;
        }
        secondEntered = true;
      }
    });
    runStandardPreflight(race.host);
    const begin = race.host.beginDisposableDiagnostic();
    const validReg = registration({
      challenge: begin.challenge,
      credentialByte: 94
    });
    const first = race.host.verifyDisposableRegistration(validReg);
    await waitUntil(() => firstEntered, "first concurrent registration");
    await assert.rejects(
      () => race.host.verifyDisposableRegistration(registration({
        challenge: begin.challenge,
        credentialByte: 95
      })),
      /DISPOSABLE_DIAGNOSTIC_REPLAY_REJECTED/
    );
    assert.equal(secondEntered, false);
    releaseFirst();
    await first;
  }

  {
    let releaseFirst;
    const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
    let gateCalls = 0;
    let assertionGateEntered = false;
    const race = createDisposableHost({
      disposableAwaitGate: async () => {
        gateCalls += 1;
        // Skip registration gate; block only the first assertion verification.
        if (gateCalls < 2) return;
        if (!assertionGateEntered) {
          assertionGateEntered = true;
          await firstGate;
        }
      }
    });
    runStandardPreflight(race.host);
    const begin = race.host.beginDisposableDiagnostic();
    const reg = registration({
      challenge: begin.challenge,
      credentialByte: 96
    });
    const verifiedReg = await race.host.verifyDisposableRegistration(reg);
    const first = race.host.verifyDisposableAssertion(assertion({
      privateKey: reg.keyPair.privateKey,
      challenge: verifiedReg.assertionChallenge,
      credentialId: reg.rawId,
      signCount: 1
    }));
    await waitUntil(() => assertionGateEntered, "first concurrent assertion");
    await assert.rejects(
      () => race.host.verifyDisposableAssertion(assertion({
        privateKey: reg.keyPair.privateKey,
        challenge: verifiedReg.assertionChallenge,
        credentialId: reg.rawId,
        signCount: 1
      })),
      /DISPOSABLE_DIAGNOSTIC_REPLAY_REJECTED/
    );
    releaseFirst();
    await first;
  }

  {
    let releaseGate;
    const gateOpen = new Promise((resolve) => { releaseGate = resolve; });
    let gateEntered = false;
    const race = createDisposableHost({
      disposableAwaitGate: async () => {
        gateEntered = true;
        await gateOpen;
      }
    });
    runStandardPreflight(race.host);
    const beginA = race.host.beginDisposableDiagnostic();
    const pending = race.host.verifyDisposableRegistration(registration({
      challenge: crypto.randomBytes(32).toString("base64url"),
      credentialByte: 97
    }));
    await waitUntil(() => gateEntered, "failed registration replace gate");
    const beginB = race.host.beginDisposableDiagnostic();
    releaseGate();
    await assert.rejects(() => pending, /DISPOSABLE_DIAGNOSTIC_SESSION_REPLACED/);
    const regB = registration({
      challenge: beginB.challenge,
      credentialByte: 98
    });
    const verifiedB = await race.host.verifyDisposableRegistration(regB);
    assert.equal(typeof verifiedB.assertionChallenge, "string");
  }

  // --- Defect 6: static preflightV3Evidence cannot spoof disposable proof ---
  {
    const spoofStore = createEncryptedRecoveryCredentialStore({
      storageRoot: path.join(root, `spoof-${crypto.randomBytes(4).toString("hex")}`),
      encryptionAdapter: encryptionAdapter()
    });
    const spoofHost = createRecoveryEnrollmentHost({
      credentialStore: spoofStore,
      originStatus: () => ({ ready: true, origin: RECOVERY_ORIGIN, rpId: RECOVERY_RP_ID }),
      secureDisplay() {},
      platformWebAuthnStartup: {
        ...configuredBase,
        configuredBeforeReady: false,
        configuredAfterReady: true
      },
      preflightV3Evidence: {
        certificatePersistence: true,
        safeStoragePersistence: true,
        disposableCreationAssertion: true,
        packagedBuild: true,
        iphoneCompanionConnectivity: true,
        iphoneRole1CredentialPolicy: true,
        noProductionSecretContamination: true
      }
    });
    const spoofed = spoofHost.preflight({
      profile: "STANDARD",
      webAuthnApiAvailable: true,
      platformAuthenticatorAvailable: true,
      packagedEnvironmentReady: true,
      dependencyAdvisoryGateReady: true
    });
    assert.equal(spoofed.preflightV3.checks.disposableCreationAssertion, false);
    assert.equal(
      spoofed.preflightV3.completeStandardCeremony.blockers.includes("disposableCreationAssertion"),
      true
    );
    assert.equal(spoofed.state, STATES.PREFLIGHT_BLOCKED);
    assert.throws(
      () => spoofHost.beginCredential(),
      /ENROLLMENT_STATE_TRANSITION_REJECTED|DISPOSABLE_DIAGNOSTIC_REQUIRED_OR_EXPIRED/
    );
  }

  {
    const dynamicPath = createDisposableHost();
    await completeDisposableDiagnostic(dynamicPath, 99);
    const ready = runStandardPreflight(dynamicPath.host);
    assert.equal(ready.preflightV3.checks.disposableCreationAssertion, true);
    assert.equal(ready.preflightV3.checks.certificatePersistence, true);
    assert.equal(ready.state, STATES.PRIMARY_PENDING);
  }

  // --- Defect 4: host-owned policy readiness (no external allowSimulator) ---
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness(null),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({ status: () => ({ port: null }) }),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => ({
        port: 18444,
        interface: { address: "8.8.8.8" },
        publicNetworkExposure: false
      })
    }),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => ({
        port: 18444,
        interface: { address: "192.168.1.20" },
        publicNetworkExposure: true
      })
    }),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  // Transport-only fixture without production policy metadata must fail closed.
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => ({
        port: 18444,
        interface: { address: "192.168.1.20" },
        publicNetworkExposure: false
      })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );

  const appSource = fs.readFileSync(
    path.resolve(__dirname, "../src/renderer/app.js"),
    "utf8"
  );
  assert.match(appSource, /desktop pairing transport\/policy ready/u);
  assert.match(appSource, /Main-verified disposable/u);
  assert.match(appSource, /policyAccepted alone has no authority/u);
  assert.match(
    appSource,
    /catch\s*\([^)]*\)\s*\{[\s\S]*?cancelDisposableDiagnostic[\s\S]*?\}/u
  );
  assert.doesNotMatch(
    appSource,
    /physical iPhone (verified|ready|readiness)/iu
  );
  assert.doesNotMatch(
    appSource,
    /disposable\.policyAccepted/u
  );

  fs.rmSync(root, { recursive: true, force: true });
  process.stdout.write("ok - O.41 encrypted recovery enrollment, pairing, offline drill, and state machine\n");
}

run().catch((error) => {
  process.stderr.write(`not ok - O.41 encrypted recovery enrollment: ${error.message}\n`);
  process.exitCode = 1;
});
