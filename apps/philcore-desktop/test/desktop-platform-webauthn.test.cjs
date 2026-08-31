const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {
  CAPABILITY_RESULTS,
  PHILCORE_DESKTOP_BUNDLE_ID,
  PHILCORE_MACOS_TEAM_ID,
  PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
  configurePlatformWebAuthn
} = require("../src/main/platform-webauthn.cjs");
const {
  evaluateRecoveryPreflightV3
} = require("../src/main/recovery-preflight-v3.cjs");

function appFixture({ ready = false, api = true, packaged = true, throws = false } = {}) {
  const calls = [];
  return {
    app: {
      isPackaged: packaged,
      isReady: () => ready,
      configureWebAuthn: api
        ? (options) => {
            calls.push(options);
            if (throws) throw new Error("fixture rejection");
          }
        : undefined
    },
    calls
  };
}

async function run() {
  const identity = {
    bundleIdentifier: PHILCORE_DESKTOP_BUNDLE_ID,
    teamIdentifier: PHILCORE_MACOS_TEAM_ID
  };

  const preReady = appFixture({ ready: false });
  const preReadyResult = configurePlatformWebAuthn({
    electronApp: preReady.app,
    platform: "darwin",
    electronVersion: "41.10.3",
    packagedIdentity: identity
  });
  assert.equal(preReadyResult.result, CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED);
  assert.equal(preReadyResult.errorCode, "PLATFORM_WEBAUTHN_CONFIGURATION_TOO_EARLY");
  assert.equal(preReadyResult.configuredBeforeReady, true);
  assert.equal(preReadyResult.configuredAfterReady, false);
  assert.equal(preReady.calls.length, 0);

  const postReady = appFixture({ ready: true });
  const result = configurePlatformWebAuthn({
    electronApp: postReady.app,
    platform: "darwin",
    electronVersion: "41.10.3",
    packagedIdentity: identity
  });
  assert.equal(result.result, CAPABILITY_RESULTS.SUPPORTED_AND_CONFIGURED);
  assert.equal(result.configuredBeforeReady, false);
  assert.equal(result.configuredAfterReady, true);
  assert.equal(result.chromiumFlagsUsed, false);
  assert.equal(postReady.calls.length, 1);
  assert.deepEqual(postReady.calls[0], {
    touchID: {
      keychainAccessGroup: PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
      promptReason: "create or use a device-bound PhilCore recovery credential for $1"
    }
  });

  assert.equal(configurePlatformWebAuthn({
    electronApp: appFixture({ api: false }).app,
    platform: "darwin",
    packagedIdentity: identity
  }).result, CAPABILITY_RESULTS.UNSUPPORTED_RUNTIME);
  assert.equal(configurePlatformWebAuthn({
    electronApp: appFixture().app,
    platform: "linux",
    packagedIdentity: identity
  }).result, CAPABILITY_RESULTS.UNSUPPORTED_PLATFORM);

  const mismatchBundle = appFixture({ ready: true });
  assert.equal(configurePlatformWebAuthn({
    electronApp: mismatchBundle.app,
    platform: "darwin",
    packagedIdentity: { ...identity, bundleIdentifier: "com.example.wrong" }
  }).result, CAPABILITY_RESULTS.PACKAGED_IDENTITY_MISMATCH);
  assert.equal(mismatchBundle.calls.length, 0);

  const mismatchTeam = appFixture({ ready: true });
  assert.equal(configurePlatformWebAuthn({
    electronApp: mismatchTeam.app,
    platform: "darwin",
    packagedIdentity: { ...identity, teamIdentifier: "WRONGTEAM1" }
  }).result, CAPABILITY_RESULTS.PACKAGED_IDENTITY_MISMATCH);
  assert.equal(mismatchTeam.calls.length, 0);

  const nativeThrow = appFixture({ ready: true, throws: true });
  assert.equal(configurePlatformWebAuthn({
    electronApp: nativeThrow.app,
    platform: "darwin",
    packagedIdentity: identity
  }).result, CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED);
  assert.equal(nativeThrow.calls.length, 1);

  const missingReadyCalls = [];
  const missingReadyResult = configurePlatformWebAuthn({
    electronApp: {
      isPackaged: true,
      configureWebAuthn(options) {
        missingReadyCalls.push(options);
      }
    },
    platform: "darwin",
    packagedIdentity: identity
  });
  assert.equal(missingReadyResult.result, CAPABILITY_RESULTS.UNSUPPORTED_RUNTIME);
  assert.equal(missingReadyResult.errorCode, "PLATFORM_WEBAUTHN_READY_CHECK_UNSUPPORTED");
  assert.equal(missingReadyResult.configuredBeforeReady, false);
  assert.equal(missingReadyResult.configuredAfterReady, false);
  assert.equal(missingReadyCalls.length, 0);

  for (const isReady of [false, true, "ready", 1, null, undefined, {}]) {
    const calls = [];
    const malformed = configurePlatformWebAuthn({
      electronApp: {
        isPackaged: true,
        isReady,
        configureWebAuthn(options) {
          calls.push(options);
        }
      },
      platform: "darwin",
      packagedIdentity: identity
    });
    assert.equal(malformed.result, CAPABILITY_RESULTS.UNSUPPORTED_RUNTIME);
    assert.equal(malformed.errorCode, "PLATFORM_WEBAUTHN_READY_CHECK_UNSUPPORTED");
    assert.equal(malformed.configuredBeforeReady, false);
    assert.equal(malformed.configuredAfterReady, false);
    assert.equal(calls.length, 0);
  }

  const throwingReadyCalls = [];
  const throwingReadyResult = configurePlatformWebAuthn({
    electronApp: {
      isPackaged: true,
      isReady() {
        throw new Error("fixture isReady rejection");
      },
      configureWebAuthn(options) {
        throwingReadyCalls.push(options);
      }
    },
    platform: "darwin",
    packagedIdentity: identity
  });
  assert.equal(throwingReadyResult.result, CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED);
  assert.equal(throwingReadyResult.errorCode, "PLATFORM_WEBAUTHN_READY_CHECK_REJECTED");
  assert.equal(throwingReadyResult.configuredBeforeReady, false);
  assert.equal(throwingReadyResult.configuredAfterReady, false);
  assert.equal(throwingReadyCalls.length, 0);

  for (const readyReturn of [false, undefined, null, 0, "true"]) {
    const fixture = appFixture();
    fixture.app.isReady = () => readyReturn;
    const early = configurePlatformWebAuthn({
      electronApp: fixture.app,
      platform: "darwin",
      packagedIdentity: identity
    });
    assert.equal(early.result, CAPABILITY_RESULTS.SUPPORTED_CONFIGURATION_FAILED);
    assert.equal(early.errorCode, "PLATFORM_WEBAUTHN_CONFIGURATION_TOO_EARLY");
    assert.equal(early.configuredBeforeReady, true);
    assert.equal(early.configuredAfterReady, false);
    assert.equal(fixture.calls.length, 0);
  }

  const primaryReadyCompanionBlocked = evaluateRecoveryPreflightV3({
    electronRuntimeCapability: true,
    startupWebAuthnConfiguration: true,
    bundleIdentity: true,
    keychainAccessGroup: true,
    secureOrigin: true,
    certificatePersistence: true,
    safeStoragePersistence: true,
    platformAuthenticator: true,
    disposableCreationAssertion: true,
    packagedBuild: true,
    iphoneCompanionConnectivity: false,
    iphoneRole1CredentialPolicy: false,
    loggingCrashExclusion: true,
    noStaleCeremonyState: true,
    noProductionSecretContamination: true
  });
  assert.equal(primaryReadyCompanionBlocked.primaryMacRole0.status, "READY");
  assert.equal(primaryReadyCompanionBlocked.iphoneRole1.status, "BLOCKED");
  assert.equal(primaryReadyCompanionBlocked.completeStandardCeremony.status, "BLOCKED");
  assert.deepEqual(
    primaryReadyCompanionBlocked.completeStandardCeremony.blockers,
    ["iphoneCompanionConnectivity", "iphoneRole1CredentialPolicy"]
  );

  const root = path.resolve(__dirname, "../../..");
  const signedEntitlements = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/build/entitlements.mac.plist"),
    "utf8"
  );
  const adHocEntitlements = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/build/entitlements.mac-adhoc.plist"),
    "utf8"
  );
  const signedPackaging = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/scripts/package-signed.cjs"),
    "utf8"
  );
  assert.match(signedEntitlements, /keychain-access-groups/u);
  assert.match(signedEntitlements, /B342738S82\.com\.philcore\.desktop\.localalpha\.webauthn/u);
  assert.doesNotMatch(adHocEntitlements, /keychain-access-groups/u);
  assert.match(signedPackaging, /PHILCORE_DESKTOP_PROVISIONING_PROFILE/u);
  assert.match(signedPackaging, /embedded\.provisionprofile/u);
  require("../src/renderer/disposable-platform-webauthn.js");
  const disposable = globalThis.PhilCoreDisposablePlatformWebAuthn;
  const authenticatorData = Buffer.alloc(37);
  authenticatorData[32] = 0x05;
  assert.deepEqual(disposable.flags(authenticatorData), {
    userPresent: true,
    userVerified: true,
    backupEligible: false,
    backupState: false
  });
  authenticatorData[32] = 0x1d;
  assert.deepEqual(disposable.flags(authenticatorData), {
    userPresent: true,
    userVerified: true,
    backupEligible: true,
    backupState: true
  });
  assert.equal(
    disposable.TEST_LABEL,
    "O42_1_DISPOSABLE_PLATFORM_WEBAUTHN_TEST_ONLY"
  );
  assert.equal(disposable.CANONICAL_RP_ID, "recovery.philcore.localhost");
  assert.equal(
    disposable.CANONICAL_ORIGIN,
    "https://recovery.philcore.localhost:18443"
  );

  const disposableSource = fs.readFileSync(
    path.join(
      root,
      "apps/philcore-desktop/src/renderer/disposable-platform-webauthn.js"
    ),
    "utf8"
  );
  function disposableContext(origin = disposable.CANONICAL_ORIGIN) {
    const requests = [];
    const data = new Uint8Array(37);
    data[32] = 0x05;
    const rawId = new Uint8Array(32).fill(7);
    const context = {
      crypto: crypto.webcrypto,
      btoa: (value) => Buffer.from(value, "binary").toString("base64"),
      atob: (value) => Buffer.from(value, "base64").toString("binary"),
      isSecureContext: true,
      location: { origin },
      PublicKeyCredential: function PublicKeyCredential() {},
      navigator: {
        credentials: {
          async create(request) {
            requests.push({ operation: "create", request });
            const clientDataJSON = new TextEncoder().encode(JSON.stringify({
              type: "webauthn.create",
              challenge: "main-issued",
              origin
            }));
            return {
              id: "synthetic-disposable",
              rawId: rawId.buffer,
              type: "public-key",
              authenticatorAttachment: "platform",
              response: {
                clientDataJSON,
                attestationObject: new Uint8Array(64).fill(9),
                getAuthenticatorData: () => data.buffer,
                getTransports: () => ["internal"],
                getPublicKey: () => new Uint8Array(65).fill(2),
                getPublicKeyAlgorithm: () => -7
              }
            };
          },
          async get(request) {
            requests.push({ operation: "get", request });
            const clientDataJSON = new TextEncoder().encode(JSON.stringify({
              type: "webauthn.get",
              challenge: "main-assertion",
              origin
            }));
            return {
              id: "synthetic-disposable",
              rawId: rawId.buffer,
              type: "public-key",
              authenticatorAttachment: "platform",
              response: {
                authenticatorData: data.buffer,
                clientDataJSON,
                signature: new Uint8Array(64).fill(3),
                userHandle: null
              }
            };
          }
        }
      }
    };
    context.globalThis = context;
    vm.runInNewContext(disposableSource, context);
    return { api: context.PhilCoreDisposablePlatformWebAuthn, requests };
  }
  function mainOrchestrationMocks(mainChallenge = "main-registration-challenge-aaaaaaaa") {
    const assertionChallenge = "main-assertion-challenge-bbbbbbbb";
    return {
      async begin() {
        return {
          challenge: mainChallenge,
          rp: { id: disposable.CANONICAL_RP_ID, name: "PhilCore Recovery" },
          testLabel: disposable.TEST_LABEL
        };
      },
      async verifyRegistration() {
        return {
          verified: true,
          assertionChallenge,
          productionAuthorityCreated: false,
          rawCredentialIdReturned: false
        };
      },
      async verifyAssertion() {
        return {
          verified: true,
          disposableCreationAssertion: true,
          productionAuthorityCreated: false,
          rawCredentialIdReturned: false,
          cleanup: "OS_CREDENTIAL_DELETION_API_UNAVAILABLE_PRODUCTION_UNREFERENCED"
        };
      },
      mainChallenge,
      assertionChallenge
    };
  }
  const disposableFixture = disposableContext();
  const mocks = mainOrchestrationMocks();
  const disposableResult = await disposableFixture.api.run({
    rpId: disposable.CANONICAL_RP_ID,
    rpName: "PhilCore Recovery Disposable Test",
    begin: mocks.begin,
    verifyRegistration: mocks.verifyRegistration,
    verifyAssertion: mocks.verifyAssertion
  });
  assert.equal(disposableResult.verified, true);
  assert.equal(disposableResult.disposableCreationAssertion, true);
  assert.equal(disposableResult.productionAuthorityCreated, false);
  assert.equal(disposableResult.rawCredentialIdReturned, false);
  assert.equal(Object.hasOwn(disposableResult, "policyAccepted"), false);
  assert.equal(disposableFixture.requests.length, 2);
  assert.equal(
    disposableFixture.requests[0].request.publicKey.rp.id,
    disposable.CANONICAL_RP_ID
  );
  assert.deepEqual(
    Buffer.from(disposableFixture.requests[0].request.publicKey.challenge),
    Buffer.from(disposableFixture.api.base64UrlToBytes(mocks.mainChallenge))
  );
  assert.deepEqual(
    Buffer.from(disposableFixture.requests[1].request.publicKey.challenge),
    Buffer.from(disposableFixture.api.base64UrlToBytes(mocks.assertionChallenge))
  );
  await assert.rejects(
    () => disposableFixture.api.run({
      rpId: disposable.CANONICAL_RP_ID,
      rpName: "PhilCore Recovery Disposable Test"
    }),
    /disposable_main_orchestration_required/
  );
  await assert.rejects(
    () => disposableFixture.api.run({
      rpId: "wrong.philcore.localhost",
      rpName: "Wrong RP",
      ...mainOrchestrationMocks()
    }),
    /disposable_rp_id_rejected/
  );
  const wrongOrigin = disposableContext("https://wrong.philcore.localhost:18443");
  await assert.rejects(
    () => wrongOrigin.api.run({
      rpId: disposable.CANONICAL_RP_ID,
      rpName: "PhilCore Recovery Disposable Test",
      ...mainOrchestrationMocks()
    }),
    /disposable_origin_rejected/
  );
  assert.match(disposableSource, /disposable_main_orchestration_required|disposable_main_challenge_required/u);
  assert.doesNotMatch(
    disposableSource,
    /crypto\.getRandomValues\([^)]*\).*challenge|challenge\s*=\s*crypto\.getRandomValues/u
  );

  const mainSource = fs.readFileSync(
    path.join(root, "apps/philcore-desktop/src/main/main.cjs"),
    "utf8"
  );
  assert.match(mainSource, /desktopCapabilityEvidenceProvider/u);
  assert.match(mainSource, /evaluateDesktopIPhoneReadiness\s*\(\s*nativeIPhonePairingHost\s*\)/u);
  assert.doesNotMatch(
    mainSource,
    /evaluateDesktopIPhoneReadiness\s*\(\s*nativeIPhonePairingHost\s*,/u
  );
  assert.match(mainSource, /cancelDisposableDiagnostic/u);
  assert.doesNotMatch(
    mainSource,
    /disposableCreationAssertion:\s*false/u
  );
  function indexAfter(source, marker, fromIndex = 0) {
    const index = source.indexOf(marker, fromIndex);
    assert.notEqual(index, -1, `missing marker: ${marker}`);
    return index;
  }
  const requireEnd = indexAfter(mainSource, 'require("./platform-webauthn.cjs");');
  const whenReady = indexAfter(mainSource, "app.whenReady()");
  const earlySlice = mainSource.slice(requireEnd, whenReady);
  assert.doesNotMatch(
    earlySlice,
    /configurePlatformWebAuthn\s*\(/u,
    "configurePlatformWebAuthn must not run at module load before app.whenReady()"
  );
  assert.match(
    earlySlice,
    /let\s+platformWebAuthnStartup\b/u,
    "platformWebAuthnStartup must be declared before the readiness callback"
  );
  const readyBody = mainSource.slice(indexAfter(mainSource, "app.whenReady().then"));
  const stage = indexAfter(readyBody, 'startupStage = "PLATFORM_WEBAUTHN_CONFIGURATION"');
  const configure = indexAfter(readyBody, "configurePlatformWebAuthn({");
  const host = indexAfter(readyBody, "createHost()");
  const recovery = indexAfter(readyBody, "createRecoveryEnvironment()");
  const window = indexAfter(readyBody, "createWindow()");
  assert.ok(stage < configure, "startup stage must label WebAuthn configuration");
  assert.ok(configure < host, "WebAuthn configuration must precede createHost()");
  assert.ok(configure < recovery, "WebAuthn configuration must precede createRecoveryEnvironment()");
  assert.ok(configure < window, "WebAuthn configuration must precede createWindow()");
  assert.match(
    readyBody.slice(configure, configure + 220),
    /electronApp:\s*app/u,
    "post-ready configure must pass the Electron app"
  );
  const e2eOverride = mainSource.match(
    /platformWebAuthnStartup:\s*isE2E\s*\?\s*\{([\s\S]*?)\}\s*:\s*platformWebAuthnStartup/u
  );
  assert.ok(e2eOverride, "E2E packaged-identity override must remain present");
  assert.doesNotMatch(
    e2eOverride[1],
    /configuredAfterReady\s*:/u,
    "E2E override must not fabricate configuredAfterReady"
  );
  assert.match(e2eOverride[1], /result:\s*CAPABILITY_RESULTS\.SUPPORTED_AND_CONFIGURED/u);
  assert.match(e2eOverride[1], /packaged:\s*true/u);
  assert.match(e2eOverride[1], /bundleIdentifier:\s*"com\.philcore\.desktop\.localalpha"/u);
  assert.match(e2eOverride[1], /teamIdentifier:\s*"B342738S82"/u);

  process.stdout.write("ok - O.42.1 platform WebAuthn configuration and Preflight V3\n");
}

run().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exit(1);
});
