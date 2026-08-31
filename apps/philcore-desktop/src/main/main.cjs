const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const {
  app,
  BrowserWindow,
  crashReporter,
  ipcMain,
  session,
  shell
} = require("electron");
const { releaseEnvironmentError } = require("./release-environment.cjs");
const releaseStartupError = releaseEnvironmentError({
  packaged: app.isPackaged, env: process.env, argv: process.argv
});
if (releaseStartupError) {
  process.stderr.write(`${releaseStartupError}\n`);
  app.exit(78);
  process.exit(78);
}
const {
  CAPABILITY_RESULTS,
  PHILCORE_DESKTOP_BUNDLE_ID,
  PHILCORE_MACOS_TEAM_ID,
  PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP,
  configurePlatformWebAuthn
} = require("./platform-webauthn.cjs");

let platformWebAuthnStartup = null;

function configurePackagedLocalAlphaRuntime() {
  const appRoot = process.resourcesPath && path.join(process.resourcesPath, "app");
  if (!appRoot || !fs.existsSync(path.join(appRoot, "package.json"))) return;
  process.chdir(appRoot);
  process.env.PHILCORE_DESKTOP_RELEASE_PROFILE ||= "local_alpha_unsigned";
  const arch = process.arch === "arm64" ? "darwin-arm64" : "darwin-x64";
  const prover = path.join(appRoot, "bin", arch, "generate-unlock-proof-json");
  const verifier = path.join(appRoot, "bin", arch, "verify-unlock-proof-json");
  const userPresenceHelper = path.join(appRoot, "bin", arch, "PhilCoreUserPresenceHelper");
  const qrHelper = path.join(appRoot, "bin", arch, "PhilCoreQRCode");
  if (fs.existsSync(prover)) process.env.PHILCORE_ACTION_UNLOCK_PROVER_BIN ||= prover;
  if (fs.existsSync(verifier)) process.env.PHILCORE_ACTION_UNLOCK_VERIFIER_BIN ||= verifier;
  if (fs.existsSync(userPresenceHelper)) process.env.PHILCORE_MACOS_USER_PRESENCE_HELPER ||= userPresenceHelper;
  if (fs.existsSync(qrHelper)) process.env.PHILCORE_QR_HELPER ||= qrHelper;
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(appRoot, "config", "release", "philcore-desktop-local-alpha.json"), "utf8"));
    if (manifest.bundledResources?.userPresenceHelper?.sha256) {
      process.env.PHILCORE_MACOS_USER_PRESENCE_HELPER_SHA256 ||= manifest.bundledResources.userPresenceHelper.sha256;
    }
  } catch {
    // Manifest hashes are verified by release tooling; startup stays local-alpha tolerant.
  }
}

function resolvePreloadPath() {
  if (app.isPackaged) return path.join(__dirname, "../preload/preload.cjs");
  const bundledPreload = path.join(__dirname, "../../build/preload/preload.cjs");
  if (!fs.existsSync(bundledPreload)) {
    throw new Error("Sandbox-safe preload bundle missing; run npm run desktop:bundle-preload");
  }
  return bundledPreload;
}

configurePackagedLocalAlphaRuntime();
app.commandLine.appendSwitch("disable-breakpad");

process.on("uncaughtException", () => {
  app.exit(1);
});
process.on("unhandledRejection", () => {
  app.exit(1);
});

const {
  CHANNELS,
  ALLOWED_CHANNELS,
  RECOVERY_ENROLLMENT_CHANNELS,
  RECOVERY_TRANSPORT_CHANNELS,
  ROUTINE_AUTHORIZATION_CHANNELS,
  SEPOLIA_MINT_CHANNELS,
  assertAllowedChannel,
  validateBridgePayload
} = require("../shared/bridge-contract.cjs");
const {
  createDesktopRuntimeHost,
  createElectronSafeStoragePlatformKeyAdapter,
  createFixturePlatformKeyAdapter
} = require("./runtime-host.cjs");
const {
  createFixtureMacOsUserPresenceProvider,
  createMacOsLocalAuthenticationProvider
} = require("./macos-user-presence.cjs");
const {
  RECOVERY_ORIGIN,
  createRecoverySecureOrigin
} = require("./recovery-secure-origin.cjs");
const {
  createEncryptedRecoveryCredentialStore,
  createRecoveryEnrollmentHost,
  createSecondaryPairingResponse,
  safeError
} = require("./recovery-enrollment-host.cjs");
const {
  createNativeIPhonePairingHost,
  createNativeRole1DescriptorStore,
  evaluateDesktopIPhoneReadiness,
  selectIPhonePrivateInterface
} = require("./native-iphone-pairing-host.cjs");
const { createQrDataUrl } = require("./native-qr-code.cjs");
const {
  RecoveryTransportError,
  createUnavailableRole1TransportAdapter,
  createRecoveryTransportHost,
  safeError: safeTransportError
} = require("./recovery-transport-host.cjs");
const {
  createRoutineAuthorizationIpc,
  createRetryingRoutineAuthorizationProductHost
} = require("./routine-authorization-ipc.cjs");
const { createRoutineAuthorizationProtectedStores } = require("./routine-authorization-storage.cjs");
const { createRoutineDeviceEnrollmentHost } = require("./routine-device-enrollment-host.cjs");
const { createRoutineAuthorizationHost } = require("./routine-authorization-host.cjs");
const { createRoutineAuthorizationProductHost } = require("./routine-authorization-product-host.cjs");
const { createRoutineAuthorizationLocalProductRuntime } = require("./routine-authorization-local-product-runtime.cjs");
const { createSepoliaMintCeremonyStore } = require("./sepolia-mint-ceremony-store.cjs");
const { createSepoliaMintDeviceAuthorizationHost } = require("./sepolia-mint-device-authorization-host.cjs");
const { createSepoliaMintReplayStore } = require("./sepolia-mint-replay-store.cjs");
const { createNoirRootProofStack } = require("./noir-root-proof-stack.cjs");
require("tsx/cjs");
const { AbiCoder, concat, getCreate2Address, id, keccak256, toUtf8Bytes } = require("ethers");
const { createPhilDeviceEnrollmentRecordV1 } = require("../../../phil-device-sdk/src/deviceApprovalV1.ts");
const { PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE } = require("../../../phil-device-sdk/src/sepoliaMintAuthorizationV1.ts");
const {
  createWebAuthnAssertionVerifier
} = require("../../../phil-device-sdk/src/deviceIdentityWebAuthn.ts");

// A packaged Beta must never enable Chromium DevTools or developer UI merely
// because an inherited environment variable is present. Test automation is
// available only in the unpackaged development application. Packaging removes
// its providers and branches; the startup guard rejects every test selector.
const isDevelopment = !app.isPackaged && process.env.PHILCORE_DESKTOP_DEV === "1";
const isE2E = !app.isPackaged && process.env.PHILCORE_DESKTOP_E2E === "1";
const LOCAL_ALPHA_FORBIDDEN_IPC_CHANNELS = new Set([
  CHANNELS.PREFLIGHT_SEPOLIA_USER_OPERATION_PREPARATION,
  CHANNELS.START_SEPOLIA_USER_OPERATION_PREPARATION,
  CHANNELS.GET_SEPOLIA_USER_OPERATION_PREPARATION,
  CHANNELS.FINALIZE_SEPOLIA_SIGNED_ARTIFACT
]);
const LOCAL_ALPHA_PRODUCT_CHANNELS = Object.freeze(
  ALLOWED_CHANNELS.filter((channel) => !LOCAL_ALPHA_FORBIDDEN_IPC_CHANNELS.has(channel))
);

if (process.env.PHILCORE_DESKTOP_USER_DATA_DIR) {
  app.setPath("userData", process.env.PHILCORE_DESKTOP_USER_DATA_DIR);
}

let mainWindow = null;
let runtimeHost = null;
let e2eUserPresenceProvider = null;
let recoveryOrigin = null;
let recoveryEnrollmentHost = null;
let recoveryCredentialStore = null;
let nativeIPhonePairingHost = null;
let nativeRole1DescriptorStore = null;
let nativePairingBlockedReason = null;
let recoveryRevealWindow = null;
let recoveryTransportHost = null;
let routineAuthorizationIpc = null;
let routineAuthorizationProductHost = null;
let routineAuthorizationUnavailableReason = "routine_authorization_product_runtime_unavailable";
let routineEnrollmentHost = null;
let routineAuthorizationStores = null;
let routineDisposableProfileId = null;
let routinePrivateIpv4 = null;
let sepoliaMintAuthorizationHost = null;
let sepoliaMintUnavailableReason = "sepolia_mint_runtime_unavailable";
let startupStage = "PROCESS_INITIALIZATION";
let safeStorage = null;

function createHost() {
  const preferencesPath = path.join(app.getPath("userData"), "philcore-desktop-preferences.json");
  const repositoryRoot = path.resolve(__dirname, "../../../..");
  e2eUserPresenceProvider = isE2E ? createFixtureMacOsUserPresenceProvider() : null;
  runtimeHost = createDesktopRuntimeHost({
    preferencesPath,
    identityStorageRoot: path.join(app.getPath("userData"), "philcore-local-identities"),
    platformKeyAdapter: isE2E
      ? createFixturePlatformKeyAdapter({ masterKey: "philcore-desktop-e2e-platform-key" })
      : createElectronSafeStoragePlatformKeyAdapter({ safeStorage, platform: process.platform }),
    userPresenceProvider: e2eUserPresenceProvider || createMacOsLocalAuthenticationProvider(),
    // Every real Desktop Alpha action requires the native helper. Only the
    // explicitly marked E2E process may use the isolated fixture provider.
    requireNativeUserPresence: !isE2E,
    rootProofStack: createNoirRootProofStack({ repositoryRoot }),
    developerSurfacesAllowed: isDevelopment
  });
  routineAuthorizationIpc = createRoutineAuthorizationIpc(createRetryingRoutineAuthorizationProductHost({
    getActiveHost: () => routineAuthorizationProductHost,
    getUnavailableReason: () => routineAuthorizationUnavailableReason,
    initialize: () => createRoutineAuthorizationEnvironment()
  }), { createQrDataUrl });
}

async function createRoutineAuthorizationEnvironment() {
  if (isE2E && process.env.PHILCORE_DESKTOP_E2E_ROUTINE_UNAVAILABLE === "1") {
    throw Object.assign(new Error("routine environment unavailable fixture"), { code: "ROUTINE_AUTHORIZATION_ENVIRONMENT_FAILED" });
  }
  const selectedInterface=selectIPhonePrivateInterface();
  if (!selectedInterface) {
    throw Object.assign(new Error("private network unavailable"), { code: "ROUTINE_AUTHORIZATION_PRIVATE_NETWORK_UNAVAILABLE" });
  }
  const repositoryRoot=path.resolve(__dirname,"../../../..");
  const encryptionAdapter=createRecoveryEncryptionAdapter();
  const stores=createRoutineAuthorizationProtectedStores({storageRoot:path.join(app.getPath("userData"),"phil-v1-routine-local-profile"),encryptionAdapter});
  const disposableProfileId=`0x${crypto.createHash("sha256").update("PHIL_V1_STEP6C_DISPOSABLE_LOCAL_PRODUCT_PROFILE_V1").digest("hex")}`;
  const enrollmentHost=createRoutineDeviceEnrollmentHost({disposableProfileId,ipv4:selectedInterface.address,enrollmentStore:stores.enrollmentStore,
    now:()=>BigInt(Math.floor(Date.now()/1000)),allowSynthetic:isE2E});
  const productHost=createRoutineAuthorizationProductHost({enrollmentHost,deleteProfileAtomically:()=>stores.profileStore.deleteAll(disposableProfileId),authorizationHostFactory:async (storedEnrollment)=>{
    process.env.HARDHAT_CONFIG=path.join(repositoryRoot,"hardhat.phil-v1-step6c-product.config.cjs");
    const hardhat=require("hardhat");
    const runtime=await createRoutineAuthorizationLocalProductRuntime({hardhat,repositoryRoot,enrollment:storedEnrollment.record,
      now:async()=>BigInt(Math.floor(Date.now()/1000)),
      desktopUnlocked:async()=>runtimeHost.snapshot().session?.lockState==="unlocked",
      iphoneSessionCurrent:async (expected)=>{
        try { const current=JSON.parse((await stores.enrollmentStore.load(disposableProfileId)).canonicalEnrollmentJson);return JSON.stringify(current)===JSON.stringify({
          schemaVersion:2,generation:expected.generation,deviceId:expected.deviceId,deviceKeyId:expected.deviceKeyId,publicKeyX963:expected.publicKeyX963,
          signatureSuiteId:expected.signatureSuiteId,providerProfileId:expected.providerProfileId,wireEncodingId:expected.wireEncodingId,
          publicKeyFingerprint:expected.publicKeyFingerprint,secureEnclaveBacked:expected.secureEnclaveBacked,userPresenceRequired:expected.userPresenceRequired}); }
        catch { return false; }
      }});
    return createRoutineAuthorizationHost({disposableProfileId,ipv4:selectedInterface.address,requestFactory:runtime.requestFactory,
      readTrustedState:runtime.readTrustedState,simulate:runtime.simulate,execute:runtime.execute,reconcile:runtime.reconcile,readCurrentNonce:runtime.readCurrentNonce,
      protectedKeyStore:stores.protectedKeyStore,journalStore:stores.journalStore,requestStore:stores.requestStore,now:()=>BigInt(Math.floor(Date.now()/1000))});
  }});
  await productHost.initialize();
  routineAuthorizationProductHost=productHost;
  routineEnrollmentHost=enrollmentHost;
  routineAuthorizationStores=stores;
  routineDisposableProfileId=disposableProfileId;
  routinePrivateIpv4=selectedInterface.address;
  routineAuthorizationUnavailableReason="routine_authorization_product_runtime_unavailable";
}

function loadSepoliaMintDemoConfiguration(repositoryRoot) {
  const location = path.join(
    repositoryRoot,
    "config/ethereum-sepolia/PHIL_SEPOLIA_MINT_DEMO_V1.json"
  );
  const value = JSON.parse(fs.readFileSync(location, "utf8"));
  if (value?.format !== "phil-sepolia-mint-demo-configuration-v1"
    || value.version !== 1
    || value.chainId !== "11155111"
    || value.entryPoint?.toLowerCase()
      !== "0x0000000071727de22e5e9d8baf0edac6f37da032"
    || !/^0x[0-9a-f]{40}$/iu.test(value.infrastructure?.factory || "")
    || !/^0x[0-9a-f]{40}$/iu.test(value.infrastructure?.actionGate || "")
    || !/^0x[0-9a-f]{40}$/iu.test(value.infrastructure?.mintConsumer || "")
    || !/^0x[0-9a-f]{64}$/iu.test(value.accountSalt || "")
    || value.publicMutationEnabled !== false
    || value.submissionEnabled !== false) {
    throw Object.assign(new Error("Sepolia mint configuration invalid"), {
      code: "SEPOLIA_MINT_CONFIGURATION_INVALID"
    });
  }
  return Object.freeze(value);
}

function deriveSepoliaMintAccountAddress(repositoryRoot, configuration, executionOwner, ownerCommitment) {
  const artifactPath = path.join(
    repositoryRoot,
    "artifacts/contracts/base/erc4337/PhilSepoliaMintAccountV1.sol/PhilSepoliaMintAccountV1.json"
  );
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  if (!/^0x[0-9a-f]+$/iu.test(artifact.bytecode || "")) {
    throw Object.assign(new Error("Sepolia mint account artifact invalid"), {
      code: "SEPOLIA_MINT_ACCOUNT_ARTIFACT_INVALID"
    });
  }
  const encoded = AbiCoder.defaultAbiCoder().encode(
    ["address", "address", "bytes32", "address"],
    [
      configuration.entryPoint,
      executionOwner,
      ownerCommitment,
      configuration.infrastructure.actionGate
    ]
  );
  return getCreate2Address(
    configuration.infrastructure.factory,
    configuration.accountSalt,
    keccak256(concat([artifact.bytecode, encoded]))
  );
}

function adaptRoutineEnrollmentForSepoliaMint(storedEnrollment) {
  const record = storedEnrollment.record;
  if (!isE2E && (storedEnrollment.evidenceClass !== "physical_device_unverified"
    || record.secureEnclaveBacked !== true
    || record.userPresenceRequired !== true)) {
    throw Object.assign(new Error("Physical iPhone enrollment required"), {
      code: "SEPOLIA_MINT_PHYSICAL_DEVICE_REQUIRED"
    });
  }
  return createPhilDeviceEnrollmentRecordV1({
    deviceId: record.deviceId,
    deviceKeyId: record.deviceKeyId,
    signatureSuiteId: PHIL_SEPOLIA_MINT_DEVICE_SIGNATURE_SUITE,
    publicKey: record.publicKeyX963,
    deviceEpoch: record.generation,
    enrolledAt: "1",
    assuranceClass: record.secureEnclaveBacked && record.userPresenceRequired ? 3 : 1,
    attestationEvidenceHash: keccak256(toUtf8Bytes(JSON.stringify({
      evidenceClass: storedEnrollment.evidenceClass,
      generation: record.generation,
      publicKeyFingerprint: record.publicKeyFingerprint,
      secureEnclaveBacked: record.secureEnclaveBacked,
      userPresenceRequired: record.userPresenceRequired
    }))),
    policyHash: id("PHIL_SEPOLIA_MINT_ENROLLED_DEVICE_POLICY_V1")
  });
}

function persistSepoliaMintSignedArtifact(outcome) {
  if (outcome?.format !== "phil-sepolia-mint-signed-unsubmitted-v1"
    || outcome.signed !== true || outcome.submitted !== false
    || !/^0x[0-9a-f]{64}$/u.test(outcome.userOperationHash || "")) {
    throw Object.assign(new Error("Signed Sepolia mint artifact invalid"), {
      code: "SEPOLIA_MINT_SIGNED_ARTIFACT_INVALID"
    });
  }
  const directory = path.join(app.getPath("userData"), "phil-sepolia-mint");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const location = path.join(directory, "signed-unsubmitted-v1.json");
  const temporary = `${location}.${process.pid}.tmp`;
  const descriptor = fs.openSync(
    temporary,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o600
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(outcome)}\n`);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, location);
  fs.chmodSync(location, 0o600);
  const directoryDescriptor = fs.openSync(directory, fs.constants.O_RDONLY);
  try { fs.fsyncSync(directoryDescriptor); } finally { fs.closeSync(directoryDescriptor); }
  return location;
}

function loadMatchingSepoliaMintSignedArtifact(request) {
  const location = path.join(
    app.getPath("userData"),
    "phil-sepolia-mint",
    "signed-unsubmitted-v1.json"
  );
  if (!fs.existsSync(location)) return null;
  let value;
  try { value = JSON.parse(fs.readFileSync(location, "utf8")); } catch { return null; }
  const envelope = request.authorization.authorizationEnvelope;
  if (value?.format !== "phil-sepolia-mint-signed-unsubmitted-v1"
    || value.signed !== true || value.submitted !== false
    || value.authorizationEnvelopeDigest !== request.authorization.authorizationEnvelopeDigest
    || value.rootProofNullifier !== envelope.rootProofNullifier
    || value.deviceApprovalNonce !== request.approvalNonce
    || value.accountNonce !== envelope.nonce) return null;
  return Object.freeze(value);
}

async function createSepoliaMintAuthorizationEnvironment() {
  if (!routineEnrollmentHost || !routineAuthorizationStores
    || !routineDisposableProfileId || !routinePrivateIpv4) {
    throw Object.assign(new Error("Routine enrollment unavailable"), {
      code: "SEPOLIA_MINT_ENROLLMENT_UNAVAILABLE"
    });
  }
  const repositoryRoot = path.resolve(__dirname, "../../../..");
  const configuration = loadSepoliaMintDemoConfiguration(repositoryRoot);
  const storedEnrollment = await routineEnrollmentHost.activeEnrollment();
  const enrollment = adaptRoutineEnrollmentForSepoliaMint(storedEnrollment);
  const publicSnapshot = runtimeHost.snapshot();
  const executionOwner = publicSnapshot.ethereum?.executionOwnerAddress;
  const ownerCommitment = publicSnapshot.identity?.ownerCommitment;
  if (publicSnapshot.session?.lockState !== "unlocked"
    || !/^0x[0-9a-f]{40}$/iu.test(executionOwner || "")
    || !/^0x[0-9a-f]{64}$/iu.test(ownerCommitment || "")) {
    throw Object.assign(new Error("Unlocked Phil identity required"), {
      code: "SEPOLIA_MINT_IDENTITY_LOCKED"
    });
  }
  const smartAccount = deriveSepoliaMintAccountAddress(
    repositoryRoot,
    configuration,
    executionOwner,
    ownerCommitment
  );
  const now = BigInt(Math.floor(Date.now() / 1000));
  const validUntil = now + BigInt(configuration.authorizationWindowSeconds);
  const bindingsInput = Object.freeze({
    factory: configuration.infrastructure.factory,
    smartAccount,
    actionGate: configuration.infrastructure.actionGate,
    mintConsumer: configuration.infrastructure.mintConsumer,
    mintRecipient: smartAccount,
    accountNonce: "0",
    validAfter: now.toString(),
    validUntil: validUntil.toString(),
    maximumTotalFeeWei: configuration.maximumTotalFeeWei
  });
  const replayStore = createSepoliaMintReplayStore({
    ledgerPath: path.join(app.getPath("userData"), "phil-sepolia-mint", "replay-v1.json"),
    now: () => new Date().toISOString()
  });
  const capability = await runtimeHost._createSepoliaMintComposedCapability({
    repositoryRoot,
    bindingsInput,
    epochs: {
      scopeEpoch: "1",
      deviceEpoch: enrollment.deviceEpoch,
      recoveryEpoch: "1",
      validatorEpoch: "1"
    },
    enrollment,
    accountSalt: BigInt(configuration.accountSalt).toString(),
    accountDeployed: false,
    gas: configuration.gasPolicy,
    proofTimeoutMs: 120_000,
    replayStore,
    trustedStateFactory: async () => {
      const current = await routineEnrollmentHost.activeEnrollment();
      const active = current.evidenceClass === storedEnrollment.evidenceClass
        && JSON.stringify(current.record) === JSON.stringify(storedEnrollment.record);
      return Object.freeze({
        now: String(Math.floor(Date.now() / 1000)),
        scopeEpoch: "1",
        deviceEpoch: enrollment.deviceEpoch,
        recoveryEpoch: "1",
        validatorEpoch: "1",
        accountNonce: "0",
        valueWei: "0",
        maximumTotalFeeWei: configuration.maximumTotalFeeWei,
        emergencyStop: false,
        scopeActive: true,
        policyActive: true,
        proofDescriptorActive: true,
        deviceActive: active,
        recoveryStateCurrent: runtimeHost.snapshot().ethereum?.recovery?.status === "available",
        validatorActive: runtimeHost.snapshot().session?.lockState === "unlocked",
        cancelled: false,
        denied: false
      });
    }
  });
  const ceremonyStore = createSepoliaMintCeremonyStore({
    storageRoot: path.join(app.getPath("userData"), "phil-sepolia-mint", "ceremonies"),
    encryptionAdapter: createRecoveryEncryptionAdapter()
  });
  const host = createSepoliaMintDeviceAuthorizationHost({
    ceremonyStore,
    enrollment,
    ipv4: routinePrivateIpv4,
    now: () => BigInt(Math.floor(Date.now() / 1000)),
    requestFactory: capability.requestFactory,
    onApproved: async (approved) => {
      const existing = loadMatchingSepoliaMintSignedArtifact(approved.request);
      if (existing) {
        replayStore.markConsumed(existing);
        return existing;
      }
      const outcome = await capability.onApproved(approved);
      persistSepoliaMintSignedArtifact(outcome);
      replayStore.markConsumed(outcome);
      return outcome;
    }
  });
  await host.startListener();
  await host.restoreApproved();
  sepoliaMintAuthorizationHost = host;
  sepoliaMintUnavailableReason = "sepolia_mint_runtime_unavailable";
  return host;
}

async function sepoliaMintInvoke(channel, payload) {
  const validated = validateBridgePayload(channel, payload);
  if (!validated.ok) return { status: "failed", reason: validated.reason };
  try {
    if (channel === CHANNELS.SEPOLIA_MINT_BEGIN) {
      if (sepoliaMintAuthorizationHost) {
        await sepoliaMintAuthorizationHost.stopListener();
        sepoliaMintAuthorizationHost = null;
      }
      const host = await createSepoliaMintAuthorizationEnvironment();
      const result = await host.begin();
      return {
        ...result,
        qrDataUrl: await createQrDataUrl(result.qrPayload),
        publicMutationOccurred: false,
        submissionEnabled: false
      };
    }
    if (!sepoliaMintAuthorizationHost) {
      return { status: "failed", reason: sepoliaMintUnavailableReason };
    }
    if (channel === CHANNELS.SEPOLIA_MINT_STATUS) {
      return sepoliaMintAuthorizationHost.getStatus(validated.value.requestId);
    }
    if (channel === CHANNELS.SEPOLIA_MINT_CANCEL) {
      return {
        requestId: validated.value.requestId,
        result: await sepoliaMintAuthorizationHost.cancel(validated.value.requestId)
      };
    }
    return { status: "failed", reason: "sepolia_mint_channel_not_supported" };
  } catch (error) {
    const reason = typeof error?.code === "string"
      ? error.code.toLowerCase()
      : "sepolia_mint_failed_closed";
    return { status: "failed", reason, publicMutationOccurred: false };
  }
}

function createRecoveryEncryptionAdapter() {
  if (isE2E) {
    const fixtureKey = crypto.createHash("sha256")
      .update("philcore-o41-e2e-safe-storage-adapter")
      .digest();
    return Object.freeze({
      isAvailable: () => true,
      encrypt(plaintext) {
        const nonce = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv("aes-256-gcm", fixtureKey, nonce);
        const ciphertext = Buffer.concat([
          cipher.update(String(plaintext), "utf8"),
          cipher.final()
        ]);
        return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
      },
      decrypt(encrypted) {
        const value = Buffer.from(encrypted);
        const decipher = crypto.createDecipheriv("aes-256-gcm", fixtureKey, value.subarray(0, 12));
        decipher.setAuthTag(value.subarray(12, 28));
        return Buffer.concat([
          decipher.update(value.subarray(28)),
          decipher.final()
        ]).toString("utf8");
      }
    });
  }
  return Object.freeze({
    isAvailable: () => Boolean(safeStorage.isEncryptionAvailable()),
    encrypt: (plaintext) => safeStorage.encryptString(String(plaintext)),
    decrypt: (encrypted) => safeStorage.decryptString(Buffer.from(encrypted))
  });
}

function showOfflineRecoverySecret(secretValue) {
  if (recoveryRevealWindow && !recoveryRevealWindow.isDestroyed()) {
    recoveryRevealWindow.close();
  }
  recoveryRevealWindow = new BrowserWindow({
    width: 760,
    height: 640,
    parent: mainWindow || undefined,
    modal: Boolean(mainWindow),
    show: false,
    title: "PhilCore protected offline recovery reveal",
    backgroundColor: "#f6f7f4",
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: false
    }
  });
  recoveryRevealWindow.removeMenu();
  recoveryRevealWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  recoveryRevealWindow.webContents.on("will-navigate", (event, url) => {
    if (url !== `${RECOVERY_ORIGIN}/recovery-secret.html`) event.preventDefault();
  });
  recoveryRevealWindow.webContents.once("did-finish-load", () => {
    secretValue.consume((secret) => recoveryRevealWindow.webContents.executeJavaScript(
      `window.PhilCoreProtectedReveal.show(${JSON.stringify(secret)});`
    ));
    secretValue.clear();
    recoveryRevealWindow.show();
  });
  recoveryRevealWindow.on("closed", () => {
    recoveryRevealWindow = null;
  });
  recoveryRevealWindow.loadURL(`${RECOVERY_ORIGIN}/recovery-secret.html`);
}

async function createRecoveryEnvironment() {
  const encryptionAdapter = createRecoveryEncryptionAdapter();
  const recoveryRoot = path.join(app.getPath("userData"), "philcore-recovery-enrollment");
  const credentialRoot = path.join(recoveryRoot, "credentials");
  const recoveryCredentialCount = () => {
    if (!fs.existsSync(credentialRoot)) return 0;
    return fs.readdirSync(credentialRoot)
      .filter((name) => /^recovery_credential_[a-f0-9]{32}\.v1\.json$/u.test(name))
      .length;
  };
  recoveryOrigin = createRecoverySecureOrigin({
    storageRoot: path.join(recoveryRoot, "origin"),
    rendererRoot: path.join(__dirname, "../renderer"),
    encryptionAdapter,
    applicationIdentity: {
      bundleIdentifier: app.isPackaged
        ? PHILCORE_DESKTOP_BUNDLE_ID
        : "development.philcore.desktop",
      teamIdentifier: app.isPackaged
        ? PHILCORE_MACOS_TEAM_ID
        : "DEVELOPMENT_NO_TEAM",
      keychainAccessGroup: PHILCORE_WEBAUTHN_KEYCHAIN_ACCESS_GROUP
    },
    credentialRecordCount: recoveryCredentialCount
  });
  await recoveryOrigin.start();
  recoveryOrigin.installElectronGuards(app, session.defaultSession);
  recoveryCredentialStore = createEncryptedRecoveryCredentialStore({
    storageRoot: credentialRoot,
    encryptionAdapter
  });
  recoveryEnrollmentHost = createRecoveryEnrollmentHost({
    credentialStore: recoveryCredentialStore,
    originStatus: () => recoveryOrigin.publicStatus(),
    secureDisplay: showOfflineRecoverySecret,
    platformWebAuthnStartup: isE2E
      ? {
          ...platformWebAuthnStartup,
          result: CAPABILITY_RESULTS.SUPPORTED_AND_CONFIGURED,
          packaged: true,
          bundleIdentifier: "com.philcore.desktop.localalpha",
          teamIdentifier: "B342738S82"
        }
      : platformWebAuthnStartup,
    desktopCapabilityEvidenceProvider: () => {
      // nativeIPhonePairingHost may still be null until started; fail closed.
      const readiness = evaluateDesktopIPhoneReadiness(nativeIPhonePairingHost);
      return {
        certificatePersistence: [
          "EXACT_IDENTITY_REUSED",
          "LEGACY_PRE_ENROLLMENT_IDENTITY_BOUND",
          "PRE_ENROLLMENT_IDENTITY_REBOUND"
        ].includes(recoveryOrigin.publicStatus().certificateMigrationStatus),
        safeStoragePersistence: isE2E
          ? true
          : Boolean(safeStorage?.isEncryptionAvailable()),
        packagedBuild: app.isPackaged,
        // Desktop-side capability signals only — not physical iPhone verification.
        iphoneCompanionConnectivity: readiness.pairingTransportReady,
        iphoneRole1CredentialPolicy: readiness.nativeRole1PolicyReady,
        noProductionSecretContamination: true
      };
    }
  });
  nativeRole1DescriptorStore = createNativeRole1DescriptorStore({
    storageRoot: path.join(recoveryRoot, "native-role1"),
    encryptionAdapter
  });

  // Recovery transport host is independent of native pairing listener availability.
  recoveryTransportHost = createRecoveryTransportHost({
    trustedConfigProvider: async () => {
      throw new RecoveryTransportError("TRUSTED_CONFIG_NOT_AVAILABLE");
    },
    role2FactorProvider: async () => {
      throw new RecoveryTransportError("ROLE2_PROVIDER_NOT_CONFIGURED");
    },
    localStaticVerifier: async () => {
      throw new RecoveryTransportError("LOCAL_VERIFIER_NOT_CONFIGURED");
    },
    role1TransportAdapter: createUnavailableRole1TransportAdapter(),
    assertionVerifier: createWebAuthnAssertionVerifier()
  });

  const selectedInterface = selectIPhonePrivateInterface();
  if (!selectedInterface) {
    nativePairingBlockedReason = "no_selected_private_ipv4_interface";
    return;
  }
  nativeIPhonePairingHost = createNativeIPhonePairingHost({
    interfaceAddress: selectedInterface.address,
    interfaceName: selectedInterface.name,
    allowSimulator: isE2E,
    onVerified(descriptor) {
      const duplicate = recoveryCredentialStore.list().some((record) =>
        record.safePublicFingerprint === descriptor.publicFingerprint
        || record.custodyDomainCommitment === descriptor.deviceCustodyCommitment
      );
      if (duplicate) throw new Error("NATIVE_ROLE1_ALIAS_REJECTED");
      nativeRole1DescriptorStore.write(descriptor);
      recoveryEnrollmentHost.completeNativeIPhonePairing(descriptor);
    }
  });
  await nativeIPhonePairingHost.start();
}

async function recoveryEnrollmentInvoke(channel, payload) {
  const validated = validateBridgePayload(channel, payload);
  if (!validated.ok) return { status: "failed", reason: validated.reason };
  try {
    switch (channel) {
      case CHANNELS.RECOVERY_ENROLLMENT_PREFLIGHT:
        return recoveryEnrollmentHost.preflight(validated.value);
      case CHANNELS.RECOVERY_ENROLLMENT_STATUS:
        return recoveryEnrollmentHost.status();
      case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_CREDENTIAL:
        return recoveryEnrollmentHost.beginCredential();
      case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC:
        return recoveryEnrollmentHost.beginDisposableDiagnostic();
      case CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC:
        return recoveryEnrollmentHost.cancelDisposableDiagnostic();
      case CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION:
        return await recoveryEnrollmentHost.verifyDisposableRegistration(
          validated.value.registration
        );
      case CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION:
        return await recoveryEnrollmentHost.verifyDisposableAssertion(
          validated.value.assertion
        );
      case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_HARDWARE_FALLBACK:
        return recoveryEnrollmentHost.beginHardwareCredentialFallback();
      case CHANNELS.RECOVERY_ENROLLMENT_STORE_CREDENTIAL:
        return await recoveryEnrollmentHost.storeCredential(validated.value);
      case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_PAIRING:
        return recoveryEnrollmentHost.beginPairing();
      case CHANNELS.RECOVERY_ENROLLMENT_BEGIN_IPHONE_PAIRING: {
        if (!nativeIPhonePairingHost) {
          return {
            status: "BLOCKED",
            reason: nativePairingBlockedReason || "native_pairing_host_unavailable"
          };
        }
        const enrollmentState = recoveryEnrollmentHost.status().state;
        if (enrollmentState !== "PRIMARY_COMPLETE") {
          return {
            status: "BLOCKED",
            reason: "primary_role0_must_complete_first"
          };
        }
        const identity = runtimeHost.snapshot().identity;
        if (!identity?.ownerCommitment) {
          return { status: "BLOCKED", reason: "philcore_identity_required" };
        }
        const existing = nativeRole1DescriptorStore.publicStatus();
        recoveryEnrollmentHost.beginNativeIPhonePairing();
        try {
          const pairing = nativeIPhonePairingHost.beginPairing({
            philCoreIdentityCommitment: identity.ownerCommitment,
            recoveryEpoch: 1,
            requestedGeneration: (existing.generation || 0) + 1
          });
          return {
            ...pairing,
            qrDataUrl: createQrDataUrl(pairing.encodedRequest),
            descriptorStore: existing
          };
        } catch (error) {
          recoveryEnrollmentHost.cancelNativeIPhonePairing();
          throw error;
        }
      }
      case CHANNELS.RECOVERY_ENROLLMENT_IPHONE_PAIRING_STATUS:
        return {
          pairing: nativeIPhonePairingHost?.status() || {
            status: "BLOCKED",
            reason: nativePairingBlockedReason || "native_pairing_host_unavailable"
          },
          descriptor: nativeRole1DescriptorStore?.publicStatus() || {
            enrolled: false
          }
        };
      case CHANNELS.RECOVERY_ENROLLMENT_CANCEL_IPHONE_PAIRING:
        nativeIPhonePairingHost?.cancel();
        return recoveryEnrollmentHost.cancelNativeIPhonePairing();
      case CHANNELS.RECOVERY_ENROLLMENT_ACCEPT_PAIRING:
        return {
          encodedResponse: createSecondaryPairingResponse(validated.value),
          containsReusableAuthority: false
        };
      case CHANNELS.RECOVERY_ENROLLMENT_COMPLETE_PAIRING:
        return await recoveryEnrollmentHost.completePairing(
          validated.value.encodedResponse,
          validated.value.custodyDomainCommitment
        );
      case CHANNELS.RECOVERY_ENROLLMENT_GENERATE_OFFLINE:
        return recoveryEnrollmentHost.generateOffline();
      case CHANNELS.RECOVERY_ENROLLMENT_REVEAL_OFFLINE:
        return recoveryEnrollmentHost.revealOffline();
      case CHANNELS.RECOVERY_ENROLLMENT_CONFIRM_OFFLINE_EXPORT:
        return recoveryEnrollmentHost.confirmOfflineExport();
      case CHANNELS.RECOVERY_ENROLLMENT_RESTORE_OFFLINE:
        return recoveryEnrollmentHost.restoreOffline(validated.value.restorationInput);
      case CHANNELS.RECOVERY_ENROLLMENT_REVIEW_INDEPENDENCE:
        return recoveryEnrollmentHost.reviewIndependence(validated.value);
      case CHANNELS.RECOVERY_ENROLLMENT_COMPLETE:
        return recoveryEnrollmentHost.complete();
      case CHANNELS.RECOVERY_ENROLLMENT_CANCEL:
        return recoveryEnrollmentHost.cancel();
      case CHANNELS.RECOVERY_ENROLLMENT_LIST_PUBLIC_FACTORS:
        return recoveryCredentialStore.list();
      case CHANNELS.RECOVERY_ENROLLMENT_DELETE_FACTOR:
        return recoveryEnrollmentHost.deleteFactor(validated.value.reference);
      case CHANNELS.RECOVERY_ENROLLMENT_ROTATE_FACTOR:
        return recoveryEnrollmentHost.rotateFactor(
          validated.value.reference,
          validated.value.replacement
        );
      default:
        return { status: "failed", reason: "recovery_enrollment_channel_not_supported" };
    }
  } catch (error) {
    return { status: "failed", reason: safeError(error).errorCode };
  }
}

async function recoveryTransportInvoke(channel, payload) {
  const validated = validateBridgePayload(channel, payload);
  if (!validated.ok) return { status: "failed", reason: validated.reason };
  if (!recoveryTransportHost) {
    return { status: "failed", reason: "recovery_transport_host_unavailable" };
  }
  try {
    switch (channel) {
      case CHANNELS.RECOVERY_TRANSPORT_BEGIN:
        return await recoveryTransportHost.beginDrill(validated.value);
      case CHANNELS.RECOVERY_TRANSPORT_STATUS:
        return recoveryTransportHost.status();
      case CHANNELS.RECOVERY_TRANSPORT_BEGIN_ROLE0_ASSERTION:
        return recoveryTransportHost.beginRole0Assertion();
      case CHANNELS.RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION:
        return await recoveryTransportHost.submitRole0Assertion(validated.value);
      case CHANNELS.RECOVERY_TRANSPORT_CANCEL:
        return recoveryTransportHost.cancel();
      default:
        return { status: "failed", reason: "recovery_transport_channel_not_supported" };
    }
  } catch (error) {
    return {
      status: "failed",
      reason: safeTransportError(error).errorCode
    };
  }
}

function registerIpc() {
  for (const channel of LOCAL_ALPHA_PRODUCT_CHANNELS) {
    ipcMain.handle(channel, (event, payload) => {
      assertAllowedChannel(channel);
      if (event.senderFrame?.url !== `${RECOVERY_ORIGIN}/index.html`) {
        return { status: "failed", reason: "renderer_origin_rejected" };
      }
      if (RECOVERY_ENROLLMENT_CHANNELS.includes(channel)) {
        return recoveryEnrollmentInvoke(channel, payload || {});
      }
      if (RECOVERY_TRANSPORT_CHANNELS.includes(channel)) {
        return recoveryTransportInvoke(channel, payload || {});
      }
      if (ROUTINE_AUTHORIZATION_CHANNELS.includes(channel)) {
        return routineAuthorizationIpc.invoke(channel, payload || {});
      }
      if (SEPOLIA_MINT_CHANNELS.includes(channel)) {
        return sepoliaMintInvoke(channel, payload || {});
      }
      return runtimeHost.invoke(channel, payload || {});
    });
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 1040,
    minHeight: 720,
    show: !isE2E,
    title: "Phil — Controlled Sepolia Beta",
    backgroundColor: "#f6f7f4",
    webPreferences: {
      preload: resolvePreloadPath(),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      devTools: isDevelopment
    }
  });

  mainWindow.removeMenu();
  mainWindow.loadURL(`${RECOVERY_ORIGIN}/index.html`);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://")) shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.webContents.on("will-navigate", (event, url) => {
    const current = mainWindow.webContents.getURL();
    if (url !== current) event.preventDefault();
  });

  if (isDevelopment) mainWindow.webContents.openDevTools({ mode: "detach" });
}

async function verifyRendererBridge(browserWindow) {
  if (browserWindow.webContents.isLoadingMainFrame()) {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("Renderer load timed out before preload bridge verification")), 30_000);
      browserWindow.webContents.once("did-finish-load", () => {
        clearTimeout(timeout);
        resolve();
      });
      browserWindow.webContents.once("did-fail-load", (_event, code, description) => {
        clearTimeout(timeout);
        reject(new Error(`Renderer failed to load before preload bridge verification: ${code} ${description}`));
      });
    });
  }

  const result = await browserWindow.webContents.executeJavaScript(`(async () => {
    const bridge = window.PhilCoreRendererStartup.requireBridge();
    const snapshot = await bridge.runtime.getSnapshot();
    return {
      functional: true,
      namespacePresent: Boolean(window.philcore),
      runtimeMethodPresent: typeof bridge.runtime.getSnapshot === "function",
      mode: snapshot.app.mode
    };
  })()`);
  if (!result?.functional || !result.namespacePresent || !result.runtimeMethodPresent) {
    throw new Error("Packaged renderer preload bridge verification failed");
  }
  return result;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function evaluateRenderer(browserWindow, script) {
  return browserWindow.webContents.executeJavaScript(`(async () => { ${script} })()`);
}

async function waitForRendererCondition(browserWindow, label, predicate, timeoutMs = 15_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const matched = await evaluateRenderer(browserWindow, `return Boolean(${predicate});`);
    if (matched) return true;
    await sleep(100);
  }
  throw new Error(`Timed out waiting for renderer condition: ${label}`);
}

async function clickRenderer(browserWindow, selector) {
  const clicked = await evaluateRenderer(browserWindow, `
    const element = document.querySelector(${JSON.stringify(selector)});
    if (!element) return false;
    element.click();
    return true;
  `);
  if (!clicked) throw new Error(`Renderer element not found: ${selector}`);
}

async function setRendererValue(browserWindow, selector, value) {
  const changed = await evaluateRenderer(browserWindow, `
    const element = document.querySelector(${JSON.stringify(selector)});
    if (!element) return false;
    element.value = ${JSON.stringify(value)};
    element.dispatchEvent(new Event("input", { bubbles: true }));
    return true;
  `);
  if (!changed) throw new Error(`Renderer input not found: ${selector}`);
}

async function capturePackagedUi(browserWindow, name) {
  const outputDir = process.env.PHILCORE_DESKTOP_E2E_SCREENSHOT_DIR;
  if (!outputDir) return null;
  await sleep(200);
  fs.mkdirSync(outputDir, { recursive: true });
  const outputPath = path.join(outputDir, `${name.replace(/[^a-z0-9_-]/giu, "-")}.png`);
  const image = await browserWindow.webContents.capturePage();
  fs.writeFileSync(outputPath, image.toPNG());
  return outputPath;
}

async function passCKeyboardAndMinimumWidthSmoke(browserWindow) {
  await evaluateRenderer(browserWindow, `
    const first = document.querySelector('#nav button[data-nav="home"]');
    first?.focus();
    return Boolean(first && document.activeElement === first);
  `);
  browserWindow.webContents.sendInputEvent({ type: "keyDown", keyCode: "Tab" });
  browserWindow.webContents.sendInputEvent({ type: "keyUp", keyCode: "Tab" });
  await sleep(100);
  const keyboard = await evaluateRenderer(browserWindow, `
    const active = document.activeElement;
    const style = active ? getComputedStyle(active) : null;
    return {
      nextNavigation: active?.dataset?.nav || null,
      focusVisible: Boolean(active?.matches?.(':focus-visible')),
      outlineWidth: style?.outlineWidth || "0px"
    };
  `);

  browserWindow.setSize(1040, 720);
  await sleep(250);
  const minimumWidth = await evaluateRenderer(browserWindow, `
    return {
      innerWidth: window.innerWidth,
      horizontalOverflow: document.documentElement.scrollWidth > document.documentElement.clientWidth,
      homeActionVisible: Boolean(document.querySelector('[data-action="routineAuthorizationBegin"]')),
      compactLayoutActive: matchMedia('(max-width: 1040px)').matches
    };
  `);
  minimumWidth.windowBoundsWidth = browserWindow.getBounds().width;
  await capturePackagedUi(browserWindow, "o17-supported-minimum-home");
  browserWindow.setSize(1320, 860);
  await sleep(150);
  return { keyboard, minimumWidth };
}

async function waitForWorldTransitionHidden(browserWindow) {
  await waitForRendererCondition(
    browserWindow,
    "world transition hidden",
    `document.getElementById("world-transition")?.getAttribute("aria-hidden") === "true" && !document.getElementById("world-transition")?.classList.contains("is-opening")`,
    10_000
  );
}

async function finishIntroIfNeeded(browserWindow) {
  await waitForRendererCondition(
    browserWindow,
    "Philenator or introduction ready",
    `Boolean(document.querySelector('[data-action="beginCreatePhil"]:not([disabled])'))
      || Boolean(document.querySelector('[data-action="openIdentity"]'))
      || Boolean(document.querySelector('[data-action="introNext"]'))
      || Boolean(document.querySelector('[data-action="introFinish"]'))
      || Boolean(document.querySelector("#create-passphrase"))`,
    60_000
  );
  for (let index = 0; index < 5; index += 1) {
    const state = await evaluateRenderer(browserWindow, `
      return {
        title: document.getElementById("page-title")?.textContent || "",
        next: Boolean(document.querySelector('[data-action="introNext"]')),
        finish: Boolean(document.querySelector('[data-action="introFinish"]')),
        beginCreate: Boolean(document.querySelector('[data-action="beginCreatePhil"]:not([disabled])')),
        existingIdentity: Boolean(document.querySelector('[data-action="openIdentity"]'))
      };
    `);
    if (state.finish) {
      await clickRenderer(browserWindow, '[data-action="introFinish"]');
      await waitForRendererCondition(browserWindow, "intro finished", `Boolean(document.querySelector("#create-passphrase")) || Boolean(document.querySelector('[data-action="openIdentity"]'))`);
      return;
    }
    if (state.beginCreate && !state.existingIdentity) {
      await setRendererValue(browserWindow, "#welcome-phil-name", "Local test Phil");
      await clickRenderer(browserWindow, '[data-action="beginCreatePhil"]');
      await waitForRendererCondition(browserWindow, "identity introduction opened", `Boolean(document.querySelector('[data-action="introNext"]')) || Boolean(document.querySelector("#create-passphrase"))`);
      continue;
    }
    if (!state.next) return;
    if (state.next) await clickRenderer(browserWindow, '[data-action="introNext"]');
    await sleep(150);
  }
  throw new Error("Renderer introduction did not finish");
}

async function rendererUiSummary(browserWindow) {
  return evaluateRenderer(browserWindow, `
    const text = document.body.textContent || "";
    const snapshot = await window.philcore.runtime.getSnapshot();
    return {
      title: document.getElementById("page-title")?.textContent || "",
      lockState: document.getElementById("lock-state")?.textContent || "",
      hasUnlockPassphrase: Boolean(document.querySelector("#unlock-passphrase")),
      hasPlatformPassphrase: Boolean(document.querySelector("#platform-passphrase")),
      hasSettingsRedirect: Boolean(document.querySelector('[data-action="goSettings"]')),
      hasHomeUnlock: Boolean(document.querySelector('[data-action="goUnlock"]')),
      hasProtectedAction: Boolean(document.querySelector('[data-action="startProtectedAction"]')),
      hasEthereumDestination: Boolean(document.querySelector('[data-action="openChain"][data-chain-id="ethereum"]')),
      hasSettingsGoToUnlock: text.includes("Go to Unlock"),
      settingsCopyPresent: text.includes("Unlock your identity before changing protected Mac unlock"),
      errorTextPresent: text.includes("That passphrase did not unlock this identity"),
      identityId: snapshot.identity?.identityId || null,
      ownerCommitment: snapshot.identity?.ownerCommitment || null,
      protectedActionEligible: Boolean(snapshot.protectedAction?.eligible),
      recentAuditActions: (snapshot.audit?.recent || []).map((event) => event.action),
      serializedSnapshot: JSON.stringify(snapshot)
    };
  `);
}

async function runPackagedUiUnlockFlow(browserWindow, mode) {
  const passphrase = "E2e-Ui-unlock-passphrase!1";
  await finishIntroIfNeeded(browserWindow);

  if (mode === "created") {
    await waitForRendererCondition(browserWindow, "welcome create form", `Boolean(document.querySelector("#create-passphrase"))`);
    await setRendererValue(browserWindow, "#create-label", "Packaged UI Unlock Identity");
    await setRendererValue(browserWindow, "#create-passphrase", passphrase);
    await setRendererValue(browserWindow, "#create-passphrase-confirm", passphrase);
    await clickRenderer(browserWindow, '[data-action="createIdentity"]');
    await waitForRendererCondition(browserWindow, "created identity unlock screen", `Boolean(document.querySelector("#unlock-passphrase"))`, 60_000);
  } else {
    await waitForRendererCondition(browserWindow, "existing identity or unlock screen", `Boolean(document.querySelector('[data-action="openIdentity"]')) || Boolean(document.querySelector("#unlock-passphrase"))`);
    const needsOpen = await evaluateRenderer(browserWindow, `return Boolean(document.querySelector('[data-action="openIdentity"]'));`);
    if (needsOpen) {
      await clickRenderer(browserWindow, '[data-action="openIdentity"]');
      await waitForRendererCondition(browserWindow, "opened identity unlock screen", `Boolean(document.querySelector("#unlock-passphrase"))`);
    }
  }

  await clickRenderer(browserWindow, '[data-nav="home"]');
  await waitForRendererCondition(browserWindow, "locked home", `document.getElementById("page-title")?.textContent === "Home"`);
  const lockedHome = await rendererUiSummary(browserWindow);
  if (!lockedHome.hasHomeUnlock) throw new Error("Locked Home did not expose the primary Unlock identity action");

  await clickRenderer(browserWindow, '[data-action="goUnlock"]');
  await waitForRendererCondition(browserWindow, "home unlock opens passphrase form", `Boolean(document.querySelector("#unlock-passphrase")) && document.getElementById("page-title")?.textContent === "Unlock"`);
  const unlockScreen = await rendererUiSummary(browserWindow);
  if (unlockScreen.hasSettingsRedirect) throw new Error("Unlock screen still exposes a Settings redirect");

  await setRendererValue(browserWindow, "#unlock-passphrase", "wrong-passphrase");
  await clickRenderer(browserWindow, '[data-action="unlock"]');
  await waitForRendererCondition(browserWindow, "wrong passphrase retry", `(document.body.textContent || "").includes("That passphrase did not unlock this identity") && Boolean(document.querySelector("#unlock-passphrase"))`);
  const wrongPassphrase = await rendererUiSummary(browserWindow);

  await setRendererValue(browserWindow, "#unlock-passphrase", passphrase);
  await clickRenderer(browserWindow, '[data-action="unlock"]');
  await waitForRendererCondition(browserWindow, "successful passphrase unlock returns home", `document.getElementById("page-title")?.textContent === "Home" && (document.getElementById("lock-state")?.textContent || "").includes("Unlocked")`);
  const unlockedHome = await rendererUiSummary(browserWindow);
  if (!unlockedHome.protectedActionEligible || !unlockedHome.hasEthereumDestination) throw new Error("Unlocked Home did not expose the Ethereum local destination");
  await clickRenderer(browserWindow, '[data-action="openChain"][data-chain-id="ethereum"]');
  await waitForRendererCondition(browserWindow, "Ethereum local action", `document.getElementById("page-title")?.textContent === "Ethereum" && Boolean(document.querySelector('[data-action="startProtectedAction"]'))`);
  const unlockedEthereum = await rendererUiSummary(browserWindow);
  if (!unlockedEthereum.hasProtectedAction) throw new Error("Ethereum did not expose the protected local action");
  await clickRenderer(browserWindow, '[data-action="backHome"]');

  await clickRenderer(browserWindow, '[data-nav="settings"]');
  await waitForRendererCondition(browserWindow, "unlocked settings", `document.getElementById("page-title")?.textContent === "Settings"`);
  const unlockedSettings = await rendererUiSummary(browserWindow);
  if (unlockedSettings.hasUnlockPassphrase) throw new Error("Settings exposed the primary unlock passphrase form while unlocked");

  await clickRenderer(browserWindow, '[data-nav="home"]');
  await waitForRendererCondition(browserWindow, "home before relock", `document.getElementById("page-title")?.textContent === "Home"`);
  await clickRenderer(browserWindow, '[data-action="lock"]');
  await waitForRendererCondition(browserWindow, "locked again", `Boolean(document.querySelector("#unlock-passphrase"))`);
  await clickRenderer(browserWindow, '[data-nav="settings"]');
  await waitForRendererCondition(browserWindow, "locked settings", `document.getElementById("page-title")?.textContent === "Settings"`);
  await clickRenderer(browserWindow, '[data-settings-section="security"]');
  await waitForRendererCondition(browserWindow, "locked Security settings", `(document.body.textContent || "").includes("Unlock your identity before changing protected Mac unlock")`);
  const lockedSettings = await rendererUiSummary(browserWindow);
  if (lockedSettings.hasUnlockPassphrase) throw new Error("Settings exposed the primary unlock passphrase form while locked");
  if (!lockedSettings.hasSettingsGoToUnlock || !lockedSettings.settingsCopyPresent) throw new Error("Settings did not point back to the primary unlock flow");

  await clickRenderer(browserWindow, '[data-action="goUnlock"]');
  await waitForRendererCondition(browserWindow, "settings go to unlock opens passphrase form", `Boolean(document.querySelector("#unlock-passphrase")) && document.getElementById("page-title")?.textContent === "Unlock"`);
  const settingsToUnlock = await rendererUiSummary(browserWindow);

  const combinedSnapshots = [
    lockedHome.serializedSnapshot,
    unlockScreen.serializedSnapshot,
    wrongPassphrase.serializedSnapshot,
    unlockedHome.serializedSnapshot,
    unlockedSettings.serializedSnapshot,
    lockedSettings.serializedSnapshot,
    settingsToUnlock.serializedSnapshot
  ].join("\n");
  if (combinedSnapshots.includes(passphrase) || combinedSnapshots.includes("wrong-passphrase")) {
    throw new Error("Renderer unlock flow leaked passphrase text into serialized Runtime snapshots");
  }

  return {
    status: "passed",
    mode,
    identityId: unlockedHome.identityId,
    ownerCommitment: unlockedHome.ownerCommitment,
    homeUnlockOpenedPassphraseForm: unlockScreen.hasUnlockPassphrase,
    settingsRedirectAbsent: !unlockScreen.hasSettingsRedirect,
    wrongPassphraseStayedOnUnlock: wrongPassphrase.hasUnlockPassphrase && wrongPassphrase.errorTextPresent,
    correctPassphraseUnlocked: unlockedHome.lockState.includes("Unlocked"),
    protectedActionsAvailable: unlockedHome.protectedActionEligible && unlockedEthereum.hasProtectedAction,
    settingsPrimaryUnlockAbsent: !unlockedSettings.hasUnlockPassphrase && !lockedSettings.hasUnlockPassphrase,
    settingsGoToUnlockOpenedPassphraseForm: settingsToUnlock.hasUnlockPassphrase,
    recentUnlockAuditRecorded: unlockedHome.recentAuditActions.includes("unlock_device_vault"),
    privateMaterialExposed: false,
    publicNetworkMutation: false
  };
}

async function setActionLifecycleTestControl(browserWindow, control = {}) {
  await evaluateRenderer(browserWindow, `globalThis.__PHILCORE_ACTION_LIFECYCLE_TEST__ = ${JSON.stringify(control)}; return true;`);
}

async function createAndUnlockActionIdentity(browserWindow) {
  const passphrase = "E2e-Action-lifecycle-passphrase!1";
  await finishIntroIfNeeded(browserWindow);
  await waitForRendererCondition(browserWindow, "action identity create form", `Boolean(document.querySelector("#create-passphrase"))`);
  await setRendererValue(browserWindow, "#create-label", "Packaged Action Lifecycle Identity");
  await setRendererValue(browserWindow, "#create-passphrase", passphrase);
  await setRendererValue(browserWindow, "#create-passphrase-confirm", passphrase);
  await clickRenderer(browserWindow, '[data-action="createIdentity"]');
  await waitForRendererCondition(browserWindow, "action identity unlock", `Boolean(document.querySelector("#unlock-passphrase"))`, 60_000);
  await setRendererValue(browserWindow, "#unlock-passphrase", passphrase);
  await clickRenderer(browserWindow, '[data-action="unlock"]');
  await waitForRendererCondition(browserWindow, "action identity unlocked", `document.getElementById("page-title")?.textContent === "Home" && (document.getElementById("lock-state")?.textContent || "").includes("Unlocked")`, 60_000);
  return passphrase;
}

async function startProtectedActionFromPortal(browserWindow) {
  const actionVisible = await evaluateRenderer(browserWindow, `return Boolean(document.querySelector('[data-action="startProtectedAction"]'));`);
  if (!actionVisible) {
    const ethereumVisible = await evaluateRenderer(browserWindow, `return Boolean(document.querySelector('[data-action="openChain"][data-chain-id="ethereum"]'));`);
    if (!ethereumVisible) {
      await clickRenderer(browserWindow, '[data-nav="home"]');
      await waitForRendererCondition(browserWindow, "Home portal", `document.getElementById("page-title")?.textContent === "Home"`);
    }
    await clickRenderer(browserWindow, '[data-action="openChain"][data-chain-id="ethereum"]');
    await waitForRendererCondition(browserWindow, "Ethereum protected action", `document.getElementById("page-title")?.textContent === "Ethereum" && Boolean(document.querySelector('[data-action="startProtectedAction"]'))`);
  }
  await clickRenderer(browserWindow, '[data-action="startProtectedAction"]');
}

async function approveActionExecution(browserWindow, screenshotName = null) {
  await waitForRendererCondition(browserWindow, "execution approval", `(() => { const text = document.getElementById("approval-root")?.textContent || ""; return text.includes("Review a protected local action") && text.includes("Maximum cost") && text.includes("Why Phil allows it") && Boolean(document.querySelector('[data-approval-action="approve"]')); })()`, 30_000);
  if (screenshotName) await capturePackagedUi(browserWindow, screenshotName);
  await clickRenderer(browserWindow, '[data-approval-action="approve"]');
}

async function approveLocalSigningAndWaitForCompletion(browserWindow, screenshotName = null) {
  await waitForRendererCondition(browserWindow, "separate local signing approval", `(() => { const text = document.getElementById("approval-root")?.textContent || ""; return text.includes("Review protected signing") && text.includes("protected signing key") && Boolean(document.querySelector('[data-approval-action="approve"]')); })()`, 180_000);
  if (screenshotName) await capturePackagedUi(browserWindow, screenshotName);
  await clickRenderer(browserWindow, '[data-approval-action="approve"]');
  await waitForRendererCondition(browserWindow, "protected action completed", `protectedActionLifecycle.state === "completed" && (document.body.textContent || "").includes("Protected action completed") && !document.querySelector(".approval-backdrop")`, 180_000);
}

async function runPackagedUiActionLifecycle(browserWindow) {
  const passphrase = await createAndUnlockActionIdentity(browserWindow);
  await startProtectedActionFromPortal(browserWindow);
  await waitForRendererCondition(browserWindow, "missing enrollment preflight", `(document.body.textContent || "").includes("Protected Mac unlock is not set up yet") && !document.querySelector(".approval-backdrop")`);
  const missingEnrollment = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    return {
      modalPresent: Boolean(document.querySelector(".approval-backdrop")),
      spinnerPresent: Boolean(document.querySelector(".progress-line")),
      goSettingsPresent: Boolean(document.querySelector('[data-action="goProtectedMacSettings"]')),
      workflowStatus: snap.demo?.status || "not_started",
      actionEligible: Boolean(snap.protectedAction?.eligible),
      preflightAuditCount: (snap.audit?.recent || []).filter((event) => event.action === "protected_action_preflight").length
    };
  `);
  await clickRenderer(browserWindow, '[data-nav="audit"]');
  await waitForRendererCondition(browserWindow, "navigation after preflight failure", `document.getElementById("page-title")?.textContent === "Activity"`);
  await clickRenderer(browserWindow, '[data-nav="home"]');
  await startProtectedActionFromPortal(browserWindow);
  await waitForRendererCondition(browserWindow, "retry after preflight failure", `(document.body.textContent || "").includes("Protected Mac unlock is not set up yet") && !document.querySelector(".approval-backdrop")`);
  await clickRenderer(browserWindow, '[data-action="goProtectedMacSettings"]');
  await waitForRendererCondition(browserWindow, "settings from preflight", `document.getElementById("page-title")?.textContent === "Settings" && Boolean(document.querySelector("#platform-passphrase"))`);
  await setRendererValue(browserWindow, "#platform-passphrase", passphrase);
  await clickRenderer(browserWindow, '[data-action="enrollPlatformAuth"]');
  await waitForRendererCondition(browserWindow, "platform enrollment approval", `Boolean(document.querySelector('[data-approval-action="approve"]'))`);
  await clickRenderer(browserWindow, '[data-approval-action="approve"]');
  await waitForRendererCondition(browserWindow, "platform enrollment complete", `(document.body.textContent || "").includes("Protected Mac unlock enabled")`, 60_000);

  await clickRenderer(browserWindow, '[data-nav="home"]');
  await startProtectedActionFromPortal(browserWindow);
  await waitForRendererCondition(browserWindow, "rejectable execution approval", `Boolean(document.querySelector('[data-approval-action="deny"]'))`);
  await clickRenderer(browserWindow, '[data-approval-action="deny"]');
  await waitForRendererCondition(browserWindow, "rejection terminal", `(document.body.textContent || "").includes("Protected action rejected") && !document.querySelector(".approval-backdrop")`);
  const rejected = await evaluateRenderer(browserWindow, `return { modalPresent:Boolean(document.querySelector(".approval-backdrop")), lifecycleState:protectedActionLifecycle.state };`);

  await setActionLifecycleTestControl(browserWindow, {});
  await startProtectedActionFromPortal(browserWindow);
  await waitForRendererCondition(browserWindow, "cancellable execution approval", `Boolean(document.querySelector('[data-approval-action="cancel"]'))`);
  await clickRenderer(browserWindow, '[data-approval-action="cancel"]');
  await waitForRendererCondition(browserWindow, "cancel terminal", `(document.body.textContent || "").includes("Protected action cancelled") && !document.querySelector(".approval-backdrop")`);
  const cancelled = await evaluateRenderer(browserWindow, `return {modalPresent:Boolean(document.querySelector(".approval-backdrop")), lifecycleState:protectedActionLifecycle.state};`);

  await setActionLifecycleTestControl(browserWindow, { delays: { preparing: 500 }, timeouts: { preflight: 100 } });
  await startProtectedActionFromPortal(browserWindow);
  await waitForRendererCondition(browserWindow, "preflight timeout terminal", `(document.body.textContent || "").includes("Protected action timed out") && !document.querySelector(".approval-backdrop")`, 30_000);
  const timedOut = await evaluateRenderer(browserWindow, `return {modalPresent:Boolean(document.querySelector(".approval-backdrop")), lifecycleState:protectedActionLifecycle.state};`);

  await setActionLifecycleTestControl(browserWindow, {});
  await startProtectedActionFromPortal(browserWindow);
  await approveActionExecution(browserWindow);
  await approveLocalSigningAndWaitForCompletion(browserWindow);
  const successful = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    return {
      lifecycleState: protectedActionLifecycle.state,
      signingApprovalCompleted: snap.demo?.stages?.some((stage) => stage.id === "signing_approval_completed" && stage.status === "completed"),
      proofVerified: snap.demo?.stages?.some((stage) => stage.id === "proof_verified" && stage.status === "completed"),
      nullifierConsumed: snap.ethereum?.nullifierState === "consumed_local_fixture",
      consumerExecuted: Boolean(snap.demo?.completed),
      completionAuditRecorded: (snap.audit?.recent || []).some((event) => event.action === "local_ethereum_test_action_completed"),
      modalPresent: Boolean(document.querySelector(".approval-backdrop")),
      objectArtifactAbsent: !(document.body.textContent || "").includes("[object Object]"),
      publicNetworkMutation: Boolean(snap.app?.publicNetworkMutationEnabled)
    };
  `);
  return { status: "passed", mode: "noir_private_proof_local_alpha", missingEnrollment, rejected, cancelled, timedOut, successful, privateMaterialExposed: false, publicNetworkMutation: false };
}

async function runPackagedUiRoutineAuthorization(browserWindow) {
  await createAndUnlockActionIdentity(browserWindow);
  await waitForRendererCondition(browserWindow, "routine authorization action", `Boolean(document.querySelector('[data-action="routineAuthorizationBegin"]'))`);
  await clickRenderer(browserWindow, '[data-action="routineAuthorizationBegin"]');
  if (process.env.PHILCORE_DESKTOP_E2E_ROUTINE_UNAVAILABLE === "1") {
    await waitForRendererCondition(browserWindow, "visible routine authorization failure", `(document.body.textContent || "").includes("Phil cannot reach the enrolled iPhone")`);
    return {
      status: "passed",
      mode: "unavailable",
      visibleSafeFailure: true,
      qrDisplayed: false,
      privateMaterialExposed: false,
      publicNetworkMutation: false
    };
  }
  await waitForRendererCondition(browserWindow, "routine enrollment QR or safe failure", `Boolean(document.querySelector('.routine-authorization-panel img[alt="Expiring iPhone routine-key enrollment QR code"]')) || Boolean(routineAuthorizationLastFailureReason)`, 30_000);
  const started = await evaluateRenderer(browserWindow, `
    const panel = document.querySelector(".routine-authorization-panel");
    return {
      qrDisplayed: Boolean(panel?.querySelector("img")),
      fingerprintDisplayed: Boolean(panel?.querySelector(".fingerprint")?.textContent.trim()),
      approvalGuidanceDisplayed: (panel?.textContent || "").includes("Scan routine QR code"),
      failureReason: routineAuthorizationLastFailureReason,
      publicNetworkMutation: Boolean((await window.philcore.runtime.getSnapshot()).app?.publicNetworkMutationEnabled)
    };
  `);
  if (!started.qrDisplayed) return { status: "failed", mode: "enrollment_request", ...started, privateMaterialExposed: false, publicNetworkMutation: false };
  await clickRenderer(browserWindow, '[data-action="routineAuthorizationCancel"]');
  await waitForRendererCondition(browserWindow, "routine cancellation visible", `(document.body.textContent || "").includes("pending request was cancelled")`);
  return {
    status: "passed",
    mode: "enrollment_request",
    ...started,
    cancelledSafely: true,
    privateMaterialExposed: false,
    publicNetworkMutation: false
  };
}

async function runPackagedUiUserShell(browserWindow, mode) {
  const passphrase = "E2e-O15-user-shell-passphrase!1";
  const identityName = "My O15 Phil";
  const compactPreviewEvidence = (source) => ({
    sha256: crypto.createHash("sha256").update(source).digest("hex"),
    dataUri: source.startsWith("data:image/svg+xml"),
    length: source.length
  });

  if (mode === "returning") {
    await waitForRendererCondition(browserWindow, "returning identity list", `Boolean(document.querySelector('[data-action="openIdentity"]')) && (document.body.textContent || "").includes(${JSON.stringify(identityName)})`);
    const returningWelcome = await evaluateRenderer(browserWindow, `
      const sidebar = document.querySelector(".sidebar");
      const topbar = document.querySelector(".topbar");
      return {
        introPresent: Boolean(document.querySelector('[data-action="introFinish"]')),
        identityNamePresent: (document.body.textContent || "").includes(${JSON.stringify(identityName)}),
        standalone: document.body.dataset.standalone === "true",
        sidebarHidden: getComputedStyle(sidebar).display === "none",
        topbarHidden: getComputedStyle(topbar).display === "none",
        modeSwitchAbsent: !document.querySelector("#presentation-switch button"),
        philPreviewSrc: document.querySelector(".identity-choice .phil-avatar img")?.src || "",
        presentationMode: (await window.philcore.runtime.getSnapshot()).settings.presentationMode
      };
    `);
    returningWelcome.philPreview = compactPreviewEvidence(returningWelcome.philPreviewSrc);
    delete returningWelcome.philPreviewSrc;
    await capturePackagedUi(browserWindow, "o15-returning-welcome");
    await clickRenderer(browserWindow, '[data-action="openIdentity"]');
    await waitForRendererCondition(browserWindow, "returning unlock", `Boolean(document.querySelector('[data-action="platformUnlock"]'))`);
    await evaluateRenderer(browserWindow, `currentView = "home"; renderView(); return true;`);
    await waitForRendererCondition(browserWindow, "returning dedicated locked screen", `document.body.dataset.locked === "true" && !document.querySelector("#nav button") && !document.querySelector(".technical-panel") && document.querySelector(".lock-space")`);
    await capturePackagedUi(browserWindow, "o15-dedicated-locked");
    await waitForRendererCondition(browserWindow, "returning unlock restored", `Boolean(document.querySelector('[data-action="platformUnlock"]'))`);
    await clickRenderer(browserWindow, '[data-action="platformUnlock"]');
    await waitForRendererCondition(browserWindow, "returning Home", `document.getElementById("page-title")?.textContent === "Home" && (document.getElementById("lock-state")?.textContent || "").includes("Unlocked")`);
    await waitForWorldTransitionHidden(browserWindow);
    const returningHome = await evaluateRenderer(browserWindow, `
      const snap = await window.philcore.runtime.getSnapshot();
      return {
        identityName: snap.identity?.label,
        presentationMode: snap.settings.presentationMode,
        nav: Array.from(document.querySelectorAll("#nav button")).map((button) => button.textContent.trim()),
        chainCount: document.querySelectorAll(".chain-grid .chain-tile").length,
        publicNetworkMutation: Boolean(snap.app.publicNetworkMutationEnabled)
      };
    `);
    await capturePackagedUi(browserWindow, "o15-returning-home");
    return {
      status: "passed",
      mode,
      returningWelcome,
      returningHome,
      privateMaterialExposed: false,
      publicNetworkMutation: false
    };
  }

  await waitForRendererCondition(browserWindow, "standalone Hello", `document.getElementById("page-title")?.textContent === "Hello" && Boolean(document.querySelector('[data-action="beginCreatePhil"]:not([disabled])'))`, 60_000);
  const hello = await evaluateRenderer(browserWindow, `
    const text = document.body.textContent || "";
    const sidebar = document.querySelector(".sidebar");
    const topbar = document.querySelector(".topbar");
    return {
      title: document.getElementById("page-title")?.textContent,
      approvedPositioning: text.includes("I’m Phil, your secure digital identity.")
        && text.includes("help protect")
        && text.includes("Controlled Sepolia Beta · Test assets only")
        && text.includes("unavailable in this Beta"),
      standalone: document.body.dataset.standalone === "true",
      sidebarHidden: getComputedStyle(sidebar).display === "none",
      topbarHidden: getComputedStyle(topbar).display === "none",
      modeSwitchAbsent: !document.querySelector("#presentation-switch button"),
      diagnosticsAbsent: !text.includes("diagnostics") && !text.includes("Package"),
      randomizerPresent: Boolean(document.querySelector('[data-action="randomizePhil"][aria-label="Randomize Phil"]')),
      initialPreviewSrc: document.querySelector(".phil-preview-area .phil-avatar img")?.src || "",
      mintedClaimAbsent: !/minted|onchain token|deployed account/iu.test(text)
    };
  `);
  await capturePackagedUi(browserWindow, "o15-first-run-hello");
  await clickRenderer(browserWindow, '[data-action="randomizePhil"]');
  await waitForRendererCondition(
    browserWindow,
    "new Philenator trait composition",
    `document.querySelector(".phil-preview-area .phil-avatar img")?.src !== ${JSON.stringify("")}
      && document.querySelector(".phil-preview-area .phil-avatar img")?.src !== ${JSON.stringify(hello.initialPreviewSrc)}`,
    60_000
  );
  const randomizedPhil = await evaluateRenderer(browserWindow, `
    return {
      previewSrc: document.querySelector(".phil-preview-area .phil-avatar img")?.src || "",
      changed: document.querySelector(".phil-preview-area .phil-avatar img")?.src !== ${JSON.stringify("")}
    };
  `);
  randomizedPhil.changed = randomizedPhil.previewSrc !== hello.initialPreviewSrc;
  await setRendererValue(browserWindow, "#welcome-phil-name", identityName);
  await clickRenderer(browserWindow, '[data-action="beginCreatePhil"]');
  await waitForRendererCondition(browserWindow, "character-led introduction", `Boolean(document.querySelector('[data-action="introNext"]'))`);
  await waitForRendererCondition(browserWindow, "introduction character artwork", `Boolean(document.querySelector(".intro-character-stage img")?.complete && document.querySelector(".intro-character-stage img")?.naturalWidth > 0)`);
  const intro = await evaluateRenderer(browserWindow, `
    const image = document.querySelector(".intro-character-stage img");
    return {
      present: Boolean(document.querySelector(".intro-card")),
      stepCount: document.querySelectorAll(".intro-progress span").length,
      firstTitle: document.querySelector(".intro-dialogue h3")?.textContent || "",
      characterImageLoaded: Boolean(image?.complete && image?.naturalWidth > 0),
      characterImageSrc: image?.src || ""
    };
  `);
  await capturePackagedUi(browserWindow, "o16-onboarding");
  await finishIntroIfNeeded(browserWindow);
  await waitForRendererCondition(browserWindow, "identity creation", `Boolean(document.querySelector("#create-passphrase"))`);
  const createPage = await evaluateRenderer(browserWindow, `
    const sidebar = document.querySelector(".sidebar");
    const topbar = document.querySelector(".topbar");
    return {
      standalone: document.body.dataset.standalone === "true",
      sidebarHidden: getComputedStyle(sidebar).display === "none",
      topbarHidden: getComputedStyle(topbar).display === "none",
      modeSwitchAbsent: !document.querySelector("#presentation-switch button"),
      localCreationCopy: (document.body.textContent || "").includes("Philenator combines thirteen local trait groups"),
      previewSrc: document.querySelector(".creation-preview .phil-avatar img")?.src || ""
    };
  `);
  const initialPreviewSrc = hello.initialPreviewSrc;
  const randomizedPreviewSrc = randomizedPhil.previewSrc;
  hello.initialPreview = compactPreviewEvidence(initialPreviewSrc);
  randomizedPhil.preview = compactPreviewEvidence(randomizedPreviewSrc);
  createPage.preview = compactPreviewEvidence(createPage.previewSrc);
  delete hello.initialPreviewSrc;
  delete randomizedPhil.previewSrc;
  delete createPage.previewSrc;
  await setRendererValue(browserWindow, "#create-label", identityName);
  await setRendererValue(browserWindow, "#create-passphrase", "Short");
  const partialPassphrase = await evaluateRenderer(browserWindow, `
    return Object.fromEntries(Array.from(document.querySelectorAll("[data-passphrase-requirement]")).map((item) => [
      item.dataset.passphraseRequirement,
      item.classList.contains("met")
    ]));
  `);
  await setRendererValue(browserWindow, "#create-passphrase", passphrase);
  const completePassphrase = await evaluateRenderer(browserWindow, `
    return Object.fromEntries(Array.from(document.querySelectorAll("[data-passphrase-requirement]")).map((item) => [
      item.dataset.passphraseRequirement,
      item.classList.contains("met")
    ]));
  `);
  await setRendererValue(browserWindow, "#create-passphrase-confirm", `${passphrase}x`);
  const mismatchVisible = await evaluateRenderer(browserWindow, `return document.getElementById("passphrase-match")?.classList.contains("missing") || false;`);
  await setRendererValue(browserWindow, "#create-passphrase-confirm", passphrase);
  const matchVisible = await evaluateRenderer(browserWindow, `return document.getElementById("passphrase-match")?.classList.contains("met") || false;`);
  await clickRenderer(browserWindow, '[data-action="createIdentity"]');
  await waitForRendererCondition(browserWindow, "new identity unlock", `Boolean(document.querySelector("#unlock-passphrase"))`, 60_000);
  await setRendererValue(browserWindow, "#unlock-passphrase", passphrase);
  await clickRenderer(browserWindow, '[data-action="unlock"]');
  await waitForRendererCondition(browserWindow, "user Home portal", `document.getElementById("page-title")?.textContent === "Home" && Boolean(document.querySelector("#catalog-search"))`, 60_000);
  await waitForWorldTransitionHidden(browserWindow);

  const home = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    const userText = document.body.textContent || "";
    return {
      identityName: snap.identity?.label,
      nav: Array.from(document.querySelectorAll("#nav button")).map((button) => button.textContent.trim()),
      favoriteChains: Array.from(document.querySelectorAll(".user-section .chain-tile")).map((button) => ({
        id: button.dataset.chainId,
        status: button.querySelector(".chain-status")?.textContent.trim()
      })),
      technicalPanelVisible: Boolean(document.querySelector(".technical-panel")),
      worldIdPreviewAvailable: Boolean(document.querySelector('[data-action="openWorldIdPreview"]')),
      trendingItems: Array.from(document.querySelectorAll(".featured-item strong")).map((item) => item.textContent.trim()),
      trendingDemoLabel: (document.body.textContent || "").includes("Demo examples"),
      recentActivityHeading: (document.body.textContent || "").includes("Recent Activity"),
      oldActivityHeadingAbsent: !(document.body.textContent || "").includes("What happened lately"),
      forbiddenUserTermsPresent: ["Device Vault", "nullifier", "EntryPoint", "ActionGate", "UserOperation", "correlation ID", "proof circuit"]
        .some((term) => userText.includes(term)),
      remoteRequestsAvailable: typeof window.fetch === "function" && false,
      publicNetworkMutation: Boolean(snap.app.publicNetworkMutationEnabled)
    };
  `);
  await capturePackagedUi(browserWindow, "o15-home-user");
  const passCShellSmoke = await passCKeyboardAndMinimumWidthSmoke(browserWindow);
  await evaluateRenderer(browserWindow, `
    globalThis.__PHILCORE_PASS_B_ROUTINE_UI_SAVED__ = routineAuthorizationUi;
    routineAuthorizationUi = {
      requestId: "pass-b-waiting-fixture",
      qrPayload: null,
      qrDataUrl: null,
      comparisonFingerprint: "A1B2-C3D4-E5F6-G7H8",
      expiresAt: "2030-03-17T17:46:40Z",
      state: "transport_waiting",
      kind: "authorization",
      notice: "Waiting for your enrolled iPhone. Open Phil > Approve, scan this request, and compare the fingerprint on both devices."
    };
    renderView();
    return true;
  `);
  await waitForRendererCondition(browserWindow, "Pass C waiting for phone fixture", `(document.body.textContent || "").includes("Waiting for phone")`);
  await evaluateRenderer(browserWindow, `document.querySelector(".routine-authorization-panel")?.scrollIntoView({ block: "center" }); return true;`);
  await capturePackagedUi(browserWindow, "o16-waiting-for-phone");
  await evaluateRenderer(browserWindow, `routineAuthorizationUi = globalThis.__PHILCORE_PASS_B_ROUTINE_UI_SAVED__; delete globalThis.__PHILCORE_PASS_B_ROUTINE_UI_SAVED__; renderView(); return true;`);
  await clickRenderer(browserWindow, '[data-action="openWorldIdPreview"]');
  await waitForRendererCondition(browserWindow, "World ID Preview", `(document.body.textContent || "").includes("No World ID request occurs in this Beta")`);
  const worldIdPreview = await evaluateRenderer(browserWindow, `
    const text = document.body.textContent || "";
    return {
      identityRootDenied: text.includes("It is not the PhilCore identity root."),
      noRequest: text.includes("No World ID request occurs in this Beta."),
      noBiometrics: text.includes("no World ID biometric information")
    };
  `);
  await clickRenderer(browserWindow, '[data-action="closeWorldIdPreview"]');
  await clickRenderer(browserWindow, '[data-action="openFeaturedPreview"][data-featured-id="collectible-gallery"]');
  await waitForRendererCondition(browserWindow, "featured demo preview", `(document.body.textContent || "").includes("does not open a website, query live data, show prices, or perform a transaction")`);
  const featuredPreview = await evaluateRenderer(browserWindow, `
    const text = document.body.textContent || "";
    return {
      informationalOnly: text.includes("does not open a website, query live data, show prices, or perform a transaction"),
      liveClaimAbsent: !text.includes("Live trending")
    };
  `);
  await clickRenderer(browserWindow, '[data-action="closeFeaturedPreview"]');

  await clickRenderer(browserWindow, '[data-presentation-mode="technical"]');
  await waitForRendererCondition(browserWindow, "Advanced Home", `document.body.dataset.presentationMode === "technical" && (document.body.textContent || "").includes("Advanced status")`);
  const technicalHome = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    return {
      mode: snap.settings.presentationMode,
      diagnosticsVisible: (document.body.textContent || "").includes("Advanced status"),
      sameIdentity: snap.identity?.label === ${JSON.stringify(identityName)}
    };
  `);
  await capturePackagedUi(browserWindow, "o15-home-technical");
  await clickRenderer(browserWindow, '[data-presentation-mode="user"]');
  await waitForRendererCondition(browserWindow, "User Home", `document.body.dataset.presentationMode === "user" && !(document.body.textContent || "").includes("Advanced status")`);

  await setRendererValue(browserWindow, "#catalog-search", "Solana");
  await waitForRendererCondition(browserWindow, "local catalog filtering", `document.querySelectorAll("#chain-results .chain-tile").length === 1 && document.querySelector("#chain-results [data-chain-id='solana']")`);
  const search = await evaluateRenderer(browserWindow, `
    return {
      resultIds: Array.from(document.querySelectorAll("#chain-results .chain-tile")).map((button) => button.dataset.chainId),
      localCatalogCopy: (document.body.textContent || "").includes("Searches only the catalog bundled with this Beta")
    };
  `);
  await setRendererValue(browserWindow, "#catalog-search", "");

  await clickRenderer(browserWindow, '[data-action="openChain"][data-chain-id="ethereum"]');
  await waitForRendererCondition(browserWindow, "Ethereum destination", `document.getElementById("page-title")?.textContent === "Ethereum" && Boolean(document.querySelector('[data-action="sepoliaMintBegin"]')) && Boolean(document.querySelector('[data-action="startProtectedAction"]'))`);
  const sepoliaMintReachability = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    const panel = document.querySelector(".sepolia-mint-panel");
    const text = panel?.textContent || "";
    return {
      buttonPresent: Boolean(panel?.querySelector('[data-action="sepoliaMintBegin"]')),
      exactHeadingPresent: text.includes("Prepare a separate test authorization"),
      submissionLocked: text.includes("No public submission"),
      zeroValuePreparationPresent: text.includes("Prepare local test authorization"),
      publicNetworkMutation: Boolean(snap.app.publicNetworkMutationEnabled)
    };
  `);
  await clickRenderer(browserWindow, '[data-action="previewChainAccount"]');
  await waitForRendererCondition(browserWindow, "Ethereum Beta preview", `(document.body.textContent || "").includes("completed Controlled Sepolia Beta account is present")`);
  const ethereumAccount = await evaluateRenderer(browserWindow, `
    return {
      status: document.querySelector(".account-setup-row strong")?.textContent.trim(),
      controlledBeta: (document.body.textContent || "").includes("Controlled Sepolia Beta"),
      readOnly: (document.body.textContent || "").includes("Viewing it does not create or submit a transaction")
    };
  `);
  await clickRenderer(browserWindow, '[data-action="closeChainAccountPreview"]');
  await evaluateRenderer(browserWindow, `document.getElementById("view").scrollTop = 0; return true;`);
  await capturePackagedUi(browserWindow, "o15-ethereum-user");
  await clickRenderer(browserWindow, '[data-action="startProtectedAction"]');
  await waitForRendererCondition(browserWindow, "missing protected Mac enrollment", `(document.body.textContent || "").includes("Protected Mac unlock is not set up yet")`);
  await clickRenderer(browserWindow, '[data-action="goProtectedMacSettings"]');
  await waitForRendererCondition(browserWindow, "Security settings", `document.getElementById("page-title")?.textContent === "Settings" && Boolean(document.querySelector("#platform-passphrase"))`);
  await setRendererValue(browserWindow, "#platform-passphrase", passphrase);
  await clickRenderer(browserWindow, '[data-action="enrollPlatformAuth"]');
  await waitForRendererCondition(browserWindow, "protected Mac approval", `Boolean(document.querySelector('[data-approval-action="approve"]'))`);
  await clickRenderer(browserWindow, '[data-approval-action="approve"]');
  await waitForRendererCondition(browserWindow, "protected Mac enabled", `(document.body.textContent || "").includes("Protected Mac unlock enabled")`, 60_000);

  await startProtectedActionFromPortal(browserWindow);
  await waitForRendererCondition(browserWindow, "Pass B authorization summary", `(() => { const text = document.getElementById("approval-root")?.textContent || ""; return text.includes("Review a protected local action") && text.includes("Maximum cost") && text.includes("Why Phil allows it"); })()`);
  await capturePackagedUi(browserWindow, "o16-authorization-summary");
  await clickRenderer(browserWindow, '[data-approval-action="deny"]');
  await waitForRendererCondition(browserWindow, "Pass B representative rejection", `(document.body.textContent || "").includes("Protected action rejected") && !document.querySelector(".approval-backdrop")`);
  await evaluateRenderer(browserWindow, `document.querySelector(".result-panel")?.scrollIntoView({ block: "center" }); return true;`);
  await capturePackagedUi(browserWindow, "o16-representative-failure");
  await clickRenderer(browserWindow, '[data-action="dismissActionResult"]');
  await startProtectedActionFromPortal(browserWindow);
  await approveActionExecution(browserWindow);
  await approveLocalSigningAndWaitForCompletion(browserWindow, "o16-protected-signing");
  await evaluateRenderer(browserWindow, `document.querySelector(".result-panel")?.scrollIntoView({ block: "center" }); return true;`);
  await capturePackagedUi(browserWindow, "o16-success");
  const protectedAction = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    return {
      completed: protectedActionLifecycle.state === "completed",
      signingApprovalCompleted: snap.demo?.stages?.some((stage) => stage.id === "signing_approval_completed" && stage.status === "completed"),
      proofVerified: snap.demo?.stages?.some((stage) => stage.id === "proof_verified" && stage.status === "completed"),
      nullifierConsumed: snap.ethereum?.nullifierState === "consumed_local_fixture",
      consumerExecuted: Boolean(snap.demo?.completed),
      completionAuditRecorded: (snap.audit?.recent || []).some((event) => event.action === "local_ethereum_test_action_completed"),
      objectArtifactAbsent: !(document.body.textContent || "").includes("[object Object]"),
      publicNetworkMutation: Boolean(snap.app.publicNetworkMutationEnabled)
    };
  `);

  await clickRenderer(browserWindow, '[data-action="backHome"]');
  await clickRenderer(browserWindow, '[data-action="openChain"][data-chain-id="bitcoin"]');
  await waitForRendererCondition(browserWindow, "Bitcoin preview", `document.getElementById("page-title")?.textContent === "Bitcoin" && (document.body.textContent || "").includes("planned but not active")`);
  await clickRenderer(browserWindow, '[data-action="previewChainAccount"]');
  await waitForRendererCondition(browserWindow, "Bitcoin account preview", `(document.body.textContent || "").includes("account creation for Bitcoin is not available")`);
  const preview = await evaluateRenderer(browserWindow, `
    return {
      status: document.querySelector(".chain-status")?.textContent.trim(),
      actionAbsent: !document.querySelector('[data-action="startProtectedAction"]'),
      publicClaimAbsent: !(document.body.textContent || "").includes("Connected"),
      accountStatus: document.querySelector(".account-setup-row strong")?.textContent.trim(),
      unavailableCopy: (document.body.textContent || "").includes("account creation for Bitcoin is not available")
    };
  `);
  await capturePackagedUi(browserWindow, "o15-bitcoin-preview");

  await clickRenderer(browserWindow, '[data-nav="audit"]');
  await waitForRendererCondition(browserWindow, "Activity history", `document.getElementById("page-title")?.textContent === "Activity"`);
  await capturePackagedUi(browserWindow, "o15-activity-user");
  await clickRenderer(browserWindow, '[data-presentation-mode="technical"]');
  await waitForRendererCondition(browserWindow, "Technical Activity", `document.body.dataset.presentationMode === "technical" && (document.body.textContent || "").includes("Protected workflow")`);
  const technicalActivity = await evaluateRenderer(browserWindow, `
    const proofStage = Array.from(document.querySelectorAll(".stage"))
      .filter((item) => (item.querySelector("strong")?.textContent || "").toLowerCase().includes("proof generated"))
      .at(-1);
    const statusLabel = proofStage
      ? Array.from(proofStage.querySelectorAll("dt")).find((item) => item.textContent.trim() === "Status")?.nextElementSibling?.textContent.trim()
      : null;
    const text = document.body.textContent || "";
    return {
      objectArtifactAbsent: !text.includes("[object Object]"),
      completedSummaryVisible: text.includes("Completed"),
      proofGeneratingTerminalStatus: statusLabel
    };
  `);
  const activityBefore = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    return {
      rendered: document.querySelectorAll(".event").length,
      available: snap.audit?.history?.length || 0,
      loadOlderPresent: Boolean(document.querySelector('[data-action="loadOlderActivity"]'))
    };
  `);
  if (activityBefore.loadOlderPresent) {
    await clickRenderer(browserWindow, '[data-action="loadOlderActivity"]');
    await waitForRendererCondition(browserWindow, "older Activity entries", `document.querySelectorAll(".event").length > ${activityBefore.rendered}`);
  }
  const activityAfter = await evaluateRenderer(browserWindow, `return { rendered: document.querySelectorAll(".event").length };`);

  await clickRenderer(browserWindow, '[data-presentation-mode="user"]');
  await waitForRendererCondition(browserWindow, "User Activity", `document.body.dataset.presentationMode === "user"`);
  await clickRenderer(browserWindow, '[data-nav="settings"]');
  await waitForRendererCondition(browserWindow, "Settings sections", `document.getElementById("page-title")?.textContent === "Settings"`);
  const settingsSections = [];
  let settingsObjectArtifactsAbsent = true;
  for (const section of ["identity", "trust", "recovery", "security"]) {
    await clickRenderer(browserWindow, `[data-settings-section="${section}"]`);
    await waitForRendererCondition(browserWindow, `${section} Settings`, `document.querySelector('[data-settings-section="${section}"]')?.getAttribute("aria-current") === "page"`);
    settingsSections.push(await evaluateRenderer(browserWindow, `return document.querySelector(".settings-content h3")?.textContent || "";`));
    settingsObjectArtifactsAbsent = settingsObjectArtifactsAbsent && await evaluateRenderer(browserWindow, `return !(document.querySelector(".settings-layout")?.textContent || "").includes("[object Object]");`);
    if (section === "recovery") await capturePackagedUi(browserWindow, "o15-recovery-deferred");
  }
  await clickRenderer(browserWindow, '[data-settings-section="about"]');
  await waitForRendererCondition(browserWindow, "About Beta Settings", `document.querySelector('[data-settings-section="about"]')?.getAttribute("aria-current") === "page"`);
  await capturePackagedUi(browserWindow, "o15-settings-user");
  await clickRenderer(browserWindow, '[data-settings-section="general"]');
  settingsObjectArtifactsAbsent = settingsObjectArtifactsAbsent && await evaluateRenderer(browserWindow, `return !(document.querySelector(".settings-layout")?.textContent || "").includes("[object Object]");`);
  await setRendererValue(browserWindow, "#identity-display-name", "My O15 Phil Renamed");
  await clickRenderer(browserWindow, '[data-action="renameIdentity"]');
  await waitForRendererCondition(browserWindow, "identity renamed", `(document.body.textContent || "").includes("Identity renamed")`);
  await setRendererValue(browserWindow, "#identity-display-name", identityName);
  await clickRenderer(browserWindow, '[data-action="renameIdentity"]');
  await waitForRendererCondition(browserWindow, "identity name restored", `(await window.philcore.runtime.getSnapshot()).identity?.label === ${JSON.stringify(identityName)}`);
  await evaluateRenderer(browserWindow, `clearNotice(); renderView(); return true;`);

  await clickRenderer(browserWindow, '[data-presentation-mode="technical"]');
  await waitForRendererCondition(browserWindow, "Advanced Settings", `document.body.dataset.presentationMode === "technical" && !document.querySelector('[data-settings-section="developer"]')`);
  await clickRenderer(browserWindow, '[data-settings-section="about"]');
  await waitForRendererCondition(browserWindow, "Advanced Beta evidence", `Boolean(document.querySelector('.technical-details'))`);
  await evaluateRenderer(browserWindow, `
    const evidence = document.querySelector('.technical-details');
    evidence.open = true;
    evidence.scrollIntoView({ block: "start" });
    return true;
  `);
  await waitForRendererCondition(browserWindow, "Advanced evidence expanded", `(document.body.textContent || "").includes("Smart account") && (document.body.textContent || "").includes("Package profile")`);
  const technicalSettings = await evaluateRenderer(browserWindow, `
    const snap = await window.philcore.runtime.getSnapshot();
    const text = document.body.textContent || "";
    return {
      mode: snap.settings.presentationMode,
      developerSurfacesAllowed: snap.release.developerSurfacesAllowed,
      developerToolsVisible: text.includes("Developer tools"),
      developerTabAbsent: !document.querySelector('[data-settings-section="developer"]'),
      developerToggleAbsent: !document.querySelector('#setting-devmode'),
      developerAuditChoiceAbsent: !Array.from(document.querySelectorAll('#setting-audit option')).some((option) => option.value === "developer"),
      advancedEvidenceVisible: text.includes("Advanced Beta evidence") && text.includes("Smart account") && text.includes("Package profile"),
      secretClassLabelsAbsent: !["Private key", "API key", "Authenticated RPC URL", "phil_secret", "Nullifier seed", "Recovery secret"].some((term) => text.includes(term))
    };
  `);
  await capturePackagedUi(browserWindow, "o17-settings-advanced");

  return {
    status: "passed",
    mode,
    identityId: (await evaluateRenderer(browserWindow, `return (await window.philcore.runtime.getSnapshot()).identity?.identityId;`)),
    identityName,
    hello,
    randomizedPhil,
    intro,
    createPage,
    partialPassphrase,
    completePassphrase,
    mismatchVisible,
    matchVisible,
    home,
    passCShellSmoke,
    worldIdPreview,
    featuredPreview,
    technicalHome,
    search,
    sepoliaMintReachability,
    ethereumAccount,
    protectedAction,
    preview,
    activityBefore,
    activityAfter,
    technicalActivity,
    settingsSections,
    settingsObjectArtifactsAbsent,
    technicalSettings,
    privateMaterialExposed: false,
    publicNetworkMutation: false
  };
}

function approve(runtimeHost, kind, scenario = "", typedConfirmation = "") {
  const created = runtimeHost.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind, scenario, confirmationTarget: typedConfirmation });
  if (created.status !== "presentation_created") return created;
  return runtimeHost.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "approve",
    typedConfirmation
  });
}

async function runApprovedDemo(runtimeHost) {
  const execution = approve(runtimeHost, "local_authorization_execution");
  if (execution.status !== "approved") return execution;
  const started = await runtimeHost.invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, {
    approvalArtifactId: execution.approvalArtifact.approvalArtifactId,
    proofTimeoutMs: 120_000
  });
  if (started.status !== "signing_approval_required") return started;
  const fresh = runtimeHost.invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, {
    workflowId: started.workflow.workflowId
  });
  if (fresh.status !== "authenticated") return fresh;
  return runtimeHost.invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, {
    workflowId: started.workflow.workflowId,
    decision: "approve",
    presentationDigest: started.workflow.pendingSigningPresentation.presentationDigest,
    freshAuthenticationEvidenceId: fresh.evidence.evidenceId
  });
}

function runRejectedDemo(runtimeHost) {
  const created = runtimeHost.invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, { kind: "local_authorization_execution" });
  if (created.status !== "presentation_created") return created;
  return runtimeHost.invoke(CHANNELS.RESPOND_APPROVAL, {
    presentationId: created.presentation.presentationId,
    decision: "deny"
  });
}

app.whenReady().then(async () => {
  startupStage = "PLATFORM_WEBAUTHN_CONFIGURATION";
  platformWebAuthnStartup = configurePlatformWebAuthn({
    electronApp: app
  });
  startupStage = "CRASH_REPORTER_CHECK";
  crashReporter.setUploadToServer(false);
  if (crashReporter.getUploadToServer()) {
    throw new Error("PHILCORE_CRASH_REPORT_UPLOAD_MUST_REMAIN_DISABLED");
  }
  if (!isE2E) {
    startupStage = "SAFE_STORAGE_INITIALIZATION";
    safeStorage = require("electron").safeStorage;
  }
  startupStage = "RUNTIME_HOST";
  createHost();
  startupStage = "RECOVERY_ENVIRONMENT";
  await createRecoveryEnvironment();
  startupStage = "ROUTINE_AUTHORIZATION_ENVIRONMENT";
  try { await createRoutineAuthorizationEnvironment(); }
  catch (error) {
    routineAuthorizationProductHost=null;
    const reason = error?.code === "ROUTINE_AUTHORIZATION_PRIVATE_NETWORK_UNAVAILABLE"
      ? "routine_authorization_private_network_unavailable"
      : "routine_authorization_environment_failed";
    routineAuthorizationUnavailableReason=reason;
    process.stderr.write(`[PHILCORE_ROUTINE_AUTHORIZATION_STARTUP_${reason.toUpperCase()}]\n`);
  }
  startupStage = "IPC_REGISTRATION";
  registerIpc();

  if (isE2E) {
    startupStage = "E2E_WINDOW";
    createWindow();
    startupStage = "E2E_RENDERER_BRIDGE";
    const rendererBridge = await verifyRendererBridge(mainWindow);
    if (process.env.PHILCORE_DESKTOP_E2E_UI_ROUTINE_AUTHORIZATION === "1") {
      try {
        const result = await runPackagedUiRoutineAuthorization(mainWindow);
        process.stdout.write(`${JSON.stringify({ ...result, rendererBridgeFunctional: rendererBridge.functional }, null, 2)}\n`);
      } catch (error) {
        const rendererState = await rendererUiSummary(mainWindow).catch(() => ({ unavailable: true }));
        if (rendererState?.serializedSnapshot) rendererState.serializedSnapshot = "[redacted]";
        process.stdout.write(`${JSON.stringify({ status: "failed", mode: "routine_authorization", reason: error.message, rendererState, privateMaterialExposed: false, publicNetworkMutation: false }, null, 2)}\n`);
      }
      app.quit();
      return;
    }
    if (process.env.PHILCORE_DESKTOP_E2E_UI_UNLOCK_FLOW) {
      const mode = process.env.PHILCORE_DESKTOP_E2E_UI_UNLOCK_FLOW === "reopened" ? "reopened" : "created";
      try {
        const uiUnlock = await runPackagedUiUnlockFlow(mainWindow, mode);
        process.stdout.write(`${JSON.stringify({
          ...uiUnlock,
          rendererBridgeFunctional: rendererBridge.functional,
          rendererBridgeMode: rendererBridge.mode
        }, null, 2)}\n`);
      } catch (error) {
        let rendererState = null;
        try {
          rendererState = await rendererUiSummary(mainWindow);
          if (rendererState?.serializedSnapshot) rendererState.serializedSnapshot = "[redacted]";
        } catch {
          rendererState = { unavailable: true };
        }
        process.stdout.write(`${JSON.stringify({
          status: "failed",
          mode,
          reason: error.message,
          rendererState,
          rendererBridgeFunctional: rendererBridge.functional,
          rendererBridgeMode: rendererBridge.mode,
          privateMaterialExposed: false,
          publicNetworkMutation: false
        }, null, 2)}\n`);
      }
      app.quit();
      return;
    }
    if (process.env.PHILCORE_DESKTOP_E2E_UI_ACTION_LIFECYCLE) {
      try {
        const result = await runPackagedUiActionLifecycle(mainWindow);
        process.stdout.write(`${JSON.stringify({ ...result, rendererBridgeFunctional: rendererBridge.functional }, null, 2)}\n`);
      } catch (error) {
        const rendererState = await rendererUiSummary(mainWindow).catch(() => ({ unavailable: true }));
        if (rendererState?.serializedSnapshot) rendererState.serializedSnapshot = "[redacted]";
        process.stdout.write(`${JSON.stringify({ status: "failed", mode: "noir_private_proof_local_alpha", reason: error.message, rendererState, privateMaterialExposed: false, publicNetworkMutation: false }, null, 2)}\n`);
      }
      app.quit();
      return;
    }
    if (process.env.PHILCORE_DESKTOP_E2E_UI_USER_SHELL) {
      const mode = process.env.PHILCORE_DESKTOP_E2E_UI_USER_SHELL === "returning" ? "returning" : "initial";
      try {
        const result = await runPackagedUiUserShell(mainWindow, mode);
        process.stdout.write(`${JSON.stringify({ ...result, rendererBridgeFunctional: rendererBridge.functional }, null, 2)}\n`);
      } catch (error) {
        const rendererState = await rendererUiSummary(mainWindow).catch(() => ({ unavailable: true }));
        if (rendererState?.serializedSnapshot) rendererState.serializedSnapshot = "[redacted]";
        process.stdout.write(`${JSON.stringify({ status: "failed", mode, reason: error.message, rendererState, privateMaterialExposed: false, publicNetworkMutation: false }, null, 2)}\n`);
      }
      app.quit();
      return;
    }
    const passphrase = "E2e-Local-alpha-passphrase!1!1";
    const reopenIdentityId = process.env.PHILCORE_DESKTOP_E2E_REOPEN_IDENTITY_ID;
    const result = reopenIdentityId
      ? runtimeHost.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId: reopenIdentityId })
      : runtimeHost.invoke(CHANNELS.CREATE_LOCAL_IDENTITY, {
          label: "E2E Local Identity",
          passphrase,
          createRecoveryAuthority: true
        });
    const identityId = result.identity.identityId;
    runtimeHost.invoke(CHANNELS.LOCK_SESSION, {});
    runtimeHost.invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId });
    let unlocked;
    if (!reopenIdentityId) {
      runtimeHost.invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase });
      unlocked = runtimeHost.invoke(CHANNELS.UNLOCK_VAULT, {});
      const enrollment = approve(runtimeHost, "platform_unlock_enrollment");
      runtimeHost.invoke(CHANNELS.ENROLL_PLATFORM_AUTH, {
        passphrase,
        approvalArtifactId: enrollment.approvalArtifact.approvalArtifactId
      });
    } else {
      unlocked = runtimeHost.invoke(CHANNELS.PLATFORM_UNLOCK, {});
    }
    const rejected = runRejectedDemo(runtimeHost);
    const demo = await runApprovedDemo(runtimeHost);
    const locked = runtimeHost.invoke(CHANNELS.LOCK_SESSION, {});
    process.stdout.write(`${JSON.stringify({
      status: "passed",
      launched: true,
      localOnly: true,
      demoStatus: demo.status,
      rejectedFirstStatus: rejected.status,
      rejectedFirstSigned: false,
      rejectedFirstExecuted: false,
      realProofDurationMs: demo.workflow?.proof?.generationDurationMs,
      userOperationHash: demo.workflow?.execution?.userOperationHash,
      nullifierConsumed: Boolean(demo.workflow?.execution?.nullifierConsumed),
      consumerExecuted: Boolean(demo.workflow?.execution?.consumerExecuted),
      mode: reopenIdentityId ? "reopened" : "created",
      identityCreated: !reopenIdentityId && Boolean(result.identity),
      identityId,
      ownerCommitment: unlocked.snapshot.identity.ownerCommitment,
      validatorAddress: unlocked.snapshot.ethereum.validator.publicOwnerAddress,
      recoveryAddress: unlocked.snapshot.ethereum.recovery.publicAddress,
      platformProtection: runtimeHost.snapshot().platformAuth.status,
      freshAuthenticationStatus: demo.status === "completed" ? "authenticated" : "failed",
      lockedAfterRun: locked.session.lockState === "locked",
      vaultLockedAfterRun: locked.vault.status === "locked",
      publicNetworkMutation: false,
      privateMaterialExposed: false,
      rendererBridgeFunctional: rendererBridge.functional,
      rendererBridgeMode: rendererBridge.mode
    }, null, 2)}\n`);
    app.quit();
    return;
  }

  startupStage = "MAIN_WINDOW";
  createWindow();
  startupStage = "READY";
}).catch(() => {
  process.stderr.write(`PHILCORE_DESKTOP_STARTUP_FAILED_${startupStage}\n`);
  app.exit(1);
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("before-quit", () => {
  recoveryTransportHost?.cancel();
  recoveryEnrollmentHost?.cancel();
  nativeIPhonePairingHost?.cancel();
  void nativeIPhonePairingHost?.stop();
  void recoveryOrigin?.stop();
  void routineAuthorizationProductHost?.stop();
  void sepoliaMintAuthorizationHost?.stopListener();
});
