const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { ethers } = require("ethers");

const {
  createPhilIdentityPrivate,
  derivePhilIdentityPublic
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  createPhilCredentialRecordFromDeviceMetadata,
  createPhilCredentialRegistry
} = require("../../apps/phil-device-sdk/src/deviceIdentityLifecycle.ts");
const {
  createEncryptedDeviceIdentityRegistryStore,
  createFileDeviceIdentityRegistryStorageBackend,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");
const {
  PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
  arrayBufferToBase64Url,
  authorizationDigestToWebAuthnChallengeBase64Url,
  createWebAuthnAssertionVerifier,
  registerWebAuthnDeviceIdentity
} = require("../../apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  runLocalDeviceSigningSessionMatrixIntegration
} = require("./run-local-device-signing-session-integration.cjs");

const REPO_ROOT = path.resolve(__dirname, "../..");
const PHIL_DEVICE_IDENTITY_DEMO_KIND = "phil-device-identity-demo-v1";
const PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_OUT =
  "./proving/out/phil_device_identity_demo/phil_device_identity_demo_result.json";
const PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_REGISTRY =
  "./proving/out/phil_device_identity_demo/phil_device_identity_demo_registry.enc.json";
const PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_SESSION_OUT_DIR =
  "./proving/out/phil_device_identity_demo/session_matrix";
const LOCAL_DEVICE_SIGNING_RESULT_PATH =
  "./proving/out/local_device_signing/local_device_signing_result.json";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH =
  "./proving/out/smart_account_deploy_signature_request/smart_account_deploy_signature_request.json";
const DEMO_FORBIDDEN_OUTPUT_PATTERNS = Object.freeze([
  /phil_secret/i,
  /privateKey/i,
  /mnemonic/i,
  /seed/i,
  /storageKey/i,
  /rawSecret/i,
  /recoverySecret/i
]);

function resolveRepoPath(value) {
  return path.isAbsolute(value) ? value : path.join(REPO_ROOT, value);
}

function loadJson(jsonPath) {
  const resolved = resolveRepoPath(jsonPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Missing ${resolved}. Run npm run generate:local-fixtures first.`);
  }
  return JSON.parse(fs.readFileSync(resolved, "utf8"));
}

function writeJson(jsonPath, value) {
  const resolved = resolveRepoPath(jsonPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  fs.writeFileSync(resolved, `${JSON.stringify(value, null, 2)}\n`);
}

function textBuffer(value) {
  return new TextEncoder().encode(value).buffer;
}

function bytesBuffer(values) {
  return new Uint8Array(values).buffer;
}

function bufferToArrayBuffer(value) {
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
}

function sha256(value) {
  return crypto.createHash("sha256").update(Buffer.from(value)).digest();
}

function cborUnsigned(value) {
  if (value < 24) {
    return Buffer.from([value]);
  }
  if (value < 256) {
    return Buffer.from([0x18, value]);
  }
  if (value < 65536) {
    return Buffer.from([0x19, value >> 8, value & 0xff]);
  }
  throw new Error("test CBOR integer too large");
}

function cborInt(value) {
  if (value >= 0) {
    return cborUnsigned(value);
  }
  const encoded = cborUnsigned(-1 - value);
  encoded[0] |= 0x20;
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
  return Buffer.concat([
    length,
    ...entries.flatMap(([key, value]) => [cborAny(key), cborAny(value)])
  ]);
}

function cborAny(value) {
  if (typeof value === "number") {
    return cborInt(value);
  }
  if (typeof value === "string") {
    return cborText(value);
  }
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return cborBytes(value);
  }
  if (Array.isArray(value)) {
    return cborMap(value);
  }
  throw new Error("unsupported test CBOR value");
}

function base64UrlToBuffer(value) {
  const padded = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function p256PublicKeyCoordinates(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  return {
    x: base64UrlToBuffer(jwk.x),
    y: base64UrlToBuffer(jwk.y)
  };
}

function buildCoseEs256PublicKey(publicKey) {
  const coordinates = p256PublicKeyCoordinates(publicKey);
  return cborMap([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, coordinates.x],
    [-3, coordinates.y]
  ]);
}

function buildRegistrationAuthenticatorData({
  rpId,
  credentialId,
  publicKey,
  flags = 0x45,
  signCount = 0
}) {
  const header = Buffer.alloc(37);
  sha256(Buffer.from(rpId, "utf8")).copy(header, 0);
  header[32] = flags;
  header.writeUInt32BE(signCount >>> 0, 33);
  const aaguid = Buffer.alloc(16);
  const credentialIdLength = Buffer.alloc(2);
  credentialIdLength.writeUInt16BE(credentialId.length, 0);
  return Buffer.concat([
    header,
    aaguid,
    credentialIdLength,
    credentialId,
    buildCoseEs256PublicKey(publicKey)
  ]);
}

function buildAttestationObject({
  rpId,
  credentialId,
  publicKey,
  signCount = 0
}) {
  return cborMap([
    ["fmt", "none"],
    [
      "authData",
      buildRegistrationAuthenticatorData({
        rpId,
        credentialId,
        publicKey,
        signCount
      })
    ],
    ["attStmt", []]
  ]);
}

function signWebAuthnAssertion({
  privateKey,
  rpId,
  origin,
  challenge,
  signCount
}) {
  const authenticatorData = Buffer.alloc(37);
  sha256(Buffer.from(rpId, "utf8")).copy(authenticatorData, 0);
  authenticatorData[32] = 0x05;
  authenticatorData.writeUInt32BE(signCount >>> 0, 33);
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  const signer = crypto.createSign("SHA256");
  signer.update(Buffer.concat([authenticatorData, sha256(clientDataJSON)]));
  signer.end();
  return {
    authenticatorData,
    clientDataJSON,
    signature: Buffer.from(signer.sign(privateKey))
  };
}

function createMockWebAuthnNavigator({
  origin,
  rpId,
  keyPair,
  credentialId,
  assertionSignCount
}) {
  const calls = {
    create: [],
    get: []
  };
  return {
    calls,
    navigatorLike: {
      credentials: {
        async create(input) {
          calls.create.push(input);
          return {
            id: "phil-demo-passkey",
            rawId: bytesBuffer([...credentialId]),
            type: "public-key",
            authenticatorAttachment: "platform",
            response: {
              attestationObject: bufferToArrayBuffer(buildAttestationObject({
                rpId,
                credentialId,
                publicKey: keyPair.publicKey
              })),
              clientDataJSON: textBuffer(JSON.stringify({
                type: "webauthn.create",
                challenge: arrayBufferToBase64Url(input.publicKey.challenge),
                origin
              })),
              getPublicKey() {
                return bufferToArrayBuffer(keyPair.publicKeySpki);
              },
              getPublicKeyAlgorithm() {
                return -7;
              },
              getTransports() {
                return ["internal"];
              }
            },
            getClientExtensionResults() {
              return {};
            }
          };
        },
        async get(input) {
          calls.get.push(input);
          const signed = signWebAuthnAssertion({
            privateKey: keyPair.privateKey,
            rpId,
            origin,
            challenge: arrayBufferToBase64Url(input.publicKey.challenge),
            signCount: assertionSignCount
          });
          return {
            id: "phil-demo-passkey",
            rawId: bytesBuffer([...credentialId]),
            type: "public-key",
            authenticatorAttachment: "platform",
            response: {
              authenticatorData: bufferToArrayBuffer(signed.authenticatorData),
              clientDataJSON: bufferToArrayBuffer(signed.clientDataJSON),
              signature: bufferToArrayBuffer(signed.signature),
              userHandle: null
            },
            getClientExtensionResults() {
              return {};
            }
          };
        }
      }
    }
  };
}

function assertDemoOutputSafe(artifact) {
  const serialized = JSON.stringify(artifact);
  const found = DEMO_FORBIDDEN_OUTPUT_PATTERNS.find((pattern) => pattern.test(serialized));
  if (found) {
    throw new Error(`Demo artifact contains a forbidden secret-bearing pattern: ${found}`);
  }
}

async function runPhilDeviceIdentityDemo(options = {}) {
  const now = options.now ?? (() => "2026-06-09T08:00:00.000Z");
  const outPath = options.outPath ?? PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_OUT;
  const registryPath = options.registryPath ?? PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_REGISTRY;
  const sessionOutDir =
    options.sessionOutDir ?? PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_SESSION_OUT_DIR;
  const philIdentityPrivate = createPhilIdentityPrivate();
  const philIdentity = derivePhilIdentityPublic(philIdentityPrivate);
  const identityRootHash = ethers.keccak256(philIdentity.identityRoot);
  const rp = {
    rpId: "localhost",
    rpName: "PhilCore Local Demo",
    origin: "http://localhost",
    userDisplayName: "Phil Demo User",
    userName: "phil-demo",
    userId: ethers.id("phil-device-identity-demo-user"),
    userVerification: "required",
    residentKey: "preferred",
    authenticatorAttachment: "platform",
    timeout: 60_000,
    label: "Phil demo passkey"
  };
  const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKeySpki = keyPair.publicKey.export({
    type: "spki",
    format: "der"
  });
  const mockWebAuthn = createMockWebAuthnNavigator({
    origin: rp.origin,
    rpId: rp.rpId,
    keyPair: {
      ...keyPair,
      publicKeySpki
    },
    credentialId: Buffer.from([1, 2, 3, 4, 5, 6]),
    assertionSignCount: 1
  });
  const registration = await registerWebAuthnDeviceIdentity({
    rp,
    philIdentityPrivate,
    navigatorLike: mockWebAuthn.navigatorLike,
    verifier: createWebAuthnAssertionVerifier(),
    now
  });
  const credential = createPhilCredentialRecordFromDeviceMetadata({
    metadata: registration.metadata,
    label: "Phil demo passkey",
    algorithm: "ES256",
    deviceType: "platform",
    createdAt: now()
  });
  const storageProvider = createLocalDevPassphraseKeyProvider({
    passphrase: "phil-device-identity-demo-local-storage-passphrase",
    scrypt: {
      N: 1024,
      r: 8,
      p: 1,
      keyLength: 32
    }
  });
  const registryStore = createEncryptedDeviceIdentityRegistryStore({
    backend: createFileDeviceIdentityRegistryStorageBackend({
      filePath: resolveRepoPath(registryPath)
    }),
    keyProvider: storageProvider,
    now
  });
  const createdSnapshot = await registryStore.createNewRegistry(philIdentity);
  const createdRegistry = createPhilCredentialRegistry({
    philIdentity,
    credentials: createdSnapshot.credentials,
    recoveryPolicy: createdSnapshot.recoveryPolicy,
    auditTrail: createdSnapshot.auditTrail,
    now
  });
  const withCredential = createdRegistry.addCredential({
    credential
  });
  const savedRegistry = await registryStore.saveRegistry(withCredential);
  const loadedRegistry = await registryStore.loadRegistry(philIdentity);
  const smartAccountDeploySignatureRequest = loadJson(
    options.smartAccountDeploySignatureRequestPath
      ?? SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PATH
  );
  const signableDigest =
    smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signableDigest;
  const expectedChallenge = authorizationDigestToWebAuthnChallengeBase64Url(signableDigest);
  const authorization = await registration.provider.authorizeDigest({
    signatureRequestId:
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signatureRequestId,
    signableDigest,
    digestEncoding: "bytes32-hex",
    signatureTarget: {
      path: smartAccountDeploySignatureRequest.path
    }
  });
  const localDeviceSigningResult = loadJson(
    options.localDeviceSigningResultPath ?? LOCAL_DEVICE_SIGNING_RESULT_PATH
  );
  const sessionMatrix = await runLocalDeviceSigningSessionMatrixIntegration({
    localDeviceSigningResult,
    smartAccountDeploySignatureRequest,
    outDir: resolveRepoPath(sessionOutDir)
  });
  const auditEventTypes = loadedRegistry.auditTrail.map((event) => event.eventType);
  const artifact = {
    version: 1,
    path: "phil-device-identity-demo",
    demoKind: PHIL_DEVICE_IDENTITY_DEMO_KIND,
    outputArtifact: resolveRepoPath(outPath),
    registryArtifact: resolveRepoPath(registryPath),
    createdAt: now(),
    identity: {
      identityRootHash,
      ownerCommitment: philIdentity.ownerCommitment
    },
    credential: {
      count: loadedRegistry.credentials.length,
      providerKind: registration.metadata.providerKind,
      credentialIdHash: registration.metadata.credentialIdHash,
      deviceType: credential.deviceType,
      algorithm: credential.algorithm,
      signCountBeforeAssertion: registration.verification.signCount,
      signCountAfterAssertion: authorization.verification.newSignCount
    },
    registry: {
      storageProviderKind: storageProvider.providerKind,
      persisted: true,
      reloaded: loadedRegistry.credentials.length === savedRegistry.credentials.length,
      encryptedAtRest: true,
      auditEventCount: loadedRegistry.auditTrail.length,
      auditEventTypes
    },
    webAuthn: {
      mocked: true,
      registrationVerified: registration.verification.verified,
      registrationVerifierKind: registration.verification.verifierKind,
      assertionVerified: authorization.verification.verified,
      assertionVerifierKind: authorization.verification.verifierKind,
      challengeBindingPreserved: authorization.verification.challengeMatched,
      rpIdHashMatched: authorization.verification.rpIdHashMatched,
      originMatched: authorization.verification.originMatched,
      signatureVerified: authorization.verification.signatureVerified,
      counterStatus: authorization.verification.counterStatus,
      browserCreateCalls: mockWebAuthn.calls.create.length,
      browserGetCalls: mockWebAuthn.calls.get.length
    },
    authorization: {
      digestAuthorized: authorization.verification.verified,
      signableDigest,
      digestEncoding: authorization.digestEncoding,
      signatureKind: authorization.signatureKind,
      signatureHash: authorization.signatureHash
    },
    sessionMatrix: {
      ready: sessionMatrix.localDeviceSigningSessionMatrixIntegrationSummary.ready,
      status: sessionMatrix.localDeviceSigningSessionMatrixIntegrationSummary.status,
      scenarioCount:
        sessionMatrix.localDeviceSigningSessionMatrixIntegrationSummary.scenarioCount,
      acceptedClassification:
        sessionMatrix.localDeviceSigningSessionMatrixIntegrationSummary
          .acceptedClassification,
      rejectedClassification:
        sessionMatrix.localDeviceSigningSessionMatrixIntegrationSummary
          .rejectedClassification,
      transportClassification:
        sessionMatrix.localDeviceSigningSessionMatrixIntegrationSummary
          .transportClassification,
      proofType: sessionMatrix.proofType,
      payloadShape: sessionMatrix.payloadShape,
      lockedBaseTupleSemanticsUnchanged:
        sessionMatrix.validationChecks.lockedBaseTupleSemanticsUnchanged,
      exactTwoFeltFactShapePreserved:
        sessionMatrix.validationChecks.exactTwoFeltFactShapePreserved
    },
    safety: {
      publicArtifactOnly: true,
      secretScanPassed: true
    },
    warnings: [
      "Local deterministic demo only; WebAuthn is mocked for automation.",
      "Encrypted file storage uses a local-dev passphrase provider.",
      "Smart-account execution remains downstream from Phil identity."
    ],
    errors: []
  };
  assertDemoOutputSafe(artifact);
  writeJson(outPath, artifact);
  return artifact;
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--out") {
      parsed.outPath = argv[index + 1];
      index += 1;
    } else if (arg === "--registry") {
      parsed.registryPath = argv[index + 1];
      index += 1;
    } else if (arg === "--session-out-dir") {
      parsed.sessionOutDir = argv[index + 1];
      index += 1;
    }
  }
  return parsed;
}

async function main() {
  const artifact = await runPhilDeviceIdentityDemo(parseArgs(process.argv.slice(2)));
  console.log(JSON.stringify(artifact, null, 2));
  return 0;
}

if (require.main === module) {
  main()
    .then((code) => {
      process.exit(code);
    })
    .catch((error) => {
      console.error(String(error && error.message ? error.message : error));
      process.exit(1);
    });
}

module.exports = {
  PHIL_DEVICE_IDENTITY_DEMO_DEFAULT_OUT,
  PHIL_DEVICE_IDENTITY_DEMO_KIND,
  DEMO_FORBIDDEN_OUTPUT_PATTERNS,
  assertDemoOutputSafe,
  runPhilDeviceIdentityDemo
};
