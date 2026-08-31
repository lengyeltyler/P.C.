const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const nodeFs = require("node:fs");
const nodeOs = require("node:os");
const nodePath = require("node:path");

const { ethers } = require("hardhat");

const {
  buildLegacyOwnerCommitmentFromAddressSalt
} = require("../../apps/phil-device-sdk/src/commitments.ts");
const {
  PHIL_SECRET_FIELD_MASK,
  createPhilIdentityPrivate,
  derivePhilIdentityPublic,
  buildPhilIdentity,
  generatePhilSecret,
  isValidPhilSecret,
  philSecretToBigInt
} = require("../../apps/phil-device-sdk/src/identity.ts");
const {
  assembleUnlockAuthorizationPayload
} = require("../../apps/phil-device-sdk/src/authorization.ts");
const {
  bindWorldIdVerificationToPhilIdentity,
  buildContextBoundWorldIdSignal,
  buildWorldIdOnboardingRequest,
  createWorldIdVerificationReceipt
} = require("../../apps/phil-device-sdk/src/worldId.ts");
const {
  PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR,
  PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM_ERROR,
  PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
  createLocalDevDeviceIdentityProvider,
  createMobileSecureHardwareDeviceIdentityProvider,
  createSecureEnclaveDeviceIdentityProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentity.ts");
const {
  PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
  arrayBufferToBase64Url,
  authorizationDigestToWebAuthnChallengeBase64Url,
  buildWebAuthnAssertionOptions,
  buildWebAuthnRegistrationOptions,
  createWebAuthnAssertionVerifier,
  createWebAuthnPasskeyDeviceIdentityProvider,
  verifyWebAuthnRegistration,
  registerWebAuthnDeviceIdentity,
  assertWebAuthnPrivateMaterialError,
  assertWebAuthnUnsupportedPlatformError
} = require("../../apps/phil-device-sdk/src/deviceIdentityWebAuthn.ts");
const {
  PHIL_CREDENTIAL_ACTION_AUTHORIZATION_REQUIREMENTS,
  createPhilCredentialRecordFromDeviceMetadata,
  createPhilCredentialRegistry
} = require("../../apps/phil-device-sdk/src/deviceIdentityLifecycle.ts");
const {
  createEncryptedDeviceIdentityRegistryStore,
  createFileDeviceIdentityRegistryStorageBackend,
  createFuturePlatformKeychainProviderScaffold,
  createFutureSecureEnclaveKeyProviderScaffold,
  createInMemoryDeviceIdentityRegistryStorageBackend,
  createInjectedRawKeyProvider,
  createLocalDevPassphraseKeyProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentityStorage.ts");
const {
  createInitialStorageKeyLifecycle,
  createVersionedBackupKeyProvider,
  createVersionedStorageKeyProvider,
  loadRegistryWithStorageKeyVersion,
  loadRegistryWithStorageKeyVersions,
  markStorageKeyRetired,
  markStorageKeyRevoked,
  rotateBackupKey,
  rotateStorageKey
} = require("../../apps/phil-device-sdk/src/deviceIdentityKeyLifecycle.ts");
const {
  createBrowserEncryptedDeviceIdentityRegistryStore,
  createBrowserInjectedRawKeyProvider,
  createBrowserPassphraseKeyProvider,
  createBrowserWebCryptoAdapter,
  createFutureBrowserPlatformKeychainProviderScaffold,
  createFutureBrowserSecureEnclaveKeyProviderScaffold,
  createFutureMobileSecureStorageKeyProviderScaffold,
  createIndexedDbDeviceIdentityRegistryStorage,
  detectPhilDeviceIdentityBrowserRuntime
} = require("../../apps/phil-device-sdk/src/deviceIdentityIndexedDbStorage.ts");

function objectContainsValue(value, candidate) {
  if (candidate === value) {
    return true;
  }
  if (!candidate || typeof candidate !== "object") {
    return false;
  }
  if (Array.isArray(candidate)) {
    return candidate.some((entry) => objectContainsValue(value, entry));
  }

  return Object.values(candidate).some((entry) => objectContainsValue(value, entry));
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

function ownedBuffer(value) {
  return Buffer.from(value);
}

function generateP256CredentialKeyPair() {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const publicKeySpki = publicKey.export({
    type: "spki",
    format: "der"
  });

  return {
    publicKey,
    privateKey,
    publicKeySpki,
    publicKeyHex: ethers.hexlify(publicKeySpki)
  };
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
  if (value && value.cborBytes) {
    return cborBytes(value.cborBytes);
  }
  throw new Error("unsupported test CBOR value");
}

function base64UrlToBuffer(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function p256PublicKeyCoordinates(publicKey) {
  const jwk = publicKey.export({
    format: "jwk"
  });
  return {
    x: base64UrlToBuffer(jwk.x),
    y: base64UrlToBuffer(jwk.y)
  };
}

function buildCoseEs256PublicKey(publicKey, algorithm = -7) {
  const coordinates = p256PublicKeyCoordinates(publicKey);
  return cborMap([
    [1, 2],
    [3, algorithm],
    [-1, 1],
    [-2, coordinates.x],
    [-3, coordinates.y]
  ]);
}

function buildRegistrationAuthenticatorData({
  rpId,
  credentialId = Buffer.from([1, 2, 3, 4, 5, 6]),
  publicKey,
  flags = 0x45,
  signCount = 0,
  algorithm = -7
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
    buildCoseEs256PublicKey(publicKey, algorithm)
  ]);
}

function buildAttestationObject({
  rpId,
  publicKey,
  credentialId = Buffer.from([1, 2, 3, 4, 5, 6]),
  flags = 0x45,
  signCount = 0,
  algorithm = -7,
  fmt = "none"
}) {
  const authData = buildRegistrationAuthenticatorData({
    rpId,
    credentialId,
    publicKey,
    flags,
    signCount,
    algorithm
  });
  return cborMap([
    ["fmt", fmt],
    ["authData", authData],
    ["attStmt", []]
  ]);
}

function buildSerializedRegistration({
  keyPair,
  rpId = "localhost",
  origin = "http://localhost",
  expectedChallenge,
  registrationChallenge = expectedChallenge,
  registrationOrigin = origin,
  registrationRpId = rpId,
  flags = 0x45,
  signCount = 0,
  algorithm = -7,
  fmt = "none",
  credentialId = Buffer.from([1, 2, 3, 4, 5, 6]),
  publicKeyAlgorithm = algorithm,
  transports = ["internal"],
  crossOrigin
}) {
  return {
    id: "phil-passkey-credential",
    rawId: arrayBufferToBase64Url(credentialId),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      attestationObject: arrayBufferToBase64Url(buildAttestationObject({
        rpId: registrationRpId,
        publicKey: keyPair.publicKey,
        credentialId,
        flags,
        signCount,
        algorithm,
        fmt
      })),
      clientDataJSON: arrayBufferToBase64Url(Buffer.from(JSON.stringify({
        type: "webauthn.create",
        challenge: registrationChallenge,
        origin: registrationOrigin,
        ...(crossOrigin === undefined ? {} : { crossOrigin })
      }))),
      publicKey: arrayBufferToBase64Url(keyPair.publicKeySpki),
      publicKeyAlgorithm,
      transports
    },
    clientExtensionResults: {}
  };
}

function sha256(value) {
  return nodeCrypto.createHash("sha256").update(ownedBuffer(value)).digest();
}

function buildAuthenticatorData({ rpId, flags = 0x05, signCount = 1 }) {
  const out = Buffer.alloc(37);
  sha256(Buffer.from(rpId, "utf8")).copy(out, 0);
  out[32] = flags;
  out.writeUInt32BE(signCount >>> 0, 33);
  return out;
}

function signWebAuthnAssertion({
  privateKey,
  rpId,
  origin,
  challenge,
  flags = 0x05,
  signCount = 1,
  invalidSignature = false
}) {
  const authenticatorData = buildAuthenticatorData({ rpId, flags, signCount });
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin
  }));
  const signedBytes = Buffer.concat([
    authenticatorData,
    sha256(clientDataJSON)
  ]);
  const signer = nodeCrypto.createSign("SHA256");
  signer.update(signedBytes);
  signer.end();
  const signature = Buffer.from(signer.sign(privateKey));
  if (invalidSignature) {
    signature[signature.length - 1] ^= 0x01;
  }

  return {
    authenticatorData,
    clientDataJSON,
    signature
  };
}

function buildSignedWebAuthnAssertion({
  credentialId = "AQIDBAUG",
  privateKey,
  rpId,
  origin,
  challenge,
  flags = 0x05,
  signCount = 1,
  invalidSignature = false
}) {
  const signed = signWebAuthnAssertion({
    privateKey,
    rpId,
    origin,
    challenge,
    flags,
    signCount,
    invalidSignature
  });

  return {
    id: "phil-passkey-credential",
    rawId: credentialId,
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      authenticatorData: arrayBufferToBase64Url(signed.authenticatorData),
      clientDataJSON: arrayBufferToBase64Url(signed.clientDataJSON),
      signature: arrayBufferToBase64Url(signed.signature),
      userHandle: null
    },
    clientExtensionResults: {}
  };
}

function mockPublicKeyCredential({
  id,
  rawId,
  response,
  authenticatorAttachment = "platform"
}) {
  return {
    id,
    rawId,
    type: "public-key",
    authenticatorAttachment,
    response,
    getClientExtensionResults() {
      return {};
    }
  };
}

function createMockWebAuthnNavigator({
  origin,
  rpId,
  keyPair,
  flags = 0x05,
  registrationFlags = 0x45,
  registrationSignCount = 0,
  registrationAlgorithm = -7,
  registrationAttestationFormat = "none",
  signCount = 1,
  invalidSignature = false
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
          return mockPublicKeyCredential({
            id: "phil-passkey-credential",
            rawId: bytesBuffer([1, 2, 3, 4, 5, 6]),
            response: {
              attestationObject: bufferToArrayBuffer(buildAttestationObject({
                rpId,
                publicKey: keyPair.publicKey,
                flags: registrationFlags,
                signCount: registrationSignCount,
                algorithm: registrationAlgorithm,
                fmt: registrationAttestationFormat
              })),
              clientDataJSON: textBuffer(JSON.stringify({
                type: "webauthn.create",
                challenge: arrayBufferToBase64Url(input.publicKey.challenge),
                origin
              })),
              getPublicKey() {
                return keyPair.publicKeySpki.buffer.slice(
                  keyPair.publicKeySpki.byteOffset,
                  keyPair.publicKeySpki.byteOffset + keyPair.publicKeySpki.byteLength
                );
              },
              getPublicKeyAlgorithm() {
                return -7;
              },
              getTransports() {
                return ["internal"];
              }
            }
          });
        },
        async get(input) {
          calls.get.push(input);
          const signed = signWebAuthnAssertion({
            privateKey: keyPair.privateKey,
            rpId,
            origin,
            challenge: arrayBufferToBase64Url(input.publicKey.challenge),
            flags,
            signCount,
            invalidSignature
          });
          return mockPublicKeyCredential({
            id: "phil-passkey-credential",
            rawId: bytesBuffer([1, 2, 3, 4, 5, 6]),
            response: {
              authenticatorData: signed.authenticatorData.buffer.slice(
                signed.authenticatorData.byteOffset,
                signed.authenticatorData.byteOffset + signed.authenticatorData.byteLength
              ),
              clientDataJSON: signed.clientDataJSON.buffer.slice(
                signed.clientDataJSON.byteOffset,
                signed.clientDataJSON.byteOffset + signed.clientDataJSON.byteLength
              ),
              signature: signed.signature.buffer.slice(
                signed.signature.byteOffset,
                signed.signature.byteOffset + signed.signature.byteLength
              ),
              userHandle: null
            }
          });
        }
      }
    }
  };
}

function buildVerificationInput({
  keyPair,
  rpId = "localhost",
  origin = "http://localhost",
  expectedChallenge,
  assertionChallenge = expectedChallenge,
  assertionOrigin = origin,
  assertionRpId = rpId,
  flags = 0x05,
  signCount = 1,
  storedSignCount = 0,
  invalidSignature = false,
  credentialId = "AQIDBAUG",
  publicKeyAlgorithm = -7,
  userVerification = "required"
}) {
  return {
    assertion: buildSignedWebAuthnAssertion({
      credentialId,
      privateKey: keyPair.privateKey,
      rpId: assertionRpId,
      origin: assertionOrigin,
      challenge: assertionChallenge,
      flags,
      signCount,
      invalidSignature
    }),
    credential: {
      credentialId,
      credentialIdHash: ethers.id("credential-id-hash"),
      rawId: credentialId,
      publicKey: keyPair.publicKeyHex,
      publicKeyAlgorithm,
      signCount: storedSignCount
    },
    expectedChallenge,
    expectedOrigin: origin,
    expectedRpId: rpId,
    expectedUserVerification: userVerification,
    storedSignCount
  };
}

function makeCredential({
  credentialId,
  label,
  providerKind = PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND,
  algorithm = "ES256",
  createdAt = "2026-06-08T00:00:00.000Z",
  lastUsedAt,
  status = "active",
  signCount = 0,
  deviceType = "platform",
  transports = ["internal"],
  priority = 100
}) {
  return {
    credentialId,
    providerKind,
    algorithm,
    label,
    createdAt,
    lastUsedAt,
    status,
    signCount,
    deviceType,
    transport: {
      transports,
      authenticatorAttachment: deviceType === "hardware-security-key" ? "cross-platform" : "platform"
    },
    priority
  };
}

function createFastStorageKeyProvider(passphrase = "local storage test passphrase") {
  return createLocalDevPassphraseKeyProvider({
    passphrase,
    scrypt: {
      N: 1024,
      r: 8,
      p: 1,
      keyLength: 32
    }
  });
}

function makeRequest(action) {
  const request = {
    result: undefined,
    error: null,
    onsuccess: null,
    onerror: null
  };
  queueMicrotask(() => {
    try {
      request.result = action();
      request.onsuccess?.({ target: request });
    } catch (error) {
      request.error = error;
      request.onerror?.({ target: request });
    }
  });
  return request;
}

function createMockIndexedDb() {
  const databases = new Map();
  function objectStoreNames(stores) {
    return {
      contains(name) {
        return stores.has(name);
      }
    };
  }
  function createDatabase() {
    const stores = new Map();
    return {
      objectStoreNames: objectStoreNames(stores),
      createObjectStore(name) {
        if (!stores.has(name)) {
          stores.set(name, new Map());
        }
        return stores.get(name);
      },
      transaction(storeNames) {
        const names = Array.isArray(storeNames) ? storeNames : [storeNames];
        return {
          objectStore(name) {
            if (!names.includes(name)) {
              throw new Error(`Store ${name} is not in transaction`);
            }
            if (!stores.has(name)) {
              stores.set(name, new Map());
            }
            const store = stores.get(name);
            return {
              put(record) {
                return makeRequest(() => {
                  store.set(record.ownerCommitment, { ...record });
                  return record.ownerCommitment;
                });
              },
              get(key) {
                return makeRequest(() => store.get(key));
              },
              delete(key) {
                return makeRequest(() => {
                  store.delete(key);
                  return undefined;
                });
              },
              getAll() {
                return makeRequest(() => [...store.values()]);
              }
            };
          }
        };
      }
    };
  }
  return {
    open(name) {
      const request = {
        result: undefined,
        error: null,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null
      };
      queueMicrotask(() => {
        const existed = databases.has(name);
        if (!existed) {
          databases.set(name, createDatabase());
        }
        request.result = databases.get(name);
        if (!existed) {
          request.onupgradeneeded?.({ target: request });
        }
        request.onsuccess?.({ target: request });
      });
      return request;
    }
  };
}

function createTestWebCryptoAdapter() {
  return createBrowserWebCryptoAdapter(globalThis.crypto ?? nodeCrypto.webcrypto);
}

async function buildStoredRegistry({
  philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate()),
  backend = createInMemoryDeviceIdentityRegistryStorageBackend(),
  keyProvider = createFastStorageKeyProvider()
} = {}) {
  const store = createEncryptedDeviceIdentityRegistryStore({
    backend,
    keyProvider,
    now: () => "2026-06-09T00:00:00.000Z"
  });
  const created = await store.createNewRegistry(philIdentity);
  const registry = createPhilCredentialRegistry({
    philIdentity,
    credentials: created.credentials,
    recoveryPolicy: created.recoveryPolicy,
    auditTrail: created.auditTrail
  });
  const withCredential = registry.addCredential({
    credential: makeCredential({
      credentialId: "stored-mac-passkey",
      label: "Stored Mac Passkey Label",
      signCount: 9
    })
  });
  const saved = await store.saveRegistry(withCredential);
  return {
    philIdentity,
    backend,
    keyProvider,
    store,
    saved
  };
}

describe("Phil identity model", function () {
  it("generates Stark-friendly phil_secret values and derives deterministic canonical commitments", function () {
    const philSecret = generatePhilSecret();
    const numeric = philSecretToBigInt(philSecret);

    assert.equal(isValidPhilSecret(philSecret), true);
    assert.ok(numeric > 0n);
    assert.ok(numeric <= PHIL_SECRET_FIELD_MASK);

    const firstIdentity = createPhilIdentityPrivate({ philSecret });
    const secondIdentity = createPhilIdentityPrivate({ philSecret });
    const publicIdentity = derivePhilIdentityPublic(firstIdentity);
    const builtPublicIdentity = buildPhilIdentity({ philSecret });

    assert.deepEqual(firstIdentity, secondIdentity);
    assert.deepEqual(publicIdentity, builtPublicIdentity);
    assert.deepEqual(publicIdentity, {
      identityRoot: firstIdentity.identityRoot,
      ownerCommitment: firstIdentity.ownerCommitment
    });
    assert.equal(Object.prototype.hasOwnProperty.call(publicIdentity, "philSecret"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(builtPublicIdentity, "philSecret"), false);
  });

  it("uses phil_secret as the canonical path and keeps public identity metadata secret-free", async function () {
    const [user] = await ethers.getSigners();
    const privateIdentity = createPhilIdentityPrivate();

    const canonicalAssembly = assembleUnlockAuthorizationPayload({
      chainId: 1n,
      consumer: ethers.Wallet.createRandom().address,
      philIdentityPrivate: privateIdentity,
      account: user.address,
      target: ethers.Wallet.createRandom().address,
      nullifierSeed: ethers.id("canonical-nullifier-seed")
    });

    assert.equal(canonicalAssembly.ownerCommitment.mode, "phil-secret");
    assert.deepEqual(
      canonicalAssembly.ownerCommitment.philIdentity,
      derivePhilIdentityPublic(privateIdentity)
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(canonicalAssembly.ownerCommitment.philIdentity, "philSecret"),
      false
    );
    assert.equal(objectContainsValue(privateIdentity.philSecret, canonicalAssembly), false);
    assert.equal(
      JSON.stringify(canonicalAssembly, (_key, value) => (
        typeof value === "bigint" ? value.toString() : value
      )).includes(privateIdentity.philSecret.slice(2)),
      false
    );
    assert.equal(canonicalAssembly.proofPackage.proofBlob, "0x");
  });

  it("enforces canonical identity inputs and blocks silent bypasses", async function () {
    const [user] = await ethers.getSigners();

    assert.throws(
      () => createPhilIdentityPrivate({ philSecret: "0x00" }),
      /phil_secret must be non-zero/
    );
    assert.throws(
      () => createPhilIdentityPrivate({ philSecret: ethers.toBeHex(1n << 251n, 32) }),
      /251-bit Stark-friendly private root range/
    );

    const canonical = createPhilIdentityPrivate({
      philSecret: ethers.toBeHex(0x123456n, 32)
    });
    assert.throws(
      () => derivePhilIdentityPublic({
        ...canonical,
        identityRoot: ethers.id("wrong-identity-root")
      }),
      /identityRoot does not match philSecret/
    );
    assert.throws(
      () => derivePhilIdentityPublic({
        ...canonical,
        ownerCommitment: ethers.id("wrong-owner-commitment")
      }),
      /ownerCommitment does not match philSecret/
    );

    const anotherIdentity = createPhilIdentityPrivate({
      philSecret: ethers.toBeHex(0x123457n, 32)
    });
    assert.notEqual(
      canonical.ownerCommitment,
      anotherIdentity.ownerCommitment,
      "distinct deterministic test secrets must bind to distinct commitments"
    );

    assert.throws(
      () =>
        assembleUnlockAuthorizationPayload({
          chainId: 1n,
          consumer: ethers.Wallet.createRandom().address,
          account: user.address,
          target: ethers.Wallet.createRandom().address,
          nullifierSeed: ethers.id("missing-identity")
        }),
      /Canonical identity required/
    );

    assert.throws(
      () =>
        assembleUnlockAuthorizationPayload({
          chainId: 1n,
          consumer: ethers.Wallet.createRandom().address,
          ownerCommitment: ethers.id("arbitrary-owner-commitment"),
          account: user.address,
          target: ethers.Wallet.createRandom().address,
          nullifierSeed: ethers.id("owner-commitment-bypass")
        }),
      /ownerCommitment injection is disabled/
    );

    assert.throws(
      () =>
        assembleUnlockAuthorizationPayload({
          chainId: 1n,
          consumer: ethers.Wallet.createRandom().address,
          legacyOwner: user.address,
          legacyOwnerSalt: ethers.id("legacy-owner-salt"),
          account: user.address,
          target: ethers.Wallet.createRandom().address,
          nullifierSeed: ethers.id("legacy-no-override")
        }),
      /LEGACY ONLY \/ TEST ONLY/
    );
  });

  it("keeps the legacy address-plus-salt helper behind an explicit test-only override", async function () {
    const [user] = await ethers.getSigners();
    const legacyOwnerSalt = ethers.id("legacy-owner-salt");

    const legacyAssembly = assembleUnlockAuthorizationPayload({
      chainId: 1n,
      consumer: ethers.Wallet.createRandom().address,
      allowLegacyOwnerCommitment: true,
      legacyOwner: user.address,
      legacyOwnerSalt,
      account: user.address,
      target: ethers.Wallet.createRandom().address,
      nullifierSeed: ethers.id("legacy-nullifier-seed")
    });

    const legacyCommitment = buildLegacyOwnerCommitmentFromAddressSalt({
      legacyOwner: user.address,
      legacyOwnerSalt
    });

    assert.equal(legacyAssembly.ownerCommitment.mode, "legacy-address-salt");
    assert.equal(legacyAssembly.ownerCommitment.ownerCommitment, legacyCommitment.ownerCommitment);
    assert.equal(legacyAssembly.ownerCommitment.legacyOwner, legacyCommitment.legacyOwner);
    assert.equal(legacyAssembly.ownerCommitment.legacyOwnerSalt, legacyCommitment.legacyOwnerSalt);
  });

  it("keeps Device Identity v1 public metadata secret-free and refuses private export", function () {
    const privateIdentity = createPhilIdentityPrivate();
    const provider = createLocalDevDeviceIdentityProvider({
      philIdentityPrivate: privateIdentity,
      devPrivateKey: ethers.id("device-identity-local-dev-key")
    });
    const metadata = provider.getPublicMetadata();
    const digest = ethers.id("device-identity-digest");
    const authorization = provider.authorizeDigest({
      signableDigest: digest,
      digestEncoding: "bytes32"
    });

    assert.equal(provider.providerKind, PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND);
    assert.equal(provider.productionSafe, false);
    assert.equal(provider.hardwareBacked, false);
    assert.equal(metadata.productionSafe, false);
    assert.equal(metadata.privateMaterialExportable, false);
    assert.equal(metadata.hardwareBacked, false);
    assert.equal(metadata.philIdentity.ownerCommitment, privateIdentity.ownerCommitment);
    assert.equal(Object.prototype.hasOwnProperty.call(metadata.philIdentity, "philSecret"), false);
    assert.equal(objectContainsValue(privateIdentity.philSecret, metadata), false);
    assert.equal(objectContainsValue(privateIdentity.philSecret, authorization), false);
    assert.equal(authorization.signableDigest, digest);
    assert.equal(ethers.recoverAddress(digest, authorization.signature), metadata.signerAddress);
    assert.throws(
      () => provider.exportPrivateMaterial(),
      (error) => error.code === PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR
    );
  });

  it("models one Phil identity with multiple active credentials", function () {
    const privateIdentity = createPhilIdentityPrivate();
    const philIdentity = derivePhilIdentityPublic(privateIdentity);
    const registry = createPhilCredentialRegistry({
      philIdentity,
      credentials: [
        makeCredential({
          credentialId: "mac-passkey",
          label: "Mac passkey",
          priority: 10
        }),
        makeCredential({
          credentialId: "iphone-passkey",
          label: "iPhone passkey",
          deviceType: "mobile",
          priority: 20
        }),
        makeCredential({
          credentialId: "security-key",
          label: "Hardware security key",
          deviceType: "hardware-security-key",
          transports: ["usb", "nfc"],
          priority: 30
        })
      ]
    });

    const snapshot = registry.getSnapshot();

    assert.equal(snapshot.philIdentity.ownerCommitment, privateIdentity.ownerCommitment);
    assert.equal(snapshot.credentials.length, 3);
    assert.equal(registry.assertCredentialCanAuthorize("mac-passkey").status, "active");
    assert.equal(registry.assertCredentialCanAuthorize("iphone-passkey").status, "active");
    assert.equal(registry.assertCredentialCanAuthorize("security-key").status, "active");
    assert.equal(snapshot.credentials[0].credentialId, "mac-passkey");
    assert.equal(snapshot.credentials[2].transport.transports.includes("usb"), true);
    assert.match(
      PHIL_CREDENTIAL_ACTION_AUTHORIZATION_REQUIREMENTS.rotateCredential,
      /old credentials are not destroyed automatically/
    );
  });

  it("adds credentials and emits immutable-style audit events", function () {
    const privateIdentity = createPhilIdentityPrivate();
    const provider = createLocalDevDeviceIdentityProvider({
      philIdentityPrivate: privateIdentity,
      devPrivateKey: ethers.id("registry-bootstrap-local-key"),
      createdAt: "2026-06-08T00:00:00.000Z"
    });
    const philIdentity = derivePhilIdentityPublic(privateIdentity);
    const bootstrapCredential = createPhilCredentialRecordFromDeviceMetadata({
      metadata: provider.getPublicMetadata(),
      label: "Local dev bootstrap",
      algorithm: "secp256k1",
      deviceType: "local-dev",
      priority: 50
    });
    const registry = createPhilCredentialRegistry({ philIdentity });

    let snapshot = registry.addCredential({
      credential: bootstrapCredential
    });

    assert.equal(snapshot.credentials.length, 1);
    assert.equal(snapshot.credentials[0].credentialId, bootstrapCredential.credentialId);
    assert.equal(snapshot.auditTrail[0].eventType, "credential-added");
    assert.equal(snapshot.auditTrail[0].ownerCommitment, philIdentity.ownerCommitment);
    assert.throws(
      () => {
        snapshot.auditTrail.push({});
      },
      /object is not extensible|read only/
    );

    snapshot = registry.addCredential({
      credential: makeCredential({
        credentialId: "mac-passkey",
        label: "Mac passkey",
        priority: 10
      }),
      authorization: {
        actorCredentialId: bootstrapCredential.credentialId
      }
    });

    assert.equal(snapshot.credentials.length, 2);
    assert.equal(snapshot.auditTrail.at(-1).eventType, "credential-added");
    assert.equal(snapshot.auditTrail.at(-1).actorCredentialId, bootstrapCredential.credentialId);
  });

  it("revokes a lost credential while another active credential preserves access", function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const registry = createPhilCredentialRegistry({
      philIdentity,
      credentials: [
        makeCredential({
          credentialId: "lost-phone",
          label: "Lost phone",
          deviceType: "mobile"
        }),
        makeCredential({
          credentialId: "mac-passkey",
          label: "Mac passkey"
        })
      ]
    });

    const snapshot = registry.revokeCredential({
      credentialId: "lost-phone",
      authorization: {
        actorCredentialId: "mac-passkey"
      },
      confirmation: {
        confirmed: true,
        reason: "device lost"
      }
    });

    assert.equal(registry.getCredential("lost-phone").status, "revoked");
    assert.equal(registry.assertCredentialCanAuthorize("mac-passkey").credentialId, "mac-passkey");
    assert.throws(
      () => registry.assertCredentialCanAuthorize("lost-phone"),
      /cannot authorize ordinary actions/
    );
    assert.equal(snapshot.auditTrail.at(-1).eventType, "credential-revoked");
    assert.equal(snapshot.auditTrail.at(-1).details.confirmationReason, "device lost");
  });

  it("rotates credentials without changing Phil identity continuity or destroying the old credential", function () {
    const privateIdentity = createPhilIdentityPrivate();
    const philIdentity = derivePhilIdentityPublic(privateIdentity);
    const registry = createPhilCredentialRegistry({
      philIdentity,
      credentials: [
        makeCredential({
          credentialId: "old-mac-passkey",
          label: "Old Mac passkey",
          signCount: 41
        })
      ]
    });

    const snapshot = registry.rotateCredential({
      oldCredentialId: "old-mac-passkey",
      newCredential: makeCredential({
        credentialId: "new-mac-passkey",
        label: "New Mac passkey",
        signCount: 0,
        priority: 5
      }),
      authorization: {
        actorCredentialId: "old-mac-passkey"
      }
    });

    assert.equal(snapshot.philIdentity.ownerCommitment, privateIdentity.ownerCommitment);
    assert.equal(registry.getCredential("old-mac-passkey").status, "active");
    assert.equal(registry.getCredential("new-mac-passkey").status, "active");
    assert.equal(registry.assertCredentialCanAuthorize("new-mac-passkey").credentialId, "new-mac-passkey");
    assert.equal(snapshot.auditTrail.at(-1).eventType, "credential-rotated");
    assert.equal(snapshot.auditTrail.at(-1).relatedCredentialId, "new-mac-passkey");
  });

  it("requires confirmation and warns before easy self-lockout", function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const registry = createPhilCredentialRegistry({
      philIdentity,
      credentials: [
        makeCredential({
          credentialId: "only-passkey",
          label: "Only passkey"
        })
      ]
    });

    assert.throws(
      () =>
        registry.revokeCredential({
          credentialId: "only-passkey",
          authorization: {
            actorCredentialId: "only-passkey"
          }
        }),
      /explicit confirmation/
    );

    const snapshot = registry.revokeCredential({
      credentialId: "only-passkey",
      authorization: {
        actorCredentialId: "only-passkey"
      },
      confirmation: {
        confirmed: true,
        reason: "intentional destructive test"
      }
    });

    assert.equal(snapshot.credentials[0].status, "revoked");
    assert.match(snapshot.warnings.join("\n"), /No active credential remains/);
    assert.match(snapshot.warnings.join("\n"), /No recovery path exists/);
  });

  it("runs recovery-pending through recovery-completed with stronger authorization", function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const registry = createPhilCredentialRegistry({
      philIdentity,
      credentials: [
        makeCredential({
          credentialId: "lost-primary",
          label: "Lost primary",
          status: "revoked"
        }),
        makeCredential({
          credentialId: "recovery-key",
          label: "Recovery key",
          status: "recovery-only",
          deviceType: "hardware-security-key",
          transports: ["usb"]
        })
      ]
    });

    assert.throws(
      () =>
        registry.startRecovery({
          mechanism: "recovery-credential",
          reason: "primary device lost",
          authorization: {
            actorCredentialId: "recovery-key"
          }
        }),
      /stronger-than-ordinary/
    );

    let snapshot = registry.startRecovery({
      mechanism: "recovery-credential",
      reason: "primary device lost",
      authorization: {
        actorCredentialId: "recovery-key",
        strongerThanOrdinaryAuthentication: true
      }
    });
    assert.equal(snapshot.recoveryPolicy.state, "recovery-pending");
    assert.equal(snapshot.auditTrail.at(-1).eventType, "recovery-started");

    snapshot = registry.approveRecovery({
      authorization: {
        actorCredentialId: "recovery-key",
        strongerThanOrdinaryAuthentication: true
      }
    });
    assert.equal(snapshot.recoveryPolicy.state, "recovery-approved");
    assert.equal(snapshot.auditTrail.at(-1).eventType, "recovery-approved");

    snapshot = registry.addCredential({
      credential: makeCredential({
        credentialId: "replacement-passkey",
        label: "Replacement passkey",
        status: "active"
      }),
      authorization: {
        recoveryApproved: true
      }
    });
    assert.equal(registry.assertCredentialCanAuthorize("replacement-passkey").status, "active");

    snapshot = registry.completeRecovery({
      completedByCredentialId: "replacement-passkey",
      authorization: {
        actorCredentialId: "recovery-key",
        strongerThanOrdinaryAuthentication: true
      }
    });

    assert.equal(snapshot.recoveryPolicy.state, "recovery-completed");
    assert.equal(snapshot.recoveryPolicy.completedByCredentialId, "replacement-passkey");
    assert.equal(snapshot.auditTrail.at(-1).eventType, "recovery-completed");
    assert.equal(snapshot.philIdentity.ownerCommitment, philIdentity.ownerCommitment);
  });

  it("saves and loads an encrypted durable credential registry through file storage", async function () {
    const privateIdentity = createPhilIdentityPrivate();
    const philIdentity = derivePhilIdentityPublic(privateIdentity);
    const tmpDir = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "phil-registry-"));
    const filePath = nodePath.join(tmpDir, "registry.json");
    const backend = createFileDeviceIdentityRegistryStorageBackend({ filePath });
    const keyProvider = createFastStorageKeyProvider();
    const { store, saved } = await buildStoredRegistry({
      philIdentity,
      backend,
      keyProvider
    });

    const encrypted = nodeFs.readFileSync(filePath, "utf8");
    const loaded = await store.loadRegistry(philIdentity);

    assert.equal(await store.validateRegistry(philIdentity), true);
    assert.equal(loaded.philIdentity.ownerCommitment, philIdentity.ownerCommitment);
    assert.equal(loaded.credentials[0].credentialId, "stored-mac-passkey");
    assert.equal(loaded.credentials[0].signCount, 9);
    assert.equal(loaded.auditTrail.some((event) => event.eventType === "registry-created"), true);
    assert.equal(loaded.auditTrail.some((event) => event.eventType === "registry-saved"), true);
    assert.equal(loaded.auditTrail.at(-1).eventType, "registry-loaded");
    assert.equal(encrypted.includes("Stored Mac Passkey Label"), false);
    assert.equal(encrypted.includes(privateIdentity.philSecret.slice(2)), false);
    assert.equal(encrypted.includes("phil_secret"), false);
    assert.equal(saved.auditTrail.some((event) => event.eventType === "credential-added"), true);
  });

  it("rejects tampered ciphertext, wrong owner, wrong passphrase, unsupported versions, and corrupted headers", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const { backend, saved } = await buildStoredRegistry({ philIdentity });
    const encrypted = await backend.read();
    const parsed = JSON.parse(encrypted);

    const tampered = {
      ...parsed,
      ciphertext: `${parsed.ciphertext.startsWith("A") ? "B" : "A"}${parsed.ciphertext.slice(1)}`
    };
    const tamperedStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(JSON.stringify(tampered)),
      keyProvider: createFastStorageKeyProvider()
    });
    await assert.rejects(
      () => tamperedStore.loadRegistry(philIdentity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_TAMPER_DETECTED"
    );
    assert.equal(
      tamperedStore.getVolatileStorageAuditEvents().at(-1).eventType,
      "registry-tamper-detected"
    );

    const wrongOwnerStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(encrypted),
      keyProvider: createFastStorageKeyProvider()
    });
    await assert.rejects(
      () => wrongOwnerStore.loadRegistry(derivePhilIdentityPublic(createPhilIdentityPrivate())),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_OWNER_MISMATCH"
    );

    const wrongPassphraseStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(encrypted),
      keyProvider: createFastStorageKeyProvider("wrong passphrase")
    });
    await assert.rejects(
      () => wrongPassphraseStore.loadRegistry(philIdentity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_TAMPER_DETECTED"
    );

    const unsupportedVersion = {
      ...parsed,
      version: 99
    };
    const unsupportedStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(JSON.stringify(unsupportedVersion)),
      keyProvider: createFastStorageKeyProvider()
    });
    await assert.rejects(
      () => unsupportedStore.loadRegistry(philIdentity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_VERSION"
    );

    const corruptedStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend("{not-json"),
      keyProvider: createFastStorageKeyProvider()
    });
    await assert.rejects(
      () => corruptedStore.loadRegistry(philIdentity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_CORRUPTED_REGISTRY"
    );

    const missingStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(),
      keyProvider: createFastStorageKeyProvider()
    });
    await assert.rejects(
      () => missingStore.loadRegistry(philIdentity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_MISSING_REGISTRY"
    );
    assert.equal(
      missingStore.getVolatileStorageAuditEvents().at(-1).eventType,
      "registry-load-failed"
    );

    assert.equal(saved.credentials.length, 1);
  });

  it("exports and imports encrypted backups without silent overwrite", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const keyProvider = createFastStorageKeyProvider();
    const { store, saved } = await buildStoredRegistry({
      philIdentity,
      keyProvider
    });
    const backup = await store.exportEncryptedBackupBlob(saved);

    assert.equal(backup.includes("Stored Mac Passkey Label"), false);
    assert.match(backup, /phil-device-identity-registry-encrypted/);

    const importBackend = createInMemoryDeviceIdentityRegistryStorageBackend();
    const importStore = createEncryptedDeviceIdentityRegistryStore({
      backend: importBackend,
      keyProvider,
      now: () => "2026-06-09T01:00:00.000Z"
    });
    const imported = await importStore.importEncryptedBackupBlob({
      encryptedBackupBlob: backup,
      expectedIdentity: philIdentity
    });

    assert.equal(imported.credentials[0].credentialId, "stored-mac-passkey");
    assert.equal(imported.auditTrail.some((event) => event.eventType === "credential-added"), true);
    assert.equal(imported.auditTrail.some((event) => event.eventType === "registry-exported"), true);
    assert.equal(imported.auditTrail.at(-1).eventType, "registry-imported");

    await assert.rejects(
      () =>
        importStore.importEncryptedBackupBlob({
          encryptedBackupBlob: backup,
          expectedIdentity: philIdentity
        }),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_REPLACE_REQUIRED"
    );

    const replaced = await importStore.importEncryptedBackupBlob({
      encryptedBackupBlob: backup,
      expectedIdentity: philIdentity,
      replaceExisting: true
    });
    assert.equal(replaced.credentials[0].credentialId, "stored-mac-passkey");
  });

  it("supports injected raw key material and rejects non-exportable future key provider scaffolds cleanly", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const keyProvider = createInjectedRawKeyProvider({
      key: nodeCrypto.createHash("sha256").update("raw storage key").digest()
    });
    const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
    const { store } = await buildStoredRegistry({
      philIdentity,
      backend,
      keyProvider
    });
    const loaded = await store.loadRegistry(philIdentity);

    assert.equal(loaded.credentials[0].credentialId, "stored-mac-passkey");
    for (const scaffold of [
      createFuturePlatformKeychainProviderScaffold(),
      createFutureSecureEnclaveKeyProviderScaffold()
    ]) {
      assert.throws(
        () =>
          scaffold.resolveKey({
            ownerCommitment: philIdentity.ownerCommitment,
            purpose: "encrypt"
          }),
        (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_UNSUPPORTED_KEY_PROVIDER"
      );
    }
  });

  it("rotates storage keys with version metadata, overlap, audit events, and identity continuity", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
    const currentProvider = createFastStorageKeyProvider("storage key v1");
    const nextProvider = createFastStorageKeyProvider("storage key v2");
    const { saved } = await buildStoredRegistry({
      philIdentity,
      backend,
      keyProvider: currentProvider
    });
    const lifecycle = createInitialStorageKeyLifecycle({
      storageKeyProvider: currentProvider,
      backupKeyProvider: createFastStorageKeyProvider("backup key v1"),
      createdAt: "2026-06-09T04:00:00.000Z"
    });
    const result = await rotateStorageKey({
      backend,
      identity: philIdentity,
      currentKey: createVersionedStorageKeyProvider({
        keyVersion: 1,
        keyProvider: currentProvider,
        createdAt: "2026-06-09T04:00:00.000Z"
      }),
      nextKey: createVersionedStorageKeyProvider({
        keyVersion: 2,
        keyProvider: nextProvider,
        createdAt: "2026-06-09T04:10:00.000Z"
      }),
      lifecycle,
      requireBackupCompleted: true,
      now: () => "2026-06-09T04:20:00.000Z"
    });
    const envelope = JSON.parse(result.rotatedEncryptedBlob);
    const loadedWithNext = await loadRegistryWithStorageKeyVersion({
      backend,
      identity: philIdentity,
      lifecycle: result.lifecycle,
      key: createVersionedStorageKeyProvider({
        keyVersion: 2,
        keyProvider: nextProvider,
        createdAt: "2026-06-09T04:10:00.000Z"
      })
    });

    assert.equal(result.snapshot.philIdentity.ownerCommitment, saved.philIdentity.ownerCommitment);
    assert.equal(result.lifecycle.storageKeys.find((key) => key.keyVersion === 1).status, "retiring");
    assert.equal(result.lifecycle.storageKeys.find((key) => key.keyVersion === 2).status, "active");
    assert.equal(envelope.keyLifecycle.keyVersion, 2);
    assert.equal(envelope.keyLifecycle.encryptionAlgorithm, "aes-256-gcm");
    assert.equal(envelope.keyLifecycle.migrationVersion, 2);
    assert.equal(result.lifecycle.migrationVersion, 2);
    assert.equal(
      result.snapshot.auditTrail.some((event) => event.eventType === "storage-key-rotation-started"),
      true
    );
    assert.equal(
      result.snapshot.auditTrail.some((event) => event.eventType === "storage-key-rotation-completed"),
      true
    );
    assert.equal(loadedWithNext.credentials[0].credentialId, "stored-mac-passkey");
  });

  it("loads by envelope key version and rejects post-rotation rollback blobs", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
    const sharedProvider = createFastStorageKeyProvider("same bytes across metadata versions");
    await buildStoredRegistry({
      philIdentity,
      backend,
      keyProvider: sharedProvider
    });
    const beforeRotationBlob = await backend.read();
    const lifecycle = createInitialStorageKeyLifecycle({
      storageKeyProvider: sharedProvider,
      createdAt: "2026-06-09T04:30:00.000Z",
      policy: {
        requireBackupBeforeRotation: false
      }
    });
    const result = await rotateStorageKey({
      backend,
      identity: philIdentity,
      currentKey: createVersionedStorageKeyProvider({
        keyVersion: 1,
        keyProvider: sharedProvider,
        createdAt: "2026-06-09T04:30:00.000Z"
      }),
      nextKey: createVersionedStorageKeyProvider({
        keyVersion: 2,
        keyProvider: sharedProvider,
        createdAt: "2026-06-09T04:40:00.000Z"
      }),
      lifecycle,
      now: () => "2026-06-09T04:50:00.000Z"
    });
    const loaded = await loadRegistryWithStorageKeyVersions({
      backend,
      identity: philIdentity,
      lifecycle: result.lifecycle,
      keyring: [
        {
          key: createVersionedStorageKeyProvider({
            keyVersion: 1,
            keyProvider: sharedProvider,
            createdAt: "2026-06-09T04:30:00.000Z"
          })
        },
        {
          key: createVersionedStorageKeyProvider({
            keyVersion: 2,
            keyProvider: sharedProvider,
            createdAt: "2026-06-09T04:40:00.000Z"
          })
        }
      ]
    });

    assert.equal(JSON.parse(result.rotatedEncryptedBlob).keyLifecycle.migrationVersion, 2);
    assert.equal(result.lifecycle.migrationVersion, 2);
    assert.equal(loaded.credentials[0].credentialId, "stored-mac-passkey");

    await backend.write(beforeRotationBlob);
    await assert.rejects(
      () =>
        loadRegistryWithStorageKeyVersions({
          backend,
          identity: philIdentity,
          lifecycle: result.lifecycle,
          keyring: [
            {
              key: createVersionedStorageKeyProvider({
                keyVersion: 1,
                keyProvider: sharedProvider,
                createdAt: "2026-06-09T04:30:00.000Z"
              })
            },
            {
              key: createVersionedStorageKeyProvider({
                keyVersion: 2,
                keyProvider: sharedProvider,
                createdAt: "2026-06-09T04:40:00.000Z"
              })
            }
          ]
        }),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_ROLLBACK_DETECTED"
    );
  });

  it("rolls back failed storage-key rotation and keeps the original key usable", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
    const currentProvider = createFastStorageKeyProvider("rollback storage key v1");
    const nextProvider = createFastStorageKeyProvider("rollback storage key v2");
    await buildStoredRegistry({
      philIdentity,
      backend,
      keyProvider: currentProvider
    });
    const beforeBlob = await backend.read();
    const lifecycle = createInitialStorageKeyLifecycle({
      storageKeyProvider: currentProvider,
      createdAt: "2026-06-09T05:00:00.000Z",
      policy: {
        requireBackupBeforeRotation: false
      }
    });

    await assert.rejects(
      () =>
        rotateStorageKey({
          backend,
          identity: philIdentity,
          currentKey: createVersionedStorageKeyProvider({
            keyVersion: 1,
            keyProvider: currentProvider,
            createdAt: "2026-06-09T05:00:00.000Z"
          }),
          nextKey: createVersionedStorageKeyProvider({
            keyVersion: 2,
            keyProvider: nextProvider,
            createdAt: "2026-06-09T05:10:00.000Z"
          }),
          lifecycle,
          simulateCommitFailure: true
        }),
      (error) =>
        error.code === "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_ROTATION_FAILED"
        && error.auditEvent.eventType === "storage-key-rotation-failed"
    );

    assert.equal(await backend.read(), beforeBlob);
    const loadedWithCurrent = await loadRegistryWithStorageKeyVersion({
      backend,
      identity: philIdentity,
      lifecycle,
      key: createVersionedStorageKeyProvider({
        keyVersion: 1,
        keyProvider: currentProvider,
        createdAt: "2026-06-09T05:00:00.000Z"
      })
    });
    assert.equal(loadedWithCurrent.credentials[0].credentialId, "stored-mac-passkey");
    const nextKeyStore = createEncryptedDeviceIdentityRegistryStore({
      backend,
      keyProvider: nextProvider
    });
    await assert.rejects(
      () => nextKeyStore.loadRegistry(philIdentity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_STORAGE_TAMPER_DETECTED"
    );
  });

  it("allows active and retiring storage keys to load while retired and revoked keys fail closed", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const backend = createInMemoryDeviceIdentityRegistryStorageBackend();
    const keyProvider = createFastStorageKeyProvider("status-gated key");
    await buildStoredRegistry({
      philIdentity,
      backend,
      keyProvider
    });
    const lifecycle = createInitialStorageKeyLifecycle({
      storageKeyProvider: keyProvider,
      createdAt: "2026-06-09T06:00:00.000Z"
    });
    const retiringLifecycle = {
      ...lifecycle,
      storageKeys: lifecycle.storageKeys.map((key) => ({ ...key, status: "retiring" }))
    };
    const retiringLoad = await loadRegistryWithStorageKeyVersion({
      backend,
      identity: philIdentity,
      lifecycle: retiringLifecycle,
      key: createVersionedStorageKeyProvider({
        keyVersion: 1,
        keyProvider,
        createdAt: "2026-06-09T06:00:00.000Z",
        status: "retiring"
      })
    });
    assert.equal(retiringLoad.credentials[0].credentialId, "stored-mac-passkey");

    const retiredLifecycle = markStorageKeyRetired({
      lifecycle,
      keyVersion: 1,
      retiredAt: "2026-06-09T06:10:00.000Z"
    });
    await assert.rejects(
      () =>
        loadRegistryWithStorageKeyVersion({
          backend,
          identity: philIdentity,
          lifecycle: retiredLifecycle,
          key: createVersionedStorageKeyProvider({
            keyVersion: 1,
            keyProvider,
            createdAt: "2026-06-09T06:00:00.000Z"
          })
        }),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_KEY_NOT_ALLOWED"
    );

    const revokedLifecycle = markStorageKeyRevoked({
      lifecycle,
      keyVersion: 1,
      revokedAt: "2026-06-09T06:20:00.000Z"
    });
    await assert.rejects(
      () =>
        loadRegistryWithStorageKeyVersion({
          backend,
          identity: philIdentity,
          lifecycle: revokedLifecycle,
          key: createVersionedStorageKeyProvider({
            keyVersion: 1,
            keyProvider,
            createdAt: "2026-06-09T06:00:00.000Z"
          })
        }),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_KEY_LIFECYCLE_KEY_NOT_ALLOWED"
    );
  });

  it("rotates encrypted backup keys and imports the rotated backup with preserved audit history", async function () {
    const philIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const backupKeyV1 = createFastStorageKeyProvider("backup lifecycle key v1");
    const backupKeyV2 = createFastStorageKeyProvider("backup lifecycle key v2");
    const { saved } = await buildStoredRegistry({ philIdentity });
    const backupStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(),
      keyProvider: backupKeyV1,
      now: () => "2026-06-09T07:00:00.000Z"
    });
    const backup = await backupStore.exportEncryptedBackupBlob(saved);
    const lifecycle = createInitialStorageKeyLifecycle({
      storageKeyProvider: createFastStorageKeyProvider("storage for backup lifecycle"),
      backupKeyProvider: backupKeyV1,
      createdAt: "2026-06-09T07:00:00.000Z"
    });
    const result = await rotateBackupKey({
      encryptedBackupBlob: backup,
      identity: philIdentity,
      currentBackupKey: createVersionedBackupKeyProvider({
        backupKeyVersion: 1,
        keyProvider: backupKeyV1,
        createdAt: "2026-06-09T07:00:00.000Z"
      }),
      nextBackupKey: createVersionedBackupKeyProvider({
        backupKeyVersion: 2,
        keyProvider: backupKeyV2,
        createdAt: "2026-06-09T07:10:00.000Z"
      }),
      lifecycle,
      now: () => "2026-06-09T07:20:00.000Z"
    });
    const envelope = JSON.parse(result.encryptedBackupBlob);
    const importStore = createEncryptedDeviceIdentityRegistryStore({
      backend: createInMemoryDeviceIdentityRegistryStorageBackend(),
      keyProvider: backupKeyV2
    });
    const imported = await importStore.importEncryptedBackupBlob({
      encryptedBackupBlob: result.encryptedBackupBlob,
      expectedIdentity: philIdentity
    });

    assert.equal(result.lifecycle.backupKeys.find((key) => key.backupKeyVersion === 1).status, "retiring");
    assert.equal(result.lifecycle.backupKeys.find((key) => key.backupKeyVersion === 2).status, "active");
    assert.equal(envelope.backupLifecycle.backupKeyVersion, 2);
    assert.equal(envelope.backupLifecycle.encryptionAlgorithm, "aes-256-gcm");
    assert.equal(imported.credentials[0].credentialId, "stored-mac-passkey");
    assert.equal(
      imported.auditTrail.some((event) => event.details.backupKeyRotation === true),
      true
    );
  });

  it("encrypts and decrypts through the browser WebCrypto adapter", async function () {
    const crypto = createTestWebCryptoAdapter();
    const key = await crypto.importAesGcmKey(
      nodeCrypto.createHash("sha256").update("browser raw key").digest()
    );
    const iv = crypto.randomBytes(12);
    const additionalData = new TextEncoder().encode("phil-browser-storage-aad");
    const plaintext = new TextEncoder().encode("browser encrypted registry payload");
    const encrypted = await crypto.encryptAesGcm({
      key,
      iv,
      plaintext,
      additionalData
    });
    const decrypted = await crypto.decryptAesGcm({
      key,
      iv,
      ciphertext: encrypted.ciphertext,
      tag: encrypted.tag,
      additionalData
    });
    const digest = await crypto.sha256("phil-browser-storage-aad");

    assert.equal(new TextDecoder().decode(decrypted), "browser encrypted registry payload");
    assert.equal(digest.byteLength, 32);
  });

  it("saves and loads encrypted browser IndexedDB registries for multiple Phil identities", async function () {
    const indexedDb = createMockIndexedDb();
    const crypto = createTestWebCryptoAdapter();
    const storage = createIndexedDbDeviceIdentityRegistryStorage({
      indexedDb,
      dbName: "phil_device_identity_test"
    });
    const keyProvider = createBrowserPassphraseKeyProvider({
      passphrase: "browser storage passphrase",
      iterations: 1000
    });
    const store = createBrowserEncryptedDeviceIdentityRegistryStore({
      storage,
      keyProvider,
      crypto,
      now: () => "2026-06-09T02:00:00.000Z"
    });
    const firstIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const secondIdentity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const firstRegistry = createPhilCredentialRegistry({
      philIdentity: firstIdentity,
      auditTrail: (await store.createNewRegistry(firstIdentity)).auditTrail
    });
    const firstSaved = await store.saveRegistry(firstRegistry.addCredential({
      credential: makeCredential({
        credentialId: "browser-mac-passkey",
        label: "Browser Mac Passkey Label"
      })
    }));
    const secondRegistry = createPhilCredentialRegistry({
      philIdentity: secondIdentity,
      auditTrail: (await store.createNewRegistry(secondIdentity)).auditTrail
    });
    await store.saveRegistry(secondRegistry.addCredential({
      credential: makeCredential({
        credentialId: "browser-phone-passkey",
        label: "Browser Phone Passkey Label"
      })
    }));

    const encrypted = await storage.loadEncryptedBlob(firstIdentity.ownerCommitment);
    const loaded = await store.loadRegistry(firstIdentity);
    const metadata = await store.listRegistryMetadata();

    assert.equal(loaded.credentials[0].credentialId, "browser-mac-passkey");
    assert.equal(loaded.auditTrail.some((event) => event.eventType === "registry-saved"), true);
    assert.equal(loaded.auditTrail.at(-1).eventType, "registry-loaded");
    assert.equal(encrypted.includes("Browser Mac Passkey Label"), false);
    assert.equal(encrypted.includes("phil_secret"), false);
    assert.equal(metadata.length, 2);
    assert.deepEqual(
      metadata.map((entry) => entry.ownerCommitment).sort(),
      [firstIdentity.ownerCommitment, secondIdentity.ownerCommitment].sort()
    );
    assert.equal(firstSaved.credentials[0].credentialId, "browser-mac-passkey");
  });

  it("fails safely for wrong browser keys, tampered blobs, corrupted entries, missing registries, and unsupported versions", async function () {
    const indexedDb = createMockIndexedDb();
    const crypto = createTestWebCryptoAdapter();
    const storage = createIndexedDbDeviceIdentityRegistryStorage({
      indexedDb,
      dbName: "phil_device_identity_tamper_test"
    });
    const identity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const keyProvider = createBrowserPassphraseKeyProvider({
      passphrase: "correct browser passphrase",
      iterations: 1000
    });
    const store = createBrowserEncryptedDeviceIdentityRegistryStore({
      storage,
      keyProvider,
      crypto
    });
    const registry = createPhilCredentialRegistry({
      philIdentity: identity,
      auditTrail: (await store.createNewRegistry(identity)).auditTrail
    });
    await store.saveRegistry(registry.addCredential({
      credential: makeCredential({
        credentialId: "browser-storage-passkey",
        label: "Browser Storage Passkey"
      })
    }));
    const encrypted = await storage.loadEncryptedBlob(identity.ownerCommitment);
    const wrongKeyStore = createBrowserEncryptedDeviceIdentityRegistryStore({
      storage,
      keyProvider: createBrowserPassphraseKeyProvider({
        passphrase: "wrong browser passphrase",
        iterations: 1000
      }),
      crypto
    });

    await assert.rejects(
      () => wrongKeyStore.loadRegistry(identity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_TAMPER_DETECTED"
    );
    assert.equal(
      wrongKeyStore.getVolatileStorageAuditEvents().at(-1).eventType,
      "registry-tamper-detected"
    );

    const parsed = JSON.parse(encrypted);
    const tampered = {
      ...parsed,
      ciphertext: `${parsed.ciphertext.startsWith("A") ? "B" : "A"}${parsed.ciphertext.slice(1)}`
    };
    await storage.saveEncryptedBlob({
      ownerCommitment: identity.ownerCommitment,
      encryptedBlob: JSON.stringify(tampered),
      updatedAt: "2026-06-09T02:10:00.000Z"
    });
    await assert.rejects(
      () => store.loadRegistry(identity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_TAMPER_DETECTED"
    );

    await storage.saveEncryptedBlob({
      ownerCommitment: identity.ownerCommitment,
      encryptedBlob: "{not-json",
      updatedAt: "2026-06-09T02:11:00.000Z"
    });
    await assert.rejects(
      () => store.loadRegistry(identity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_CORRUPTED_REGISTRY"
    );

    await storage.saveEncryptedBlob({
      ownerCommitment: identity.ownerCommitment,
      encryptedBlob: JSON.stringify({ ...parsed, version: 99 }),
      updatedAt: "2026-06-09T02:12:00.000Z"
    });
    await assert.rejects(
      () => store.loadRegistry(identity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_VERSION"
    );

    await store.deleteRegistry(identity.ownerCommitment);
    await assert.rejects(
      () => store.loadRegistry(identity),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_MISSING_REGISTRY"
    );
    assert.equal(store.getVolatileStorageAuditEvents().at(-1).eventType, "registry-load-failed");
  });

  it("exports and imports browser encrypted backups with overwrite protection", async function () {
    const crypto = createTestWebCryptoAdapter();
    const keyProvider = createBrowserInjectedRawKeyProvider({
      key: nodeCrypto.createHash("sha256").update("browser backup key").digest()
    });
    const sourceStorage = createIndexedDbDeviceIdentityRegistryStorage({
      indexedDb: createMockIndexedDb(),
      dbName: "phil_device_identity_backup_source"
    });
    const importStorage = createIndexedDbDeviceIdentityRegistryStorage({
      indexedDb: createMockIndexedDb(),
      dbName: "phil_device_identity_backup_import"
    });
    const identity = derivePhilIdentityPublic(createPhilIdentityPrivate());
    const sourceStore = createBrowserEncryptedDeviceIdentityRegistryStore({
      storage: sourceStorage,
      keyProvider,
      crypto,
      now: () => "2026-06-09T03:00:00.000Z"
    });
    const sourceRegistry = createPhilCredentialRegistry({
      philIdentity: identity,
      auditTrail: (await sourceStore.createNewRegistry(identity)).auditTrail
    });
    const saved = await sourceStore.saveRegistry(sourceRegistry.addCredential({
      credential: makeCredential({
        credentialId: "browser-backup-passkey",
        label: "Browser Backup Passkey"
      })
    }));
    const backup = await sourceStore.exportEncryptedBackupBlob(saved);
    const importStore = createBrowserEncryptedDeviceIdentityRegistryStore({
      storage: importStorage,
      keyProvider,
      crypto,
      now: () => "2026-06-09T03:01:00.000Z"
    });

    const imported = await importStore.importEncryptedBackupBlob({
      encryptedBackupBlob: backup,
      expectedIdentity: identity
    });

    assert.equal(backup.includes("Browser Backup Passkey"), false);
    assert.equal(imported.credentials[0].credentialId, "browser-backup-passkey");
    assert.equal(imported.auditTrail.some((event) => event.eventType === "registry-exported"), true);
    assert.equal(imported.auditTrail.at(-1).eventType, "registry-imported");
    await assert.rejects(
      () =>
        importStore.importEncryptedBackupBlob({
          encryptedBackupBlob: backup,
          expectedIdentity: identity
        }),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_REPLACE_REQUIRED"
    );
    const replaced = await importStore.importEncryptedBackupBlob({
      encryptedBackupBlob: backup,
      expectedIdentity: identity,
      replaceExisting: true
    });
    assert.equal(replaced.credentials[0].credentialId, "browser-backup-passkey");
  });

  it("detects browser storage runtime support and fails unsupported browser provider scaffolds clearly", async function () {
    const crypto = createTestWebCryptoAdapter();
    const indexedDb = createMockIndexedDb();

    assert.equal(
      detectPhilDeviceIdentityBrowserRuntime({
        indexedDb,
        crypto: globalThis.crypto ?? nodeCrypto.webcrypto
      }),
      "browser"
    );
    assert.equal(detectPhilDeviceIdentityBrowserRuntime({ indexedDb: undefined, crypto: undefined }), "node");
    assert.throws(
      () => createIndexedDbDeviceIdentityRegistryStorage({ indexedDb: undefined }),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_RUNTIME"
    );
    assert.throws(
      () => createBrowserWebCryptoAdapter({}),
      (error) => error.code === "PHIL_DEVICE_IDENTITY_BROWSER_CRYPTO_UNSUPPORTED"
    );

    for (const provider of [
      createFutureBrowserPlatformKeychainProviderScaffold(),
      createFutureBrowserSecureEnclaveKeyProviderScaffold(),
      createFutureMobileSecureStorageKeyProviderScaffold()
    ]) {
      await assert.rejects(
        () =>
          provider.resolveKey({
            ownerCommitment: ethers.id("browser-storage-owner"),
            purpose: "encrypt",
            crypto
          }),
        (error) => error.code === "PHIL_DEVICE_IDENTITY_INDEXEDDB_UNSUPPORTED_KEY_PROVIDER"
      );
      assert.equal(provider.rawKeyExportable, false);
    }
  });

  it("scaffolds non-WebAuthn hardware Device Identity providers with clean unsupported-platform failures", function () {
    const providers = [
      createSecureEnclaveDeviceIdentityProvider(),
      createMobileSecureHardwareDeviceIdentityProvider()
    ];

    for (const provider of providers) {
      const metadata = provider.getPublicMetadata();

      assert.equal(provider.hardwareBacked, true);
      assert.equal(metadata.hardwareBacked, true);
      assert.equal(metadata.privateMaterialExportable, false);
      assert.equal(objectContainsValue("phil_secret", metadata), false);
      assert.throws(
        () =>
          provider.authorizeDigest({
            signableDigest: ethers.id("unsupported-hardware-digest"),
            digestEncoding: "bytes32"
          }),
        (error) => error.code === PHIL_DEVICE_IDENTITY_UNSUPPORTED_PLATFORM_ERROR
      );
      assert.throws(
        () => provider.exportPrivateMaterial(),
        (error) => error.code === PHIL_DEVICE_IDENTITY_PRIVATE_MATERIAL_EXPORT_ERROR
      );
    }
  });

  it("rejects WebAuthn registration and authentication in unsupported Node environments", async function () {
    const privateIdentity = createPhilIdentityPrivate();
    const rp = {
      rpId: "localhost",
      rpName: "PhilCore Local",
      origin: "http://localhost",
      userDisplayName: "Phil Test User",
      userName: "phil-test",
      userId: ethers.id("phil-webauthn-user")
    };

    await assert.rejects(
      () =>
        registerWebAuthnDeviceIdentity({
          rp,
          philIdentityPrivate: privateIdentity
        }),
      assertWebAuthnUnsupportedPlatformError
    );

    const provider = createWebAuthnPasskeyDeviceIdentityProvider({
      rp,
      philIdentityPrivate: privateIdentity,
      credential: {
        credentialId: "AQID",
        credentialIdHash: ethers.id("credential-id-hash"),
        rawId: "AQID"
      }
    });

    await assert.rejects(
      () =>
        provider.authorizeDigest({
          signableDigest: ethers.id("webauthn-node-unsupported"),
          digestEncoding: "bytes32-hex"
        }),
      assertWebAuthnUnsupportedPlatformError
    );
  });

  it("builds WebAuthn registration options with expected relying-party policy", function () {
    const privateIdentity = createPhilIdentityPrivate();
    const publicIdentity = derivePhilIdentityPublic(privateIdentity);
    const options = buildWebAuthnRegistrationOptions({
      philIdentity: publicIdentity,
      rp: {
        rpId: "localhost",
        rpName: "PhilCore Local",
        origin: "http://localhost",
        userDisplayName: "Phil Test User",
        userName: "phil-test",
        userId: ethers.id("phil-webauthn-user"),
        userVerification: "required",
        residentKey: "preferred",
        authenticatorAttachment: "platform",
        timeout: 12_345
      },
      challenge: ethers.id("registration-challenge")
    });

    assert.equal(options.rp.id, "localhost");
    assert.equal(options.rp.name, "PhilCore Local");
    assert.equal(options.user.name, "phil-test");
    assert.equal(options.user.displayName, "Phil Test User");
    assert.deepEqual(options.pubKeyCredParams, [{ type: "public-key", alg: -7 }]);
    assert.equal(options.timeout, 12_345);
    assert.equal(options.authenticatorSelection.authenticatorAttachment, "platform");
    assert.equal(options.authenticatorSelection.residentKey, "preferred");
    assert.equal(options.authenticatorSelection.userVerification, "required");
    assert.equal(
      arrayBufferToBase64Url(options.challenge),
      authorizationDigestToWebAuthnChallengeBase64Url(
        ethers.id("registration-challenge")
      )
    );
  });

  it("verifies WebAuthn registration clientDataJSON, authenticatorData, COSE key, and attestation policy", async function () {
    const keyPair = generateP256CredentialKeyPair();
    const challenge = authorizationDigestToWebAuthnChallengeBase64Url(
      ethers.id("webauthn-registration-verifier-challenge")
    );
    const validRegistration = buildSerializedRegistration({
      keyPair,
      expectedChallenge: challenge,
      signCount: 12
    });

    const valid = await verifyWebAuthnRegistration({
      registration: validRegistration,
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required",
      attestationPolicy: {
        mode: "none"
      }
    });

    assert.equal(valid.verified, true);
    assert.equal(valid.productionVerified, true);
    assert.equal(valid.credentialId, validRegistration.rawId);
    assert.equal(valid.credentialPublicKey, keyPair.publicKeyHex);
    assert.equal(valid.algorithm, -7);
    assert.equal(valid.signCount, 12);
    assert.equal(valid.challengeMatched, true);
    assert.equal(valid.originMatched, true);
    assert.equal(valid.rpIdHashMatched, true);
    assert.equal(valid.userPresent, true);
    assert.equal(valid.userVerified, true);
    assert.equal(valid.attestedCredentialDataIncluded, true);
    assert.equal(valid.attestationType, "none");
    assert.equal(valid.attestationPolicyMode, "none");
    assert.deepEqual(valid.transports, ["internal"]);

    const wrongChallenge = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        registrationChallenge: authorizationDigestToWebAuthnChallengeBase64Url(
          ethers.id("wrong-registration-challenge")
        )
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required"
    });
    assert.equal(wrongChallenge.verified, false);
    assert.equal(wrongChallenge.challengeMatched, false);

    const wrongOrigin = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        registrationOrigin: "https://evil.example"
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required"
    });
    assert.equal(wrongOrigin.verified, false);
    assert.equal(wrongOrigin.originMatched, false);

    const wrongRpId = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        registrationRpId: "evil.example"
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required"
    });
    assert.equal(wrongRpId.verified, false);
    assert.equal(wrongRpId.rpIdHashMatched, false);

    const missingUserPresence = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        flags: 0x44
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required"
    });
    assert.equal(missingUserPresence.verified, false);
    assert.equal(missingUserPresence.userPresent, false);

    const missingUserVerification = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        flags: 0x41
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required"
    });
    assert.equal(missingUserVerification.verified, false);
    assert.equal(missingUserVerification.userVerified, false);

    const unsupportedAlgorithm = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        algorithm: -257,
        publicKeyAlgorithm: -257
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required",
      expectedAlgorithms: [-7]
    });
    assert.equal(unsupportedAlgorithm.verified, false);
    assert.match(unsupportedAlgorithm.errors.join("\n"), /ES256|algorithm/);

    const permissive = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        fmt: "packed"
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required",
      attestationPolicy: {
        mode: "permissive"
      }
    });
    assert.equal(permissive.verified, true);
    assert.equal(permissive.attestationType, "packed");
    assert.match(permissive.warnings.join("\n"), /does not validate trusted attestation roots/);

    const direct = await verifyWebAuthnRegistration({
      registration: buildSerializedRegistration({
        keyPair,
        expectedChallenge: challenge,
        fmt: "packed"
      }),
      expectedChallenge: challenge,
      expectedOrigin: "http://localhost",
      expectedRpId: "localhost",
      expectedUserVerification: "required",
      attestationPolicy: {
        mode: "direct"
      }
    });
    assert.equal(direct.verified, false);
    assert.match(direct.errors.join("\n"), /Direct attestation trust root validation is not implemented/);
  });

  it("registers and authorizes a Phil digest through mocked browser WebAuthn", async function () {
    const privateIdentity = createPhilIdentityPrivate();
    const signableDigest = ethers.id("phil-webauthn-signable-digest");
    const rp = {
      rpId: "localhost",
      rpName: "PhilCore Local",
      origin: "http://localhost",
      userDisplayName: "Phil Test User",
      userName: "phil-test",
      userId: ethers.id("phil-webauthn-user"),
      userVerification: "required",
      residentKey: "preferred",
      authenticatorAttachment: "platform",
      timeout: 60_000,
      label: "Phil laptop passkey"
    };
    const keyPair = generateP256CredentialKeyPair();
    const mock = createMockWebAuthnNavigator({
      origin: rp.origin,
      rpId: rp.rpId,
      keyPair,
      signCount: 1
    });
    const registration = await registerWebAuthnDeviceIdentity({
      rp,
      philIdentityPrivate: privateIdentity,
      navigatorLike: mock.navigatorLike,
      now: () => "2026-06-08T00:00:00.000Z"
    });
    const provider = registration.provider;
    const metadata = provider.getPublicMetadata();
    const assertionOptions = provider.buildAssertionOptions({
      signableDigest,
      digestEncoding: "bytes32-hex"
    });
    const directAssertionOptions = buildWebAuthnAssertionOptions({
      rp,
      credential: {
        credentialId: registration.credential.rawId,
        credentialIdHash: metadata.credentialIdHash,
        rawId: registration.credential.rawId,
        transports: ["internal"]
      },
      signableDigest
    });
    const authorization = await provider.authorizeDigest({
      signableDigest,
      digestEncoding: "bytes32-hex"
    });

    assert.equal(provider.providerKind, PHIL_WEBAUTHN_DEVICE_IDENTITY_PROVIDER_KIND);
    assert.equal(provider.hardwareBacked, true);
    assert.equal(provider.productionSafe, false);
    assert.equal(metadata.rpId, rp.rpId);
    assert.equal(metadata.rpName, rp.rpName);
    assert.equal(metadata.origin, rp.origin);
    assert.equal(metadata.userVerification, "required");
    assert.equal(metadata.residentKey, "preferred");
    assert.equal(metadata.privateMaterialExportable, false);
    assert.equal(metadata.philIdentity.ownerCommitment, privateIdentity.ownerCommitment);
    assert.equal(registration.verification.verified, true);
    assert.equal(registration.verification.credentialPublicKey, keyPair.publicKeyHex);
    assert.equal(registration.verification.algorithm, -7);
    assert.equal(registration.verification.signCount, 0);
    assert.equal(Object.prototype.hasOwnProperty.call(metadata.philIdentity, "philSecret"), false);
    assert.equal(objectContainsValue(privateIdentity.philSecret, metadata), false);
    assert.equal(objectContainsValue("privateKey", metadata), false);
    assert.equal(
      arrayBufferToBase64Url(assertionOptions.challenge),
      authorizationDigestToWebAuthnChallengeBase64Url(signableDigest)
    );
    assert.equal(
      arrayBufferToBase64Url(directAssertionOptions.challenge),
      authorizationDigestToWebAuthnChallengeBase64Url(signableDigest)
    );
    assert.equal(mock.calls.create.length, 1);
    assert.equal(mock.calls.get.length, 1);
    assert.equal(
      arrayBufferToBase64Url(mock.calls.get[0].publicKey.challenge),
      authorizationDigestToWebAuthnChallengeBase64Url(signableDigest)
    );
    assert.equal(authorization.signableDigest, signableDigest);
    assert.match(authorization.signature, /^0x[0-9a-f]+$/);
    assert.equal(authorization.verification.verified, true);
    assert.equal(authorization.verification.productionVerified, true);
    assert.equal(authorization.verification.challengeMatched, true);
    assert.equal(authorization.verification.originMatched, true);
    assert.equal(authorization.verification.rpIdHashMatched, true);
    assert.equal(authorization.verification.signatureVerified, true);
    assert.equal(authorization.verification.userPresent, true);
    assert.equal(authorization.verification.userVerified, true);
    assert.equal(authorization.verification.counterStatus, "advanced");
    assert.equal(authorization.verification.newSignCount, 1);
    assert.equal(objectContainsValue(privateIdentity.philSecret, authorization), false);
    assert.throws(
      () => provider.exportPrivateMaterial(),
      assertWebAuthnPrivateMaterialError
    );
  });

  it("verifies WebAuthn assertions with ES256 signatures, rpIdHash, flags, and counters", async function () {
    const keyPair = generateP256CredentialKeyPair();
    const verifier = createWebAuthnAssertionVerifier();
    const challenge = authorizationDigestToWebAuthnChallengeBase64Url(
      ethers.id("webauthn-verifier-digest")
    );

    const valid = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        signCount: 7,
        storedSignCount: 6
      })
    );
    assert.equal(valid.verified, true);
    assert.equal(valid.productionVerified, true);
    assert.equal(valid.signatureVerified, true);
    assert.equal(valid.rpIdHashMatched, true);
    assert.equal(valid.userPresent, true);
    assert.equal(valid.userVerified, true);
    assert.equal(valid.counterStatus, "advanced");
    assert.equal(valid.newSignCount, 7);

    const wrongChallenge = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        assertionChallenge: authorizationDigestToWebAuthnChallengeBase64Url(
          ethers.id("wrong-challenge")
        )
      })
    );
    assert.equal(wrongChallenge.verified, false);
    assert.equal(wrongChallenge.challengeMatched, false);

    const wrongOrigin = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        assertionOrigin: "https://evil.example"
      })
    );
    assert.equal(wrongOrigin.verified, false);
    assert.equal(wrongOrigin.originMatched, false);

    const wrongRpId = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        assertionRpId: "evil.example"
      })
    );
    assert.equal(wrongRpId.verified, false);
    assert.equal(wrongRpId.rpIdHashMatched, false);

    const missingUserPresence = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        flags: 0x04
      })
    );
    assert.equal(missingUserPresence.verified, false);
    assert.equal(missingUserPresence.userPresent, false);

    const missingUserVerification = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        flags: 0x01
      })
    );
    assert.equal(missingUserVerification.verified, false);
    assert.equal(missingUserVerification.userVerified, false);

    const invalidSignature = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        invalidSignature: true
      })
    );
    assert.equal(invalidSignature.verified, false);
    assert.equal(invalidSignature.signatureVerified, false);

    const rollback = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        signCount: 4,
        storedSignCount: 5
      })
    );
    assert.equal(rollback.verified, false);
    assert.equal(rollback.counterStatus, "rollback");

    const cloneSuspected = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        signCount: 5,
        storedSignCount: 5
      })
    );
    assert.equal(cloneSuspected.verified, false);
    assert.equal(cloneSuspected.counterStatus, "clone-suspected");

    const zeroCounter = await verifier.verifyAssertion(
      buildVerificationInput({
        keyPair,
        expectedChallenge: challenge,
        signCount: 0,
        storedSignCount: 0
      })
    );
    assert.equal(zeroCounter.verified, true);
    assert.equal(zeroCounter.counterStatus, "unchanged-zero");
    assert.match(zeroCounter.warnings.join("\n"), /may not support counters/);
  });

  it("builds a deterministic context-bound World ID signal and binding", function () {
    const identity = createPhilIdentityPrivate();
    const onboarding = buildWorldIdOnboardingRequest({
      ownerCommitment: derivePhilIdentityPublic(identity).ownerCommitment,
      appId: "app_staging_philtls"
    });
    const repeatedSignal = buildContextBoundWorldIdSignal({
      ownerCommitment: onboarding.ownerCommitment,
      appId: onboarding.appId,
      action: onboarding.action
    });
    const changedAppSignal = buildContextBoundWorldIdSignal({
      ownerCommitment: onboarding.ownerCommitment,
      appId: "app_other_philtls",
      action: onboarding.action
    });
    const changedActionSignal = buildContextBoundWorldIdSignal({
      ownerCommitment: onboarding.ownerCommitment,
      appId: onboarding.appId,
      action: "phil-human-onboarding-v2"
    });

    assert.equal(onboarding.signal, repeatedSignal);
    assert.notEqual(onboarding.signal, changedAppSignal);
    assert.notEqual(onboarding.signal, changedActionSignal);

    const receipt = createWorldIdVerificationReceipt({
      appId: onboarding.appId,
      action: onboarding.action,
      signal: onboarding.signal,
      nullifierHash: ethers.id("world-id-nullifier-hash"),
      merkleRoot: ethers.id("world-id-merkle-root"),
      proof: "proof-placeholder",
      verificationLevel: "orb",
      verifiedAt: 1_710_000_000
    });

    const binding = bindWorldIdVerificationToPhilIdentity({
      ownerCommitment: derivePhilIdentityPublic(identity).ownerCommitment,
      receipt
    });

    assert.equal(binding.storageModel, "offchain");
    assert.equal(binding.status, "verified");
    assert.equal(binding.ownerCommitment, derivePhilIdentityPublic(identity).ownerCommitment);
    assert.equal(binding.worldId.appId, onboarding.appId);
    assert.equal(binding.worldId.action, onboarding.action);
    assert.equal(binding.worldId.signal, onboarding.signal);
    assert.equal(binding.worldId.nullifierHash, receipt.nullifierHash);
    assert.equal(binding.bindingHash.startsWith("0x"), true);
  });

  it("rejects mismatched World ID signals before binding them to a Phil identity", function () {
    const identity = createPhilIdentityPrivate();
    const publicIdentity = derivePhilIdentityPublic(identity);
    const onboarding = buildWorldIdOnboardingRequest({
      ownerCommitment: publicIdentity.ownerCommitment,
      appId: "app_staging_philtls"
    });

    const mismatchedReceipt = createWorldIdVerificationReceipt({
      appId: onboarding.appId,
      action: onboarding.action,
      signal: buildContextBoundWorldIdSignal({
        ownerCommitment: publicIdentity.ownerCommitment,
        appId: onboarding.appId,
        action: "different-action"
      }),
      nullifierHash: ethers.id("world-id-nullifier")
    });

    assert.throws(
      () =>
        bindWorldIdVerificationToPhilIdentity({
          ownerCommitment: publicIdentity.ownerCommitment,
          receipt: mismatchedReceipt
        }),
      /World ID signal does not match/
    );
  });
});
