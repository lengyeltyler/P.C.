const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  ACCOUNT_VERSION_ID,
  APPLICATION_IDENTITY,
  LOCAL_APPROVAL_POLICY,
  SECURITY_MODEL_ID,
  canonicalTranscript,
  createNativeIPhonePairingHost,
  createNativeRole1DescriptorStore,
  displayFingerprint,
  evaluateDesktopIPhoneReadiness,
  keyFromSharedSecret,
  listPrivateInterfaces,
  parseMacHardwarePorts,
  selectIPhonePrivateInterface,
  sha256
} = require("../src/main/native-iphone-pairing-host.cjs");

function productionPolicyStatus(overrides = {}) {
  return {
    port: 18444,
    interface: { address: "192.168.1.20" },
    publicNetworkExposure: false,
    policyMode: "PRODUCTION",
    applicationIdentity: APPLICATION_IDENTITY,
    localApprovalPolicy: LOCAL_APPROVAL_POLICY,
    accountVersionId: ACCOUNT_VERSION_ID,
    securityModelId: SECURITY_MODEL_ID,
    verifierKind: 4,
    simulatorCredentialsAllowed: false,
    secureEnclaveRequired: true,
    ...overrides
  };
}

function decodeRequest(encodedRequest) {
  const encoded = new URL(encodedRequest).searchParams.get("request");
  return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
}

function rawPublicKey(keyObject) {
  const jwk = keyObject.export({ format: "jwk" });
  return Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url")
  ]);
}

function seal(value, sessionId, phonePublic, key) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(`PHONE_TO_DESKTOP|${sessionId}`, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final()
  ]);
  return {
    version: 1,
    sessionId,
    phoneEphemeralPublicKey: phonePublic.toString("base64url"),
    nonce: nonce.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url")
  };
}

function buildPhoneMessage(request, overrides = {}) {
  const phoneEcdh = crypto.createECDH("prime256v1");
  const phonePublic = phoneEcdh.generateKeys();
  const secret = phoneEcdh.computeSecret(
    Buffer.from(request.desktopEphemeralPublicKey, "base64url")
  );
  const transcript = canonicalTranscript(request);
  const transcriptHash = sha256(transcript);
  const key = keyFromSharedSecret(secret, transcriptHash);
  const credential = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const credentialPublic = rawPublicKey(credential.publicKey);
  const generation = Buffer.alloc(8);
  generation.writeBigUInt64BE(BigInt(request.requestedGeneration));
  const payload = {
    protocolVersion: 1,
    sessionId: request.sessionId,
    phoneEphemeralPublicKey: phonePublic.toString("base64url"),
    transcriptHash: transcriptHash.toString("base64url"),
    credentialPublicKey: credentialPublic.toString("base64url"),
    credentialFingerprint: displayFingerprint(credentialPublic),
    credentialIdentifierCommitment: sha256(
      Buffer.from("PHILCORE_NATIVE_CREDENTIAL_ID_V1"),
      credentialPublic
    ).toString("base64url"),
    applicationIdentity: APPLICATION_IDENTITY,
    applicationIdentityHash: sha256(Buffer.from(APPLICATION_IDENTITY))
      .toString("base64url"),
    deviceCustodyCommitment: sha256(
      Buffer.from("PHILCORE_NATIVE_DEVICE_CUSTODY_V1"),
      credentialPublic,
      generation
    ).toString("base64url"),
    localApprovalPolicyHash: sha256(Buffer.from(LOCAL_APPROVAL_POLICY))
      .toString("base64url"),
    generation: request.requestedGeneration,
    secureEnclaveBacked: false,
    simulatorOnly: true,
    enrollmentSignatureDER: crypto.sign(
      "sha256",
      transcript,
      credential.privateKey
    ).toString("base64url"),
    ...overrides
  };
  return {
    key,
    message: seal(payload, request.sessionId, phonePublic, key)
  };
}

function post(endpoint, body) {
  return new Promise((resolve, reject) => {
    const request = http.request(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" }
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({
        status: response.statusCode,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8"))
      }));
    });
    request.on("error", reject);
    request.end(JSON.stringify(body));
  });
}

async function run() {
  const selected = listPrivateInterfaces()[0];
  assert.ok(selected, "A private interface is required for the LAN host test");
  let verified = null;
  const host = createNativeIPhonePairingHost({
    interfaceAddress: selected.address,
    interfaceName: selected.name,
    allowSimulator: true,
    onVerified(descriptor) {
      verified = descriptor;
    }
  });
  await host.start();
  const pairing = host.beginPairing({
    philCoreIdentityCommitment: `0x${"43".repeat(32)}`,
    recoveryEpoch: 7,
    requestedGeneration: 2
  });
  assert.equal(pairing.containsPrivateAuthority, false);
  assert.equal(pairing.containsLongLivedBearerToken, false);
  assert.match(pairing.comparisonFingerprint, /^[0-9A-F]{4}( [0-9A-F]{4}){5}$/u);
  const decoded = decodeRequest(pairing.encodedRequest);
  assert.equal(decoded.endpoint.startsWith(`http://${selected.address}:`), true);
  assert.equal(decoded.endpoint.includes("localhost"), false);
  assert.equal(decoded.applicationIdentity, APPLICATION_IDENTITY);
  assert.equal(decoded.recoveryEpoch, 7);

  const phone = buildPhoneMessage(decoded);
  const completed = await post(decoded.endpoint, phone.message);
  assert.equal(completed.status, 200);
  assert.equal(verified.role, 1);
  assert.equal(verified.verifierKind, 4);
  assert.equal(verified.simulatorCredential, true);
  assert.equal(verified.secureEnclaveRequired, false);
  assert.equal(host.status().status, "VERIFIED");

  const replay = await post(decoded.endpoint, phone.message);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.reason, "PAIRING_SESSION_EXPIRED_OR_USED");

  const substitutionPairing = host.beginPairing({
    philCoreIdentityCommitment: `0x${"44".repeat(32)}`,
    recoveryEpoch: 8,
    requestedGeneration: 3
  });
  const substitutionRequest = decodeRequest(substitutionPairing.encodedRequest);
  const substitution = buildPhoneMessage(substitutionRequest, {
    applicationIdentity: "PHILCORE_IOS_NATIVE_ROLE1_V1|WRONG|wrong.bundle"
  });
  const rejected = await post(substitutionRequest.endpoint, substitution.message);
  assert.equal(rejected.status, 400);
  assert.equal(rejected.body.reason, "PAIRING_RESPONSE_BINDING_INVALID");

  const simulatorStatus = host.status();
  assert.equal(simulatorStatus.policyMode, "SIMULATOR_TEST");
  assert.equal(simulatorStatus.applicationIdentity, APPLICATION_IDENTITY);
  assert.equal(simulatorStatus.localApprovalPolicy, LOCAL_APPROVAL_POLICY);
  assert.equal(simulatorStatus.accountVersionId, ACCOUNT_VERSION_ID);
  assert.equal(simulatorStatus.securityModelId, SECURITY_MODEL_ID);
  assert.equal(simulatorStatus.verifierKind, 4);
  assert.equal(simulatorStatus.simulatorCredentialsAllowed, true);
  assert.equal(simulatorStatus.secureEnclaveRequired, false);
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness(host),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness(null),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status() {
        throw new Error("malformed");
      }
    }),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({
        port: 9,
        interface: { address: "1.1.1.1" }
      })
    }),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({
        applicationIdentity: "tampered-identity"
      })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({
        localApprovalPolicy: "tampered-policy"
      })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({
        accountVersionId: `0x${"00".repeat(32)}`
      })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({
        securityModelId: `0x${"00".repeat(32)}`
      })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({ verifierKind: 3 })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({ simulatorCredentialsAllowed: true })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({ secureEnclaveRequired: false })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({ policyMode: "SIMULATOR_TEST" })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: false }
  );
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

  host.cancel();
  await host.stop();
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness(host),
    { pairingTransportReady: false, nativeRole1PolicyReady: false }
  );

  const productionStyleHost = createNativeIPhonePairingHost({
    interfaceAddress: selected.address,
    interfaceName: selected.name,
    allowSimulator: false
  });
  await productionStyleHost.start();
  const productionStatus = productionStyleHost.status();
  assert.equal(productionStatus.policyMode, "PRODUCTION");
  assert.equal(productionStatus.simulatorCredentialsAllowed, false);
  assert.equal(productionStatus.secureEnclaveRequired, true);
  assert.equal(productionStatus.verifierKind, 4);
  assert.equal(productionStatus.applicationIdentity, APPLICATION_IDENTITY);
  assert.equal(productionStatus.localApprovalPolicy, LOCAL_APPROVAL_POLICY);
  assert.equal(productionStatus.accountVersionId, ACCOUNT_VERSION_ID);
  assert.equal(productionStatus.securityModelId, SECURITY_MODEL_ID);
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness(productionStyleHost),
    { pairingTransportReady: true, nativeRole1PolicyReady: true }
  );
  assert.deepEqual(
    evaluateDesktopIPhoneReadiness({
      status: () => productionPolicyStatus({
        port: productionStatus.port,
        interface: productionStatus.interface,
        publicNetworkExposure: false
      })
    }),
    { pairingTransportReady: true, nativeRole1PolicyReady: true }
  );
  assert.equal(
    productionStyleHost.status().completedDescriptor,
    null,
    "desktop readiness must not require Role 1 enrollment"
  );
  await productionStyleHost.stop();

  assert.deepEqual(listPrivateInterfaces({
    lo0: [{ family: "IPv4", internal: true, address: "127.0.0.1" }],
    public0: [{ family: "IPv4", internal: false, address: "8.8.8.8" }],
    en7: [{ family: "IPv4", internal: false, address: "192.168.50.4" }]
  }), [{ name: "en7", address: "192.168.50.4" }]);
  const dualInterfaceFixture = {
    en0: [{ family: "IPv4", internal: false, address: "192.168.50.20" }],
    en1: [{ family: "IPv4", internal: false, address: "192.168.50.21" }]
  };
  const hardwarePortsFixture = [
    "Hardware Port: Ethernet",
    "Device: en0",
    "Ethernet Address: 00:00:00:00:00:01",
    "",
    "Hardware Port: Wi-Fi",
    "Device: en1",
    "Ethernet Address: 00:00:00:00:00:02"
  ].join("\n");
  assert.deepEqual(parseMacHardwarePorts(hardwarePortsFixture), ["en1"]);
  assert.deepEqual(
    selectIPhonePrivateInterface({ networkInterfaces: dualInterfaceFixture, hardwarePortsText: hardwarePortsFixture }),
    { name: "en1", address: "192.168.50.21" },
    "iPhone-local transport must prefer the active Wi-Fi interface over wired en0"
  );
  assert.deepEqual(
    selectIPhonePrivateInterface({ networkInterfaces: dualInterfaceFixture, hardwarePortsText: "" }),
    { name: "en0", address: "192.168.50.20" },
    "selection must preserve the prior deterministic fallback when Wi-Fi discovery is unavailable"
  );
  assert.throws(
    () => createNativeIPhonePairingHost({ interfaceAddress: "0.0.0.0" }),
    /PAIRING_PRIVATE_INTERFACE_REQUIRED/
  );

  const storageRoot = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o43-native-"));
  const storageKey = crypto.randomBytes(32);
  const encryptionAdapter = {
    isAvailable: () => true,
    encrypt(plaintext) {
      const nonce = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", storageKey, nonce);
      const ciphertext = Buffer.concat([
        cipher.update(String(plaintext), "utf8"),
        cipher.final()
      ]);
      return Buffer.concat([nonce, cipher.getAuthTag(), ciphertext]);
    },
    decrypt(encrypted) {
      const value = Buffer.from(encrypted);
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        storageKey,
        value.subarray(0, 12)
      );
      decipher.setAuthTag(value.subarray(12, 28));
      return Buffer.concat([
        decipher.update(value.subarray(28)),
        decipher.final()
      ]).toString("utf8");
    }
  };
  const descriptorStore = createNativeRole1DescriptorStore({
    storageRoot,
    encryptionAdapter
  });
  assert.equal(descriptorStore.publicStatus().enrolled, false);
  descriptorStore.write(verified);
  assert.deepEqual(descriptorStore.publicStatus(), {
    enrolled: true,
    lostDevice: false,
    generation: 2,
    publicFingerprint: verified.publicFingerprint,
    applicationIdentity: APPLICATION_IDENTITY,
    simulatorCredential: true,
    containsPrivateKey: false
  });
  assert.equal(
    fs.readFileSync(descriptorStore.filePath, "utf8")
      .includes(verified.publicKeyX963),
    false
  );
  assert.throws(() => descriptorStore.write(verified), /GENERATION_INVALID/);
  descriptorStore.markLost();
  assert.equal(descriptorStore.publicStatus().lostDevice, true);
  fs.rmSync(storageRoot, { recursive: true, force: true });
  process.stdout.write("ok - O.43 native iPhone pairing host\n");
}

run().catch((error) => {
  process.stderr.write(`${error.stack}\n`);
  process.exitCode = 1;
});
