const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  PHIL_DEVICE_IDENTITY_VERSION,
  PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
  LOCAL_DEV_DEVICE_IDENTITY_PRODUCTION_SAFE,
  createLocalDevDeviceIdentityProvider
} = require("../../apps/phil-device-sdk/src/deviceIdentity.ts");
const {
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
} = require("./build-smart-account-deploy-signature-request.cjs");
const {
  buildSmartAccountDeploySignedUserOp
} = require("./build-smart-account-deploy-signed-userop.cjs");

const LOCAL_DEVICE_SIGNING_DOMAIN_LABEL =
  "PHIL_LOCAL_SMART_ACCOUNT_DEPLOY_DEVICE_SIGNING_V1";
const LOCAL_DEVICE_SIGNING_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(LOCAL_DEVICE_SIGNING_DOMAIN_LABEL)
);
const LOCAL_DEVICE_SIGNING_KIND =
  "local-smart-account-deploy-device-signing-phase0-v1";
const LOCAL_DEVICE_SIGNING_SIGNATURE_KIND =
  "local-secp256k1-userop-hash-signature-v1";
const LOCAL_DEVICE_SIGNING_DEFAULT_SIGNATURE_REQUEST_PATH =
  "./proving/out/smart_account_deploy_signature_request/smart_account_deploy_signature_request.json";
const LOCAL_DEVICE_SIGNING_DEFAULT_OUT =
  "./proving/out/local_device_signing/local_device_signing_result.json";
const LOCAL_DEVICE_SIGNING_DEFAULT_DEV_KEY_LABEL =
  "phil-local-device-signing-dev-key-phase0-v1";

function loadJson(jsonPath) {
  if (!fs.existsSync(jsonPath)) {
    throw new Error(
      `Missing ${jsonPath}. Run npm run generate:local-fixtures first.`
    );
  }
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function writeJson(jsonPath, value) {
  fs.mkdirSync(path.dirname(jsonPath), { recursive: true });
  fs.writeFileSync(jsonPath, `${JSON.stringify(value, null, 2)}\n`);
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label} mismatch`);
  }
}

function assertTrue(value, label) {
  if (value !== true) {
    throw new Error(`${label} must be true`);
  }
}

function normalizeBytes(value, label) {
  try {
    return ethers.hexlify(ethers.getBytes(value)).toLowerCase();
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function normalizeHex32(value, label) {
  const normalized = normalizeBytes(value, label);
  if (normalized.length !== 66) {
    throw new Error(`Invalid ${label}: ${normalized}`);
  }
  return normalized;
}

function normalizeAddress(value, label) {
  try {
    return ethers.getAddress(value);
  } catch {
    throw new Error(`Invalid ${label}: ${String(value || "").trim() || "<empty>"}`);
  }
}

function normalizeString(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    throw new Error(`Invalid ${label}: <empty>`);
  }
  return normalized;
}

function normalizePrivateKey(value, label) {
  const normalized = normalizeHex32(value, label);
  if (BigInt(normalized) === 0n) {
    throw new Error(`${label} must not be zero`);
  }
  try {
    new ethers.SigningKey(normalized);
  } catch {
    throw new Error(`Invalid ${label}: signing key rejected`);
  }
  return normalized;
}

function deriveDefaultDevPrivateKey() {
  return normalizePrivateKey(
    ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "string"],
        [LOCAL_DEVICE_SIGNING_DOMAIN_HASH, LOCAL_DEVICE_SIGNING_DEFAULT_DEV_KEY_LABEL]
      )
    ),
    "deterministicDevPrivateKey"
  );
}

function parseDevKeyFile(devKeyFilePath) {
  const raw = fs.readFileSync(devKeyFilePath, "utf8").trim();
  if (!raw) {
    throw new Error(`Invalid dev key file: ${devKeyFilePath}`);
  }

  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      return parsed.privateKey || parsed.devPrivateKey;
    }
  } catch {
    return raw;
  }

  return raw;
}

function loadLocalDevSigningKey({ devPrivateKey, devKeyFile } = {}) {
  if (devPrivateKey && devKeyFile) {
    throw new Error("Choose either --dev-private-key or --dev-key-file, not both");
  }

  let privateKey;
  let keySource;
  let keySourcePath = null;

  if (devPrivateKey) {
    privateKey = normalizePrivateKey(devPrivateKey, "devPrivateKey");
    keySource = "explicit-local-dev-private-key";
  } else if (devKeyFile) {
    const resolvedDevKeyFile = path.resolve(devKeyFile);
    privateKey = normalizePrivateKey(
      parseDevKeyFile(resolvedDevKeyFile),
      "devKeyFile.privateKey"
    );
    keySource = "local-dev-key-file";
    keySourcePath = resolvedDevKeyFile;
  } else {
    privateKey = deriveDefaultDevPrivateKey();
    keySource = "deterministic-local-dev-key";
  }

  const signingKey = new ethers.SigningKey(privateKey);
  const signerAddress = ethers.computeAddress(signingKey.publicKey);
  const publicKey = normalizeBytes(signingKey.publicKey, "publicKey");
  const publicKeyHash = ethers.keccak256(publicKey);
  const devKeyId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "bytes32"],
      [LOCAL_DEVICE_SIGNING_DOMAIN_HASH, signerAddress, publicKeyHash]
    )
  );

  return {
    privateKey,
    keySource,
    keySourcePath,
    signerAddress,
    publicKey,
    publicKeyHash,
    devKeyId,
    deviceIdentityProvider: createLocalDevDeviceIdentityProvider({
      devPrivateKey: privateKey,
      keySource,
      keySourcePath
    })
  };
}

function signPreparedDigest({ privateKey, signableDigest }) {
  const signature = ethers.Signature.from(
    new ethers.SigningKey(privateKey).sign(signableDigest)
  ).serialized.toLowerCase();
  const recoveredAddress = normalizeAddress(
    ethers.recoverAddress(signableDigest, signature),
    "recoveredAddress"
  );

  return {
    signature,
    recoveredAddress,
    signatureHash: ethers.keccak256(signature)
  };
}

function validateSignatureRequest(smartAccountDeploySignatureRequest) {
  if (
    !smartAccountDeploySignatureRequest ||
    typeof smartAccountDeploySignatureRequest !== "object"
  ) {
    throw new Error("smartAccountDeploySignatureRequest is required");
  }

  assertEqual(
    smartAccountDeploySignatureRequest.path,
    "phil-smart-account-deploy-signature-request",
    "smartAccountDeploySignatureRequest.path"
  );
  assertEqual(
    smartAccountDeploySignatureRequest.proofType,
    "stwo-unlock-keccak-v1",
    "smartAccountDeploySignatureRequest.proofType"
  );
  assertEqual(
    smartAccountDeploySignatureRequest.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeploySignatureRequest.payloadShape"
  );

  if (
    !smartAccountDeploySignatureRequest.validationChecks ||
    typeof smartAccountDeploySignatureRequest.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeploySignatureRequest.validationChecks is required");
  }
  if (
    !smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary ||
    typeof smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary is required"
    );
  }
  if (
    !smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest ||
    typeof smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest is required"
    );
  }
  if (
    !smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest ||
    typeof smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest !==
      "object"
  ) {
    throw new Error(
      "smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest is required"
    );
  }

  assertTrue(
    smartAccountDeploySignatureRequest.validationChecks
      .smartAccountDeployUserOpHashPathValid,
    "validationChecks.smartAccountDeployUserOpHashPathValid"
  );
  assertTrue(
    smartAccountDeploySignatureRequest.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeploySignatureRequest.validationChecks
      .upstreamSmartAccountDeployUserOpHashValid,
    "validationChecks.upstreamSmartAccountDeployUserOpHashValid"
  );
  assertTrue(
    smartAccountDeploySignatureRequest.validationChecks
      .deterministicSmartAccountDeploySignatureRequestDerived,
    "validationChecks.deterministicSmartAccountDeploySignatureRequestDerived"
  );
  assertTrue(
    smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.ready,
    "smartAccountDeploySignatureRequestSummary.ready"
  );
  assertEqual(
    smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.status,
    "smart-account-deploy-signature-request-ready",
    "smartAccountDeploySignatureRequestSummary.status"
  );
  assertTrue(
    smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary
      .parityProven,
    "smartAccountDeploySignatureRequestSummary.parityProven"
  );

  const request =
    smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest;
  const appRequest =
    smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest;

  const ownerCommitment = normalizeHex32(request.ownerCommitment, "ownerCommitment");
  const consumerDataHash = normalizeHex32(request.consumerDataHash, "consumerDataHash");
  const canonicalRecipient = normalizeAddress(
    request.canonicalRecipient,
    "canonicalRecipient"
  );
  const targetAddress = normalizeAddress(request.targetAddress, "targetAddress");
  const entryPointAddress = normalizeAddress(
    request.entryPointAddress,
    "entryPointAddress"
  );
  const userOpHash = normalizeHex32(request.userOpHash, "userOpHash");
  const signableDigest = normalizeHex32(request.signableDigest, "signableDigest");
  const signerPayloadHash = normalizeHex32(
    request.signerPayloadHash,
    "signerPayloadHash"
  );
  const signatureRequestHash = normalizeHex32(
    request.signatureRequestHash,
    "signatureRequestHash"
  );
  const signatureRequestId = normalizeHex32(
    request.signatureRequestId,
    "signatureRequestId"
  );
  const signingContextHash = normalizeHex32(
    request.signingContextHash,
    "signingContextHash"
  );
  const signingContextId = normalizeHex32(
    request.signingContextId,
    "signingContextId"
  );

  assertEqual(request.signatureRequestKind, SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND, "signatureRequestKind");
  assertEqual(signableDigest, userOpHash, "signableDigest/userOpHash");
  assertEqual(
    request.signableDigestBytes,
    signableDigest,
    "signableDigestBytes/signableDigest"
  );
  assertEqual(
    request.digestEncoding,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    "digestEncoding"
  );

  if (!request.signerPayload || typeof request.signerPayload !== "object") {
    throw new Error("signerPayload is required");
  }
  if (!request.signatureTarget || typeof request.signatureTarget !== "object") {
    throw new Error("signatureTarget is required");
  }
  if (!request.signatureRequest || typeof request.signatureRequest !== "object") {
    throw new Error("signatureRequest is required");
  }

  assertEqual(
    request.signerPayload.payloadKind,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND,
    "signerPayload.payloadKind"
  );
  assertEqual(
    normalizeHex32(request.signerPayload.signableDigest, "signerPayload.signableDigest"),
    signableDigest,
    "signerPayload.signableDigest/signableDigest"
  );
  assertEqual(
    request.signerPayload.digestEncoding,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    "signerPayload.digestEncoding"
  );
  assertEqual(
    normalizeAddress(request.signerPayload.sender, "signerPayload.sender").toLowerCase(),
    targetAddress.toLowerCase(),
    "signerPayload.sender/targetAddress"
  );
  assertEqual(
    request.signerPayload.signatureField,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
    "signerPayload.signatureField"
  );
  assertEqual(
    normalizeBytes(request.signerPayload.signaturePlaceholder, "signerPayload.signaturePlaceholder"),
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "signerPayload.signaturePlaceholder"
  );
  assertEqual(
    request.signerPayloadJson,
    JSON.stringify(request.signerPayload),
    "signerPayloadJson"
  );
  assertEqual(
    normalizeBytes(request.signerPayloadBytes, "signerPayloadBytes"),
    ethers.hexlify(ethers.toUtf8Bytes(request.signerPayloadJson)),
    "signerPayloadBytes"
  );
  assertEqual(
    signerPayloadHash,
    ethers.keccak256(ethers.toUtf8Bytes(request.signerPayloadJson)),
    "signerPayloadHash"
  );
  assertEqual(
    request.signatureTarget.userOperationField,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
    "signatureTarget.userOperationField"
  );
  assertEqual(
    request.signatureTarget.bundlerRequestPath,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
    "signatureTarget.bundlerRequestPath"
  );
  assertEqual(
    normalizeBytes(request.signatureTarget.signaturePlaceholder, "signatureTarget.signaturePlaceholder"),
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "signatureTarget.signaturePlaceholder"
  );
  assertEqual(
    request.signatureRequestJson,
    JSON.stringify(request.signatureRequest),
    "signatureRequestJson"
  );
  assertEqual(
    normalizeBytes(request.signatureRequestBytes, "signatureRequestBytes"),
    ethers.hexlify(ethers.toUtf8Bytes(request.signatureRequestJson)),
    "signatureRequestBytes"
  );
  assertEqual(
    signatureRequestHash,
    ethers.keccak256(ethers.toUtf8Bytes(request.signatureRequestJson)),
    "signatureRequestHash"
  );

  assertEqual(
    normalizeAddress(appRequest.recipient, "app.recipient").toLowerCase(),
    canonicalRecipient.toLowerCase(),
    "app.recipient/canonicalRecipient"
  );
  assertEqual(
    normalizeAddress(appRequest.sender, "app.sender").toLowerCase(),
    targetAddress.toLowerCase(),
    "app.sender/targetAddress"
  );
  assertEqual(
    normalizeAddress(appRequest.entryPointAddress, "app.entryPointAddress").toLowerCase(),
    entryPointAddress.toLowerCase(),
    "app.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    normalizeHex32(appRequest.userOpHash, "app.userOpHash"),
    userOpHash,
    "app.userOpHash/userOpHash"
  );
  assertEqual(
    normalizeHex32(appRequest.signatureRequestId, "app.signatureRequestId"),
    signatureRequestId,
    "app.signatureRequestId/signatureRequestId"
  );
  assertTrue(appRequest.ready === true, "app.ready");
  assertEqual(
    String(appRequest.status || ""),
    "smart-account-deploy-signature-request-ready",
    "app.status"
  );
  assertTrue(appRequest.parityProven === true, "app.parityProven");

  return {
    ownerCommitment,
    consumerDataHash,
    canonicalRecipient,
    targetAddress,
    entryPointAddress,
    chainId: normalizeString(request.chainId, "chainId"),
    userOpHash,
    signableDigest,
    signerPayloadHash,
    signatureRequestHash,
    signatureRequestId,
    signingContextHash,
    signingContextId,
    signatureTarget: {
      userOperationField: request.signatureTarget.userOperationField,
      bundlerRequestPath: request.signatureTarget.bundlerRequestPath,
      signaturePlaceholder: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
    }
  };
}

function runLocalSmartAccountDeploySigning({
  smartAccountDeploySignatureRequest,
  devPrivateKey,
  devKeyFile,
  now = () => new Date().toISOString()
}) {
  const validatedRequest = validateSignatureRequest(smartAccountDeploySignatureRequest);
  const devKey = loadLocalDevSigningKey({ devPrivateKey, devKeyFile });
  const deviceIdentityPublicMetadata = devKey.deviceIdentityProvider.getPublicMetadata();
  const deviceAuthorization = devKey.deviceIdentityProvider.authorizeDigest({
    signatureRequestId: validatedRequest.signatureRequestId,
    signerPayloadHash: validatedRequest.signerPayloadHash,
    signatureRequestHash: validatedRequest.signatureRequestHash,
    signableDigest: validatedRequest.signableDigest,
    digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    signatureTarget: validatedRequest.signatureTarget
  });
  const localSignature = {
    signature: deviceAuthorization.signature,
    recoveredAddress: normalizeAddress(
      deviceAuthorization.recoveredAddress,
      "deviceAuthorization.recoveredAddress"
    ),
    signatureHash: deviceAuthorization.signatureHash
  };
  const legacyDirectSignature = signPreparedDigest({
    privateKey: devKey.privateKey,
    signableDigest: validatedRequest.signableDigest
  });

  if (
    localSignature.signature ===
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
  ) {
    throw new Error("local signature must not be the placeholder value");
  }
  assertEqual(
    localSignature.recoveredAddress.toLowerCase(),
    devKey.signerAddress.toLowerCase(),
    "recoveredAddress/signerAddress"
  );
  assertEqual(
    localSignature.signature,
    legacyDirectSignature.signature,
    "deviceIdentitySignature/legacyDirectSignature"
  );

  const signedUserOpArtifact = buildSmartAccountDeploySignedUserOp({
    smartAccountDeploySignatureRequest,
    externalSignature: localSignature.signature
  });

  assertEqual(
    signedUserOpArtifact.path,
    "phil-smart-account-deploy-signed-userop",
    "signedUserOp.path"
  );
  assertTrue(
    signedUserOpArtifact.validationChecks.externalSignatureAccepted,
    "signedUserOp.validationChecks.externalSignatureAccepted"
  );
  assertEqual(
    signedUserOpArtifact.smartAccountDeploySignedUserOp.externalSignature,
    localSignature.signature,
    "signedUserOp.externalSignature/localSignature"
  );
  assertEqual(
    signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOperation.signature,
    localSignature.signature,
    "signedUserOperation.signature/localSignature"
  );
  assertEqual(
    signedUserOpArtifact.appSmartAccountDeploySignedUserOp.recipient.toLowerCase(),
    validatedRequest.canonicalRecipient.toLowerCase(),
    "signedUserOp.recipient/canonicalRecipient"
  );
  assertEqual(
    signedUserOpArtifact.appSmartAccountDeploySignedUserOp.sender.toLowerCase(),
    validatedRequest.targetAddress.toLowerCase(),
    "signedUserOp.sender/targetAddress"
  );
  assertEqual(
    signedUserOpArtifact.appSmartAccountDeploySignedUserOp.userOpHash,
    validatedRequest.userOpHash,
    "signedUserOp.userOpHash/userOpHash"
  );

  const signingRecord = {
    signingKind: LOCAL_DEVICE_SIGNING_KIND,
    signatureKind: LOCAL_DEVICE_SIGNING_SIGNATURE_KIND,
    keySource: devKey.keySource,
    signerAddress: devKey.signerAddress,
    devKeyId: devKey.devKeyId,
    signatureRequestId: validatedRequest.signatureRequestId,
    signerPayloadHash: validatedRequest.signerPayloadHash,
    signableDigest: validatedRequest.signableDigest,
    digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    signatureTarget: validatedRequest.signatureTarget,
    localSignatureHash: localSignature.signatureHash,
    signedUserOpId:
      signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOpId,
    signedBundlerRequestHash:
      signedUserOpArtifact.smartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
    executedAt: now(),
    localOnly: true,
    externalBundlerCallPerformed: false
  };
  const signingRecordJson = JSON.stringify(signingRecord);
  const signingRecordHash = ethers.keccak256(ethers.toUtf8Bytes(signingRecordJson));
  const localDeviceSigningId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32"],
      [LOCAL_DEVICE_SIGNING_DOMAIN_HASH, signingRecordHash]
    )
  );

  return {
    version: 1,
    path: "phil-local-smart-account-deploy-device-signing",
    localDeviceSigningSource:
      "scripts/base/run-local-smart-account-deploy-signing.cjs",
    smartAccountDeploySignatureRequestSource:
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSource,
    smartAccountDeploySignedUserOpSource:
      "scripts/base/build-smart-account-deploy-signed-userop.cjs",
    consumedPath: smartAccountDeploySignatureRequest.path,
    proofType: smartAccountDeploySignatureRequest.proofType,
    payloadShape: smartAccountDeploySignatureRequest.payloadShape,
    localDeviceSigningDomain: {
      label: LOCAL_DEVICE_SIGNING_DOMAIN_LABEL,
      hash: LOCAL_DEVICE_SIGNING_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeploySignatureRequestPathValid: true,
      proofTypeValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeploySignatureRequestValid: true,
      signerPayloadConsumed: true,
      signableDigestMatchesUserOpHash: true,
      signatureTargetPreserved: true,
      localDevSigningKeyResolved: true,
      deviceIdentityProviderResolved: true,
      deviceIdentitySignedExpectedDigest: true,
      localDevProviderMarkedUnsafeForProduction: true,
      realLocalSignatureProduced: true,
      signatureRecoverable: true,
      existingSignedUserOpPathReused: true,
      signedUserOpSignatureMatchesLocalSignature: true,
      canonicalRecipientPreserved: true,
      exactTwoFeltFactShapePreserved: true,
      lockedBaseTupleSemanticsUnchanged: true,
      localOnlyNoExternalBundlerCall: true
    },
    localDeviceSigningSummary: {
      ready: true,
      status: "local-device-signing-complete",
      reason: "validated-signature-request-signed-locally",
      localOnly: true,
      realLocalSignatureProduced: true,
      signedUserOpPathReused: true,
      keySource: devKey.keySource,
      signerAddress: devKey.signerAddress,
      deviceIdentityVersion: PHIL_DEVICE_IDENTITY_VERSION,
      deviceIdentityProviderKind: PHIL_LOCAL_DEV_DEVICE_IDENTITY_PROVIDER_KIND,
      deviceIdentityProviderProductionSafe: LOCAL_DEV_DEVICE_IDENTITY_PRODUCTION_SAFE,
      signatureRequestId: validatedRequest.signatureRequestId,
      signableDigest: validatedRequest.signableDigest,
      signedUserOpId:
        signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOpId,
      signedBundlerRequestHash:
        signedUserOpArtifact.smartAccountDeploySignedUserOp
          .signedBundlerRequestHash,
      parityProven: true
    },
    localDeviceSigning: {
      localDeviceSigningKind: LOCAL_DEVICE_SIGNING_KIND,
      localDeviceSigningId,
      signingRecord,
      signingRecordJson,
      signingRecordHash,
      key: {
        keySource: devKey.keySource,
        keySourcePath: devKey.keySourcePath,
        devKeyId: devKey.devKeyId,
        deviceIdentityId: deviceIdentityPublicMetadata.deviceIdentityId,
        deviceKeyId: deviceIdentityPublicMetadata.deviceKeyId,
        providerKind: deviceIdentityPublicMetadata.providerKind,
        productionSafe: deviceIdentityPublicMetadata.productionSafe,
        hardwareBacked: deviceIdentityPublicMetadata.hardwareBacked,
        privateMaterialExportable:
          deviceIdentityPublicMetadata.privateMaterialExportable,
        signerAddress: devKey.signerAddress,
        publicKey: devKey.publicKey,
        publicKeyHash: devKey.publicKeyHash
      },
      deviceIdentity: {
        publicMetadata: deviceIdentityPublicMetadata,
        authorization: {
          version: deviceAuthorization.version,
          providerKind: deviceAuthorization.providerKind,
          deviceIdentityId: deviceAuthorization.deviceIdentityId,
          deviceKeyId: deviceAuthorization.deviceKeyId,
          signatureKind: deviceAuthorization.signatureKind,
          signableDigest: deviceAuthorization.signableDigest,
          digestEncoding: deviceAuthorization.digestEncoding,
          signatureHash: deviceAuthorization.signatureHash,
          recoveredAddress: deviceAuthorization.recoveredAddress
        }
      },
      signatureInput: {
        signatureRequestId: validatedRequest.signatureRequestId,
        signerPayloadHash: validatedRequest.signerPayloadHash,
        signatureRequestHash: validatedRequest.signatureRequestHash,
        signableDigest: validatedRequest.signableDigest,
        digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
        signatureTarget: validatedRequest.signatureTarget
      },
      localSignature: localSignature.signature,
      localSignatureHash: localSignature.signatureHash,
      recoveredAddress: localSignature.recoveredAddress
    },
    signedUserOpResult: {
      path: signedUserOpArtifact.path,
      validationChecks: signedUserOpArtifact.validationChecks,
      smartAccountDeploySignedUserOpSummary:
        signedUserOpArtifact.smartAccountDeploySignedUserOpSummary,
      smartAccountDeploySignedUserOp: {
        signatureRequestId:
          signedUserOpArtifact.smartAccountDeploySignedUserOp.signatureRequestId,
        signedUserOpKind:
          signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOpKind,
        externalSignature:
          signedUserOpArtifact.smartAccountDeploySignedUserOp.externalSignature,
        signedUserOperation:
          signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOperation,
        signedUserOperationHash:
          signedUserOpArtifact.smartAccountDeploySignedUserOp
            .signedUserOperationHash,
        signedBundlerRequest:
          signedUserOpArtifact.smartAccountDeploySignedUserOp.signedBundlerRequest,
        signedBundlerRequestHash:
          signedUserOpArtifact.smartAccountDeploySignedUserOp
            .signedBundlerRequestHash,
        signedUserOpId:
          signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOpId
      },
      appSmartAccountDeploySignedUserOp:
        signedUserOpArtifact.appSmartAccountDeploySignedUserOp
    },
    appLocalDeviceSigning: {
      recipient: validatedRequest.canonicalRecipient,
      sender: validatedRequest.targetAddress,
      entryPointAddress: validatedRequest.entryPointAddress,
      chainId: validatedRequest.chainId,
      userOpHash: validatedRequest.userOpHash,
      signatureRequestId: validatedRequest.signatureRequestId,
      signerAddress: devKey.signerAddress,
      deviceIdentityId: deviceIdentityPublicMetadata.deviceIdentityId,
      deviceIdentityProviderKind: deviceIdentityPublicMetadata.providerKind,
      signedUserOpId:
        signedUserOpArtifact.smartAccountDeploySignedUserOp.signedUserOpId,
      signedBundlerRequestHash:
        signedUserOpArtifact.smartAccountDeploySignedUserOp
          .signedBundlerRequestHash,
      ready: true,
      status: "local-device-signing-complete",
      localOnly: true,
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-signature-request") {
      parsed.smartAccountDeploySignatureRequestPath = argv[i + 1];
      i += 1;
    } else if (arg === "--dev-private-key") {
      parsed.devPrivateKey = argv[i + 1];
      i += 1;
    } else if (arg === "--dev-key-file") {
      parsed.devKeyFile = argv[i + 1];
      i += 1;
    } else if (arg === "--out") {
      parsed.out = argv[i + 1];
      i += 1;
    } else if (arg === "--help") {
      parsed.help = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return parsed;
}

function printUsage() {
  console.log(
    [
      "Usage:",
      "  node scripts/base/run-local-smart-account-deploy-signing.cjs \\",
      `    [--smart-account-deploy-signature-request ${LOCAL_DEVICE_SIGNING_DEFAULT_SIGNATURE_REQUEST_PATH}] \\`,
      "    [--dev-private-key <hex> | --dev-key-file <path>] \\",
      `    [--out ${LOCAL_DEVICE_SIGNING_DEFAULT_OUT}]`
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help) {
      printUsage();
      process.exit(0);
    }

    const smartAccountDeploySignatureRequestPath = path.resolve(
      parsed.smartAccountDeploySignatureRequestPath ||
        LOCAL_DEVICE_SIGNING_DEFAULT_SIGNATURE_REQUEST_PATH
    );
    const outPath = path.resolve(parsed.out || LOCAL_DEVICE_SIGNING_DEFAULT_OUT);
    const artifact = runLocalSmartAccountDeploySigning({
      smartAccountDeploySignatureRequest: loadJson(smartAccountDeploySignatureRequestPath),
      devPrivateKey: parsed.devPrivateKey,
      devKeyFile: parsed.devKeyFile
    });

    writeJson(outPath, artifact);
    console.log(JSON.stringify(artifact, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  LOCAL_DEVICE_SIGNING_DOMAIN_LABEL,
  LOCAL_DEVICE_SIGNING_DOMAIN_HASH,
  LOCAL_DEVICE_SIGNING_KIND,
  LOCAL_DEVICE_SIGNING_SIGNATURE_KIND,
  LOCAL_DEVICE_SIGNING_DEFAULT_SIGNATURE_REQUEST_PATH,
  LOCAL_DEVICE_SIGNING_DEFAULT_OUT,
  deriveDefaultDevPrivateKey,
  loadLocalDevSigningKey,
  runLocalSmartAccountDeploySigning
};
