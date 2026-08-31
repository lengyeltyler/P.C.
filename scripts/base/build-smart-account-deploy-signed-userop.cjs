const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_USEROP_KIND,
  SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
} = require("./build-smart-account-deploy-userop.cjs");
const {
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
} = require("./build-smart-account-deploy-signature-request.cjs");

const SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_V1";
const SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND =
  "erc4337-smart-account-deploy-userop-v0.6-signed-v1";

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
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

function normalizeUintString(value, label) {
  const normalized = String(value || "").trim();
  if (!/^[0-9]+$/.test(normalized)) {
    throw new Error(`Invalid ${label}: ${normalized || "<empty>"}`);
  }
  return normalized;
}

function normalizeUnsignedUserOperation(unsignedUserOperation) {
  if (!unsignedUserOperation || typeof unsignedUserOperation !== "object") {
    throw new Error("unsignedUserOperation is required");
  }

  return {
    sender: normalizeAddress(unsignedUserOperation.sender, "unsignedUserOperation.sender"),
    nonce: normalizeUintString(unsignedUserOperation.nonce, "unsignedUserOperation.nonce"),
    initCode: normalizeBytes(unsignedUserOperation.initCode, "unsignedUserOperation.initCode"),
    callData: normalizeBytes(unsignedUserOperation.callData, "unsignedUserOperation.callData"),
    callGasLimit: normalizeUintString(
      unsignedUserOperation.callGasLimit,
      "unsignedUserOperation.callGasLimit"
    ),
    verificationGasLimit: normalizeUintString(
      unsignedUserOperation.verificationGasLimit,
      "unsignedUserOperation.verificationGasLimit"
    ),
    preVerificationGas: normalizeUintString(
      unsignedUserOperation.preVerificationGas,
      "unsignedUserOperation.preVerificationGas"
    ),
    maxFeePerGas: normalizeUintString(
      unsignedUserOperation.maxFeePerGas,
      "unsignedUserOperation.maxFeePerGas"
    ),
    maxPriorityFeePerGas: normalizeUintString(
      unsignedUserOperation.maxPriorityFeePerGas,
      "unsignedUserOperation.maxPriorityFeePerGas"
    ),
    paymasterAndData: normalizeBytes(
      unsignedUserOperation.paymasterAndData,
      "unsignedUserOperation.paymasterAndData"
    ),
    signature: normalizeBytes(unsignedUserOperation.signature, "unsignedUserOperation.signature")
  };
}

function deriveDeterministicSmartAccountDeploySignedUserOp({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  userOpKind,
  entryPointVersion,
  entryPointAddress,
  chainId,
  bundlerRpcMethod,
  userOpHash,
  signingContextHash,
  signingContextId,
  signatureRequestId,
  unsignedUserOperation,
  externalSignature
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedUserOpKind = normalizeString(userOpKind, "userOpKind");
  const normalizedEntryPointVersion = normalizeString(
    entryPointVersion,
    "entryPointVersion"
  );
  const normalizedEntryPointAddress = normalizeAddress(
    entryPointAddress,
    "entryPointAddress"
  );
  const normalizedChainId = normalizeUintString(chainId, "chainId");
  const normalizedBundlerRpcMethod = normalizeString(
    bundlerRpcMethod,
    "bundlerRpcMethod"
  );
  const normalizedUserOpHash = normalizeHex32(userOpHash, "userOpHash");
  const normalizedSigningContextHash = normalizeHex32(
    signingContextHash,
    "signingContextHash"
  );
  const normalizedSigningContextId = normalizeHex32(signingContextId, "signingContextId");
  const normalizedSignatureRequestId = normalizeHex32(
    signatureRequestId,
    "signatureRequestId"
  );
  const normalizedUnsignedUserOperation = normalizeUnsignedUserOperation(unsignedUserOperation);
  const normalizedExternalSignature = normalizeBytes(
    externalSignature,
    "externalSignature"
  );

  assertEqual(normalizedUserOpKind, SMART_ACCOUNT_DEPLOY_USEROP_KIND, "userOpKind");
  assertEqual(
    normalizedEntryPointVersion,
    SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
    "entryPointVersion"
  );
  assertEqual(normalizedBundlerRpcMethod, "eth_sendUserOperation", "bundlerRpcMethod");
  assertEqual(
    normalizedUnsignedUserOperation.sender.toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "unsignedUserOperation.sender/targetAddress"
  );
  if (
    normalizedExternalSignature ===
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
  ) {
    throw new Error("externalSignature must not be the placeholder value");
  }
  assertEqual(
    normalizedUnsignedUserOperation.signature,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "unsignedUserOperation.signature"
  );

  const signedUserOperation = {
    ...normalizedUnsignedUserOperation,
    signature: normalizedExternalSignature
  };

  const signedUserOperationJson = JSON.stringify(signedUserOperation);
  const signedUserOperationBytes = ethers.hexlify(
    ethers.toUtf8Bytes(signedUserOperationJson)
  );

  const initCodeHash = ethers.keccak256(signedUserOperation.initCode);
  const callDataHash = ethers.keccak256(signedUserOperation.callData);
  const paymasterAndDataHash = ethers.keccak256(signedUserOperation.paymasterAndData);
  const signatureHash = ethers.keccak256(signedUserOperation.signature);

  const signedUserOperationHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "bytes32",
        "address",
        "uint256",
        "bytes32",
        "bytes32",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "bytes32",
        "bytes32"
      ],
      [
        SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH,
        signedUserOperation.sender,
        BigInt(signedUserOperation.nonce),
        initCodeHash,
        callDataHash,
        BigInt(signedUserOperation.callGasLimit),
        BigInt(signedUserOperation.verificationGasLimit),
        BigInt(signedUserOperation.preVerificationGas),
        BigInt(signedUserOperation.maxFeePerGas),
        BigInt(signedUserOperation.maxPriorityFeePerGas),
        paymasterAndDataHash,
        signatureHash
      ]
    )
  );

  const signedBundlerRequest = {
    jsonrpc: "2.0",
    method: normalizedBundlerRpcMethod,
    params: [signedUserOperation, normalizedEntryPointAddress]
  };
  const signedBundlerRequestJson = JSON.stringify(signedBundlerRequest);
  const signedBundlerRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(signedBundlerRequestJson)
  );
  const signedBundlerRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(signedBundlerRequestJson)
  );

  const signedUserOpId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedSignatureRequestId,
        signedBundlerRequestHash
      ]
    )
  );

  return {
    ownerCommitment: normalizedOwnerCommitment,
    consumerDataHash: normalizedConsumerDataHash,
    canonicalRecipient: normalizedCanonicalRecipient,
    walletId: normalizedWalletId,
    targetId: normalizedTargetId,
    targetAddress: normalizedTargetAddress,
    userOpKind: normalizedUserOpKind,
    entryPointVersion: normalizedEntryPointVersion,
    entryPointAddress: normalizedEntryPointAddress,
    chainId: normalizedChainId,
    bundlerRpcMethod: normalizedBundlerRpcMethod,
    userOpHash: normalizedUserOpHash,
    signingContextHash: normalizedSigningContextHash,
    signingContextId: normalizedSigningContextId,
    signatureRequestId: normalizedSignatureRequestId,
    signedUserOpKind: SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND,
    externalSignature: normalizedExternalSignature,
    signedUserOperation,
    signedUserOperationJson,
    signedUserOperationBytes,
    signedUserOperationHash,
    signedBundlerRequest,
    signedBundlerRequestJson,
    signedBundlerRequestBytes,
    signedBundlerRequestHash,
    signedUserOpId
  };
}

function buildSmartAccountDeploySignedUserOp({
  smartAccountDeploySignatureRequest,
  externalSignature
}) {
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
    smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSummary.parityProven,
    "smartAccountDeploySignatureRequestSummary.parityProven"
  );

  const deterministicSmartAccountDeploySignatureRequest = {
    ownerCommitment: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.ownerCommitment,
      "smartAccountDeploySignatureRequest.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.consumerDataHash,
      "smartAccountDeploySignatureRequest.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .canonicalRecipient,
      "smartAccountDeploySignatureRequest.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.walletId,
      "smartAccountDeploySignatureRequest.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.targetId,
      "smartAccountDeploySignatureRequest.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .targetAddress,
      "smartAccountDeploySignatureRequest.targetAddress"
    ),
    userOpKind: normalizeString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.userOpKind,
      "smartAccountDeploySignatureRequest.userOpKind"
    ),
    entryPointVersion: normalizeString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .entryPointVersion,
      "smartAccountDeploySignatureRequest.entryPointVersion"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .entryPointAddress,
      "smartAccountDeploySignatureRequest.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.chainId,
      "smartAccountDeploySignatureRequest.chainId"
    ),
    bundlerRpcMethod: normalizeString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .bundlerRpcMethod,
      "smartAccountDeploySignatureRequest.bundlerRpcMethod"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.userOpHash,
      "smartAccountDeploySignatureRequest.userOpHash"
    ),
    signingContextHash: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signingContextHash,
      "smartAccountDeploySignatureRequest.signingContextHash"
    ),
    signingContextId: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signingContextId,
      "smartAccountDeploySignatureRequest.signingContextId"
    ),
    signatureRequestKind: normalizeString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestKind,
      "smartAccountDeploySignatureRequest.signatureRequestKind"
    ),
    signableDigest: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signableDigest,
      "smartAccountDeploySignatureRequest.signableDigest"
    ),
    digestEncoding: normalizeString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .digestEncoding,
      "smartAccountDeploySignatureRequest.digestEncoding"
    ),
    signatureTarget:
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureTarget,
    unsignedUserOperation: normalizeUnsignedUserOperation(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .unsignedUserOperation
    ),
    signatureRequestJson: normalizeString(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestJson,
      "smartAccountDeploySignatureRequest.signatureRequestJson"
    ),
    signatureRequestBytes: normalizeBytes(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestBytes,
      "smartAccountDeploySignatureRequest.signatureRequestBytes"
    ),
    signatureRequestHash: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestHash,
      "smartAccountDeploySignatureRequest.signatureRequestHash"
    ),
    signatureRequestId: normalizeHex32(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest
        .signatureRequestId,
      "smartAccountDeploySignatureRequest.signatureRequestId"
    )
  };

  if (
    !deterministicSmartAccountDeploySignatureRequest.signatureTarget ||
    typeof deterministicSmartAccountDeploySignatureRequest.signatureTarget !== "object"
  ) {
    throw new Error("smartAccountDeploySignatureRequest.signatureTarget is required");
  }

  const normalizedSignatureTarget = {
    userOperationField: normalizeString(
      deterministicSmartAccountDeploySignatureRequest.signatureTarget.userOperationField,
      "smartAccountDeploySignatureRequest.signatureTarget.userOperationField"
    ),
    bundlerRequestPath: normalizeString(
      deterministicSmartAccountDeploySignatureRequest.signatureTarget.bundlerRequestPath,
      "smartAccountDeploySignatureRequest.signatureTarget.bundlerRequestPath"
    ),
    signaturePlaceholder: normalizeBytes(
      deterministicSmartAccountDeploySignatureRequest.signatureTarget
        .signaturePlaceholder,
      "smartAccountDeploySignatureRequest.signatureTarget.signaturePlaceholder"
    )
  };

  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.userOpKind,
    SMART_ACCOUNT_DEPLOY_USEROP_KIND,
    "smartAccountDeploySignatureRequest.userOpKind"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.entryPointVersion,
    SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
    "smartAccountDeploySignatureRequest.entryPointVersion"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.signatureRequestKind,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
    "smartAccountDeploySignatureRequest.signatureRequestKind"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.signableDigest,
    deterministicSmartAccountDeploySignatureRequest.userOpHash,
    "smartAccountDeploySignatureRequest.signableDigest/userOpHash"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.digestEncoding,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    "smartAccountDeploySignatureRequest.digestEncoding"
  );
  assertEqual(
    normalizedSignatureTarget.userOperationField,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
    "smartAccountDeploySignatureRequest.signatureTarget.userOperationField"
  );
  assertEqual(
    normalizedSignatureTarget.bundlerRequestPath,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
    "smartAccountDeploySignatureRequest.signatureTarget.bundlerRequestPath"
  );
  assertEqual(
    normalizedSignatureTarget.signaturePlaceholder,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "smartAccountDeploySignatureRequest.signatureTarget.signaturePlaceholder"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.unsignedUserOperation.signature,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "smartAccountDeploySignatureRequest.unsignedUserOperation.signature"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.signatureRequestJson,
    JSON.stringify(
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequest.signatureRequest
    ),
    "smartAccountDeploySignatureRequest.signatureRequestJson"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.signatureRequestBytes,
    ethers.hexlify(
      ethers.toUtf8Bytes(
        deterministicSmartAccountDeploySignatureRequest.signatureRequestJson
      )
    ),
    "smartAccountDeploySignatureRequest.signatureRequestBytes"
  );
  assertEqual(
    deterministicSmartAccountDeploySignatureRequest.signatureRequestHash,
    ethers.keccak256(
      ethers.toUtf8Bytes(
        deterministicSmartAccountDeploySignatureRequest.signatureRequestJson
      )
    ),
    "smartAccountDeploySignatureRequest.signatureRequestHash"
  );

  const appSmartAccountDeploySignatureRequest = {
    recipient: normalizeAddress(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.recipient,
      "appSmartAccountDeploySignatureRequest.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.sender,
      "appSmartAccountDeploySignatureRequest.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .entryPointAddress,
      "appSmartAccountDeploySignatureRequest.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.chainId,
      "appSmartAccountDeploySignatureRequest.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.userOpHash,
      "appSmartAccountDeploySignatureRequest.userOpHash"
    ),
    signatureRequestKind: normalizeString(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .signatureRequestKind,
      "appSmartAccountDeploySignatureRequest.signatureRequestKind"
    ),
    signableDigest: normalizeHex32(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .signableDigest,
      "appSmartAccountDeploySignatureRequest.signableDigest"
    ),
    signatureRequestId: normalizeHex32(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .signatureRequestId,
      "appSmartAccountDeploySignatureRequest.signatureRequestId"
    ),
    ready:
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.ready ===
      true,
    status: String(
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest.status ||
        ""
    ),
    parityProven:
      smartAccountDeploySignatureRequest.appSmartAccountDeploySignatureRequest
        .parityProven === true
  };

  assertTrue(
    appSmartAccountDeploySignatureRequest.ready,
    "appSmartAccountDeploySignatureRequest.ready"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.status,
    "smart-account-deploy-signature-request-ready",
    "appSmartAccountDeploySignatureRequest.status"
  );
  assertTrue(
    appSmartAccountDeploySignatureRequest.parityProven,
    "appSmartAccountDeploySignatureRequest.parityProven"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.recipient.toLowerCase(),
    deterministicSmartAccountDeploySignatureRequest.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeploySignatureRequest.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.sender.toLowerCase(),
    deterministicSmartAccountDeploySignatureRequest.targetAddress.toLowerCase(),
    "appSmartAccountDeploySignatureRequest.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeploySignatureRequest.entryPointAddress.toLowerCase(),
    "appSmartAccountDeploySignatureRequest.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.chainId,
    deterministicSmartAccountDeploySignatureRequest.chainId,
    "appSmartAccountDeploySignatureRequest.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.userOpHash,
    deterministicSmartAccountDeploySignatureRequest.userOpHash,
    "appSmartAccountDeploySignatureRequest.userOpHash/userOpHash"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.signatureRequestKind,
    deterministicSmartAccountDeploySignatureRequest.signatureRequestKind,
    "appSmartAccountDeploySignatureRequest.signatureRequestKind/signatureRequestKind"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.signableDigest,
    deterministicSmartAccountDeploySignatureRequest.signableDigest,
    "appSmartAccountDeploySignatureRequest.signableDigest/signableDigest"
  );
  assertEqual(
    appSmartAccountDeploySignatureRequest.signatureRequestId,
    deterministicSmartAccountDeploySignatureRequest.signatureRequestId,
    "appSmartAccountDeploySignatureRequest.signatureRequestId/signatureRequestId"
  );

  const smartAccountDeploySignedUserOp = deriveDeterministicSmartAccountDeploySignedUserOp(
    {
      ownerCommitment: deterministicSmartAccountDeploySignatureRequest.ownerCommitment,
      consumerDataHash: deterministicSmartAccountDeploySignatureRequest.consumerDataHash,
      canonicalRecipient:
        deterministicSmartAccountDeploySignatureRequest.canonicalRecipient,
      walletId: deterministicSmartAccountDeploySignatureRequest.walletId,
      targetId: deterministicSmartAccountDeploySignatureRequest.targetId,
      targetAddress: deterministicSmartAccountDeploySignatureRequest.targetAddress,
      userOpKind: deterministicSmartAccountDeploySignatureRequest.userOpKind,
      entryPointVersion:
        deterministicSmartAccountDeploySignatureRequest.entryPointVersion,
      entryPointAddress:
        deterministicSmartAccountDeploySignatureRequest.entryPointAddress,
      chainId: deterministicSmartAccountDeploySignatureRequest.chainId,
      bundlerRpcMethod: deterministicSmartAccountDeploySignatureRequest.bundlerRpcMethod,
      userOpHash: deterministicSmartAccountDeploySignatureRequest.userOpHash,
      signingContextHash:
        deterministicSmartAccountDeploySignatureRequest.signingContextHash,
      signingContextId:
        deterministicSmartAccountDeploySignatureRequest.signingContextId,
      signatureRequestId:
        deterministicSmartAccountDeploySignatureRequest.signatureRequestId,
      unsignedUserOperation:
        deterministicSmartAccountDeploySignatureRequest.unsignedUserOperation,
      externalSignature
    }
  );

  return {
    version: 1,
    path: "phil-smart-account-deploy-signed-userop",
    smartAccountDeploySignedUserOpSource:
      "scripts/base/build-smart-account-deploy-signed-userop.cjs",
    smartAccountDeploySignatureRequestSource:
      smartAccountDeploySignatureRequest.smartAccountDeploySignatureRequestSource,
    consumedPath: smartAccountDeploySignatureRequest.path,
    proofType: smartAccountDeploySignatureRequest.proofType,
    payloadShape: smartAccountDeploySignatureRequest.payloadShape,
    smartAccountDeploySignedUserOpDomain: {
      label: SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeploySignatureRequestPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeploySignatureRequestValid: true,
      externalSignatureAccepted: true,
      deterministicSmartAccountDeploySignedUserOpDerived: true
    },
    smartAccountDeploySignedUserOpSummary: {
      ready: true,
      status: "smart-account-deploy-signed-userop-ready",
      reason: "validated-smart-account-deploy-signature-request",
      parityProven: true
    },
    smartAccountDeploySignedUserOp: {
      ownerCommitment: smartAccountDeploySignedUserOp.ownerCommitment,
      consumerDataHash: smartAccountDeploySignedUserOp.consumerDataHash,
      canonicalRecipient: smartAccountDeploySignedUserOp.canonicalRecipient,
      walletId: smartAccountDeploySignedUserOp.walletId,
      targetId: smartAccountDeploySignedUserOp.targetId,
      targetAddress: smartAccountDeploySignedUserOp.targetAddress,
      userOpKind: smartAccountDeploySignedUserOp.userOpKind,
      entryPointVersion: smartAccountDeploySignedUserOp.entryPointVersion,
      entryPointAddress: smartAccountDeploySignedUserOp.entryPointAddress,
      chainId: smartAccountDeploySignedUserOp.chainId,
      bundlerRpcMethod: smartAccountDeploySignedUserOp.bundlerRpcMethod,
      userOpHash: smartAccountDeploySignedUserOp.userOpHash,
      signingContextHash: smartAccountDeploySignedUserOp.signingContextHash,
      signingContextId: smartAccountDeploySignedUserOp.signingContextId,
      signatureRequestId: smartAccountDeploySignedUserOp.signatureRequestId,
      signedUserOpKind: smartAccountDeploySignedUserOp.signedUserOpKind,
      externalSignature: smartAccountDeploySignedUserOp.externalSignature,
      signedUserOperation: smartAccountDeploySignedUserOp.signedUserOperation,
      signedUserOperationJson: smartAccountDeploySignedUserOp.signedUserOperationJson,
      signedUserOperationBytes:
        smartAccountDeploySignedUserOp.signedUserOperationBytes,
      signedUserOperationHash:
        smartAccountDeploySignedUserOp.signedUserOperationHash,
      signedBundlerRequest: smartAccountDeploySignedUserOp.signedBundlerRequest,
      signedBundlerRequestJson:
        smartAccountDeploySignedUserOp.signedBundlerRequestJson,
      signedBundlerRequestBytes:
        smartAccountDeploySignedUserOp.signedBundlerRequestBytes,
      signedBundlerRequestHash:
        smartAccountDeploySignedUserOp.signedBundlerRequestHash,
      signedUserOpId: smartAccountDeploySignedUserOp.signedUserOpId
    },
    appSmartAccountDeploySignedUserOp: {
      recipient: smartAccountDeploySignedUserOp.canonicalRecipient,
      sender: smartAccountDeploySignedUserOp.targetAddress,
      entryPointAddress: smartAccountDeploySignedUserOp.entryPointAddress,
      chainId: smartAccountDeploySignedUserOp.chainId,
      userOpHash: smartAccountDeploySignedUserOp.userOpHash,
      signedUserOpKind: smartAccountDeploySignedUserOp.signedUserOpKind,
      signedUserOpId: smartAccountDeploySignedUserOp.signedUserOpId,
      signedBundlerRequestHash: smartAccountDeploySignedUserOp.signedBundlerRequestHash,
      ready: true,
      status: "smart-account-deploy-signed-userop-ready",
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
    } else if (arg === "--signature") {
      parsed.externalSignature = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-signed-userop.cjs --smart-account-deploy-signature-request <path> --signature <hex>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (
      parsed.help ||
      !parsed.smartAccountDeploySignatureRequestPath ||
      !parsed.externalSignature
    ) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeploySignedUserOp = buildSmartAccountDeploySignedUserOp({
      smartAccountDeploySignatureRequest: loadJson(
        path.resolve(parsed.smartAccountDeploySignatureRequestPath)
      ),
      externalSignature: parsed.externalSignature
    });
    console.log(JSON.stringify(smartAccountDeploySignedUserOp, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND,
  deriveDeterministicSmartAccountDeploySignedUserOp,
  buildSmartAccountDeploySignedUserOp
};
