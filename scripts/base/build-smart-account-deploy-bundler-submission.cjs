const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_USEROP_KIND,
  SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION
} = require("./build-smart-account-deploy-userop.cjs");
const {
  SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND
} = require("./build-smart-account-deploy-signed-userop.cjs");

const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_V1";
const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND =
  "erc4337-smart-account-deploy-bundler-submission-v1";
const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND =
  "erc4337-bundler-json-rpc-http-v1";
const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD = "POST";
const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE = "application/json";
const SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT = "application/json";

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

function normalizeSignedUserOperation(signedUserOperation) {
  if (!signedUserOperation || typeof signedUserOperation !== "object") {
    throw new Error("signedUserOperation is required");
  }

  return {
    sender: normalizeAddress(signedUserOperation.sender, "signedUserOperation.sender"),
    nonce: normalizeUintString(signedUserOperation.nonce, "signedUserOperation.nonce"),
    initCode: normalizeBytes(signedUserOperation.initCode, "signedUserOperation.initCode"),
    callData: normalizeBytes(signedUserOperation.callData, "signedUserOperation.callData"),
    callGasLimit: normalizeUintString(
      signedUserOperation.callGasLimit,
      "signedUserOperation.callGasLimit"
    ),
    verificationGasLimit: normalizeUintString(
      signedUserOperation.verificationGasLimit,
      "signedUserOperation.verificationGasLimit"
    ),
    preVerificationGas: normalizeUintString(
      signedUserOperation.preVerificationGas,
      "signedUserOperation.preVerificationGas"
    ),
    maxFeePerGas: normalizeUintString(
      signedUserOperation.maxFeePerGas,
      "signedUserOperation.maxFeePerGas"
    ),
    maxPriorityFeePerGas: normalizeUintString(
      signedUserOperation.maxPriorityFeePerGas,
      "signedUserOperation.maxPriorityFeePerGas"
    ),
    paymasterAndData: normalizeBytes(
      signedUserOperation.paymasterAndData,
      "signedUserOperation.paymasterAndData"
    ),
    signature: normalizeBytes(signedUserOperation.signature, "signedUserOperation.signature")
  };
}

function normalizeSignedBundlerRequest(signedBundlerRequest) {
  if (!signedBundlerRequest || typeof signedBundlerRequest !== "object") {
    throw new Error("signedBundlerRequest is required");
  }
  if (!Array.isArray(signedBundlerRequest.params) || signedBundlerRequest.params.length !== 2) {
    throw new Error("signedBundlerRequest.params must contain [signedUserOperation, entryPoint]");
  }

  return {
    jsonrpc: normalizeString(signedBundlerRequest.jsonrpc, "signedBundlerRequest.jsonrpc"),
    method: normalizeString(signedBundlerRequest.method, "signedBundlerRequest.method"),
    params: [
      normalizeSignedUserOperation(signedBundlerRequest.params[0]),
      normalizeAddress(signedBundlerRequest.params[1], "signedBundlerRequest.params[1]")
    ]
  };
}

function deriveSignedUserOperationHash(signedUserOperation) {
  const initCodeHash = ethers.keccak256(signedUserOperation.initCode);
  const callDataHash = ethers.keccak256(signedUserOperation.callData);
  const paymasterAndDataHash = ethers.keccak256(signedUserOperation.paymasterAndData);
  const signatureHash = ethers.keccak256(signedUserOperation.signature);

  return ethers.keccak256(
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
}

function deriveDeterministicSmartAccountDeployBundlerSubmission({
  proofType,
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
  signedUserOpKind,
  signedUserOpId,
  signedUserOperationHash,
  signedBundlerRequestHash,
  signedUserOperation,
  signedUserOperationJson,
  signedUserOperationBytes,
  signedBundlerRequest,
  signedBundlerRequestJson,
  signedBundlerRequestBytes
}) {
  const normalizedProofType = normalizeString(proofType, "proofType");
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
  const normalizedSignedUserOpKind = normalizeString(signedUserOpKind, "signedUserOpKind");
  const normalizedSignedUserOpId = normalizeHex32(signedUserOpId, "signedUserOpId");
  const normalizedSignedUserOperationHash = normalizeHex32(
    signedUserOperationHash,
    "signedUserOperationHash"
  );
  const normalizedSignedBundlerRequestHash = normalizeHex32(
    signedBundlerRequestHash,
    "signedBundlerRequestHash"
  );
  const normalizedSignedUserOperation = normalizeSignedUserOperation(signedUserOperation);
  const normalizedSignedUserOperationJson = normalizeString(
    signedUserOperationJson,
    "signedUserOperationJson"
  );
  const normalizedSignedUserOperationBytes = normalizeBytes(
    signedUserOperationBytes,
    "signedUserOperationBytes"
  );
  const normalizedSignedBundlerRequest = normalizeSignedBundlerRequest(signedBundlerRequest);
  const normalizedSignedBundlerRequestJson = normalizeString(
    signedBundlerRequestJson,
    "signedBundlerRequestJson"
  );
  const normalizedSignedBundlerRequestBytes = normalizeBytes(
    signedBundlerRequestBytes,
    "signedBundlerRequestBytes"
  );

  assertEqual(normalizedUserOpKind, SMART_ACCOUNT_DEPLOY_USEROP_KIND, "userOpKind");
  assertEqual(
    normalizedEntryPointVersion,
    SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
    "entryPointVersion"
  );
  assertEqual(
    normalizedSignedUserOpKind,
    SMART_ACCOUNT_DEPLOY_SIGNED_USEROP_KIND,
    "signedUserOpKind"
  );
  assertEqual(
    normalizedSignedUserOperation.sender.toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "signedUserOperation.sender/targetAddress"
  );
  assertEqual(normalizedSignedBundlerRequest.jsonrpc, "2.0", "signedBundlerRequest.jsonrpc");
  assertEqual(
    normalizedSignedBundlerRequest.method,
    normalizedBundlerRpcMethod,
    "signedBundlerRequest.method"
  );
  assertEqual(
    normalizedSignedBundlerRequest.params[1].toLowerCase(),
    normalizedEntryPointAddress.toLowerCase(),
    "signedBundlerRequest.params[1]/entryPointAddress"
  );
  assertEqual(
    JSON.stringify(normalizedSignedBundlerRequest.params[0]),
    JSON.stringify(normalizedSignedUserOperation),
    "signedBundlerRequest.params[0]/signedUserOperation"
  );

  const recomputedSignedUserOperationJson = JSON.stringify(normalizedSignedUserOperation);
  const recomputedSignedUserOperationBytes = ethers.hexlify(
    ethers.toUtf8Bytes(recomputedSignedUserOperationJson)
  );
  const recomputedSignedUserOperationHash = deriveSignedUserOperationHash(
    normalizedSignedUserOperation
  );

  assertEqual(
    recomputedSignedUserOperationJson,
    normalizedSignedUserOperationJson,
    "signedUserOperationJson"
  );
  assertEqual(
    recomputedSignedUserOperationBytes,
    normalizedSignedUserOperationBytes,
    "signedUserOperationBytes"
  );
  assertEqual(
    recomputedSignedUserOperationHash,
    normalizedSignedUserOperationHash,
    "signedUserOperationHash"
  );

  const recomputedSignedBundlerRequestJson = JSON.stringify(normalizedSignedBundlerRequest);
  const recomputedSignedBundlerRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(recomputedSignedBundlerRequestJson)
  );
  const recomputedSignedBundlerRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(recomputedSignedBundlerRequestJson)
  );

  assertEqual(
    recomputedSignedBundlerRequestJson,
    normalizedSignedBundlerRequestJson,
    "signedBundlerRequestJson"
  );
  assertEqual(
    recomputedSignedBundlerRequestBytes,
    normalizedSignedBundlerRequestBytes,
    "signedBundlerRequestBytes"
  );
  assertEqual(
    recomputedSignedBundlerRequestHash,
    normalizedSignedBundlerRequestHash,
    "signedBundlerRequestHash"
  );

  const bundlerSubmissionTarget = {
    transportKind: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND,
    rpcMethod: normalizedBundlerRpcMethod,
    entryPointAddress: normalizedEntryPointAddress,
    chainId: normalizedChainId
  };

  const bundlerSubmissionIdempotencyKey = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH,
        normalizedSignedUserOpId,
        normalizedSignedBundlerRequestHash,
        normalizedTargetId
      ]
    )
  );

  const bundlerSubmissionHeaders = {
    accept: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT,
    "content-type": SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE,
    "idempotency-key": bundlerSubmissionIdempotencyKey,
    "x-phil-proof-type": normalizedProofType,
    "x-phil-chain-id": normalizedChainId,
    "x-phil-entry-point-address": normalizedEntryPointAddress,
    "x-phil-target-address": normalizedTargetAddress,
    "x-phil-userop-hash": normalizedUserOpHash,
    "x-phil-signed-userop-kind": normalizedSignedUserOpKind,
    "x-phil-signed-userop-id": normalizedSignedUserOpId,
    "x-phil-signed-bundler-request-hash": normalizedSignedBundlerRequestHash
  };

  const bundlerSubmissionHeadersJson = JSON.stringify(bundlerSubmissionHeaders);
  const bundlerSubmissionHeadersHash = ethers.keccak256(
    ethers.toUtf8Bytes(bundlerSubmissionHeadersJson)
  );

  const bundlerSubmissionRequest = {
    method: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
    headers: bundlerSubmissionHeaders,
    body: normalizedSignedBundlerRequest
  };
  const bundlerSubmissionRequestJson = JSON.stringify(bundlerSubmissionRequest);
  const bundlerSubmissionRequestBytes = ethers.hexlify(
    ethers.toUtf8Bytes(bundlerSubmissionRequestJson)
  );
  const bundlerSubmissionRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(bundlerSubmissionRequestJson)
  );

  const bundlerSubmissionId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedSignedUserOpId,
        bundlerSubmissionRequestHash
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
    signedUserOpKind: normalizedSignedUserOpKind,
    signedUserOpId: normalizedSignedUserOpId,
    signedUserOperationHash: normalizedSignedUserOperationHash,
    signedBundlerRequestHash: normalizedSignedBundlerRequestHash,
    bundlerSubmissionKind: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND,
    bundlerSubmissionTarget,
    bundlerSubmissionBody: normalizedSignedBundlerRequest,
    bundlerSubmissionBodyJson: normalizedSignedBundlerRequestJson,
    bundlerSubmissionBodyBytes: normalizedSignedBundlerRequestBytes,
    bundlerSubmissionBodyHash: normalizedSignedBundlerRequestHash,
    bundlerSubmissionHeaders,
    bundlerSubmissionHeadersJson,
    bundlerSubmissionHeadersHash,
    bundlerSubmissionIdempotencyKey,
    bundlerSubmissionRequest,
    bundlerSubmissionRequestJson,
    bundlerSubmissionRequestBytes,
    bundlerSubmissionRequestHash,
    bundlerSubmissionId
  };
}

function buildSmartAccountDeployBundlerSubmission({ smartAccountDeploySignedUserOp }) {
  if (!smartAccountDeploySignedUserOp || typeof smartAccountDeploySignedUserOp !== "object") {
    throw new Error("smartAccountDeploySignedUserOp is required");
  }

  assertEqual(
    smartAccountDeploySignedUserOp.path,
    "phil-smart-account-deploy-signed-userop",
    "smartAccountDeploySignedUserOp.path"
  );
  assertEqual(
    smartAccountDeploySignedUserOp.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeploySignedUserOp.payloadShape"
  );

  if (
    !smartAccountDeploySignedUserOp.validationChecks ||
    typeof smartAccountDeploySignedUserOp.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeploySignedUserOp.validationChecks is required");
  }
  if (
    !smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary ||
    typeof smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary !== "object"
  ) {
    throw new Error("smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary is required");
  }
  if (
    !smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp ||
    typeof smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp !== "object"
  ) {
    throw new Error("smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp is required");
  }
  if (
    !smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp ||
    typeof smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp !== "object"
  ) {
    throw new Error("smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp is required");
  }

  assertTrue(
    smartAccountDeploySignedUserOp.validationChecks.smartAccountDeploySignatureRequestPathValid,
    "validationChecks.smartAccountDeploySignatureRequestPathValid"
  );
  assertTrue(
    smartAccountDeploySignedUserOp.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeploySignedUserOp.validationChecks
      .upstreamSmartAccountDeploySignatureRequestValid,
    "validationChecks.upstreamSmartAccountDeploySignatureRequestValid"
  );
  assertTrue(
    smartAccountDeploySignedUserOp.validationChecks.externalSignatureAccepted,
    "validationChecks.externalSignatureAccepted"
  );
  assertTrue(
    smartAccountDeploySignedUserOp.validationChecks
      .deterministicSmartAccountDeploySignedUserOpDerived,
    "validationChecks.deterministicSmartAccountDeploySignedUserOpDerived"
  );
  assertTrue(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.ready,
    "smartAccountDeploySignedUserOpSummary.ready"
  );
  assertEqual(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.status,
    "smart-account-deploy-signed-userop-ready",
    "smartAccountDeploySignedUserOpSummary.status"
  );
  assertTrue(
    smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSummary.parityProven,
    "smartAccountDeploySignedUserOpSummary.parityProven"
  );

  const deterministicSmartAccountDeploySignedUserOp = {
    ownerCommitment: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.ownerCommitment,
      "smartAccountDeploySignedUserOp.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.consumerDataHash,
      "smartAccountDeploySignedUserOp.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.canonicalRecipient,
      "smartAccountDeploySignedUserOp.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.walletId,
      "smartAccountDeploySignedUserOp.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetId,
      "smartAccountDeploySignedUserOp.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.targetAddress,
      "smartAccountDeploySignedUserOp.targetAddress"
    ),
    userOpKind: normalizeString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.userOpKind,
      "smartAccountDeploySignedUserOp.userOpKind"
    ),
    entryPointVersion: normalizeString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.entryPointVersion,
      "smartAccountDeploySignedUserOp.entryPointVersion"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.entryPointAddress,
      "smartAccountDeploySignedUserOp.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.chainId,
      "smartAccountDeploySignedUserOp.chainId"
    ),
    bundlerRpcMethod: normalizeString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.bundlerRpcMethod,
      "smartAccountDeploySignedUserOp.bundlerRpcMethod"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.userOpHash,
      "smartAccountDeploySignedUserOp.userOpHash"
    ),
    signingContextHash: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signingContextHash,
      "smartAccountDeploySignedUserOp.signingContextHash"
    ),
    signingContextId: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signingContextId,
      "smartAccountDeploySignedUserOp.signingContextId"
    ),
    signatureRequestId: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signatureRequestId,
      "smartAccountDeploySignedUserOp.signatureRequestId"
    ),
    signedUserOpKind: normalizeString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpKind,
      "smartAccountDeploySignedUserOp.signedUserOpKind"
    ),
    signedUserOpId: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOpId,
      "smartAccountDeploySignedUserOp.signedUserOpId"
    ),
    signedUserOperationHash: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOperationHash,
      "smartAccountDeploySignedUserOp.signedUserOperationHash"
    ),
    signedBundlerRequestHash: normalizeHex32(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedBundlerRequestHash,
      "smartAccountDeploySignedUserOp.signedBundlerRequestHash"
    ),
    signedUserOperation: normalizeSignedUserOperation(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOperation
    ),
    signedUserOperationJson: normalizeString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOperationJson,
      "smartAccountDeploySignedUserOp.signedUserOperationJson"
    ),
    signedUserOperationBytes: normalizeBytes(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedUserOperationBytes,
      "smartAccountDeploySignedUserOp.signedUserOperationBytes"
    ),
    signedBundlerRequest: normalizeSignedBundlerRequest(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedBundlerRequest
    ),
    signedBundlerRequestJson: normalizeString(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedBundlerRequestJson,
      "smartAccountDeploySignedUserOp.signedBundlerRequestJson"
    ),
    signedBundlerRequestBytes: normalizeBytes(
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOp.signedBundlerRequestBytes,
      "smartAccountDeploySignedUserOp.signedBundlerRequestBytes"
    )
  };

  const appSmartAccountDeploySignedUserOp = {
    recipient: normalizeAddress(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.recipient,
      "appSmartAccountDeploySignedUserOp.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.sender,
      "appSmartAccountDeploySignedUserOp.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.entryPointAddress,
      "appSmartAccountDeploySignedUserOp.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.chainId,
      "appSmartAccountDeploySignedUserOp.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.userOpHash,
      "appSmartAccountDeploySignedUserOp.userOpHash"
    ),
    signedUserOpKind: normalizeString(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.signedUserOpKind,
      "appSmartAccountDeploySignedUserOp.signedUserOpKind"
    ),
    signedUserOpId: normalizeHex32(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.signedUserOpId,
      "appSmartAccountDeploySignedUserOp.signedUserOpId"
    ),
    signedBundlerRequestHash: normalizeHex32(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp
        .signedBundlerRequestHash,
      "appSmartAccountDeploySignedUserOp.signedBundlerRequestHash"
    ),
    ready: smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.ready === true,
    status: normalizeString(
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.status,
      "appSmartAccountDeploySignedUserOp.status"
    ),
    parityProven:
      smartAccountDeploySignedUserOp.appSmartAccountDeploySignedUserOp.parityProven ===
      true
  };

  assertTrue(appSmartAccountDeploySignedUserOp.ready, "appSmartAccountDeploySignedUserOp.ready");
  assertEqual(
    appSmartAccountDeploySignedUserOp.status,
    "smart-account-deploy-signed-userop-ready",
    "appSmartAccountDeploySignedUserOp.status"
  );
  assertTrue(
    appSmartAccountDeploySignedUserOp.parityProven,
    "appSmartAccountDeploySignedUserOp.parityProven"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.recipient.toLowerCase(),
    deterministicSmartAccountDeploySignedUserOp.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeploySignedUserOp.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.sender.toLowerCase(),
    deterministicSmartAccountDeploySignedUserOp.targetAddress.toLowerCase(),
    "appSmartAccountDeploySignedUserOp.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeploySignedUserOp.entryPointAddress.toLowerCase(),
    "appSmartAccountDeploySignedUserOp.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.chainId,
    deterministicSmartAccountDeploySignedUserOp.chainId,
    "appSmartAccountDeploySignedUserOp.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.userOpHash,
    deterministicSmartAccountDeploySignedUserOp.userOpHash,
    "appSmartAccountDeploySignedUserOp.userOpHash/userOpHash"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.signedUserOpKind,
    deterministicSmartAccountDeploySignedUserOp.signedUserOpKind,
    "appSmartAccountDeploySignedUserOp.signedUserOpKind/signedUserOpKind"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.signedUserOpId,
    deterministicSmartAccountDeploySignedUserOp.signedUserOpId,
    "appSmartAccountDeploySignedUserOp.signedUserOpId/signedUserOpId"
  );
  assertEqual(
    appSmartAccountDeploySignedUserOp.signedBundlerRequestHash,
    deterministicSmartAccountDeploySignedUserOp.signedBundlerRequestHash,
    "appSmartAccountDeploySignedUserOp.signedBundlerRequestHash/signedBundlerRequestHash"
  );

  const smartAccountDeployBundlerSubmission =
    deriveDeterministicSmartAccountDeployBundlerSubmission({
      proofType: smartAccountDeploySignedUserOp.proofType,
      ownerCommitment: deterministicSmartAccountDeploySignedUserOp.ownerCommitment,
      consumerDataHash: deterministicSmartAccountDeploySignedUserOp.consumerDataHash,
      canonicalRecipient: deterministicSmartAccountDeploySignedUserOp.canonicalRecipient,
      walletId: deterministicSmartAccountDeploySignedUserOp.walletId,
      targetId: deterministicSmartAccountDeploySignedUserOp.targetId,
      targetAddress: deterministicSmartAccountDeploySignedUserOp.targetAddress,
      userOpKind: deterministicSmartAccountDeploySignedUserOp.userOpKind,
      entryPointVersion:
        deterministicSmartAccountDeploySignedUserOp.entryPointVersion,
      entryPointAddress:
        deterministicSmartAccountDeploySignedUserOp.entryPointAddress,
      chainId: deterministicSmartAccountDeploySignedUserOp.chainId,
      bundlerRpcMethod: deterministicSmartAccountDeploySignedUserOp.bundlerRpcMethod,
      userOpHash: deterministicSmartAccountDeploySignedUserOp.userOpHash,
      signingContextHash:
        deterministicSmartAccountDeploySignedUserOp.signingContextHash,
      signingContextId:
        deterministicSmartAccountDeploySignedUserOp.signingContextId,
      signatureRequestId:
        deterministicSmartAccountDeploySignedUserOp.signatureRequestId,
      signedUserOpKind:
        deterministicSmartAccountDeploySignedUserOp.signedUserOpKind,
      signedUserOpId: deterministicSmartAccountDeploySignedUserOp.signedUserOpId,
      signedUserOperationHash:
        deterministicSmartAccountDeploySignedUserOp.signedUserOperationHash,
      signedBundlerRequestHash:
        deterministicSmartAccountDeploySignedUserOp.signedBundlerRequestHash,
      signedUserOperation:
        deterministicSmartAccountDeploySignedUserOp.signedUserOperation,
      signedUserOperationJson:
        deterministicSmartAccountDeploySignedUserOp.signedUserOperationJson,
      signedUserOperationBytes:
        deterministicSmartAccountDeploySignedUserOp.signedUserOperationBytes,
      signedBundlerRequest:
        deterministicSmartAccountDeploySignedUserOp.signedBundlerRequest,
      signedBundlerRequestJson:
        deterministicSmartAccountDeploySignedUserOp.signedBundlerRequestJson,
      signedBundlerRequestBytes:
        deterministicSmartAccountDeploySignedUserOp.signedBundlerRequestBytes
    });

  return {
    version: 1,
    path: "phil-smart-account-deploy-bundler-submission",
    smartAccountDeployBundlerSubmissionSource:
      "scripts/base/build-smart-account-deploy-bundler-submission.cjs",
    smartAccountDeploySignedUserOpSource:
      smartAccountDeploySignedUserOp.smartAccountDeploySignedUserOpSource,
    consumedPath: smartAccountDeploySignedUserOp.path,
    proofType: smartAccountDeploySignedUserOp.proofType,
    payloadShape: smartAccountDeploySignedUserOp.payloadShape,
    smartAccountDeployBundlerSubmissionDomain: {
      label: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeploySignedUserOpPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeploySignedUserOpValid: true,
      deterministicSmartAccountDeployBundlerSubmissionDerived: true
    },
    smartAccountDeployBundlerSubmissionSummary: {
      ready: true,
      status: "smart-account-deploy-bundler-submission-ready",
      reason: "validated-smart-account-deploy-signed-userop",
      parityProven: true
    },
    smartAccountDeployBundlerSubmission: {
      ownerCommitment: smartAccountDeployBundlerSubmission.ownerCommitment,
      consumerDataHash: smartAccountDeployBundlerSubmission.consumerDataHash,
      canonicalRecipient: smartAccountDeployBundlerSubmission.canonicalRecipient,
      walletId: smartAccountDeployBundlerSubmission.walletId,
      targetId: smartAccountDeployBundlerSubmission.targetId,
      targetAddress: smartAccountDeployBundlerSubmission.targetAddress,
      userOpKind: smartAccountDeployBundlerSubmission.userOpKind,
      entryPointVersion: smartAccountDeployBundlerSubmission.entryPointVersion,
      entryPointAddress: smartAccountDeployBundlerSubmission.entryPointAddress,
      chainId: smartAccountDeployBundlerSubmission.chainId,
      bundlerRpcMethod: smartAccountDeployBundlerSubmission.bundlerRpcMethod,
      userOpHash: smartAccountDeployBundlerSubmission.userOpHash,
      signingContextHash: smartAccountDeployBundlerSubmission.signingContextHash,
      signingContextId: smartAccountDeployBundlerSubmission.signingContextId,
      signatureRequestId: smartAccountDeployBundlerSubmission.signatureRequestId,
      signedUserOpKind: smartAccountDeployBundlerSubmission.signedUserOpKind,
      signedUserOpId: smartAccountDeployBundlerSubmission.signedUserOpId,
      signedUserOperationHash:
        smartAccountDeployBundlerSubmission.signedUserOperationHash,
      signedBundlerRequestHash:
        smartAccountDeployBundlerSubmission.signedBundlerRequestHash,
      bundlerSubmissionKind:
        smartAccountDeployBundlerSubmission.bundlerSubmissionKind,
      bundlerSubmissionTarget:
        smartAccountDeployBundlerSubmission.bundlerSubmissionTarget,
      bundlerSubmissionBody:
        smartAccountDeployBundlerSubmission.bundlerSubmissionBody,
      bundlerSubmissionBodyJson:
        smartAccountDeployBundlerSubmission.bundlerSubmissionBodyJson,
      bundlerSubmissionBodyBytes:
        smartAccountDeployBundlerSubmission.bundlerSubmissionBodyBytes,
      bundlerSubmissionBodyHash:
        smartAccountDeployBundlerSubmission.bundlerSubmissionBodyHash,
      bundlerSubmissionHeaders:
        smartAccountDeployBundlerSubmission.bundlerSubmissionHeaders,
      bundlerSubmissionHeadersJson:
        smartAccountDeployBundlerSubmission.bundlerSubmissionHeadersJson,
      bundlerSubmissionHeadersHash:
        smartAccountDeployBundlerSubmission.bundlerSubmissionHeadersHash,
      bundlerSubmissionIdempotencyKey:
        smartAccountDeployBundlerSubmission.bundlerSubmissionIdempotencyKey,
      bundlerSubmissionRequest:
        smartAccountDeployBundlerSubmission.bundlerSubmissionRequest,
      bundlerSubmissionRequestJson:
        smartAccountDeployBundlerSubmission.bundlerSubmissionRequestJson,
      bundlerSubmissionRequestBytes:
        smartAccountDeployBundlerSubmission.bundlerSubmissionRequestBytes,
      bundlerSubmissionRequestHash:
        smartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash,
      bundlerSubmissionId: smartAccountDeployBundlerSubmission.bundlerSubmissionId
    },
    appSmartAccountDeployBundlerSubmission: {
      recipient: smartAccountDeployBundlerSubmission.canonicalRecipient,
      sender: smartAccountDeployBundlerSubmission.targetAddress,
      entryPointAddress: smartAccountDeployBundlerSubmission.entryPointAddress,
      chainId: smartAccountDeployBundlerSubmission.chainId,
      userOpHash: smartAccountDeployBundlerSubmission.userOpHash,
      signedUserOpId: smartAccountDeployBundlerSubmission.signedUserOpId,
      bundlerSubmissionKind:
        smartAccountDeployBundlerSubmission.bundlerSubmissionKind,
      bundlerSubmissionId: smartAccountDeployBundlerSubmission.bundlerSubmissionId,
      bundlerSubmissionRequestHash:
        smartAccountDeployBundlerSubmission.bundlerSubmissionRequestHash,
      ready: true,
      status: "smart-account-deploy-bundler-submission-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-signed-userop") {
      parsed.smartAccountDeploySignedUserOpPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-bundler-submission.cjs --smart-account-deploy-signed-userop <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeploySignedUserOpPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployBundlerSubmission =
      buildSmartAccountDeployBundlerSubmission({
        smartAccountDeploySignedUserOp: loadJson(
          path.resolve(parsed.smartAccountDeploySignedUserOpPath)
        )
      });
    console.log(JSON.stringify(smartAccountDeployBundlerSubmission, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_KIND,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_TRANSPORT_KIND,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_METHOD,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_CONTENT_TYPE,
  SMART_ACCOUNT_DEPLOY_BUNDLER_SUBMISSION_ACCEPT,
  deriveDeterministicSmartAccountDeployBundlerSubmission,
  buildSmartAccountDeployBundlerSubmission
};
