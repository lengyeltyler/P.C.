const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_V1";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND =
  "erc4337-smart-account-deploy-signature-request-v1";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND =
  "erc4337-userop-hash-signature-payload-v1";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING = "bytes32-hex";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD = "signature";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH = "params[0].signature";
const SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER = "0x";

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

function deriveDeterministicSmartAccountDeploySignatureRequest({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  userOpKind,
  networkName,
  entryPointVersion,
  entryPointAddress,
  chainId,
  bundlerRpcMethod,
  userOpHash,
  signingContextHash,
  signingContextId,
  bundlerRequestTemplateHash,
  unsignedUserOperation
}) {
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedUserOpKind = normalizeString(userOpKind, "userOpKind");
  const normalizedNetworkName = normalizeString(networkName, "networkName");
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
  const normalizedBundlerRequestTemplateHash = normalizeHex32(
    bundlerRequestTemplateHash,
    "bundlerRequestTemplateHash"
  );
  if (!unsignedUserOperation || typeof unsignedUserOperation !== "object") {
    throw new Error("unsignedUserOperation is required");
  }
  const normalizedUnsignedUserOperation = {
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

  assertEqual(
    normalizedUserOpKind,
    "erc4337-smart-account-deploy-userop-v0.6-unsigned-v1",
    "userOpKind"
  );
  assertEqual(normalizedEntryPointVersion, "erc4337-v0.6", "entryPointVersion");
  assertEqual(normalizedBundlerRpcMethod, "eth_sendUserOperation", "bundlerRpcMethod");
  assertEqual(
    normalizedUnsignedUserOperation.sender.toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "unsignedUserOperation.sender/targetAddress"
  );
  assertEqual(
    normalizedUnsignedUserOperation.signature,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "unsignedUserOperation.signature"
  );

  const signerPayload = {
    payloadKind: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND,
    signableDigest: normalizedUserOpHash,
    digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    networkName: normalizedNetworkName,
    chainId: normalizedChainId,
    sender: normalizedTargetAddress,
    entryPointVersion: normalizedEntryPointVersion,
    entryPointAddress: normalizedEntryPointAddress,
    signatureField: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
    signaturePlaceholder: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
  };

  const signerPayloadJson = JSON.stringify(signerPayload);
  const signerPayloadBytes = ethers.hexlify(ethers.toUtf8Bytes(signerPayloadJson));
  const signerPayloadHash = ethers.keccak256(ethers.toUtf8Bytes(signerPayloadJson));

  const signatureTarget = {
    userOperationField: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
    bundlerRequestPath: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
    signaturePlaceholder: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER
  };

  const submissionContext = {
    bundlerRpcMethod: normalizedBundlerRpcMethod,
    entryPointAddress: normalizedEntryPointAddress,
    chainId: normalizedChainId,
    bundlerRequestTemplateHash: normalizedBundlerRequestTemplateHash
  };

  const signatureRequest = {
    requestKind: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
    signableDigest: normalizedUserOpHash,
    digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    signerPayload,
    signatureTarget,
    submissionContext
  };

  const signatureRequestJson = JSON.stringify(signatureRequest);
  const signatureRequestBytes = ethers.hexlify(ethers.toUtf8Bytes(signatureRequestJson));
  const signatureRequestHash = ethers.keccak256(
    ethers.toUtf8Bytes(signatureRequestJson)
  );

  const signatureRequestId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedSigningContextId,
        signatureRequestHash
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
    networkName: normalizedNetworkName,
    entryPointVersion: normalizedEntryPointVersion,
    entryPointAddress: normalizedEntryPointAddress,
    chainId: normalizedChainId,
    bundlerRpcMethod: normalizedBundlerRpcMethod,
    userOpHash: normalizedUserOpHash,
    signingContextHash: normalizedSigningContextHash,
    signingContextId: normalizedSigningContextId,
    bundlerRequestTemplateHash: normalizedBundlerRequestTemplateHash,
    unsignedUserOperation: normalizedUnsignedUserOperation,
    signatureRequestKind: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
    signableDigest: normalizedUserOpHash,
    signableDigestBytes: normalizedUserOpHash,
    digestEncoding: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
    signerPayload,
    signerPayloadJson,
    signerPayloadBytes,
    signerPayloadHash,
    signatureTarget,
    signatureRequest,
    signatureRequestJson,
    signatureRequestBytes,
    signatureRequestHash,
    signatureRequestId
  };
}

function buildSmartAccountDeploySignatureRequest({ smartAccountDeployUserOpHash }) {
  if (!smartAccountDeployUserOpHash || typeof smartAccountDeployUserOpHash !== "object") {
    throw new Error("smartAccountDeployUserOpHash is required");
  }

  assertEqual(
    smartAccountDeployUserOpHash.path,
    "phil-smart-account-deploy-userop-hash",
    "smartAccountDeployUserOpHash.path"
  );
  assertEqual(
    smartAccountDeployUserOpHash.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployUserOpHash.payloadShape"
  );

  if (
    !smartAccountDeployUserOpHash.validationChecks ||
    typeof smartAccountDeployUserOpHash.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployUserOpHash.validationChecks is required");
  }
  if (
    !smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary ||
    typeof smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary !== "object"
  ) {
    throw new Error(
      "smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary is required"
    );
  }
  if (
    !smartAccountDeployUserOpHash.smartAccountDeployUserOpHash ||
    typeof smartAccountDeployUserOpHash.smartAccountDeployUserOpHash !== "object"
  ) {
    throw new Error("smartAccountDeployUserOpHash.smartAccountDeployUserOpHash is required");
  }
  if (
    !smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash ||
    typeof smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash !== "object"
  ) {
    throw new Error(
      "smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash is required"
    );
  }

  assertTrue(
    smartAccountDeployUserOpHash.validationChecks.smartAccountDeployUserOpPathValid,
    "validationChecks.smartAccountDeployUserOpPathValid"
  );
  assertTrue(
    smartAccountDeployUserOpHash.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployUserOpHash.validationChecks.upstreamSmartAccountDeployUserOpValid,
    "validationChecks.upstreamSmartAccountDeployUserOpValid"
  );
  assertTrue(
    smartAccountDeployUserOpHash.validationChecks
      .deterministicSmartAccountDeployUserOpHashDerived,
    "validationChecks.deterministicSmartAccountDeployUserOpHashDerived"
  );
  assertTrue(
    smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.ready,
    "smartAccountDeployUserOpHashSummary.ready"
  );
  assertEqual(
    smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.status,
    "smart-account-deploy-userop-hash-ready",
    "smartAccountDeployUserOpHashSummary.status"
  );
  assertTrue(
    smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSummary.parityProven,
    "smartAccountDeployUserOpHashSummary.parityProven"
  );

  const deterministicSmartAccountDeployUserOpHash = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.ownerCommitment,
      "smartAccountDeployUserOpHash.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.consumerDataHash,
      "smartAccountDeployUserOpHash.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.canonicalRecipient,
      "smartAccountDeployUserOpHash.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.walletId,
      "smartAccountDeployUserOpHash.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetId,
      "smartAccountDeployUserOpHash.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.targetAddress,
      "smartAccountDeployUserOpHash.targetAddress"
    ),
    userOpKind: normalizeString(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpKind,
      "smartAccountDeployUserOpHash.userOpKind"
    ),
    entryPointVersion: normalizeString(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.entryPointVersion,
      "smartAccountDeployUserOpHash.entryPointVersion"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.entryPointAddress,
      "smartAccountDeployUserOpHash.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.chainId,
      "smartAccountDeployUserOpHash.chainId"
    ),
    bundlerRpcMethod: normalizeString(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRpcMethod,
      "smartAccountDeployUserOpHash.bundlerRpcMethod"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.userOpHash,
      "smartAccountDeployUserOpHash.userOpHash"
    ),
    signingContext: smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContext,
    signingContextJson: String(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextJson || ""
    ),
    signingContextBytes: normalizeBytes(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextBytes,
      "smartAccountDeployUserOpHash.signingContextBytes"
    ),
    signingContextHash: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextHash,
      "smartAccountDeployUserOpHash.signingContextHash"
    ),
    bundlerRequestTemplate:
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplate,
    bundlerRequestTemplateJson: String(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateJson ||
        ""
    ),
    bundlerRequestTemplateBytes: normalizeBytes(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateBytes,
      "smartAccountDeployUserOpHash.bundlerRequestTemplateBytes"
    ),
    bundlerRequestTemplateHash: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.bundlerRequestTemplateHash,
      "smartAccountDeployUserOpHash.bundlerRequestTemplateHash"
    ),
    signingContextId: normalizeHex32(
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHash.signingContextId,
      "smartAccountDeployUserOpHash.signingContextId"
    )
  };

  if (
    !deterministicSmartAccountDeployUserOpHash.signingContext ||
    typeof deterministicSmartAccountDeployUserOpHash.signingContext !== "object"
  ) {
    throw new Error("smartAccountDeployUserOpHash.signingContext is required");
  }
  if (
    !deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplate ||
    typeof deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplate !== "object"
  ) {
    throw new Error("smartAccountDeployUserOpHash.bundlerRequestTemplate is required");
  }

  const normalizedSigningContext = {
    networkName: normalizeString(
      deterministicSmartAccountDeployUserOpHash.signingContext.networkName,
      "smartAccountDeployUserOpHash.signingContext.networkName"
    ),
    chainId: normalizeUintString(
      deterministicSmartAccountDeployUserOpHash.signingContext.chainId,
      "smartAccountDeployUserOpHash.signingContext.chainId"
    ),
    entryPointVersion: normalizeString(
      deterministicSmartAccountDeployUserOpHash.signingContext.entryPointVersion,
      "smartAccountDeployUserOpHash.signingContext.entryPointVersion"
    ),
    entryPointAddress: normalizeAddress(
      deterministicSmartAccountDeployUserOpHash.signingContext.entryPointAddress,
      "smartAccountDeployUserOpHash.signingContext.entryPointAddress"
    ),
    userOpHash: normalizeHex32(
      deterministicSmartAccountDeployUserOpHash.signingContext.userOpHash,
      "smartAccountDeployUserOpHash.signingContext.userOpHash"
    ),
    signatureField: normalizeString(
      deterministicSmartAccountDeployUserOpHash.signingContext.signatureField,
      "smartAccountDeployUserOpHash.signingContext.signatureField"
    ),
    signaturePlaceholder: normalizeBytes(
      deterministicSmartAccountDeployUserOpHash.signingContext.signaturePlaceholder,
      "smartAccountDeployUserOpHash.signingContext.signaturePlaceholder"
    )
  };

  assertEqual(
    deterministicSmartAccountDeployUserOpHash.signingContextJson,
    JSON.stringify(normalizedSigningContext),
    "smartAccountDeployUserOpHash.signingContextJson"
  );
  assertEqual(
    deterministicSmartAccountDeployUserOpHash.signingContextBytes,
    ethers.hexlify(
      ethers.toUtf8Bytes(deterministicSmartAccountDeployUserOpHash.signingContextJson)
    ),
    "smartAccountDeployUserOpHash.signingContextBytes"
  );
  assertEqual(
    deterministicSmartAccountDeployUserOpHash.signingContextHash,
    ethers.keccak256(
      ethers.toUtf8Bytes(deterministicSmartAccountDeployUserOpHash.signingContextJson)
    ),
    "smartAccountDeployUserOpHash.signingContextHash"
  );
  assertEqual(
    normalizedSigningContext.entryPointVersion,
    deterministicSmartAccountDeployUserOpHash.entryPointVersion,
    "signingContext.entryPointVersion/entryPointVersion"
  );
  assertEqual(
    normalizedSigningContext.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployUserOpHash.entryPointAddress.toLowerCase(),
    "signingContext.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    normalizedSigningContext.chainId,
    deterministicSmartAccountDeployUserOpHash.chainId,
    "signingContext.chainId/chainId"
  );
  assertEqual(
    normalizedSigningContext.userOpHash,
    deterministicSmartAccountDeployUserOpHash.userOpHash,
    "signingContext.userOpHash/userOpHash"
  );
  assertEqual(
    normalizedSigningContext.signatureField,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
    "signingContext.signatureField"
  );
  assertEqual(
    normalizedSigningContext.signaturePlaceholder,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "signingContext.signaturePlaceholder"
  );

  const normalizedBundlerRequestTemplate = {
    jsonrpc: normalizeString(
      deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplate.jsonrpc,
      "smartAccountDeployUserOpHash.bundlerRequestTemplate.jsonrpc"
    ),
    method: normalizeString(
      deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplate.method,
      "smartAccountDeployUserOpHash.bundlerRequestTemplate.method"
    ),
    params: deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplate.params
  };

  if (
    !Array.isArray(normalizedBundlerRequestTemplate.params) ||
    normalizedBundlerRequestTemplate.params.length !== 2 ||
    !normalizedBundlerRequestTemplate.params[0] ||
    typeof normalizedBundlerRequestTemplate.params[0] !== "object"
  ) {
    throw new Error("smartAccountDeployUserOpHash.bundlerRequestTemplate.params is invalid");
  }

  const normalizedBundlerUserOp = {
    sender: normalizeAddress(
      normalizedBundlerRequestTemplate.params[0].sender,
      "bundlerRequestTemplate.params[0].sender"
    ),
    nonce: normalizeUintString(
      normalizedBundlerRequestTemplate.params[0].nonce,
      "bundlerRequestTemplate.params[0].nonce"
    ),
    initCode: normalizeBytes(
      normalizedBundlerRequestTemplate.params[0].initCode,
      "bundlerRequestTemplate.params[0].initCode"
    ),
    callData: normalizeBytes(
      normalizedBundlerRequestTemplate.params[0].callData,
      "bundlerRequestTemplate.params[0].callData"
    ),
    callGasLimit: normalizeUintString(
      normalizedBundlerRequestTemplate.params[0].callGasLimit,
      "bundlerRequestTemplate.params[0].callGasLimit"
    ),
    verificationGasLimit: normalizeUintString(
      normalizedBundlerRequestTemplate.params[0].verificationGasLimit,
      "bundlerRequestTemplate.params[0].verificationGasLimit"
    ),
    preVerificationGas: normalizeUintString(
      normalizedBundlerRequestTemplate.params[0].preVerificationGas,
      "bundlerRequestTemplate.params[0].preVerificationGas"
    ),
    maxFeePerGas: normalizeUintString(
      normalizedBundlerRequestTemplate.params[0].maxFeePerGas,
      "bundlerRequestTemplate.params[0].maxFeePerGas"
    ),
    maxPriorityFeePerGas: normalizeUintString(
      normalizedBundlerRequestTemplate.params[0].maxPriorityFeePerGas,
      "bundlerRequestTemplate.params[0].maxPriorityFeePerGas"
    ),
    paymasterAndData: normalizeBytes(
      normalizedBundlerRequestTemplate.params[0].paymasterAndData,
      "bundlerRequestTemplate.params[0].paymasterAndData"
    ),
    signature: normalizeBytes(
      normalizedBundlerRequestTemplate.params[0].signature,
      "bundlerRequestTemplate.params[0].signature"
    )
  };
  const normalizedBundlerEntryPoint = normalizeAddress(
    normalizedBundlerRequestTemplate.params[1],
    "bundlerRequestTemplate.params[1]"
  );

  assertEqual(
    deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplateJson,
    JSON.stringify(deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplate),
    "smartAccountDeployUserOpHash.bundlerRequestTemplateJson"
  );
  assertEqual(
    deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplateBytes,
    ethers.hexlify(
      ethers.toUtf8Bytes(
        deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplateJson
      )
    ),
    "smartAccountDeployUserOpHash.bundlerRequestTemplateBytes"
  );
  assertEqual(
    deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplateHash,
    ethers.keccak256(
      ethers.toUtf8Bytes(
        deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplateJson
      )
    ),
    "smartAccountDeployUserOpHash.bundlerRequestTemplateHash"
  );
  assertEqual(
    normalizedBundlerRequestTemplate.jsonrpc,
    "2.0",
    "bundlerRequestTemplate.jsonrpc"
  );
  assertEqual(
    normalizedBundlerRequestTemplate.method,
    deterministicSmartAccountDeployUserOpHash.bundlerRpcMethod,
    "bundlerRequestTemplate.method/bundlerRpcMethod"
  );
  assertEqual(
    normalizedBundlerUserOp.sender.toLowerCase(),
    deterministicSmartAccountDeployUserOpHash.targetAddress.toLowerCase(),
    "bundlerRequestTemplate.params[0].sender/targetAddress"
  );
  assertEqual(
    normalizedBundlerUserOp.signature,
    SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
    "bundlerRequestTemplate.params[0].signature"
  );
  assertEqual(
    JSON.stringify(normalizedBundlerUserOp),
    JSON.stringify({
      sender: normalizeAddress(
        normalizedBundlerRequestTemplate.params[0].sender,
        "bundlerRequestTemplate.params[0].sender"
      ),
      nonce: normalizeUintString(
        normalizedBundlerRequestTemplate.params[0].nonce,
        "bundlerRequestTemplate.params[0].nonce"
      ),
      initCode: normalizeBytes(
        normalizedBundlerRequestTemplate.params[0].initCode,
        "bundlerRequestTemplate.params[0].initCode"
      ),
      callData: normalizeBytes(
        normalizedBundlerRequestTemplate.params[0].callData,
        "bundlerRequestTemplate.params[0].callData"
      ),
      callGasLimit: normalizeUintString(
        normalizedBundlerRequestTemplate.params[0].callGasLimit,
        "bundlerRequestTemplate.params[0].callGasLimit"
      ),
      verificationGasLimit: normalizeUintString(
        normalizedBundlerRequestTemplate.params[0].verificationGasLimit,
        "bundlerRequestTemplate.params[0].verificationGasLimit"
      ),
      preVerificationGas: normalizeUintString(
        normalizedBundlerRequestTemplate.params[0].preVerificationGas,
        "bundlerRequestTemplate.params[0].preVerificationGas"
      ),
      maxFeePerGas: normalizeUintString(
        normalizedBundlerRequestTemplate.params[0].maxFeePerGas,
        "bundlerRequestTemplate.params[0].maxFeePerGas"
      ),
      maxPriorityFeePerGas: normalizeUintString(
        normalizedBundlerRequestTemplate.params[0].maxPriorityFeePerGas,
        "bundlerRequestTemplate.params[0].maxPriorityFeePerGas"
      ),
      paymasterAndData: normalizeBytes(
        normalizedBundlerRequestTemplate.params[0].paymasterAndData,
        "bundlerRequestTemplate.params[0].paymasterAndData"
      ),
      signature: normalizeBytes(
        normalizedBundlerRequestTemplate.params[0].signature,
        "bundlerRequestTemplate.params[0].signature"
      )
    }),
    "bundlerRequestTemplate.params[0]"
  );
  assertEqual(
    normalizedBundlerEntryPoint.toLowerCase(),
    deterministicSmartAccountDeployUserOpHash.entryPointAddress.toLowerCase(),
    "bundlerRequestTemplate.params[1]/entryPointAddress"
  );

  const appSmartAccountDeployUserOpHash = {
    recipient: normalizeAddress(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.recipient,
      "appSmartAccountDeployUserOpHash.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.sender,
      "appSmartAccountDeployUserOpHash.sender"
    ),
    entryPointAddress: normalizeAddress(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.entryPointAddress,
      "appSmartAccountDeployUserOpHash.entryPointAddress"
    ),
    chainId: normalizeUintString(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.chainId,
      "appSmartAccountDeployUserOpHash.chainId"
    ),
    userOpHash: normalizeHex32(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.userOpHash,
      "appSmartAccountDeployUserOpHash.userOpHash"
    ),
    bundlerRpcMethod: normalizeString(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.bundlerRpcMethod,
      "appSmartAccountDeployUserOpHash.bundlerRpcMethod"
    ),
    ready: smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.ready === true,
    status: String(
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.status || ""
    ),
    parityProven:
      smartAccountDeployUserOpHash.appSmartAccountDeployUserOpHash.parityProven ===
      true
  };

  assertTrue(
    appSmartAccountDeployUserOpHash.ready,
    "appSmartAccountDeployUserOpHash.ready"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.status,
    "smart-account-deploy-userop-hash-ready",
    "appSmartAccountDeployUserOpHash.status"
  );
  assertTrue(
    appSmartAccountDeployUserOpHash.parityProven,
    "appSmartAccountDeployUserOpHash.parityProven"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.recipient.toLowerCase(),
    deterministicSmartAccountDeployUserOpHash.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployUserOpHash.recipient/canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.sender.toLowerCase(),
    deterministicSmartAccountDeployUserOpHash.targetAddress.toLowerCase(),
    "appSmartAccountDeployUserOpHash.sender/targetAddress"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.entryPointAddress.toLowerCase(),
    deterministicSmartAccountDeployUserOpHash.entryPointAddress.toLowerCase(),
    "appSmartAccountDeployUserOpHash.entryPointAddress/entryPointAddress"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.chainId,
    deterministicSmartAccountDeployUserOpHash.chainId,
    "appSmartAccountDeployUserOpHash.chainId/chainId"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.userOpHash,
    deterministicSmartAccountDeployUserOpHash.userOpHash,
    "appSmartAccountDeployUserOpHash.userOpHash/userOpHash"
  );
  assertEqual(
    appSmartAccountDeployUserOpHash.bundlerRpcMethod,
    deterministicSmartAccountDeployUserOpHash.bundlerRpcMethod,
    "appSmartAccountDeployUserOpHash.bundlerRpcMethod/bundlerRpcMethod"
  );

  const smartAccountDeploySignatureRequest = deriveDeterministicSmartAccountDeploySignatureRequest({
    ownerCommitment: deterministicSmartAccountDeployUserOpHash.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployUserOpHash.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployUserOpHash.canonicalRecipient,
    walletId: deterministicSmartAccountDeployUserOpHash.walletId,
    targetId: deterministicSmartAccountDeployUserOpHash.targetId,
    targetAddress: deterministicSmartAccountDeployUserOpHash.targetAddress,
    userOpKind: deterministicSmartAccountDeployUserOpHash.userOpKind,
    networkName: normalizedSigningContext.networkName,
    entryPointVersion: deterministicSmartAccountDeployUserOpHash.entryPointVersion,
    entryPointAddress: deterministicSmartAccountDeployUserOpHash.entryPointAddress,
    chainId: deterministicSmartAccountDeployUserOpHash.chainId,
    bundlerRpcMethod: deterministicSmartAccountDeployUserOpHash.bundlerRpcMethod,
    userOpHash: deterministicSmartAccountDeployUserOpHash.userOpHash,
    signingContextHash: deterministicSmartAccountDeployUserOpHash.signingContextHash,
    signingContextId: deterministicSmartAccountDeployUserOpHash.signingContextId,
    bundlerRequestTemplateHash:
      deterministicSmartAccountDeployUserOpHash.bundlerRequestTemplateHash
    ,
    unsignedUserOperation: normalizedBundlerUserOp
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-signature-request",
    smartAccountDeploySignatureRequestSource:
      "scripts/base/build-smart-account-deploy-signature-request.cjs",
    smartAccountDeployUserOpHashSource:
      smartAccountDeployUserOpHash.smartAccountDeployUserOpHashSource,
    consumedPath: smartAccountDeployUserOpHash.path,
    proofType: smartAccountDeployUserOpHash.proofType,
    payloadShape: smartAccountDeployUserOpHash.payloadShape,
    smartAccountDeploySignatureRequestDomain: {
      label: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployUserOpHashPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployUserOpHashValid: true,
      deterministicSmartAccountDeploySignatureRequestDerived: true
    },
    smartAccountDeploySignatureRequestSummary: {
      ready: true,
      status: "smart-account-deploy-signature-request-ready",
      reason: "validated-smart-account-deploy-userop-hash",
      parityProven: true
    },
    smartAccountDeploySignatureRequest: {
      ownerCommitment: smartAccountDeploySignatureRequest.ownerCommitment,
      consumerDataHash: smartAccountDeploySignatureRequest.consumerDataHash,
      canonicalRecipient: smartAccountDeploySignatureRequest.canonicalRecipient,
      walletId: smartAccountDeploySignatureRequest.walletId,
      targetId: smartAccountDeploySignatureRequest.targetId,
      targetAddress: smartAccountDeploySignatureRequest.targetAddress,
      userOpKind: smartAccountDeploySignatureRequest.userOpKind,
      networkName: smartAccountDeploySignatureRequest.networkName,
      entryPointVersion: smartAccountDeploySignatureRequest.entryPointVersion,
      entryPointAddress: smartAccountDeploySignatureRequest.entryPointAddress,
      chainId: smartAccountDeploySignatureRequest.chainId,
      bundlerRpcMethod: smartAccountDeploySignatureRequest.bundlerRpcMethod,
      userOpHash: smartAccountDeploySignatureRequest.userOpHash,
      signingContextHash: smartAccountDeploySignatureRequest.signingContextHash,
      signingContextId: smartAccountDeploySignatureRequest.signingContextId,
      bundlerRequestTemplateHash:
        smartAccountDeploySignatureRequest.bundlerRequestTemplateHash,
      unsignedUserOperation: smartAccountDeploySignatureRequest.unsignedUserOperation,
      signatureRequestKind: smartAccountDeploySignatureRequest.signatureRequestKind,
      signableDigest: smartAccountDeploySignatureRequest.signableDigest,
      signableDigestBytes: smartAccountDeploySignatureRequest.signableDigestBytes,
      digestEncoding: smartAccountDeploySignatureRequest.digestEncoding,
      signerPayload: smartAccountDeploySignatureRequest.signerPayload,
      signerPayloadJson: smartAccountDeploySignatureRequest.signerPayloadJson,
      signerPayloadBytes: smartAccountDeploySignatureRequest.signerPayloadBytes,
      signerPayloadHash: smartAccountDeploySignatureRequest.signerPayloadHash,
      signatureTarget: smartAccountDeploySignatureRequest.signatureTarget,
      signatureRequest: smartAccountDeploySignatureRequest.signatureRequest,
      signatureRequestJson: smartAccountDeploySignatureRequest.signatureRequestJson,
      signatureRequestBytes: smartAccountDeploySignatureRequest.signatureRequestBytes,
      signatureRequestHash: smartAccountDeploySignatureRequest.signatureRequestHash,
      signatureRequestId: smartAccountDeploySignatureRequest.signatureRequestId
    },
    appSmartAccountDeploySignatureRequest: {
      recipient: smartAccountDeploySignatureRequest.canonicalRecipient,
      sender: smartAccountDeploySignatureRequest.targetAddress,
      entryPointAddress: smartAccountDeploySignatureRequest.entryPointAddress,
      chainId: smartAccountDeploySignatureRequest.chainId,
      userOpHash: smartAccountDeploySignatureRequest.userOpHash,
      unsignedUserOperation: smartAccountDeploySignatureRequest.unsignedUserOperation,
      signatureRequestKind: smartAccountDeploySignatureRequest.signatureRequestKind,
      signableDigest: smartAccountDeploySignatureRequest.signableDigest,
      signatureRequestId: smartAccountDeploySignatureRequest.signatureRequestId,
      ready: true,
      status: "smart-account-deploy-signature-request-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-userop-hash") {
      parsed.smartAccountDeployUserOpHashPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-signature-request.cjs --smart-account-deploy-userop-hash <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployUserOpHashPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeploySignatureRequest = buildSmartAccountDeploySignatureRequest({
      smartAccountDeployUserOpHash: loadJson(
        path.resolve(parsed.smartAccountDeployUserOpHashPath)
      )
    });
    console.log(JSON.stringify(smartAccountDeploySignatureRequest, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_PAYLOAD_KIND,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_DIGEST_ENCODING,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_FIELD,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_TARGET_PATH,
  SMART_ACCOUNT_DEPLOY_SIGNATURE_REQUEST_SIGNATURE_PLACEHOLDER,
  deriveDeterministicSmartAccountDeploySignatureRequest,
  buildSmartAccountDeploySignatureRequest
};
