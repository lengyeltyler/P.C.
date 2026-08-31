const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_LABEL = "PHIL_SMART_ACCOUNT_DEPLOY_USEROP_V1";
const SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_USEROP_KIND = "erc4337-smart-account-deploy-userop-v0.6-unsigned-v1";
const SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION = "erc4337-v0.6";
const SMART_ACCOUNT_DEPLOY_USEROP_NONCE = "0";
const SMART_ACCOUNT_DEPLOY_USEROP_CALL_DATA = "0x";
const SMART_ACCOUNT_DEPLOY_USEROP_MAX_FEE_PER_GAS = "0";
const SMART_ACCOUNT_DEPLOY_USEROP_MAX_PRIORITY_FEE_PER_GAS = "0";
const SMART_ACCOUNT_DEPLOY_USEROP_PAYMASTER_AND_DATA = "0x";
const SMART_ACCOUNT_DEPLOY_USEROP_SIGNATURE = "0x";

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

function deriveDeterministicSmartAccountDeployUserOp({
  proofType,
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  submissionKind,
  submitId,
  submitRequestHash,
  submitRequestBytes,
  submitBody
}) {
  const normalizedProofType = normalizeString(proofType, "proofType");
  const normalizedOwnerCommitment = normalizeHex32(ownerCommitment, "ownerCommitment");
  const normalizedConsumerDataHash = normalizeHex32(consumerDataHash, "consumerDataHash");
  const normalizedCanonicalRecipient = normalizeAddress(canonicalRecipient, "canonicalRecipient");
  const normalizedWalletId = normalizeHex32(walletId, "walletId");
  const normalizedTargetId = normalizeHex32(targetId, "targetId");
  const normalizedTargetAddress = normalizeAddress(targetAddress, "targetAddress");
  const normalizedSubmissionKind = normalizeString(submissionKind, "submissionKind");
  const normalizedSubmitId = normalizeHex32(submitId, "submitId");
  const normalizedSubmitRequestHash = normalizeHex32(submitRequestHash, "submitRequestHash");
  const normalizedSubmitRequestBytes = normalizeBytes(submitRequestBytes, "submitRequestBytes");
  const normalizedSubmitBody = normalizeString(submitBody, "submitBody");
  const recomputedSubmitRequestHash = ethers.keccak256(normalizedSubmitRequestBytes);

  assertEqual(
    recomputedSubmitRequestHash,
    normalizedSubmitRequestHash,
    "submitRequestHash/submitRequestBytes"
  );

  const parsedSubmitBody = JSON.parse(normalizedSubmitBody);
  if (!parsedSubmitBody || typeof parsedSubmitBody !== "object") {
    throw new Error("submitBody must decode to an object");
  }

  const normalizedRequestType = normalizeString(parsedSubmitBody.requestType, "submitBody.requestType");
  const normalizedBodyProofType = normalizeString(parsedSubmitBody.proofType, "submitBody.proofType");
  const normalizedExpectedDeployedAddress = normalizeAddress(
    parsedSubmitBody.expectedDeployedAddress,
    "submitBody.expectedDeployedAddress"
  );
  const normalizedDeployCalldata = normalizeBytes(
    parsedSubmitBody.deployCalldata,
    "submitBody.deployCalldata"
  );
  const normalizedDeployPayloadHash = normalizeHex32(
    parsedSubmitBody.deployPayloadHash,
    "submitBody.deployPayloadHash"
  );
  const normalizedPayloadEncoding = normalizeString(
    parsedSubmitBody.payloadEncoding,
    "submitBody.payloadEncoding"
  );
  const normalizedExecutionValue = normalizeString(
    parsedSubmitBody.executionValue,
    "submitBody.executionValue"
  );

  assertEqual(normalizedRequestType, "smart-account-deploy", "submitBody.requestType");
  assertEqual(normalizedBodyProofType, normalizedProofType, "submitBody.proofType/proofType");
  assertEqual(
    normalizedExpectedDeployedAddress.toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "submitBody.expectedDeployedAddress/targetAddress"
  );
  assertEqual(
    normalizeAddress(parsedSubmitBody.canonicalRecipient, "submitBody.canonicalRecipient").toLowerCase(),
    normalizedCanonicalRecipient.toLowerCase(),
    "submitBody.canonicalRecipient/canonicalRecipient"
  );
  assertEqual(normalizedExecutionValue, "0", "submitBody.executionValue");
  assertEqual(normalizedSubmissionKind, "smart-account-deploy-submit-relay-http-v1", "submissionKind");

  const sender = normalizedTargetAddress;
  const nonce = SMART_ACCOUNT_DEPLOY_USEROP_NONCE;
  const initCode = normalizedDeployCalldata;
  const callData = SMART_ACCOUNT_DEPLOY_USEROP_CALL_DATA;
  const initCodeHash = ethers.keccak256(initCode);
  const callDataHash = ethers.keccak256(callData);
  const initCodeLengthBytes = BigInt(ethers.getBytes(initCode).length);
  const submitRequestLengthBytes = BigInt(ethers.getBytes(normalizedSubmitRequestBytes).length);
  const callGasLimit = "0";
  const verificationGasLimit = (140000n + initCodeLengthBytes * 32n).toString();
  const preVerificationGas = (30000n + submitRequestLengthBytes * 3n).toString();
  const maxFeePerGas = SMART_ACCOUNT_DEPLOY_USEROP_MAX_FEE_PER_GAS;
  const maxPriorityFeePerGas = SMART_ACCOUNT_DEPLOY_USEROP_MAX_PRIORITY_FEE_PER_GAS;
  const paymasterAndData = SMART_ACCOUNT_DEPLOY_USEROP_PAYMASTER_AND_DATA;
  const signature = SMART_ACCOUNT_DEPLOY_USEROP_SIGNATURE;
  const paymasterAndDataHash = ethers.keccak256(paymasterAndData);
  const signatureHash = ethers.keccak256(signature);

  const unsignedUserOperation = {
    sender,
    nonce,
    initCode,
    callData,
    callGasLimit,
    verificationGasLimit,
    preVerificationGas,
    maxFeePerGas,
    maxPriorityFeePerGas,
    paymasterAndData,
    signature
  };

  const unsignedUserOpJson = JSON.stringify(unsignedUserOperation);
  const unsignedUserOpBytes = ethers.hexlify(ethers.toUtf8Bytes(unsignedUserOpJson));
  const unsignedUserOpHash = ethers.keccak256(
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
        sender,
        BigInt(nonce),
        initCodeHash,
        callDataHash,
        BigInt(callGasLimit),
        BigInt(verificationGasLimit),
        BigInt(preVerificationGas),
        BigInt(maxFeePerGas),
        BigInt(maxPriorityFeePerGas),
        paymasterAndDataHash,
        signatureHash
      ]
    )
  );

  const userOpId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedSubmitId,
        unsignedUserOpHash
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
    submissionKind: normalizedSubmissionKind,
    submitId: normalizedSubmitId,
    submitRequestHash: normalizedSubmitRequestHash,
    userOpKind: SMART_ACCOUNT_DEPLOY_USEROP_KIND,
    entryPointVersion: SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
    sender,
    nonce,
    initCodeSource: "submitBody.deployCalldata",
    payloadEncoding: normalizedPayloadEncoding,
    executionValue: normalizedExecutionValue,
    deployPayloadHash: normalizedDeployPayloadHash,
    initCodeHash,
    callDataHash,
    unsignedUserOperation,
    unsignedUserOpJson,
    unsignedUserOpBytes,
    unsignedUserOpHash,
    userOpId
  };
}

function buildSmartAccountDeployUserOp({ smartAccountDeploySubmit }) {
  if (!smartAccountDeploySubmit || typeof smartAccountDeploySubmit !== "object") {
    throw new Error("smartAccountDeploySubmit is required");
  }

  assertEqual(
    smartAccountDeploySubmit.path,
    "phil-smart-account-deploy-submit",
    "smartAccountDeploySubmit.path"
  );
  assertEqual(
    smartAccountDeploySubmit.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeploySubmit.payloadShape"
  );

  if (
    !smartAccountDeploySubmit.validationChecks ||
    typeof smartAccountDeploySubmit.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeploySubmit.validationChecks is required");
  }
  if (
    !smartAccountDeploySubmit.smartAccountDeploySubmitSummary ||
    typeof smartAccountDeploySubmit.smartAccountDeploySubmitSummary !== "object"
  ) {
    throw new Error("smartAccountDeploySubmit.smartAccountDeploySubmitSummary is required");
  }
  if (
    !smartAccountDeploySubmit.smartAccountDeploySubmit ||
    typeof smartAccountDeploySubmit.smartAccountDeploySubmit !== "object"
  ) {
    throw new Error("smartAccountDeploySubmit.smartAccountDeploySubmit is required");
  }
  if (
    !smartAccountDeploySubmit.appSmartAccountDeploySubmit ||
    typeof smartAccountDeploySubmit.appSmartAccountDeploySubmit !== "object"
  ) {
    throw new Error("smartAccountDeploySubmit.appSmartAccountDeploySubmit is required");
  }

  assertTrue(
    smartAccountDeploySubmit.validationChecks.smartAccountDeployTransportPathValid,
    "validationChecks.smartAccountDeployTransportPathValid"
  );
  assertTrue(
    smartAccountDeploySubmit.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeploySubmit.validationChecks.upstreamSmartAccountDeployTransportValid,
    "validationChecks.upstreamSmartAccountDeployTransportValid"
  );
  assertTrue(
    smartAccountDeploySubmit.validationChecks.deterministicSmartAccountDeploySubmitDerived,
    "validationChecks.deterministicSmartAccountDeploySubmitDerived"
  );
  assertTrue(
    smartAccountDeploySubmit.smartAccountDeploySubmitSummary.ready,
    "smartAccountDeploySubmitSummary.ready"
  );
  assertEqual(
    smartAccountDeploySubmit.smartAccountDeploySubmitSummary.status,
    "smart-account-deploy-submit-ready",
    "smartAccountDeploySubmitSummary.status"
  );
  assertTrue(
    smartAccountDeploySubmit.smartAccountDeploySubmitSummary.parityProven,
    "smartAccountDeploySubmitSummary.parityProven"
  );

  const deterministicSmartAccountDeploySubmit = {
    ownerCommitment: normalizeHex32(
      smartAccountDeploySubmit.smartAccountDeploySubmit.ownerCommitment,
      "smartAccountDeploySubmit.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeploySubmit.smartAccountDeploySubmit.consumerDataHash,
      "smartAccountDeploySubmit.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeploySubmit.smartAccountDeploySubmit.canonicalRecipient,
      "smartAccountDeploySubmit.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeploySubmit.smartAccountDeploySubmit.walletId,
      "smartAccountDeploySubmit.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetId,
      "smartAccountDeploySubmit.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeploySubmit.smartAccountDeploySubmit.targetAddress,
      "smartAccountDeploySubmit.targetAddress"
    ),
    submissionKind: normalizeString(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submissionKind,
      "smartAccountDeploySubmit.submissionKind"
    ),
    submitId: normalizeHex32(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitId,
      "smartAccountDeploySubmit.submitId"
    ),
    submitRequestHash: normalizeHex32(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestHash,
      "smartAccountDeploySubmit.submitRequestHash"
    ),
    submitRequestBytes: normalizeBytes(
      smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequestBytes,
      "smartAccountDeploySubmit.submitRequestBytes"
    ),
    submitRequest: smartAccountDeploySubmit.smartAccountDeploySubmit.submitRequest
  };

  if (
    !deterministicSmartAccountDeploySubmit.submitRequest ||
    typeof deterministicSmartAccountDeploySubmit.submitRequest !== "object"
  ) {
    throw new Error("smartAccountDeploySubmit.submitRequest is required");
  }

  const appSmartAccountDeploySubmit = {
    recipient: normalizeAddress(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.recipient,
      "appSmartAccountDeploySubmit.recipient"
    ),
    expectedDeployedAddress: normalizeAddress(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.expectedDeployedAddress,
      "appSmartAccountDeploySubmit.expectedDeployedAddress"
    ),
    request: smartAccountDeploySubmit.appSmartAccountDeploySubmit.request,
    submitId: normalizeHex32(
      smartAccountDeploySubmit.appSmartAccountDeploySubmit.submitId,
      "appSmartAccountDeploySubmit.submitId"
    ),
    ready: smartAccountDeploySubmit.appSmartAccountDeploySubmit.ready === true,
    status: String(smartAccountDeploySubmit.appSmartAccountDeploySubmit.status || ""),
    parityProven: smartAccountDeploySubmit.appSmartAccountDeploySubmit.parityProven === true
  };

  if (!appSmartAccountDeploySubmit.request || typeof appSmartAccountDeploySubmit.request !== "object") {
    throw new Error("appSmartAccountDeploySubmit.request is required");
  }

  assertTrue(appSmartAccountDeploySubmit.ready, "appSmartAccountDeploySubmit.ready");
  assertEqual(
    appSmartAccountDeploySubmit.status,
    "smart-account-deploy-submit-ready",
    "appSmartAccountDeploySubmit.status"
  );
  assertTrue(
    appSmartAccountDeploySubmit.parityProven,
    "appSmartAccountDeploySubmit.parityProven"
  );
  assertEqual(
    appSmartAccountDeploySubmit.recipient.toLowerCase(),
    deterministicSmartAccountDeploySubmit.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeploySubmit.recipient/smartAccountDeploySubmit.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeploySubmit.expectedDeployedAddress.toLowerCase(),
    deterministicSmartAccountDeploySubmit.targetAddress.toLowerCase(),
    "appSmartAccountDeploySubmit.expectedDeployedAddress/smartAccountDeploySubmit.targetAddress"
  );
  assertEqual(
    appSmartAccountDeploySubmit.submitId,
    deterministicSmartAccountDeploySubmit.submitId,
    "appSmartAccountDeploySubmit.submitId/smartAccountDeploySubmit.submitId"
  );

  const submitBody = normalizeString(
    deterministicSmartAccountDeploySubmit.submitRequest.body,
    "smartAccountDeploySubmit.submitRequest.body"
  );

  const smartAccountDeployUserOp = deriveDeterministicSmartAccountDeployUserOp({
    proofType: smartAccountDeploySubmit.proofType,
    ownerCommitment: deterministicSmartAccountDeploySubmit.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeploySubmit.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeploySubmit.canonicalRecipient,
    walletId: deterministicSmartAccountDeploySubmit.walletId,
    targetId: deterministicSmartAccountDeploySubmit.targetId,
    targetAddress: deterministicSmartAccountDeploySubmit.targetAddress,
    submissionKind: deterministicSmartAccountDeploySubmit.submissionKind,
    submitId: deterministicSmartAccountDeploySubmit.submitId,
    submitRequestHash: deterministicSmartAccountDeploySubmit.submitRequestHash,
    submitRequestBytes: deterministicSmartAccountDeploySubmit.submitRequestBytes,
    submitBody
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-userop",
    smartAccountDeployUserOpSource: "scripts/base/build-smart-account-deploy-userop.cjs",
    smartAccountDeploySubmitSource: smartAccountDeploySubmit.smartAccountDeploySubmitSource,
    consumedPath: smartAccountDeploySubmit.path,
    proofType: smartAccountDeploySubmit.proofType,
    payloadShape: smartAccountDeploySubmit.payloadShape,
    smartAccountDeployUserOpDomain: {
      label: SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeploySubmitPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeploySubmitValid: true,
      deterministicSmartAccountDeployUserOpDerived: true
    },
    smartAccountDeployUserOpSummary: {
      ready: true,
      status: "smart-account-deploy-userop-ready",
      reason: "validated-smart-account-deploy-submit",
      parityProven: true
    },
    smartAccountDeployUserOp: {
      ownerCommitment: smartAccountDeployUserOp.ownerCommitment,
      consumerDataHash: smartAccountDeployUserOp.consumerDataHash,
      canonicalRecipient: smartAccountDeployUserOp.canonicalRecipient,
      walletId: smartAccountDeployUserOp.walletId,
      targetId: smartAccountDeployUserOp.targetId,
      targetAddress: smartAccountDeployUserOp.targetAddress,
      submissionKind: smartAccountDeployUserOp.submissionKind,
      submitId: smartAccountDeployUserOp.submitId,
      submitRequestHash: smartAccountDeployUserOp.submitRequestHash,
      userOpKind: smartAccountDeployUserOp.userOpKind,
      entryPointVersion: smartAccountDeployUserOp.entryPointVersion,
      sender: smartAccountDeployUserOp.sender,
      nonce: smartAccountDeployUserOp.nonce,
      initCodeSource: smartAccountDeployUserOp.initCodeSource,
      payloadEncoding: smartAccountDeployUserOp.payloadEncoding,
      executionValue: smartAccountDeployUserOp.executionValue,
      deployPayloadHash: smartAccountDeployUserOp.deployPayloadHash,
      initCodeHash: smartAccountDeployUserOp.initCodeHash,
      callDataHash: smartAccountDeployUserOp.callDataHash,
      unsignedUserOperation: smartAccountDeployUserOp.unsignedUserOperation,
      unsignedUserOpJson: smartAccountDeployUserOp.unsignedUserOpJson,
      unsignedUserOpBytes: smartAccountDeployUserOp.unsignedUserOpBytes,
      unsignedUserOpHash: smartAccountDeployUserOp.unsignedUserOpHash,
      userOpId: smartAccountDeployUserOp.userOpId
    },
    appSmartAccountDeployUserOp: {
      recipient: smartAccountDeployUserOp.canonicalRecipient,
      sender: smartAccountDeployUserOp.sender,
      unsignedUserOperation: smartAccountDeployUserOp.unsignedUserOperation,
      userOpId: smartAccountDeployUserOp.userOpId,
      ready: true,
      status: "smart-account-deploy-userop-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-submit") {
      parsed.smartAccountDeploySubmitPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-userop.cjs --smart-account-deploy-submit <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeploySubmitPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployUserOp = buildSmartAccountDeployUserOp({
      smartAccountDeploySubmit: loadJson(path.resolve(parsed.smartAccountDeploySubmitPath))
    });
    console.log(JSON.stringify(smartAccountDeployUserOp, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_USEROP_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_USEROP_KIND,
  SMART_ACCOUNT_DEPLOY_USEROP_ENTRYPOINT_VERSION,
  SMART_ACCOUNT_DEPLOY_USEROP_NONCE,
  SMART_ACCOUNT_DEPLOY_USEROP_CALL_DATA,
  SMART_ACCOUNT_DEPLOY_USEROP_MAX_FEE_PER_GAS,
  SMART_ACCOUNT_DEPLOY_USEROP_MAX_PRIORITY_FEE_PER_GAS,
  SMART_ACCOUNT_DEPLOY_USEROP_PAYMASTER_AND_DATA,
  SMART_ACCOUNT_DEPLOY_USEROP_SIGNATURE,
  deriveDeterministicSmartAccountDeployUserOp,
  buildSmartAccountDeployUserOp
};
