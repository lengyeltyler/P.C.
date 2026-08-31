const fs = require("node:fs");
const path = require("node:path");
const { ethers } = require("ethers");

const {
  resolveBaseMessengerConfig
} = require("../../config/base-messenger-config.cjs");

const SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_LABEL =
  "PHIL_SMART_ACCOUNT_DEPLOY_USEROP_HASH_V1";
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_HASH = ethers.keccak256(
  ethers.toUtf8Bytes(SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_LABEL)
);
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME = "base";
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID = String(
  resolveBaseMessengerConfig(SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME).chainId
);
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS = ethers.getAddress(
  "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
);
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD = "eth_sendUserOperation";
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_FIELD = "signature";
const SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_PLACEHOLDER = "0x";

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

function deriveDeterministicSmartAccountDeployUserOpHash({
  ownerCommitment,
  consumerDataHash,
  canonicalRecipient,
  walletId,
  targetId,
  targetAddress,
  userOpKind,
  entryPointVersion,
  submitId,
  unsignedUserOperation
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
  const normalizedSubmitId = normalizeHex32(submitId, "submitId");

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
  assertEqual(
    normalizedUnsignedUserOperation.sender.toLowerCase(),
    normalizedTargetAddress.toLowerCase(),
    "unsignedUserOperation.sender/targetAddress"
  );
  assertEqual(
    normalizedUnsignedUserOperation.signature,
    SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_PLACEHOLDER,
    "unsignedUserOperation.signature"
  );

  const initCodeHash = ethers.keccak256(normalizedUnsignedUserOperation.initCode);
  const callDataHash = ethers.keccak256(normalizedUnsignedUserOperation.callData);
  const paymasterAndDataHash = ethers.keccak256(normalizedUnsignedUserOperation.paymasterAndData);

  const erc4337PackHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      [
        "address",
        "uint256",
        "bytes32",
        "bytes32",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "bytes32"
      ],
      [
        normalizedUnsignedUserOperation.sender,
        BigInt(normalizedUnsignedUserOperation.nonce),
        initCodeHash,
        callDataHash,
        BigInt(normalizedUnsignedUserOperation.callGasLimit),
        BigInt(normalizedUnsignedUserOperation.verificationGasLimit),
        BigInt(normalizedUnsignedUserOperation.preVerificationGas),
        BigInt(normalizedUnsignedUserOperation.maxFeePerGas),
        BigInt(normalizedUnsignedUserOperation.maxPriorityFeePerGas),
        paymasterAndDataHash
      ]
    )
  );

  const userOpHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "address", "uint256"],
      [
        erc4337PackHash,
        SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
        BigInt(SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID)
      ]
    )
  );

  const signingContext = {
    networkName: SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME,
    chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
    entryPointVersion: normalizedEntryPointVersion,
    entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
    userOpHash,
    signatureField: SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_FIELD,
    signaturePlaceholder: SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_PLACEHOLDER
  };

  const signingContextJson = JSON.stringify(signingContext);
  const signingContextBytes = ethers.hexlify(ethers.toUtf8Bytes(signingContextJson));
  const signingContextHash = ethers.keccak256(ethers.toUtf8Bytes(signingContextJson));

  const bundlerRequestTemplate = {
    jsonrpc: "2.0",
    method: SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
    params: [
      normalizedUnsignedUserOperation,
      SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS
    ]
  };

  const bundlerRequestTemplateJson = JSON.stringify(bundlerRequestTemplate);
  const bundlerRequestTemplateBytes = ethers.hexlify(
    ethers.toUtf8Bytes(bundlerRequestTemplateJson)
  );
  const bundlerRequestTemplateHash = ethers.keccak256(
    ethers.toUtf8Bytes(bundlerRequestTemplateJson)
  );

  const signingContextId = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
      [
        SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_HASH,
        normalizedWalletId,
        normalizedTargetId,
        normalizedSubmitId,
        userOpHash
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
    entryPointAddress: SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
    chainId: SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
    bundlerRpcMethod: SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
    erc4337PackHash,
    userOpHash,
    signingContext,
    signingContextJson,
    signingContextBytes,
    signingContextHash,
    bundlerRequestTemplate,
    bundlerRequestTemplateJson,
    bundlerRequestTemplateBytes,
    bundlerRequestTemplateHash,
    signingContextId
  };
}

function buildSmartAccountDeployUserOpHash({ smartAccountDeployUserOp }) {
  if (!smartAccountDeployUserOp || typeof smartAccountDeployUserOp !== "object") {
    throw new Error("smartAccountDeployUserOp is required");
  }

  assertEqual(
    smartAccountDeployUserOp.path,
    "phil-smart-account-deploy-userop",
    "smartAccountDeployUserOp.path"
  );
  assertEqual(
    smartAccountDeployUserOp.payloadShape,
    "[fact_high, fact_low]",
    "smartAccountDeployUserOp.payloadShape"
  );

  if (
    !smartAccountDeployUserOp.validationChecks ||
    typeof smartAccountDeployUserOp.validationChecks !== "object"
  ) {
    throw new Error("smartAccountDeployUserOp.validationChecks is required");
  }
  if (
    !smartAccountDeployUserOp.smartAccountDeployUserOpSummary ||
    typeof smartAccountDeployUserOp.smartAccountDeployUserOpSummary !== "object"
  ) {
    throw new Error("smartAccountDeployUserOp.smartAccountDeployUserOpSummary is required");
  }
  if (
    !smartAccountDeployUserOp.smartAccountDeployUserOp ||
    typeof smartAccountDeployUserOp.smartAccountDeployUserOp !== "object"
  ) {
    throw new Error("smartAccountDeployUserOp.smartAccountDeployUserOp is required");
  }
  if (
    !smartAccountDeployUserOp.appSmartAccountDeployUserOp ||
    typeof smartAccountDeployUserOp.appSmartAccountDeployUserOp !== "object"
  ) {
    throw new Error("smartAccountDeployUserOp.appSmartAccountDeployUserOp is required");
  }

  assertTrue(
    smartAccountDeployUserOp.validationChecks.smartAccountDeploySubmitPathValid,
    "validationChecks.smartAccountDeploySubmitPathValid"
  );
  assertTrue(
    smartAccountDeployUserOp.validationChecks.payloadShapeValid,
    "validationChecks.payloadShapeValid"
  );
  assertTrue(
    smartAccountDeployUserOp.validationChecks.upstreamSmartAccountDeploySubmitValid,
    "validationChecks.upstreamSmartAccountDeploySubmitValid"
  );
  assertTrue(
    smartAccountDeployUserOp.validationChecks.deterministicSmartAccountDeployUserOpDerived,
    "validationChecks.deterministicSmartAccountDeployUserOpDerived"
  );
  assertTrue(
    smartAccountDeployUserOp.smartAccountDeployUserOpSummary.ready,
    "smartAccountDeployUserOpSummary.ready"
  );
  assertEqual(
    smartAccountDeployUserOp.smartAccountDeployUserOpSummary.status,
    "smart-account-deploy-userop-ready",
    "smartAccountDeployUserOpSummary.status"
  );
  assertTrue(
    smartAccountDeployUserOp.smartAccountDeployUserOpSummary.parityProven,
    "smartAccountDeployUserOpSummary.parityProven"
  );

  const deterministicSmartAccountDeployUserOp = {
    ownerCommitment: normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.ownerCommitment,
      "smartAccountDeployUserOp.ownerCommitment"
    ),
    consumerDataHash: normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.consumerDataHash,
      "smartAccountDeployUserOp.consumerDataHash"
    ),
    canonicalRecipient: normalizeAddress(
      smartAccountDeployUserOp.smartAccountDeployUserOp.canonicalRecipient,
      "smartAccountDeployUserOp.canonicalRecipient"
    ),
    walletId: normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.walletId,
      "smartAccountDeployUserOp.walletId"
    ),
    targetId: normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.targetId,
      "smartAccountDeployUserOp.targetId"
    ),
    targetAddress: normalizeAddress(
      smartAccountDeployUserOp.smartAccountDeployUserOp.targetAddress,
      "smartAccountDeployUserOp.targetAddress"
    ),
    userOpKind: normalizeString(
      smartAccountDeployUserOp.smartAccountDeployUserOp.userOpKind,
      "smartAccountDeployUserOp.userOpKind"
    ),
    entryPointVersion: normalizeString(
      smartAccountDeployUserOp.smartAccountDeployUserOp.entryPointVersion,
      "smartAccountDeployUserOp.entryPointVersion"
    ),
    submitId: normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.submitId,
      "smartAccountDeployUserOp.submitId"
    ),
    unsignedUserOperation:
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOperation
  };

  if (
    !deterministicSmartAccountDeployUserOp.unsignedUserOperation ||
    typeof deterministicSmartAccountDeployUserOp.unsignedUserOperation !== "object"
  ) {
    throw new Error("smartAccountDeployUserOp.unsignedUserOperation is required");
  }

  const normalizedUnsignedUserOpBytes = normalizeBytes(
    smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOpBytes,
    "smartAccountDeployUserOp.unsignedUserOpBytes"
  );
  const recomputedUnsignedUserOpHash = ethers.keccak256(
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
        smartAccountDeployUserOp.smartAccountDeployUserOpDomain.hash,
        normalizeAddress(
          deterministicSmartAccountDeployUserOp.unsignedUserOperation.sender,
          "unsignedUserOperation.sender"
        ),
        BigInt(
          normalizeUintString(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.nonce,
            "unsignedUserOperation.nonce"
          )
        ),
        normalizeHex32(
          smartAccountDeployUserOp.smartAccountDeployUserOp.initCodeHash,
          "smartAccountDeployUserOp.initCodeHash"
        ),
        normalizeHex32(
          smartAccountDeployUserOp.smartAccountDeployUserOp.callDataHash,
          "smartAccountDeployUserOp.callDataHash"
        ),
        BigInt(
          normalizeUintString(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.callGasLimit,
            "unsignedUserOperation.callGasLimit"
          )
        ),
        BigInt(
          normalizeUintString(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.verificationGasLimit,
            "unsignedUserOperation.verificationGasLimit"
          )
        ),
        BigInt(
          normalizeUintString(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.preVerificationGas,
            "unsignedUserOperation.preVerificationGas"
          )
        ),
        BigInt(
          normalizeUintString(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.maxFeePerGas,
            "unsignedUserOperation.maxFeePerGas"
          )
        ),
        BigInt(
          normalizeUintString(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.maxPriorityFeePerGas,
            "unsignedUserOperation.maxPriorityFeePerGas"
          )
        ),
        ethers.keccak256(
          normalizeBytes(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.paymasterAndData,
            "unsignedUserOperation.paymasterAndData"
          )
        ),
        ethers.keccak256(
          normalizeBytes(
            deterministicSmartAccountDeployUserOp.unsignedUserOperation.signature,
            "unsignedUserOperation.signature"
          )
        )
      ]
    )
  );

  assertEqual(
    normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.unsignedUserOpHash,
      "smartAccountDeployUserOp.unsignedUserOpHash"
    ),
    recomputedUnsignedUserOpHash,
    "smartAccountDeployUserOp.unsignedUserOpHash"
  );

  // Keep the bytes normalized so upstream object continuity is checked as part of this seam.
  if (!normalizedUnsignedUserOpBytes.startsWith("0x")) {
    throw new Error("smartAccountDeployUserOp.unsignedUserOpBytes must be hex");
  }

  const appSmartAccountDeployUserOp = {
    recipient: normalizeAddress(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.recipient,
      "appSmartAccountDeployUserOp.recipient"
    ),
    sender: normalizeAddress(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.sender,
      "appSmartAccountDeployUserOp.sender"
    ),
    unsignedUserOperation:
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.unsignedUserOperation,
    userOpId: normalizeHex32(
      smartAccountDeployUserOp.appSmartAccountDeployUserOp.userOpId,
      "appSmartAccountDeployUserOp.userOpId"
    ),
    ready: smartAccountDeployUserOp.appSmartAccountDeployUserOp.ready === true,
    status: String(smartAccountDeployUserOp.appSmartAccountDeployUserOp.status || ""),
    parityProven: smartAccountDeployUserOp.appSmartAccountDeployUserOp.parityProven === true
  };

  assertTrue(appSmartAccountDeployUserOp.ready, "appSmartAccountDeployUserOp.ready");
  assertEqual(
    appSmartAccountDeployUserOp.status,
    "smart-account-deploy-userop-ready",
    "appSmartAccountDeployUserOp.status"
  );
  assertTrue(
    appSmartAccountDeployUserOp.parityProven,
    "appSmartAccountDeployUserOp.parityProven"
  );
  assertEqual(
    appSmartAccountDeployUserOp.recipient.toLowerCase(),
    deterministicSmartAccountDeployUserOp.canonicalRecipient.toLowerCase(),
    "appSmartAccountDeployUserOp.recipient/smartAccountDeployUserOp.canonicalRecipient"
  );
  assertEqual(
    appSmartAccountDeployUserOp.sender.toLowerCase(),
    deterministicSmartAccountDeployUserOp.targetAddress.toLowerCase(),
    "appSmartAccountDeployUserOp.sender/smartAccountDeployUserOp.targetAddress"
  );
  assertEqual(
    appSmartAccountDeployUserOp.userOpId,
    normalizeHex32(
      smartAccountDeployUserOp.smartAccountDeployUserOp.userOpId,
      "smartAccountDeployUserOp.userOpId"
    ),
    "appSmartAccountDeployUserOp.userOpId/smartAccountDeployUserOp.userOpId"
  );

  const smartAccountDeployUserOpHashArtifact = deriveDeterministicSmartAccountDeployUserOpHash({
    ownerCommitment: deterministicSmartAccountDeployUserOp.ownerCommitment,
    consumerDataHash: deterministicSmartAccountDeployUserOp.consumerDataHash,
    canonicalRecipient: deterministicSmartAccountDeployUserOp.canonicalRecipient,
    walletId: deterministicSmartAccountDeployUserOp.walletId,
    targetId: deterministicSmartAccountDeployUserOp.targetId,
    targetAddress: deterministicSmartAccountDeployUserOp.targetAddress,
    userOpKind: deterministicSmartAccountDeployUserOp.userOpKind,
    entryPointVersion: deterministicSmartAccountDeployUserOp.entryPointVersion,
    submitId: deterministicSmartAccountDeployUserOp.submitId,
    unsignedUserOperation: deterministicSmartAccountDeployUserOp.unsignedUserOperation
  });

  return {
    version: 1,
    path: "phil-smart-account-deploy-userop-hash",
    smartAccountDeployUserOpHashSource:
      "scripts/base/build-smart-account-deploy-userop-hash.cjs",
    smartAccountDeployUserOpSource: smartAccountDeployUserOp.smartAccountDeployUserOpSource,
    consumedPath: smartAccountDeployUserOp.path,
    proofType: smartAccountDeployUserOp.proofType,
    payloadShape: smartAccountDeployUserOp.payloadShape,
    smartAccountDeployUserOpHashDomain: {
      label: SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_LABEL,
      hash: SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_HASH
    },
    validationChecks: {
      smartAccountDeployUserOpPathValid: true,
      payloadShapeValid: true,
      upstreamSmartAccountDeployUserOpValid: true,
      deterministicSmartAccountDeployUserOpHashDerived: true
    },
    smartAccountDeployUserOpHashSummary: {
      ready: true,
      status: "smart-account-deploy-userop-hash-ready",
      reason: "validated-smart-account-deploy-userop",
      parityProven: true
    },
    smartAccountDeployUserOpHash: {
      ownerCommitment: smartAccountDeployUserOpHashArtifact.ownerCommitment,
      consumerDataHash: smartAccountDeployUserOpHashArtifact.consumerDataHash,
      canonicalRecipient: smartAccountDeployUserOpHashArtifact.canonicalRecipient,
      walletId: smartAccountDeployUserOpHashArtifact.walletId,
      targetId: smartAccountDeployUserOpHashArtifact.targetId,
      targetAddress: smartAccountDeployUserOpHashArtifact.targetAddress,
      userOpKind: smartAccountDeployUserOpHashArtifact.userOpKind,
      entryPointVersion: smartAccountDeployUserOpHashArtifact.entryPointVersion,
      entryPointAddress: smartAccountDeployUserOpHashArtifact.entryPointAddress,
      chainId: smartAccountDeployUserOpHashArtifact.chainId,
      bundlerRpcMethod: smartAccountDeployUserOpHashArtifact.bundlerRpcMethod,
      erc4337PackHash: smartAccountDeployUserOpHashArtifact.erc4337PackHash,
      userOpHash: smartAccountDeployUserOpHashArtifact.userOpHash,
      signingContext: smartAccountDeployUserOpHashArtifact.signingContext,
      signingContextJson: smartAccountDeployUserOpHashArtifact.signingContextJson,
      signingContextBytes: smartAccountDeployUserOpHashArtifact.signingContextBytes,
      signingContextHash: smartAccountDeployUserOpHashArtifact.signingContextHash,
      bundlerRequestTemplate: smartAccountDeployUserOpHashArtifact.bundlerRequestTemplate,
      bundlerRequestTemplateJson:
        smartAccountDeployUserOpHashArtifact.bundlerRequestTemplateJson,
      bundlerRequestTemplateBytes:
        smartAccountDeployUserOpHashArtifact.bundlerRequestTemplateBytes,
      bundlerRequestTemplateHash:
        smartAccountDeployUserOpHashArtifact.bundlerRequestTemplateHash,
      signingContextId: smartAccountDeployUserOpHashArtifact.signingContextId
    },
    appSmartAccountDeployUserOpHash: {
      recipient: smartAccountDeployUserOpHashArtifact.canonicalRecipient,
      sender: smartAccountDeployUserOpHashArtifact.targetAddress,
      entryPointAddress: smartAccountDeployUserOpHashArtifact.entryPointAddress,
      chainId: smartAccountDeployUserOpHashArtifact.chainId,
      userOpHash: smartAccountDeployUserOpHashArtifact.userOpHash,
      bundlerRpcMethod: smartAccountDeployUserOpHashArtifact.bundlerRpcMethod,
      ready: true,
      status: "smart-account-deploy-userop-hash-ready",
      parityProven: true
    }
  };
}

function parseArgs(argv) {
  const parsed = {};

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--smart-account-deploy-userop") {
      parsed.smartAccountDeployUserOpPath = argv[i + 1];
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
      "  node scripts/base/build-smart-account-deploy-userop-hash.cjs --smart-account-deploy-userop <path>"
    ].join("\n")
  );
}

if (require.main === module) {
  try {
    const parsed = parseArgs(process.argv.slice(2));
    if (parsed.help || !parsed.smartAccountDeployUserOpPath) {
      printUsage();
      process.exit(parsed.help ? 0 : 1);
    }

    const smartAccountDeployUserOpHash = buildSmartAccountDeployUserOpHash({
      smartAccountDeployUserOp: loadJson(path.resolve(parsed.smartAccountDeployUserOpPath))
    });
    console.log(JSON.stringify(smartAccountDeployUserOpHash, null, 2));
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    process.exit(1);
  }
}

module.exports = {
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_LABEL,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_DOMAIN_HASH,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_NETWORK_NAME,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_CHAIN_ID,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_ENTRYPOINT_ADDRESS,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_BUNDLER_RPC_METHOD,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_FIELD,
  SMART_ACCOUNT_DEPLOY_USEROP_HASH_SIGNATURE_PLACEHOLDER,
  deriveDeterministicSmartAccountDeployUserOpHash,
  buildSmartAccountDeployUserOpHash
};
