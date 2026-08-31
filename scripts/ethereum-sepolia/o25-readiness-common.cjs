require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  AbiCoder,
  Interface,
  concat,
  formatEther,
  formatUnits,
  getAddress,
  keccak256,
  toBeHex,
  zeroPadValue
} = require("ethers");

const {
  LOCAL_PROOF_GATED_PREPARATION_LIMITS,
  deriveLocalProofGatedValidatorKeyIdBinding
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  EXPECTED_DEPLOYER,
  EXPECTED_FUNDING,
  EXPECTED_VALIDATOR,
  ROOT,
  ensureNoSecrets,
  readJson
} = require("./o23r-common.cjs");
const {
  EXPECTED_ACCOUNT,
  EXPECTED_FACTORY,
  EXPECTED_TARGET,
  calculateO24Addresses
} = require("./o24-factory-common.cjs");

const O25_READINESS_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O25_COUNTERFACTUAL_ACCOUNT_READINESS.json"
);
const O25_PREFUND_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O25_ACCOUNT_PREFUND_PROPOSAL.json"
);
const O25_USER_OPERATION_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O25_ESTIMATION_ONLY_USER_OPERATION.json"
);
const ACCOUNT_ARTIFACT_PATH = path.join(
  ROOT,
  "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
);
const FACTORY_ARTIFACT_PATH = path.join(
  ROOT,
  "artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountFactoryV1.sol/PhilCore4337LocalProofAccountFactoryV1.json"
);

const ESTIMATION_ACTION_ID = keccak256(
  Buffer.from("PHILCORE_O25_ESTIMATION_ONLY_ACTION_NOT_AUTHORITY")
);
const ESTIMATION_AUTHORIZATION_DIGEST = keccak256(
  Buffer.from("PHILCORE_O25_ESTIMATION_ONLY_AUTHORIZATION_NOT_AUTHORITY")
);
const EMPTY_BYTES32 = `0x${"00".repeat(32)}`;
const PLACEHOLDER_SIGNATURE_LENGTH = 9 * 32;
const PROPOSAL_FRESHNESS_SECONDS = 15 * 60;
const RECOMMENDED_FEE_MARGIN_BASIS_POINTS = 2_500n;
const DIRECT_TRANSFER_GAS_LIMIT = 21_000n;

const factoryInterface = new Interface(readJson(FACTORY_ARTIFACT_PATH).abi);
const accountInterface = new Interface(readJson(ACCOUNT_ARTIFACT_PATH).abi);
const abiCoder = AbiCoder.defaultAbiCoder();

function amount(value) {
  const parsed = BigInt(value);
  return Object.freeze({
    wei: parsed.toString(),
    gwei: formatUnits(parsed, "gwei"),
    eth: formatEther(parsed)
  });
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    ).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalDigest(value) {
  return `0x${crypto.createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function pack128(high, low) {
  const highValue = BigInt(high);
  const lowValue = BigInt(low);
  if (highValue < 0n || lowValue < 0n || highValue >= 2n ** 128n || lowValue >= 2n ** 128n) {
    throw new Error("packed_uint128_out_of_range");
  }
  return toBeHex((highValue << 128n) | lowValue, 32);
}

function calculateNoPaymasterRequiredPrefund(input) {
  const verificationGasLimit = BigInt(input.verificationGasLimit);
  const callGasLimit = BigInt(input.callGasLimit);
  const preVerificationGas = BigInt(input.preVerificationGas);
  const maxFeePerGas = BigInt(input.maxFeePerGas);
  const paymasterVerificationGasLimit = BigInt(input.paymasterVerificationGasLimit ?? 0);
  const paymasterPostOpGasLimit = BigInt(input.paymasterPostOpGasLimit ?? 0);
  if (paymasterVerificationGasLimit !== 0n || paymasterPostOpGasLimit !== 0n) {
    throw new Error("o25_paymaster_not_permitted");
  }
  const requiredGas =
    verificationGasLimit
    + callGasLimit
    + preVerificationGas
    + paymasterVerificationGasLimit
    + paymasterPostOpGasLimit;
  return Object.freeze({
    formula:
      "(verificationGasLimit + callGasLimit + paymasterVerificationGasLimit + paymasterPostOpGasLimit + preVerificationGas) * maxFeePerGas",
    verificationGasLimit: verificationGasLimit.toString(),
    callGasLimit: callGasLimit.toString(),
    preVerificationGas: preVerificationGas.toString(),
    paymasterVerificationGasLimit: "0",
    paymasterPostOpGasLimit: "0",
    requiredGas: requiredGas.toString(),
    maxFeePerGasWei: maxFeePerGas.toString(),
    requiredPrefundWei: (requiredGas * maxFeePerGas).toString()
  });
}

function calculateFeeScenarios(input) {
  const baseFee = BigInt(input.baseFeePerGasWei);
  const observedPriority = BigInt(input.maxPriorityFeePerGasWei);
  const rpcSuggestedMaxFee = BigInt(input.maxFeePerGasWei);
  const currentMaxFee = rpcSuggestedMaxFee > baseFee + observedPriority
    ? rpcSuggestedMaxFee
    : baseFee + observedPriority;
  const recommendedMaxFee =
    currentMaxFee * (10_000n + RECOMMENDED_FEE_MARGIN_BASIS_POINTS) / 10_000n;
  const recommendedPriority =
    observedPriority * (10_000n + RECOMMENDED_FEE_MARGIN_BASIS_POINTS) / 10_000n;
  const limits = LOCAL_PROOF_GATED_PREPARATION_LIMITS;
  if (
    recommendedMaxFee > limits.maxFeePerGasWei
    || recommendedPriority > limits.maxPriorityFeePerGasWei
  ) {
    throw new Error("recommended_fee_exceeds_o25_ceiling");
  }
  return Object.freeze({
    current: Object.freeze({
      label: "current_rpc_observation",
      maxFeePerGas: amount(currentMaxFee),
      maxPriorityFeePerGas: amount(observedPriority)
    }),
    recommended: Object.freeze({
      label: "current_rpc_observation_plus_25_percent",
      marginBasisPoints: Number(RECOMMENDED_FEE_MARGIN_BASIS_POINTS),
      maxFeePerGas: amount(recommendedMaxFee),
      maxPriorityFeePerGas: amount(recommendedPriority)
    }),
    rejectionCeiling: Object.freeze({
      label: "absolute_rejection_ceiling_not_a_funding_recommendation",
      maxFeePerGas: amount(limits.maxFeePerGasWei),
      maxPriorityFeePerGas: amount(limits.maxPriorityFeePerGasWei)
    })
  });
}

function buildEstimationOnlyUserOperation(input) {
  const identity = input.identity;
  const addresses = calculateO24Addresses(identity, input.accountSalt);
  const validatorKeyIdBinding = deriveLocalProofGatedValidatorKeyIdBinding(
    identity.validatorKeyId
  );
  const factoryData = factoryInterface.encodeFunctionData("createAccount", [
    identity.validatorAddress,
    identity.ownerCommitment,
    validatorKeyIdBinding,
    BigInt(input.accountSalt)
  ]);
  const expiry = BigInt(input.expiry);
  const callData = accountInterface.encodeFunctionData(
    "executeLocalProofAuthorization",
    [ESTIMATION_ACTION_ID, ESTIMATION_AUTHORIZATION_DIGEST, expiry]
  );
  const limits = LOCAL_PROOF_GATED_PREPARATION_LIMITS;
  const placeholderSignature = `0x${"00".repeat(PLACEHOLDER_SIGNATURE_LENGTH)}`;
  const packed = Object.freeze({
    sender: EXPECTED_ACCOUNT,
    nonce: "0",
    initCode: concat([EXPECTED_FACTORY, factoryData]),
    callData,
    accountGasLimits: pack128(
      limits.maxVerificationGasLimit,
      limits.maxCallGasLimit
    ),
    preVerificationGas: limits.maxPreVerificationGas.toString(),
    gasFees: pack128(input.maxPriorityFeePerGas, input.maxFeePerGas),
    paymasterAndData: "0x",
    signature: placeholderSignature
  });
  const artifact = {
    schemaVersion: "philcore-o25-estimation-only-packed-user-operation-v1",
    phase: "O.25",
    status: "estimation_only",
    securityModel: "local-proof-gated-v1",
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    entryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
    factory: EXPECTED_FACTORY,
    factoryMethod: "createAccount(address,bytes32,bytes32,uint256)",
    factoryData,
    factoryDataHash: keccak256(factoryData),
    sender: EXPECTED_ACCOUNT,
    expectedSender: addresses.account,
    target: EXPECTED_TARGET,
    targetMethod: "confirmPhilCoreAction(bytes32,bytes32)",
    valueWei: "0",
    rpcV07Representation: {
      sender: packed.sender,
      nonce: "0x0",
      factory: EXPECTED_FACTORY,
      factoryData,
      callData,
      verificationGasLimit: toBeHex(limits.maxVerificationGasLimit),
      callGasLimit: toBeHex(limits.maxCallGasLimit),
      preVerificationGas: toBeHex(limits.maxPreVerificationGas),
      maxFeePerGas: toBeHex(input.maxFeePerGas),
      maxPriorityFeePerGas: toBeHex(input.maxPriorityFeePerGas),
      paymaster: null,
      signature: placeholderSignature
    },
    packedUserOperation: packed,
    placeholders: {
      actionId: ESTIMATION_ACTION_ID,
      authorizationDigest: ESTIMATION_AUTHORIZATION_DIGEST,
      expiry: expiry.toString(),
      signatureKind: "fixed_zero_bytes_invalid_for_submission",
      signatureLengthBytes: PLACEHOLDER_SIGNATURE_LENGTH
    },
    estimationOnly: true,
    submissionReady: false,
    proofGenerated: false,
    authorizationGenerated: false,
    userApprovalGenerated: false,
    freshPresenceGenerated: false,
    deviceVaultSignatureGenerated: false,
    userOperationSigned: false,
    userOperationSubmitted: false,
    paymasterEnabled: false,
    tokenMovement: false,
    batchEnabled: false,
    delegatecallEnabled: false,
    publicMutationAuthorized: false,
    publicMutationOccurred: false,
    limitations: [
      "Placeholder fields are not Runtime authority.",
      "The zero-byte signature is deliberately invalid.",
      "A bundler estimate cannot make this artifact submission-ready.",
      "Any field change requires a fresh proof, authorization, approval, presence event, and Device Vault signature."
    ]
  };
  artifact.artifactDigest = canonicalDigest(artifact);
  validateEstimationOnlyUserOperation(artifact);
  return Object.freeze(artifact);
}

function validateEstimationOnlyUserOperation(artifact) {
  const limits = LOCAL_PROOF_GATED_PREPARATION_LIMITS;
  if (artifact.sender !== EXPECTED_ACCOUNT || artifact.expectedSender !== EXPECTED_ACCOUNT) {
    throw new Error("o25_sender_mismatch");
  }
  if (artifact.factory !== EXPECTED_FACTORY || artifact.target !== EXPECTED_TARGET) {
    throw new Error("o25_deployment_binding_mismatch");
  }
  if (artifact.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) throw new Error("o25_chain_mismatch");
  if (artifact.entryPoint !== ERC4337_V07_CANONICAL_ENTRYPOINT) {
    throw new Error("o25_entrypoint_mismatch");
  }
  if (
    artifact.estimationOnly !== true
    || artifact.submissionReady !== false
    || artifact.proofGenerated !== false
    || artifact.authorizationGenerated !== false
    || artifact.deviceVaultSignatureGenerated !== false
    || artifact.userOperationSubmitted !== false
    || artifact.publicMutationOccurred !== false
  ) {
    throw new Error("o25_authority_marker_invalid");
  }
  if (artifact.packedUserOperation.paymasterAndData !== "0x") {
    throw new Error("o25_paymaster_not_permitted");
  }
  if (artifact.packedUserOperation.signature.length !== 2 + PLACEHOLDER_SIGNATURE_LENGTH * 2) {
    throw new Error("o25_placeholder_signature_shape_invalid");
  }
  if (!/^0x0+$/.test(artifact.packedUserOperation.signature)) {
    throw new Error("o25_placeholder_signature_must_be_zero");
  }
  const maxFee = BigInt(artifact.rpcV07Representation.maxFeePerGas);
  const priority = BigInt(artifact.rpcV07Representation.maxPriorityFeePerGas);
  if (maxFee > limits.maxFeePerGasWei || priority > limits.maxPriorityFeePerGasWei) {
    throw new Error("o25_fee_ceiling_exceeded");
  }
  ensureNoSecrets(artifact);
  return true;
}

function buildFundingProposal(input) {
  const value = BigInt(input.valueWei);
  const gasLimit = DIRECT_TRANSFER_GAS_LIMIT;
  const maxFee = BigInt(input.maxFeePerGasWei);
  const maximumGasCost = gasLimit * maxFee;
  const senderBalance = BigInt(input.senderBalanceWei);
  const maximumTotalDebit = value + maximumGasCost;
  if (senderBalance < maximumTotalDebit) throw new Error("account2_balance_insufficient");
  const proposal = {
    schemaVersion: "philcore-o25-account2-funding-proposal-v1",
    phase: "O.25",
    status: "proposed",
    approved: false,
    signed: false,
    broadcast: false,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    transactionType: 2,
    sender: EXPECTED_FUNDING,
    recipient: EXPECTED_ACCOUNT,
    nonce: String(input.nonce),
    value: amount(value),
    calldata: "0x",
    gasLimit: gasLimit.toString(),
    maxFeePerGas: amount(maxFee),
    maxPriorityFeePerGas: amount(input.maxPriorityFeePerGasWei),
    maximumGasCost: amount(maximumGasCost),
    maximumTotalDebit: amount(maximumTotalDebit),
    senderBalanceBefore: amount(senderBalance),
    senderBalanceAfterAtMaximumCost: amount(senderBalance - maximumTotalDebit),
    smartAccountBalanceBefore: amount(input.smartAccountBalanceWei),
    expectedSmartAccountBalanceAfter: amount(
      BigInt(input.smartAccountBalanceWei) + value
    ),
    latestBlockNumber: String(input.latestBlockNumber),
    latestBlockHash: input.latestBlockHash,
    observedAt: input.observedAt,
    expiresAt: input.expiresAt,
    mechanism: "direct_eth_transfer_to_counterfactual_address",
    factoryCall: false,
    entryPointCall: false,
    accountDeployment: false,
    publicMutationAuthorized: false,
    publicMutationOccurred: false,
    stopConditions: [
      "wrong chain, recipient, account prediction, or nonce",
      "target, factory, or EntryPoint deployment binding changed",
      "smart account code, balance, deposit, or EntryPoint nonce changed",
      "transaction value or fee envelope changed",
      "nonempty calldata",
      "stale evidence",
      "bundler remains unapproved or incompatible",
      "first-operation model changed"
    ]
  };
  proposal.proposalDigest = canonicalDigest(proposal);
  validateFundingProposal(proposal, { now: new Date(input.observedAt).getTime() });
  return Object.freeze(proposal);
}

function validateFundingProposal(proposal, options = {}) {
  if (
    proposal.status !== "proposed"
    || proposal.approved !== false
    || proposal.signed !== false
    || proposal.broadcast !== false
  ) {
    throw new Error("o25_funding_authority_marker_invalid");
  }
  if (proposal.chainId !== ETHEREUM_SEPOLIA_CHAIN_ID) throw new Error("o25_wrong_chain");
  if (getAddress(proposal.sender) !== EXPECTED_FUNDING) throw new Error("o25_wrong_funder");
  if (getAddress(proposal.recipient) !== EXPECTED_ACCOUNT) throw new Error("o25_wrong_recipient");
  if (proposal.calldata !== "0x") throw new Error("o25_direct_transfer_calldata_nonempty");
  if (BigInt(proposal.gasLimit) !== DIRECT_TRANSFER_GAS_LIMIT) {
    throw new Error("o25_direct_transfer_gas_changed");
  }
  if (BigInt(proposal.maxFeePerGas.wei) > LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxFeePerGasWei) {
    throw new Error("o25_max_fee_ceiling_exceeded");
  }
  if (
    BigInt(proposal.maxPriorityFeePerGas.wei)
      > LOCAL_PROOF_GATED_PREPARATION_LIMITS.maxPriorityFeePerGasWei
  ) {
    throw new Error("o25_priority_fee_ceiling_exceeded");
  }
  const now = options.now ?? Date.now();
  if (new Date(proposal.expiresAt).getTime() <= now) throw new Error("o25_funding_proposal_expired");
  ensureNoSecrets(proposal);
  return true;
}

function writeJson(location, value) {
  ensureNoSecrets(value);
  fs.writeFileSync(location, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

module.exports = {
  ACCOUNT_ARTIFACT_PATH,
  DIRECT_TRANSFER_GAS_LIMIT,
  EMPTY_BYTES32,
  ESTIMATION_ACTION_ID,
  ESTIMATION_AUTHORIZATION_DIGEST,
  O25_PREFUND_PATH,
  O25_READINESS_PATH,
  O25_USER_OPERATION_PATH,
  PROPOSAL_FRESHNESS_SECONDS,
  amount,
  buildEstimationOnlyUserOperation,
  buildFundingProposal,
  calculateFeeScenarios,
  calculateNoPaymasterRequiredPrefund,
  canonicalDigest,
  pack128,
  validateEstimationOnlyUserOperation,
  validateFundingProposal,
  writeJson
};
