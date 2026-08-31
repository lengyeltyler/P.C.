"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const { ethers } = require("ethers");
const common = require("./phil-sepolia-mint-public-common.cjs");

common.assertLegacyAlphaRunnerRetired();

let receiptPath = common.DEFAULT_RECEIPT_PATH;
let evidence;

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) common.fail(`PHIL_SEPOLIA_MINT_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

function persist() {
  if (evidence) common.atomicWriteJson(receiptPath, evidence);
}

function sourceIdentityMatches(source) {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: common.ROOT, encoding: "utf8" }).trim();
  const tree = execFileSync("git", ["rev-parse", "HEAD^{tree}"], { cwd: common.ROOT, encoding: "utf8" }).trim();
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: common.ROOT, encoding: "utf8" })
    .trim().split("\n").filter(Boolean);
  const protectedHash = crypto.createHash("sha256").update(fs.readFileSync(`${common.ROOT}/pqREADME.md`)).digest("hex");
  return commit === source.commit && tree === source.tree
    && status.length === 1 && status[0] === "?? pqREADME.md"
    && protectedHash === source.protectedUntrackedFileSha256;
}

async function signedTransaction(wallet, transaction, expectedHash) {
  const raw = await wallet.signTransaction(transaction);
  if (ethers.keccak256(raw).toLowerCase() !== expectedHash.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_TRANSACTION_HASH_CHANGED");
  }
  return raw;
}

async function waitForUserOperationReceipt(bundler, userOperationHash, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const result = await bundler.send("eth_getUserOperationReceipt", [userOperationHash]);
    if (result) return result;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  common.fail("PHIL_SEPOLIA_MINT_USER_OPERATION_RECEIPT_AMBIGUOUS");
}

function parsedEvents(logs, interfaceValue, name) {
  return logs.flatMap((log) => {
    try {
      const parsed = interfaceValue.parseLog(log);
      return parsed?.name === name ? [parsed] : [];
    } catch {
      return [];
    }
  });
}

function sameAddress(left, right) {
  return ethers.getAddress(left) === ethers.getAddress(right);
}

function assertExactPlanBindings(plan, config, parsed) {
  if (plan.chainId !== String(common.CHAIN_ID)
    || plan.entryPoint.toLowerCase() !== common.ENTRY_POINT
    || !sameAddress(plan.deployer, config.deployer)
    || plan.startingNonce !== config.startingNonce
    || JSON.stringify(plan.infrastructure) !== JSON.stringify(config.infrastructure)
    || BigInt(plan.feePolicy.maxFeePerGas) !== BigInt(config.gasPolicy.maxFeePerGas)
    || BigInt(plan.feePolicy.maxPriorityFeePerGas) !== BigInt(config.gasPolicy.maxPriorityFeePerGas)
    || !Array.isArray(plan.deployments) || plan.deployments.length !== 3
    || !Array.isArray(plan.mutations) || plan.mutations.length !== 5) {
    common.fail("PHIL_SEPOLIA_MINT_PLAN_CONFIGURATION_BINDING_INVALID");
  }
  const labels = ["factory", "actionGate", "mintConsumer"];
  for (let index = 0; index < labels.length; index += 1) {
    const deployment = plan.deployments[index];
    const mutation = plan.mutations[index];
    if (deployment.label !== labels[index]
      || deployment.nonce !== String(Number(config.startingNonce) + index)
      || !sameAddress(deployment.expectedContractAddress, config.infrastructure[labels[index]])
      || mutation.order !== index + 1 || mutation.kind !== "contract_deployment"
      || mutation.transactionHash.toLowerCase() !== deployment.transactionHash.toLowerCase()
      || !sameAddress(mutation.target, deployment.expectedContractAddress)) {
      common.fail("PHIL_SEPOLIA_MINT_DEPLOYMENT_SEQUENCE_INVALID");
    }
  }
  const fundingMutation = plan.mutations[3];
  const operationMutation = plan.mutations[4];
  if (plan.funding.nonce !== String(Number(config.startingNonce) + 3)
    || !sameAddress(plan.funding.recipient, parsed.recipient)
    || BigInt(plan.funding.valueWei) !== parsed.maximumTotalFeeWei
    || fundingMutation.order !== 4 || fundingMutation.kind !== "exact_sepolia_prefund"
    || fundingMutation.transactionHash.toLowerCase() !== plan.funding.transactionHash.toLowerCase()
    || !sameAddress(fundingMutation.target, parsed.recipient)
    || BigInt(fundingMutation.valueWei) !== parsed.maximumTotalFeeWei
    || operationMutation.order !== 5 || operationMutation.kind !== "single_signed_user_operation"
    || operationMutation.userOperationHash.toLowerCase() !== parsed.localUserOperationHash.toLowerCase()
    || !sameAddress(operationMutation.target, parsed.recipient)) {
    common.fail("PHIL_SEPOLIA_MINT_MUTATION_SEQUENCE_INVALID");
  }
  const maximumTransactionFees = plan.deployments.reduce(
    (total, deployment) => total + BigInt(deployment.gasLimit) * BigInt(plan.feePolicy.maxFeePerGas),
    BigInt(plan.funding.gasLimit) * BigInt(plan.feePolicy.maxFeePerGas)
  );
  if (BigInt(plan.maximumPublicCostWei) !== maximumTransactionFees + parsed.maximumTotalFeeWei) {
    common.fail("PHIL_SEPOLIA_MINT_MAXIMUM_PUBLIC_COST_INVALID");
  }
}

async function main() {
  const planPath = argument("--plan", common.DEFAULT_PLAN_PATH);
  const signedArtifactPath = argument("--signed-artifact");
  const approvedDigest = argument("--plan-digest");
  receiptPath = argument("--receipt-output", common.DEFAULT_RECEIPT_PATH);
  if (!signedArtifactPath) common.fail("PHIL_SEPOLIA_MINT_SIGNED_ARTIFACT_PATH_REQUIRED");
  if (!approvedDigest) common.fail("PHIL_SEPOLIA_MINT_EXPLICIT_PLAN_DIGEST_REQUIRED");
  const approvalPhrase = common.required("PHILCORE_SEPOLIA_MINT_PUBLIC_MUTATION_APPROVAL");
  if (approvalPhrase !== common.APPROVAL_PHRASE) common.fail("PHIL_SEPOLIA_MINT_EXPLICIT_APPROVAL_REQUIRED");
  const rpcUrl = common.required("PHILCORE_SEPOLIA_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_SEPOLIA_BUNDLER_URL");
  const privateKey = common.required("PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY");
  const plan = common.readJson(planPath);
  const { planDigest, ...body } = plan;
  if (plan?.format !== "phil-sepolia-mint-public-mutation-plan-v1"
    || plan.status !== "EXACT_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || plan.publicMutationOccurred !== false || plan.approval?.approved !== false
    || plan.automaticRetryAllowed !== false
    || common.canonicalDigest(body).toLowerCase() !== planDigest.toLowerCase()
    || planDigest.toLowerCase() !== approvedDigest.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_PLAN_OR_APPROVAL_DIGEST_INVALID");
  }
  common.assertEndpointBindings(plan.endpointBindings, rpcUrl, bundlerUrl);
  if (!sourceIdentityMatches(plan.source)) common.fail("PHIL_SEPOLIA_MINT_SOURCE_IDENTITY_CHANGED");
  const signedBytes = fs.readFileSync(signedArtifactPath);
  if (crypto.createHash("sha256").update(signedBytes).digest("hex") !== plan.userOperation.signedArtifactSha256) {
    common.fail("PHIL_SEPOLIA_MINT_SIGNED_ARTIFACT_CHANGED");
  }
  const config = common.readJson(common.CONFIG_PATH);
  const preflight = common.readJson(common.PREFLIGHT_PATH);
  const compiled = common.artifacts();
  const signed = JSON.parse(signedBytes);
  const parsed = common.parseSignedArtifact(signed, config, compiled);
  if (parsed.localUserOperationHash.toLowerCase() !== plan.userOperation.hash.toLowerCase()
    || parsed.validUntil.toString() !== plan.userOperation.validUntil
    || parsed.validUntil <= BigInt(Math.floor(Date.now() / 1000)) + 180n) {
    common.fail("PHIL_SEPOLIA_MINT_SIGNED_OPERATION_NO_LONGER_VALID");
  }
  assertExactPlanBindings(plan, config, parsed);
  const provider = new ethers.JsonRpcProvider(rpcUrl, common.CHAIN_ID, { staticNetwork: true });
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, { staticNetwork: true });
  const wallet = new ethers.Wallet(privateKey, provider);
  if (wallet.address.toLowerCase() !== plan.deployer.toLowerCase()) common.fail("PHIL_SEPOLIA_MINT_DEPLOYER_KEY_MISMATCH");
  const network = await provider.getNetwork();
  if (Number(network.chainId) !== common.CHAIN_ID) common.fail("PHIL_SEPOLIA_MINT_WRONG_CHAIN");
  const entryPointCode = await provider.getCode(common.ENTRY_POINT);
  if (entryPointCode === "0x" || ethers.keccak256(entryPointCode) !== preflight.entryPoint.codeHash) {
    common.fail("PHIL_SEPOLIA_MINT_ENTRYPOINT_CHANGED");
  }
  const supported = await bundler.send("eth_supportedEntryPoints", []);
  if (!Array.isArray(supported) || !supported.some((value) => value.toLowerCase() === common.ENTRY_POINT)) {
    common.fail("PHIL_SEPOLIA_MINT_BUNDLER_ENTRYPOINT_UNSUPPORTED");
  }
  const liveFee = await provider.getFeeData();
  if ((liveFee.maxFeePerGas && liveFee.maxFeePerGas > BigInt(plan.feePolicy.maxFeePerGas))
    || (liveFee.maxPriorityFeePerGas
      && liveFee.maxPriorityFeePerGas > BigInt(plan.feePolicy.maxPriorityFeePerGas))) {
    common.fail("PHIL_SEPOLIA_MINT_FEE_CAP_STALE");
  }
  const latestNonce = await provider.getTransactionCount(plan.deployer, "latest");
  const pendingNonce = await provider.getTransactionCount(plan.deployer, "pending");
  if (latestNonce !== Number(plan.startingNonce) || pendingNonce !== latestNonce) {
    common.fail("PHIL_SEPOLIA_MINT_DEPLOYER_NONCE_CHANGED");
  }
  for (const address of Object.values(plan.infrastructure)) {
    if (await provider.getCode(address) !== "0x") common.fail("PHIL_SEPOLIA_MINT_INFRASTRUCTURE_ADDRESS_OCCUPIED");
  }
  if (await provider.getCode(parsed.recipient) !== "0x" || await provider.getBalance(parsed.recipient) !== 0n) {
    common.fail("PHIL_SEPOLIA_MINT_COUNTERFACTUAL_ACCOUNT_STATE_CHANGED");
  }
  const regenerated = await common.deploymentTransactions(config, compiled, provider);
  const fee = {
    chainId: common.CHAIN_ID,
    type: 2,
    maxFeePerGas: BigInt(plan.feePolicy.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(plan.feePolicy.maxPriorityFeePerGas)
  };
  const rawDeployments = [];
  for (let index = 0; index < plan.deployments.length; index += 1) {
    const expected = plan.deployments[index];
    const current = regenerated[index];
    if (current.label !== expected.label || current.data !== expected.data
      || current.expectedContractAddress.toLowerCase() !== expected.expectedContractAddress.toLowerCase()
      || BigInt(current.gasEstimate) > BigInt(expected.gasLimit)) {
      common.fail("PHIL_SEPOLIA_MINT_DEPLOYMENT_PLAN_CHANGED");
    }
    rawDeployments.push(await signedTransaction(wallet, {
      ...fee, nonce: Number(expected.nonce), gasLimit: BigInt(expected.gasLimit),
      data: expected.data, value: 0n
    }, expected.transactionHash));
  }
  const funding = plan.funding;
  if (funding.recipient.toLowerCase() !== parsed.recipient.toLowerCase()
    || BigInt(funding.valueWei) !== parsed.maximumTotalFeeWei) common.fail("PHIL_SEPOLIA_MINT_FUNDING_PLAN_INVALID");
  const currentFundingGas = await provider.estimateGas({
    from: plan.deployer,
    to: funding.recipient,
    nonce: Number(funding.nonce),
    value: BigInt(funding.valueWei)
  });
  if (currentFundingGas > BigInt(funding.gasLimit)) common.fail("PHIL_SEPOLIA_MINT_FUNDING_GAS_LIMIT_STALE");
  const rawFunding = await signedTransaction(wallet, {
    ...fee, nonce: Number(funding.nonce), to: funding.recipient,
    gasLimit: BigInt(funding.gasLimit), value: BigInt(funding.valueWei), data: "0x"
  }, funding.transactionHash);
  const deployerBalance = await provider.getBalance(plan.deployer);
  if (deployerBalance < BigInt(plan.maximumPublicCostWei)) common.fail("PHIL_SEPOLIA_MINT_DEPLOYER_BALANCE_CHANGED");

  // No public mutation is reachable above this line. This record is persisted
  // immediately before broadcasting the first exact, pre-signed transaction.
  evidence = {
    format: "phil-sepolia-mint-public-mutation-receipt-v1",
    version: 1,
    status: "APPROVAL_VERIFIED_EXECUTION_STARTING",
    generatedAt: new Date().toISOString(),
    planDigest,
    source: plan.source,
    chainId: String(common.CHAIN_ID),
    rpc: common.sanitizedEndpoint(rpcUrl),
    bundler: common.sanitizedEndpoint(bundlerUrl),
    approval: { phraseMatched: true, planDigestMatched: true, verifiedAt: new Date().toISOString() },
    deploymentReceipts: [],
    fundingReceipt: null,
    userOperationReceipt: null,
    publicMutationOccurred: false,
    automaticRetryOccurred: false
  };
  persist();

  for (let index = 0; index < rawDeployments.length; index += 1) {
    const expected = plan.deployments[index];
    evidence.status = `DEPLOYMENT_${index + 1}_BROADCAST`;
    evidence.publicMutationOccurred = true;
    evidence.deploymentReceipts.push({ label: expected.label, transactionHash: expected.transactionHash, status: "broadcast" });
    persist();
    const response = await provider.broadcastTransaction(rawDeployments[index]);
    if (response.hash.toLowerCase() !== expected.transactionHash.toLowerCase()) common.fail("PHIL_SEPOLIA_MINT_DEPLOYMENT_HASH_MISMATCH");
    const receipt = await response.wait(1, 180_000);
    if (!receipt || receipt.status !== 1 || receipt.contractAddress?.toLowerCase() !== expected.expectedContractAddress.toLowerCase()) {
      common.fail("PHIL_SEPOLIA_MINT_DEPLOYMENT_RECEIPT_INVALID");
    }
    evidence.deploymentReceipts[index] = {
      label: expected.label, transactionHash: receipt.hash, blockNumber: String(receipt.blockNumber),
      contractAddress: receipt.contractAddress, gasUsed: receipt.gasUsed.toString(), status: "confirmed"
    };
    persist();
  }
  evidence.status = "FUNDING_BROADCAST";
  evidence.fundingReceipt = { transactionHash: funding.transactionHash, status: "broadcast", recipient: funding.recipient, valueWei: funding.valueWei };
  persist();
  const fundingResponse = await provider.broadcastTransaction(rawFunding);
  if (fundingResponse.hash.toLowerCase() !== funding.transactionHash.toLowerCase()) common.fail("PHIL_SEPOLIA_MINT_FUNDING_HASH_MISMATCH");
  const fundingReceipt = await fundingResponse.wait(1, 180_000);
  if (!fundingReceipt || fundingReceipt.status !== 1) common.fail("PHIL_SEPOLIA_MINT_FUNDING_RECEIPT_INVALID");
  if (await provider.getBalance(parsed.recipient) !== BigInt(funding.valueWei)) common.fail("PHIL_SEPOLIA_MINT_FUNDING_BALANCE_INVALID");
  evidence.fundingReceipt = {
    transactionHash: fundingReceipt.hash, blockNumber: String(fundingReceipt.blockNumber),
    recipient: funding.recipient, valueWei: funding.valueWei, gasUsed: fundingReceipt.gasUsed.toString(), status: "confirmed"
  };
  persist();

  const estimate = await bundler.send("eth_estimateUserOperationGas", [parsed.rpc, common.ENTRY_POINT]);
  for (const [field, limit] of [
    ["verificationGasLimit", parsed.rpc.verificationGasLimit],
    ["callGasLimit", parsed.rpc.callGasLimit],
    ["preVerificationGas", parsed.rpc.preVerificationGas]
  ]) {
    if (!estimate?.[field] || BigInt(estimate[field]) > BigInt(limit)) common.fail("PHIL_SEPOLIA_MINT_BUNDLER_ESTIMATE_EXCEEDS_SIGNED_LIMIT");
  }
  evidence.status = "USER_OPERATION_SUBMISSION_REQUESTED";
  evidence.userOperationReceipt = { userOperationHash: parsed.localUserOperationHash, status: "submission_requested", gasEstimate: estimate };
  persist();
  const returnedHash = await bundler.send("eth_sendUserOperation", [parsed.rpc, common.ENTRY_POINT]);
  if (returnedHash.toLowerCase() !== parsed.localUserOperationHash.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_BUNDLER_RETURNED_HASH_MISMATCH");
  }
  evidence.userOperationReceipt.status = "accepted_by_bundler";
  persist();
  const bundlerReceipt = await waitForUserOperationReceipt(bundler, parsed.localUserOperationHash, 180_000);
  if (bundlerReceipt.success !== true || !bundlerReceipt.receipt?.transactionHash) {
    common.fail("PHIL_SEPOLIA_MINT_USER_OPERATION_FAILED");
  }
  const transactionReceipt = await provider.getTransactionReceipt(bundlerReceipt.receipt.transactionHash);
  if (!transactionReceipt || transactionReceipt.status !== 1) common.fail("PHIL_SEPOLIA_MINT_TRANSACTION_RECEIPT_INVALID");
  const entryPointInterface = new ethers.Interface([
    "event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)"
  ]);
  const userEvents = parsedEvents(transactionReceipt.logs, entryPointInterface, "UserOperationEvent")
    .filter((event) => event.args.userOpHash.toLowerCase() === parsed.localUserOperationHash.toLowerCase());
  const gateEvents = parsedEvents(transactionReceipt.logs, common.gateInterface, "PhilSepoliaLocalComposedAuthorizationConsumed");
  const passEvents = parsedEvents(transactionReceipt.logs, common.consumerInterface, "PhilSepoliaMintPassIssued");
  if (userEvents.length !== 1 || userEvents[0].args.success !== true
    || gateEvents.length !== 1 || passEvents.length !== 1) common.fail("PHIL_SEPOLIA_MINT_EVENT_VERIFICATION_FAILED");
  const tokenId = gateEvents[0].args.tokenId;
  if (tokenId !== passEvents[0].args.tokenId
    || gateEvents[0].args.authorizationEnvelopeDigest.toLowerCase() !== signed.authorizationEnvelopeDigest.toLowerCase()
    || gateEvents[0].args.rootProofNullifier.toLowerCase() !== signed.rootProofNullifier.toLowerCase()
    || gateEvents[0].args.deviceApprovalNonce.toLowerCase() !== signed.deviceApprovalNonce.toLowerCase()
    || gateEvents[0].args.account.toLowerCase() !== parsed.recipient.toLowerCase()
    || gateEvents[0].args.recipient.toLowerCase() !== parsed.recipient.toLowerCase()
    || passEvents[0].args.recipient.toLowerCase() !== parsed.recipient.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_EVENT_BINDING_FAILED");
  }
  const factory = new ethers.Contract(plan.infrastructure.factory, common.factoryInterface, provider);
  const gate = new ethers.Contract(plan.infrastructure.actionGate, common.gateInterface, provider);
  const consumer = new ethers.Contract(plan.infrastructure.mintConsumer, common.consumerInterface, provider);
  const state = {
    factoryRegistered: await factory.isPhilSepoliaMintAccount(parsed.recipient),
    envelopeConsumed: await gate.consumedEnvelopeDigest(signed.authorizationEnvelopeDigest),
    nullifierConsumed: await gate.consumedRootNullifier(signed.rootProofNullifier),
    approvalNonceConsumed: await gate.consumedDeviceApprovalNonce(signed.deviceApprovalNonce),
    tokenIdByEnvelope: (await consumer.tokenIdByEnvelopeDigest(signed.authorizationEnvelopeDigest)).toString(),
    tokenIdByNullifier: (await consumer.tokenIdByRootNullifier(signed.rootProofNullifier)).toString(),
    tokenOwner: await consumer.ownerOf(tokenId),
    accountCodeHash: ethers.keccak256(await provider.getCode(parsed.recipient))
  };
  if (!state.factoryRegistered || !state.envelopeConsumed || !state.nullifierConsumed
    || !state.approvalNonceConsumed || state.tokenIdByEnvelope !== tokenId.toString()
    || state.tokenIdByNullifier !== tokenId.toString()
    || state.tokenOwner.toLowerCase() !== parsed.recipient.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_ONCHAIN_STATE_VERIFICATION_FAILED");
  }
  evidence.status = "END_TO_END_SEPOLIA_MINT_CONFIRMED";
  evidence.completedAt = new Date().toISOString();
  evidence.userOperationReceipt = {
    userOperationHash: parsed.localUserOperationHash,
    transactionHash: transactionReceipt.hash,
    blockNumber: String(transactionReceipt.blockNumber),
    success: true,
    tokenId: tokenId.toString(),
    actualGasCost: userEvents[0].args.actualGasCost.toString(),
    actualGasUsed: userEvents[0].args.actualGasUsed.toString(),
    state
  };
  persist();
  process.stdout.write(`${JSON.stringify({ status: evidence.status, planDigest, receiptPath, userOperationReceipt: evidence.userOperationReceipt }, null, 2)}\n`);
}

main().catch((error) => {
  if (evidence) {
    evidence.status = "STOPPED_REQUIRES_READ_ONLY_RECONCILIATION";
    evidence.stoppedAt = new Date().toISOString();
    evidence.failureCode = error?.code || error?.message || "PHIL_SEPOLIA_MINT_EXECUTION_FAILED";
    evidence.automaticRetryOccurred = false;
    persist();
  }
  process.stderr.write(`${error?.code || error?.message || "PHIL_SEPOLIA_MINT_EXECUTION_FAILED"}\n`);
  process.exitCode = 1;
});
