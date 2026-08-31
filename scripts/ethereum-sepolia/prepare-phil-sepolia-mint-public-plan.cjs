"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const { ethers } = require("ethers");
const common = require("./phil-sepolia-mint-public-common.cjs");

common.assertLegacyAlphaRunnerRetired();

function argument(name, fallback) {
  const index = process.argv.indexOf(name);
  if (index < 0) return fallback;
  if (!process.argv[index + 1]) common.fail(`PHIL_SEPOLIA_MINT_ARGUMENT_${name.slice(2).toUpperCase()}_REQUIRED`);
  return process.argv[index + 1];
}

function sourceIdentity() {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: common.ROOT, encoding: "utf8" }).trim();
  const tree = execFileSync("git", ["rev-parse", "HEAD^{tree}"], { cwd: common.ROOT, encoding: "utf8" }).trim();
  const status = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: common.ROOT, encoding: "utf8" })
    .trim().split("\n").filter(Boolean);
  const allowed = status.filter((line) => line === "?? pqREADME.md");
  const unexpected = status.filter((line) => line !== "?? pqREADME.md");
  if (unexpected.length > 0 || allowed.length !== 1) common.fail("PHIL_SEPOLIA_MINT_SOURCE_NOT_FROZEN");
  const protectedHash = crypto.createHash("sha256")
    .update(fs.readFileSync(`${common.ROOT}/pqREADME.md`)).digest("hex");
  if (protectedHash !== "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8") {
    common.fail("PHIL_SEPOLIA_MINT_PROTECTED_FILE_CHANGED");
  }
  return { commit, tree, protectedUntrackedFile: "pqREADME.md", protectedUntrackedFileSha256: protectedHash };
}

async function transactionHash(wallet, transaction) {
  return ethers.keccak256(await wallet.signTransaction(transaction));
}

async function main() {
  const signedArtifactPath = argument("--signed-artifact");
  if (!signedArtifactPath) common.fail("PHIL_SEPOLIA_MINT_SIGNED_ARTIFACT_PATH_REQUIRED");
  const outputPath = argument("--output", common.DEFAULT_PLAN_PATH);
  const rpcUrl = common.required("PHILCORE_SEPOLIA_RPC_URL");
  const bundlerUrl = common.required("PHILCORE_SEPOLIA_BUNDLER_URL");
  const privateKey = common.required("PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY");
  const provider = new ethers.JsonRpcProvider(rpcUrl, common.CHAIN_ID, { staticNetwork: true });
  const bundler = new ethers.JsonRpcProvider(bundlerUrl, common.CHAIN_ID, { staticNetwork: true });
  const wallet = new ethers.Wallet(privateKey);
  const config = common.readJson(common.CONFIG_PATH);
  const preflight = common.readJson(common.PREFLIGHT_PATH);
  const compiled = common.artifacts();
  const signed = common.readJson(signedArtifactPath);
  if (config?.format !== "phil-sepolia-mint-demo-configuration-v1"
    || config.chainId !== String(common.CHAIN_ID)
    || config.entryPoint.toLowerCase() !== common.ENTRY_POINT
    || config.publicMutationEnabled !== false || config.submissionEnabled !== false
    || preflight?.status !== "READ_ONLY_PREFLIGHT_PASSED_PUBLIC_MUTATION_NOT_AUTHORIZED"
    || preflight.publicMutationOccurred !== false) common.fail("PHIL_SEPOLIA_MINT_CONFIGURATION_INVALID");
  if (wallet.address.toLowerCase() !== config.deployer.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_DEPLOYER_KEY_MISMATCH");
  }
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
  const latestNonce = await provider.getTransactionCount(config.deployer, "latest");
  const pendingNonce = await provider.getTransactionCount(config.deployer, "pending");
  if (latestNonce !== Number(config.startingNonce) || pendingNonce !== latestNonce) {
    common.fail("PHIL_SEPOLIA_MINT_DEPLOYER_NONCE_CHANGED");
  }
  for (const address of Object.values(config.infrastructure)) {
    if (await provider.getCode(address) !== "0x") common.fail("PHIL_SEPOLIA_MINT_INFRASTRUCTURE_ADDRESS_OCCUPIED");
  }
  const parsed = common.parseSignedArtifact(signed, config, compiled);
  const now = BigInt(Math.floor(Date.now() / 1000));
  if (parsed.validUntil <= now + 300n) common.fail("PHIL_SEPOLIA_MINT_AUTHORIZATION_TOO_CLOSE_TO_EXPIRY");
  const entryPoint = new ethers.Contract(common.ENTRY_POINT, [
    "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)) view returns (bytes32)"
  ], provider);
  const chainHash = await entryPoint.getUserOpHash(signed.userOperation);
  if (chainHash.toLowerCase() !== parsed.localUserOperationHash.toLowerCase()) {
    common.fail("PHIL_SEPOLIA_MINT_ENTRYPOINT_HASH_MISMATCH");
  }
  const feeData = await provider.getFeeData();
  const maxFeePerGas = BigInt(config.gasPolicy.maxFeePerGas);
  const maxPriorityFeePerGas = BigInt(config.gasPolicy.maxPriorityFeePerGas);
  if ((feeData.maxFeePerGas && feeData.maxFeePerGas > maxFeePerGas)
    || (feeData.maxPriorityFeePerGas && feeData.maxPriorityFeePerGas > maxPriorityFeePerGas)) {
    common.fail("PHIL_SEPOLIA_MINT_FEE_CAP_STALE");
  }
  const deployments = await common.deploymentTransactions(config, compiled, provider);
  const transactionBase = { chainId: common.CHAIN_ID, type: 2, maxFeePerGas, maxPriorityFeePerGas };
  for (const deployment of deployments) {
    deployment.transactionHash = await transactionHash(wallet, {
      ...transactionBase,
      nonce: Number(deployment.nonce),
      gasLimit: BigInt(deployment.gasLimit),
      data: deployment.data,
      value: 0n
    });
  }
  const fundingNonce = Number(config.startingNonce) + 3;
  const fundingValue = parsed.maximumTotalFeeWei;
  const fundingGasEstimate = await provider.estimateGas({
    from: config.deployer, to: parsed.recipient, nonce: fundingNonce, value: fundingValue
  });
  const fundingGasLimit = fundingGasEstimate * 125n / 100n;
  const fundingTransaction = {
    nonce: String(fundingNonce),
    recipient: parsed.recipient,
    valueWei: fundingValue.toString(),
    gasEstimate: fundingGasEstimate.toString(),
    gasLimit: fundingGasLimit.toString(),
    transactionHash: await transactionHash(wallet, {
      ...transactionBase, nonce: fundingNonce, to: parsed.recipient,
      value: fundingValue, gasLimit: fundingGasLimit, data: "0x"
    })
  };
  const maximumTransactionFees = deployments.reduce(
    (total, item) => total + BigInt(item.gasLimit) * maxFeePerGas,
    fundingGasLimit * maxFeePerGas
  );
  const deployerBalance = await provider.getBalance(config.deployer);
  if (deployerBalance < maximumTransactionFees + fundingValue) {
    common.fail("PHIL_SEPOLIA_MINT_DEPLOYER_BALANCE_INSUFFICIENT");
  }
  const body = {
    format: "phil-sepolia-mint-public-mutation-plan-v1",
    version: 1,
    status: "EXACT_PLAN_READY_PUBLIC_MUTATION_NOT_AUTHORIZED",
    generatedAt: new Date().toISOString(),
    source: sourceIdentity(),
    chainId: String(common.CHAIN_ID),
    rpc: common.sanitizedEndpoint(rpcUrl),
    bundler: common.sanitizedEndpoint(bundlerUrl),
    endpointBindings: {
      rpcUrlSha256: common.endpointDigest(rpcUrl),
      bundlerUrlSha256: common.endpointDigest(bundlerUrl)
    },
    entryPoint: common.ENTRY_POINT,
    deployer: ethers.getAddress(config.deployer),
    startingNonce: config.startingNonce,
    feePolicy: { maxFeePerGas: maxFeePerGas.toString(), maxPriorityFeePerGas: maxPriorityFeePerGas.toString() },
    infrastructure: config.infrastructure,
    deployments,
    funding: fundingTransaction,
    userOperation: {
      hash: parsed.localUserOperationHash,
      sender: parsed.recipient,
      validUntil: parsed.validUntil.toString(),
      maximumTotalFeeWei: parsed.maximumTotalFeeWei.toString(),
      authorizationEnvelopeDigest: signed.authorizationEnvelopeDigest,
      rootProofNullifier: signed.rootProofNullifier,
      deviceApprovalNonce: signed.deviceApprovalNonce,
      rpcV07: parsed.rpc,
      signedArtifactSha256: crypto.createHash("sha256").update(fs.readFileSync(signedArtifactPath)).digest("hex")
    },
    maximumPublicCostWei: (maximumTransactionFees + fundingValue).toString(),
    mutations: [
      { order: 1, kind: "contract_deployment", transactionHash: deployments[0].transactionHash, target: deployments[0].expectedContractAddress },
      { order: 2, kind: "contract_deployment", transactionHash: deployments[1].transactionHash, target: deployments[1].expectedContractAddress },
      { order: 3, kind: "contract_deployment", transactionHash: deployments[2].transactionHash, target: deployments[2].expectedContractAddress },
      { order: 4, kind: "exact_sepolia_prefund", transactionHash: fundingTransaction.transactionHash, target: fundingTransaction.recipient, valueWei: fundingTransaction.valueWei },
      { order: 5, kind: "single_signed_user_operation", userOperationHash: parsed.localUserOperationHash, target: parsed.recipient }
    ],
    approval: { requiredPhrase: common.APPROVAL_PHRASE, approved: false },
    publicMutationOccurred: false,
    automaticRetryAllowed: false
  };
  const plan = { ...body, planDigest: common.canonicalDigest(body) };
  common.atomicWriteJson(outputPath, plan);
  process.stdout.write(`${JSON.stringify({ status: plan.status, planDigest: plan.planDigest, outputPath, mutations: plan.mutations, publicMutationOccurred: false }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error?.code || error?.message || "PHIL_SEPOLIA_MINT_PUBLIC_PLAN_FAILED"}\n`);
  process.exitCode = 1;
});
