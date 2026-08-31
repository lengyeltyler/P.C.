"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { ethers } = require("ethers");

const ROOT = path.resolve(__dirname, "../..");
const CHAIN_ID = 11155111;
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const LEGACY_ALPHA_FUNDING_SOURCE = "0x549A5C770085b00B60F6D729DB99f8Bffb72eE12";
const RECOVERY_DELAY_SECONDS = 172800n;
const RECOVERY_EXPIRY_SECONDS = 604800n;
const P1_MUTATION_COUNT = 4;
const P1_RECOVERY_MUTATION_COUNT = 3;
const PROTECTED_FILE = "pqREADME.md";
const PROTECTED_FILE_SHA256 = "7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8";
const DEFAULT_PLAN_PATH = path.join(
  ROOT,
  "artifacts/philcore-controlled-sepolia-beta/p1-plan.json"
);
const DEFAULT_RECEIPT_PATH = path.join(
  ROOT,
  "artifacts/philcore-controlled-sepolia-beta/p1-receipt.json"
);
const DEFAULT_RECOVERY_PLAN_PATH = path.join(
  ROOT,
  "artifacts/philcore-controlled-sepolia-beta/p1-recovery-plan.json"
);
const DEFAULT_RECOVERY_RECEIPT_PATH = path.join(
  ROOT,
  "artifacts/philcore-controlled-sepolia-beta/p1-recovery-receipt.json"
);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function required(name) {
  const value = process.env[name];
  if (!value) fail(`${name}_REQUIRED`);
  return value;
}

function readJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

function atomicWriteJson(location, value) {
  fs.mkdirSync(path.dirname(location), { recursive: true, mode: 0o700 });
  const temporary = `${location}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx"
  });
  fs.renameSync(temporary, location);
  fs.chmodSync(location, 0o600);
}

function atomicCreateJson(location, value) {
  fs.mkdirSync(path.dirname(location), { recursive: true, mode: 0o700 });
  const temporary = `${location}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      mode: 0o600,
      flag: "wx"
    });
    fs.linkSync(temporary, location);
    fs.chmodSync(location, 0o600);
  } finally {
    try {
      fs.unlinkSync(temporary);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, stable(nested)])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function canonicalSha256(value) {
  return `0x${crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

function sha256Bytes(value) {
  return `0x${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function endpointDigest(value) {
  new URL(value);
  return sha256Bytes(Buffer.from(value, "utf8"));
}

function sanitizedEndpoint(value) {
  const parsed = new URL(value);
  return `${parsed.protocol}//${parsed.hostname}/<redacted>`;
}

function sourceIdentity() {
  const commit = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();
  const tree = execFileSync("git", ["rev-parse", "HEAD^{tree}"], {
    cwd: ROOT,
    encoding: "utf8"
  }).trim();
  const lines = execFileSync(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=all"],
    { cwd: ROOT, encoding: "utf8" }
  ).trim().split("\n").filter(Boolean);
  const unexpected = lines.filter((line) => line !== `?? ${PROTECTED_FILE}`);
  if (unexpected.length > 0 || lines.filter((line) => line === `?? ${PROTECTED_FILE}`).length > 1) {
    fail("PHILCORE_CONTROLLED_BETA_SOURCE_NOT_FROZEN");
  }
  let protectedUntrackedFile = null;
  let protectedUntrackedFileSha256 = null;
  const protectedPath = path.join(ROOT, PROTECTED_FILE);
  if (fs.existsSync(protectedPath)) {
    protectedUntrackedFile = PROTECTED_FILE;
    protectedUntrackedFileSha256 = crypto.createHash("sha256")
      .update(fs.readFileSync(protectedPath)).digest("hex");
    if (protectedUntrackedFileSha256 !== PROTECTED_FILE_SHA256) {
      fail("PHILCORE_CONTROLLED_BETA_PROTECTED_FILE_CHANGED");
    }
  }
  return { commit, tree, protectedUntrackedFile, protectedUntrackedFileSha256 };
}

function sourceIdentityMatches(source) {
  const current = sourceIdentity();
  return canonicalJson(current) === canonicalJson(source);
}

function artifact(relative) {
  const value = readJson(path.join(ROOT, "artifacts", relative));
  if (!value?.abi || !/^0x[0-9a-f]+$/iu.test(value.bytecode || "")) {
    fail("PHILCORE_CONTROLLED_BETA_ARTIFACT_INVALID");
  }
  return value;
}

function artifacts() {
  return {
    consumer: artifact(
      "contracts/base/PhilSepoliaMintPassConsumerV1.sol/PhilSepoliaMintPassConsumerV1.json"
    ),
    gate: artifact(
      "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol/PhilSepoliaLocalComposedActionGateV1.json"
    ),
    factory: artifact(
      "contracts/base/erc4337/PhilCore4337AccountFactory.sol/PhilCore4337AccountFactory.json"
    ),
    account: artifact(
      "contracts/base/erc4337/PhilCore4337Account.sol/PhilCore4337Account.json"
    )
  };
}

function compilerIdentity() {
  const debugFiles = [
    "contracts/base/PhilSepoliaMintPassConsumerV1.sol/PhilSepoliaMintPassConsumerV1.dbg.json",
    "contracts/base/PhilSepoliaLocalComposedActionGateV1.sol/PhilSepoliaLocalComposedActionGateV1.dbg.json",
    "contracts/base/erc4337/PhilCore4337AccountFactory.sol/PhilCore4337AccountFactory.dbg.json",
    "contracts/base/erc4337/PhilCore4337Account.sol/PhilCore4337Account.dbg.json"
  ];
  const buildInfoPaths = debugFiles.map((relative) => {
    const debugPath = path.join(ROOT, "artifacts", relative);
    const debug = readJson(debugPath);
    return path.resolve(path.dirname(debugPath), debug.buildInfo);
  });
  if (new Set(buildInfoPaths).size !== 1) fail("PHILCORE_CONTROLLED_BETA_BUILD_INFO_AMBIGUOUS");
  const buildInfoPath = buildInfoPaths[0];
  const bytes = fs.readFileSync(buildInfoPath);
  const buildInfo = JSON.parse(bytes);
  if (!buildInfo.solcVersion || !buildInfo.solcLongVersion || !buildInfo.input?.settings) {
    fail("PHILCORE_CONTROLLED_BETA_BUILD_INFO_INVALID");
  }
  return {
    solcVersion: buildInfo.solcVersion,
    solcLongVersion: buildInfo.solcLongVersion,
    compilerSettingsSha256: canonicalSha256(buildInfo.input.settings),
    buildInfoSha256: sha256Bytes(bytes)
  };
}

function normalizePublicMetadata(value) {
  if (value?.format !== "philcore-controlled-sepolia-beta-public-credential-metadata-v1"
    || value.network?.chainId !== CHAIN_ID
    || value.addresses?.allFiveDistinct !== true
    || value.publicNetworkMutation !== false) {
    fail("PHILCORE_CONTROLLED_BETA_PUBLIC_METADATA_INVALID");
  }
  const addresses = Object.fromEntries(
    Object.entries(value.addresses)
      .filter(([key]) => key !== "allFiveDistinct")
      .map(([key, address]) => [key, ethers.getAddress(address)])
  );
  const distinct = new Set(Object.values(addresses).map((address) => address.toLowerCase()));
  if (distinct.size !== 5) fail("PHILCORE_CONTROLLED_BETA_AUTHORITY_ADDRESSES_NOT_DISTINCT");
  const ownerCommitment = value.ownerCommitment?.toLowerCase();
  const accountSalt = value.account?.salt?.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/u.test(ownerCommitment || "") || /^0x0{64}$/u.test(ownerCommitment)
    || !/^0x[0-9a-f]{64}$/u.test(accountSalt || "")) {
    fail("PHILCORE_CONTROLLED_BETA_ACCOUNT_BINDING_INVALID");
  }
  return {
    addresses,
    ownerCommitment,
    accountSalt,
    keychainServices: value.keychainServices || {},
    recordedPredictions: value.predictedContracts || {},
    recordedAccount: value.account || {}
  };
}

function deploymentGraph(input) {
  const compiled = input.compiled;
  const deployer = ethers.getAddress(input.deployer);
  const startingNonce = Number(input.startingNonce);
  if (!Number.isSafeInteger(startingNonce) || startingNonce < 0) {
    fail("PHILCORE_CONTROLLED_BETA_DEPLOYER_NONCE_INVALID");
  }
  const consumer = ethers.getCreateAddress({ from: deployer, nonce: startingNonce });
  const gate = ethers.getCreateAddress({ from: deployer, nonce: startingNonce + 1 });
  const factory = ethers.getCreateAddress({ from: deployer, nonce: startingNonce + 2 });
  const recoveryAuthority = ethers.getAddress(input.recoveryAuthority);
  const executionOwner = ethers.getAddress(input.executionOwner);
  const accountConstructor = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "address", "bytes32", "address", "address", "uint64", "uint64"],
    [
      ENTRY_POINT,
      executionOwner,
      input.ownerCommitment,
      gate,
      recoveryAuthority,
      RECOVERY_DELAY_SECONDS,
      RECOVERY_EXPIRY_SECONDS
    ]
  );
  const account = ethers.getCreate2Address(
    factory,
    ethers.zeroPadValue(ethers.toBeHex(BigInt(input.accountSalt)), 32),
    ethers.keccak256(ethers.concat([compiled.account.bytecode, accountConstructor]))
  );
  return { consumer, gate, factory, account };
}

async function deploymentDescriptors(input) {
  const { compiled, graph, deployer, startingNonce, provider } = input;
  const rows = [
    {
      label: "PhilSepoliaMintPassConsumerV1",
      artifact: compiled.consumer,
      address: graph.consumer,
      nonce: startingNonce,
      args: [graph.gate]
    },
    {
      label: "PhilSepoliaLocalComposedActionGateV1",
      artifact: compiled.gate,
      address: graph.gate,
      nonce: startingNonce + 1,
      args: [CHAIN_ID, graph.factory, graph.consumer, graph.account]
    },
    {
      label: "PhilCore4337AccountFactory",
      artifact: compiled.factory,
      address: graph.factory,
      nonce: startingNonce + 2,
      args: [
        ENTRY_POINT,
        graph.gate,
        input.recoveryAuthority,
        RECOVERY_DELAY_SECONDS,
        RECOVERY_EXPIRY_SECONDS
      ]
    }
  ];
  const result = [];
  for (const row of rows) {
    const factory = new ethers.ContractFactory(row.artifact.abi, row.artifact.bytecode);
    const data = (await factory.getDeployTransaction(...row.args)).data;
    const gasEstimate = await provider.estimateGas({ from: deployer, nonce: row.nonce, data });
    const gasLimit = gasEstimate * 125n / 100n;
    const runtimeCode = await provider.call({ from: deployer, nonce: row.nonce, data });
    if (!/^0x[0-9a-f]+$/iu.test(runtimeCode || "") || runtimeCode === "0x") {
      fail("PHILCORE_CONTROLLED_BETA_RUNTIME_SIMULATION_FAILED");
    }
    result.push({
      label: row.label,
      nonce: String(row.nonce),
      expectedContractAddress: ethers.getAddress(row.address),
      constructorArguments: row.args.map((value) => typeof value === "bigint" ? value.toString() : value),
      creationCodeHash: ethers.keccak256(row.artifact.bytecode),
      deploymentDataHash: ethers.keccak256(data),
      expectedRuntimeCodeHash: ethers.keccak256(runtimeCode),
      gasEstimate: gasEstimate.toString(),
      gasLimit: gasLimit.toString(),
      data
    });
  }
  return result;
}

function approvalPhrase(stageId, planDigest) {
  if (!/^(?:P[1-5]|P1R|P2R|P2A|P2F)$/u.test(stageId)
    || !/^0x[0-9a-f]{64}$/u.test(planDigest)) {
    fail("PHILCORE_CONTROLLED_BETA_APPROVAL_INPUT_INVALID");
  }
  return `I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_${stageId}_${planDigest.slice(2).toUpperCase()}`;
}

async function signedDeploymentTransactions(plan, deployerWallet) {
  const base = transactionBase(plan);
  const result = [];
  for (const deployment of plan.deployments) {
    const raw = await deployerWallet.signTransaction({
      ...base,
      nonce: Number(deployment.nonce),
      value: 0n,
      gasLimit: BigInt(deployment.gasLimit),
      data: deployment.data
    });
    const hash = ethers.keccak256(raw);
    if (deployment.transactionHash && hash.toLowerCase() !== deployment.transactionHash.toLowerCase()) {
      fail("PHILCORE_CONTROLLED_BETA_SIGNED_TRANSACTION_CHANGED");
    }
    result.push({ label: `DEPLOY_${deployment.label}`, hash, raw });
  }
  return result;
}

function keychainSecret(service) {
  if (typeof service !== "string" || service.length < 1 || service.length > 200) {
    fail("PHILCORE_CONTROLLED_BETA_KEYCHAIN_SERVICE_INVALID");
  }
  try {
    return execFileSync("security", ["find-generic-password", "-s", service, "-w"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    fail("PHILCORE_CONTROLLED_BETA_KEYCHAIN_SECRET_UNAVAILABLE");
  }
}

function walletFromKeychain(service, expectedAddress) {
  const wallet = new ethers.Wallet(keychainSecret(service));
  if (wallet.address.toLowerCase() !== ethers.getAddress(expectedAddress).toLowerCase()) {
    fail("PHILCORE_CONTROLLED_BETA_KEYCHAIN_ADDRESS_MISMATCH");
  }
  return wallet;
}

function assertEndpointBindings(bindings, primary, reconciliation, bundler) {
  const expected = {
    primaryRpcUrlSha256: endpointDigest(primary),
    reconciliationRpcUrlSha256: endpointDigest(reconciliation),
    bundlerUrlSha256: endpointDigest(bundler)
  };
  if (canonicalJson(bindings) !== canonicalJson(expected)) {
    fail("PHILCORE_CONTROLLED_BETA_ENDPOINT_BINDING_MISMATCH");
  }
  return expected;
}

function transactionBase(plan) {
  return {
    chainId: CHAIN_ID,
    type: 2,
    maxFeePerGas: BigInt(plan.feePolicy.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(plan.feePolicy.maxPriorityFeePerGas)
  };
}

async function signedP1Transactions(plan, fundingWallet, deployerWallet) {
  const base = transactionBase(plan);
  const rows = [
    {
      label: "FUND_BETA_DEPLOYER_FROM_LEGACY_ALPHA_SOURCE",
      wallet: fundingWallet,
      transaction: {
        ...base,
        nonce: Number(plan.funding.nonce),
        to: plan.funding.recipient,
        value: BigInt(plan.funding.valueWei),
        gasLimit: BigInt(plan.funding.gasLimit),
        data: "0x"
      },
      expectedHash: plan.funding.transactionHash
    },
    ...plan.deployments.map((deployment) => ({
      label: `DEPLOY_${deployment.label}`,
      wallet: deployerWallet,
      transaction: {
        ...base,
        nonce: Number(deployment.nonce),
        value: 0n,
        gasLimit: BigInt(deployment.gasLimit),
        data: deployment.data
      },
      expectedHash: deployment.transactionHash
    }))
  ];
  const result = [];
  for (const row of rows) {
    const raw = await row.wallet.signTransaction(row.transaction);
    const hash = ethers.keccak256(raw);
    if (row.expectedHash && hash.toLowerCase() !== row.expectedHash.toLowerCase()) {
      fail("PHILCORE_CONTROLLED_BETA_SIGNED_TRANSACTION_CHANGED");
    }
    result.push({ label: row.label, hash, raw });
  }
  return result;
}

module.exports = {
  ROOT,
  CHAIN_ID,
  ENTRY_POINT,
  LEGACY_ALPHA_FUNDING_SOURCE,
  RECOVERY_DELAY_SECONDS,
  RECOVERY_EXPIRY_SECONDS,
  P1_MUTATION_COUNT,
  P1_RECOVERY_MUTATION_COUNT,
  PROTECTED_FILE_SHA256,
  DEFAULT_PLAN_PATH,
  DEFAULT_RECEIPT_PATH,
  DEFAULT_RECOVERY_PLAN_PATH,
  DEFAULT_RECOVERY_RECEIPT_PATH,
  fail,
  required,
  readJson,
  atomicWriteJson,
  atomicCreateJson,
  canonicalJson,
  canonicalSha256,
  endpointDigest,
  sanitizedEndpoint,
  sourceIdentity,
  sourceIdentityMatches,
  artifacts,
  compilerIdentity,
  normalizePublicMetadata,
  deploymentGraph,
  deploymentDescriptors,
  approvalPhrase,
  walletFromKeychain,
  assertEndpointBindings,
  signedP1Transactions,
  signedDeploymentTransactions
};
