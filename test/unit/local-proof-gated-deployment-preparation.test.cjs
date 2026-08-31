const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { keccak256, toUtf8Bytes } = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  LOCAL_PROOF_GATED_UI_PREPARATION
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedAccount.ts");
const {
  LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_STATUS,
  calculateLocalProofGatedFundingPlan,
  calculateLocalProofGatedProposedAddresses,
  createLocalProofGatedFirstUserOperationProposal,
  createRestrictedSepoliaBundlerClient,
  createRestrictedSepoliaReadOnlyClient,
  evaluateLocalProofGatedMutationGate,
  hashLocalProofGatedConstructorData,
  redactRpcEndpoint,
  runLocalProofGatedPreparationPreflight
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");

const ROOT = path.resolve(__dirname, "../..");
const manifestPath = path.join(
  ROOT,
  "config/ethereum-sepolia/LOCAL_PROOF_GATED_DEPLOYMENT_MANIFEST_PROPOSED.json"
);
const accountArtifact = require(
  "../../artifacts/contracts/base/erc4337/PhilCore4337LocalProofAccountV1.sol/PhilCore4337LocalProofAccountV1.json"
);
const H = (label) => keccak256(toUtf8Bytes(label));
const DEPLOYER = "0x1000000000000000000000000000000000000001";
const OWNER = "0x2000000000000000000000000000000000000002";

function addressInputs(overrides = {}) {
  return {
    deployerAddress: DEPLOYER,
    deployerNonce: "4",
    ownerAddress: OWNER,
    ownerCommitment: H("owner-commitment"),
    validatorKeyId: H("validator-key"),
    accountSalt: "7",
    accountCreationBytecode: accountArtifact.bytecode,
    ...overrides
  };
}

function userOperationInputs(addresses, overrides = {}) {
  return {
    sender: addresses.accountAddress,
    factoryAddress: addresses.factoryAddress,
    ownerAddress: OWNER,
    ownerCommitment: H("owner-commitment"),
    validatorKeyId: H("validator-key"),
    accountSalt: "7",
    actionId: H("action"),
    authorizationDigest: H("authorization"),
    expiry: "1700000300",
    nonce: "0",
    verificationGasLimit: "900000",
    callGasLimit: "150000",
    preVerificationGas: "100000",
    maxFeePerGas: "30000000000",
    maxPriorityFeePerGas: "1000000000",
    nowSeconds: 1700000000,
    ...overrides
  };
}

describe("O.19 local-proof-gated deployment preparation", function () {
  it("records scoped architecture approval while keeping the manifest proposed and non-production", function () {
    const manifest = JSON.parse(fs.readFileSync(manifestPath));
    assert.equal(
      manifest.approval.architectureApprovalStatus,
      LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_STATUS
    );
    assert.equal(manifest.approval.architecturePreparationApproved, true);
    assert.equal(manifest.status, "proposed");
    assert.equal(manifest.approval.acp0002Status, "Proposed");
    assert.equal(manifest.approval.deploymentApproved, false);
    assert.equal(manifest.approval.productionApproved, false);
    assert.equal(manifest.security.starkVerifiedOnchain, false);
    assert.equal(LOCAL_PROOF_GATED_UI_PREPARATION.status, "Preparing");
    assert.equal(LOCAL_PROOF_GATED_UI_PREPARATION.mutationControlsEnabled, false);
    assert.equal(LOCAL_PROOF_GATED_UI_PREPARATION.connected, false);
    assert.equal(LOCAL_PROOF_GATED_UI_PREPARATION.deployed, false);
    assert.match(LOCAL_PROOF_GATED_UI_PREPARATION.securityNote, /not independently verify/);
  });

  it("redacts endpoint credentials, usernames, paths, and query parameters", function () {
    const redacted = redactRpcEndpoint(
      "https://user:secret@rpc.example.test/private/key?apiKey=top-secret"
    );
    assert.equal(redacted, "https://rpc.example.test/<redacted>");
    assert.doesNotMatch(redacted, /user|secret|apiKey|private|top-secret/);
  });

  it("requires chain verification first and rejects the wrong chain before other reads", async function () {
    const calls = [];
    const wrong = createRestrictedSepoliaReadOnlyClient({
      url: "https://rpc.example.test/key",
      transport: {
        async request(method) {
          calls.push(method);
          return "0x1";
        }
      }
    });
    await assert.rejects(() => wrong.request("eth_getCode", [ERC4337_V07_CANONICAL_ENTRYPOINT]));
    await assert.rejects(() => wrong.request("eth_chainId", []), /WRONG_ETHEREUM_CHAIN/);
    assert.deepEqual(calls, ["eth_chainId"]);
    assert.equal(wrong.mutationMethodsExposed, false);
    await assert.rejects(
      () => wrong.request("eth_sendRawTransaction", ["0x"]),
      /RPC_METHOD_NOT_ALLOWED/
    );
  });

  it("performs read-only EntryPoint and empty-address checks without mutation methods", async function () {
    const addresses = calculateLocalProofGatedProposedAddresses(addressInputs());
    const calls = [];
    const client = createRestrictedSepoliaReadOnlyClient({
      url: "https://rpc.example.test/key",
      transport: {
        async request(method, params) {
          calls.push(method);
          if (method === "eth_chainId") return "0xaa36a7";
          if (method === "eth_blockNumber") return "0x123";
          if (method === "eth_getCode") {
            return String(params[0]).toLowerCase()
              === ERC4337_V07_CANONICAL_ENTRYPOINT.toLowerCase()
              ? "0x6001600055"
              : "0x";
          }
          if (method === "eth_getBalance") return "0x0";
          if (method === "eth_call") return `0x${"0".repeat(64)}`;
          if (method === "eth_gasPrice") return "0x3b9aca00";
          throw new Error(`unexpected ${method}`);
        }
      }
    });
    const result = await runLocalProofGatedPreparationPreflight({
      client,
      proposedAddresses: {
        target: addresses.targetAddress,
        factory: addresses.factoryAddress,
        account: addresses.accountAddress
      },
      checkedAt: "2026-07-25T00:00:00.000Z"
    });
    assert.equal(result.status, "READ_ONLY_PREFLIGHT_PASSED", result.errors.join(", "));
    assert.equal(result.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(result.entryPoint.codePresent, true);
    assert.equal(result.entryPoint.getNonceCallSupported, true);
    assert.equal(result.deployer, undefined);
    assert.ok(Object.values(result.proposedAddresses).every((value) => value.codeStatus === "empty"));
    assert.equal(result.mutationMethodsExposed, false);
    assert.equal(result.publicMutationOccurred, false);
    assert.ok(!calls.includes("eth_sendRawTransaction"));
  });

  it("records latest and pending deployer nonces independently", async function () {
    const client = createRestrictedSepoliaReadOnlyClient({
      url: "https://rpc.example.test/key",
      transport: {
        async request(method, params) {
          if (method === "eth_chainId") return "0xaa36a7";
          if (method === "eth_blockNumber") return "0x123";
          if (method === "eth_getCode") {
            return String(params[0]).toLowerCase()
              === ERC4337_V07_CANONICAL_ENTRYPOINT.toLowerCase()
              ? "0x6001600055"
              : "0x";
          }
          if (method === "eth_getBalance") return "0x0";
          if (method === "eth_call") return `0x${"0".repeat(64)}`;
          if (method === "eth_gasPrice") return "0x3b9aca00";
          if (method === "eth_getTransactionCount") {
            return params[1] === "latest" ? "0x25" : "0x26";
          }
          throw new Error(`unexpected ${method}`);
        }
      }
    });
    const result = await runLocalProofGatedPreparationPreflight({
      client,
      deployer: {
        address: DEPLOYER,
        configuredPendingNonce: "38"
      }
    });
    assert.equal(result.status, "READ_ONLY_PREFLIGHT_PASSED", result.errors.join(", "));
    assert.equal(result.deployer.observedLatestNonce, "37");
    assert.equal(result.deployer.observedPendingNonce, "38");
    assert.equal(result.deployer.nonceMatched, true);
  });

  it("fails on missing EntryPoint code and proposed-address collisions", async function () {
    const client = createRestrictedSepoliaReadOnlyClient({
      url: "https://rpc.example.test",
      transport: {
        async request(method) {
          if (method === "eth_chainId") return "0xaa36a7";
          if (method === "eth_blockNumber") return "0x1";
          if (method === "eth_getCode") return "0x6000";
          if (method === "eth_getBalance") return "0x0";
          if (method === "eth_call") return "0x";
          if (method === "eth_gasPrice") return "0x1";
          throw new Error("unexpected");
        }
      }
    });
    const result = await runLocalProofGatedPreparationPreflight({
      client,
      proposedAddresses: { target: DEPLOYER }
    });
    assert.equal(result.status, "READ_ONLY_PREFLIGHT_FAILED");
    assert.ok(result.errors.includes("target_address_collision"));
  });

  it("calculates target, factory, and CREATE2 account addresses reproducibly", function () {
    const first = calculateLocalProofGatedProposedAddresses(addressInputs());
    const second = calculateLocalProofGatedProposedAddresses(addressInputs());
    assert.equal(first.status, "calculated");
    assert.deepEqual(first, second);
    assert.notEqual(first.targetAddress, first.factoryAddress);
    assert.notEqual(first.factoryAddress, first.accountAddress);
    assert.equal(first.targetDeploymentNonce, "4");
    assert.equal(first.factoryDeploymentNonce, "5");
  });

  it("hashes constructor data deterministically and changes on constructor substitution", function () {
    const first = hashLocalProofGatedConstructorData({
      types: ["address", "uint256"],
      values: [DEPLOYER, ETHEREUM_SEPOLIA_CHAIN_ID]
    });
    const second = hashLocalProofGatedConstructorData({
      types: ["address", "uint256"],
      values: [DEPLOYER, 1]
    });
    assert.notEqual(first, second);
  });

  it("calculates bounded funding with a conservative buffer and rejects an undersized maximum", function () {
    const estimates = {
      source: "live_read_only_rpc",
      targetDeploymentGas: "100000",
      factoryDeploymentGas: "500000",
      counterfactualAccountVerificationGas: "700000",
      firstUserOperationCallGas: "150000",
      firstUserOperationPreVerificationGas: "100000",
      gasPriceWei: "1000000000",
      maxFeePerGasWei: "2000000000",
      maxPriorityFeePerGasWei: "1000000000",
      bundlerEstimateStatus: "configured_read_only"
    };
    const valid = calculateLocalProofGatedFundingPlan({
      estimates,
      bufferBasisPoints: 2500,
      hardMaximumExposureWei: "4000000000000000"
    });
    assert.equal(valid.status, "calculated");
    assert.equal(valid.totalMinimumWei, "3100000000000000");
    assert.equal(valid.conservativeRecommendedWei, "3875000000000000");
    assert.equal(valid.entryPointDepositRequired, false);
    const invalid = calculateLocalProofGatedFundingPlan({
      estimates,
      hardMaximumExposureWei: "1"
    });
    assert.equal(invalid.status, "invalid");
  });

  it("exposes only preparation-compatible bundler methods", async function () {
    const methods = [];
    const client = createRestrictedSepoliaBundlerClient({
      url: "https://bundler.example.test/private",
      transport: {
        async request(method) {
          methods.push(method);
          return [ERC4337_V07_CANONICAL_ENTRYPOINT];
        }
      }
    });
    assert.deepEqual(await client.request("eth_supportedEntryPoints", []), [
      ERC4337_V07_CANONICAL_ENTRYPOINT
    ]);
    await assert.rejects(
      () => client.request("eth_sendUserOperation", []),
      /BUNDLER_METHOD_NOT_ALLOWED/
    );
    assert.deepEqual(methods, ["eth_supportedEntryPoints"]);
    assert.equal(client.mutationMethodsExposed, false);
  });

  it("creates an unsigned, zero-value, token-free, paymaster-free first UserOperation", function () {
    const addresses = calculateLocalProofGatedProposedAddresses(addressInputs());
    const proposal = createLocalProofGatedFirstUserOperationProposal(
      userOperationInputs(addresses)
    );
    assert.equal(proposal.status, "proposed_unsigned");
    assert.equal(proposal.userOperation.sender, addresses.accountAddress);
    assert.equal(proposal.userOperation.signature, "0x");
    assert.equal(proposal.userOperation.paymasterAndData, "0x");
    assert.equal(proposal.valueWei, "0");
    assert.equal(proposal.tokenMovement, false);
    assert.equal(proposal.batchEnabled, false);
    assert.equal(proposal.delegatecallEnabled, false);
    assert.equal(proposal.publicMutationAuthorized, false);
    assert.equal(proposal.publicMutationOccurred, false);
    assert.match(proposal.userOperation.initCode, new RegExp(`^${addresses.factoryAddress}`, "i"));
  });

  it("rejects gas, fee, and expiry values outside the reviewed first-operation envelope", function () {
    const addresses = calculateLocalProofGatedProposedAddresses(addressInputs());
    assert.throws(
      () => createLocalProofGatedFirstUserOperationProposal(
        userOperationInputs(addresses, { callGasLimit: "300001" })
      ),
      /call_gas_cap_exceeded/
    );
    assert.throws(
      () => createLocalProofGatedFirstUserOperationProposal(
        userOperationInputs(addresses, { maxFeePerGas: "100000000001" })
      ),
      /max_fee_cap_exceeded/
    );
    assert.throws(
      () => createLocalProofGatedFirstUserOperationProposal(
        userOperationInputs(addresses, { expiry: "1700000601" })
      ),
      /authorization_lifetime_exceeded/
    );
  });

  it("requires a distinct stage gate and never lets one approval authorize all mutations", function () {
    const common = {
      PHILCORE_PUBLIC_NETWORK_APPROVED: "1",
      PHILCORE_ETHEREUM_SEPOLIA_APPROVED: "1",
      PHILCORE_LOCAL_PROOF_ACCOUNT_MODEL_APPROVED: "1",
      PHILCORE_SEPOLIA_TARGET_DEPLOYMENT_APPROVED: "1"
    };
    const target = evaluateLocalProofGatedMutationGate({
      stage: "target_deployment",
      environment: common,
      manifestStatus: "accepted",
      architectureApprovalStatus: LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_STATUS,
      repositoryClean: true
    });
    assert.equal(target.allowed, true);
    for (const stage of [
      "factory_deployment",
      "account_funding",
      "first_user_operation_submission"
    ]) {
      const result = evaluateLocalProofGatedMutationGate({
        stage,
        environment: common,
        manifestStatus: "accepted",
        architectureApprovalStatus: LOCAL_PROOF_GATED_ARCHITECTURE_APPROVAL_STATUS,
        repositoryClean: true
      });
      assert.equal(result.allowed, false, stage);
    }
  });

  it("keeps every mutation command transport-free and bound to its stage-specific gate", function () {
    const stages = [
      ["deploy-confirmation-target", "PHILCORE_SEPOLIA_TARGET_DEPLOYMENT_APPROVED_missing"],
      ["deploy-account-factory", "PHILCORE_SEPOLIA_ACCOUNT_DEPLOYMENT_APPROVED_missing"],
      ["fund-local-proof-account", "PHILCORE_SEPOLIA_FUNDING_APPROVED_missing"],
      ["submit-first-userop", "PHILCORE_SEPOLIA_USEROP_SUBMISSION_APPROVED_missing"]
    ];
    for (const [stage, expectedError] of stages) {
      const result = spawnSync(
        process.execPath,
        ["scripts/ethereum-sepolia/run-local-proof-account.cjs", "--stage", stage],
        { cwd: ROOT, encoding: "utf8", env: {} }
      );
      assert.equal(result.status, 2, `${stage}: ${result.stderr}`);
      const output = JSON.parse(result.stdout);
      assert.equal(output.allowed, false);
      assert.equal(output.transportImplemented, false);
      assert.equal(output.publicMutationPerformed, false);
      assert.ok(output.errors.includes(expectedError), `${stage}: ${output.errors.join(", ")}`);
    }
    const standalone = spawnSync(
      process.execPath,
      ["scripts/ethereum-sepolia/run-local-proof-account.cjs", "--stage", "deploy-account-implementation"],
      { cwd: ROOT, encoding: "utf8", env: {} }
    );
    assert.equal(standalone.status, 2);
    assert.deepEqual(
      JSON.parse(standalone.stdout).errors,
      ["standalone_account_implementation_deployment_not_supported"]
    );
  });

  it("records sanitized read-only O.20 evidence while keeping mutation disabled", function () {
    const evidence = fs.readFileSync(path.join(
      ROOT,
      "config/ethereum-sepolia/LOCAL_PROOF_GATED_PREPARATION_EVIDENCE.json"
    ), "utf8");
    const parsed = JSON.parse(evidence);
    assert.equal(parsed.phase, "O.20");
    assert.equal(parsed.readOnlyPreflight.status, "READ_ONLY_PREFLIGHT_PASSED");
    assert.equal(parsed.readOnlyPreflight.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(parsed.readOnlyPreflight.deployer.nonceMatched, true);
    assert.equal(parsed.canonicalIdentityBinding.sameCanonicalRecord, true);
    assert.equal(parsed.bundler.status, "BUNDLER_ESTIMATE_NOT_CONFIGURED");
    assert.equal(parsed.firstUserOperation.status, "inputs_required");
    assert.equal(parsed.deploymentManifestAccepted, false);
    assert.equal(parsed.mutationAttempted, false);
    assert.equal(parsed.publicMutationOccurred, false);
    assert.match(parsed.readOnlyPreflight.rpcClassification, /<redacted>$/);
    assert.doesNotMatch(evidence, /api[_-]?key|private[_-]?key|mnemonic|phil_secret/i);
  });
});
