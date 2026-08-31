require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { Interface } = require("ethers");

const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");

const ROOT = path.resolve(__dirname, "../..");
const proposalPath = path.join(
  ROOT,
  "config/ethereum-sepolia/O21_3_FIRST_SEPOLIA_EXECUTION_PROPOSAL.json"
);
const manifestPath = path.join(
  ROOT,
  "config/ethereum-sepolia/LOCAL_PROOF_GATED_DEPLOYMENT_MANIFEST_PROPOSED.json"
);

function loadJson(location) {
  return JSON.parse(fs.readFileSync(location, "utf8"));
}

describe("O.21.3 final Ethereum submission boundary review", function () {
  it("defines the exact bounded first-operation shape from actual ABIs", function () {
    const proposal = loadJson(proposalPath);
    const operation = proposal.operation;
    const factory = new Interface([
      "function createAccount(address owner,bytes32 ownerCommitment,bytes32 validatorKeyId,uint256 salt)"
    ]);
    const account = new Interface([
      "function executeLocalProofAuthorization(bytes32 actionId,bytes32 authorizationDigest,uint64 expiry)"
    ]);
    const target = new Interface([
      "function confirmPhilCoreAction(bytes32 actionId,bytes32 authorizationDigest)"
    ]);

    assert.equal(operation.chainId, ETHEREUM_SEPOLIA_CHAIN_ID);
    assert.equal(operation.entryPointAddress, ERC4337_V07_CANONICAL_ENTRYPOINT);
    assert.equal(
      operation.factoryMethodSelector,
      factory.getFunction("createAccount").selector
    );
    assert.equal(
      operation.accountMethodSelector,
      account.getFunction("executeLocalProofAuthorization").selector
    );
    assert.equal(
      operation.targetMethodSelector,
      target.getFunction("confirmPhilCoreAction").selector
    );
    assert.equal(operation.accountMode, "counterfactual_create2");
    assert.equal(operation.valueWei, "0");
    assert.equal(operation.paymasterEnabled, false);
    assert.equal(operation.tokenMovement, false);
    assert.equal(operation.ethereumVerifiedProof, false);
  });

  it("keeps every address proposed and consistent with the deployment manifest", function () {
    const proposal = loadJson(proposalPath);
    const manifest = loadJson(manifestPath);

    assert.equal(proposal.operation.sender, manifest.proposedAddresses.firstAccount);
    assert.equal(proposal.operation.factory, manifest.proposedAddresses.factory);
    assert.equal(proposal.operation.target, manifest.proposedAddresses.target);
    assert.match(proposal.operation.senderClassification, /^proposed_/);
    assert.match(proposal.operation.factoryClassification, /^proposed_/);
    assert.match(proposal.operation.targetClassification, /^proposed_/);
    assert.equal(manifest.status, "proposed");
    assert.equal(manifest.approval.acceptedAddressesPresent, false);
  });

  it("records no deployment, funding, bundler, or submission authority", function () {
    const proposal = loadJson(proposalPath);
    assert.equal(proposal.status, "review_complete_submission_blocked");
    assert.ok(Object.values(proposal.humanApprovals).every((value) => value === false));
    assert.ok(Object.values(proposal.mutationState).every((value) => value === false));
    assert.equal(proposal.productionApproved, false);
    assert.equal(proposal.baseSepoliaApproved, false);
    assert.equal(proposal.acp0002Status, "Proposed");
    assert.ok(proposal.currentBlockers.includes("no O.21 submission adapter is implemented"));
  });

  it("keeps renderer and preload free of signing and submission transports", function () {
    const host = fs.readFileSync(path.join(
      ROOT,
      "apps/philcore-desktop/src/main/runtime-host.cjs"
    ), "utf8");
    const preload = fs.readFileSync(path.join(
      ROOT,
      "apps/philcore-desktop/src/preload/preload.cjs"
    ), "utf8");

    assert.ok(host.includes("finalizeSepoliaSignedArtifact"));
    assert.equal(host.includes("requestSepoliaUserOperationSubmission"), false);
    assert.equal(preload.includes("submitSepolia"), false);
    assert.equal(preload.includes("eth_sendUserOperation"), false);
    assert.equal(preload.includes("eth_sendRawTransaction"), false);
  });

  it("contains no secret material or false public-mutation claim", function () {
    const source = fs.readFileSync(proposalPath, "utf8");
    assert.doesNotMatch(
      source,
      /privateKey|private_key|phil_secret|nullifierSeed|mnemonic|seedPhrase|vaultKey/i
    );
    const proposal = JSON.parse(source);
    assert.equal(proposal.mutationState.publicMutationOccurred, false);
    assert.equal(proposal.mutationState.ethMoved, false);
    assert.equal(proposal.mutationState.userOperationSubmitted, false);
  });
});
