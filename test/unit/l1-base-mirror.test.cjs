const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");
const { ethers } = hre;

const { deployContract, expectRevert } = require("../helpers/context.cjs");
const {
  BASE_MESSENGER_NETWORK_CONFIG,
  CANONICAL_BASE_CROSS_DOMAIN_MESSENGER
} = require("../../config/base-messenger-config.cjs");
const {
  runLocalBaseMirrorDeployment
} = require("../../scripts/base/run-local-base-mirror-deployment.cjs");
const {
  buildBaseMirrorDeploymentReceipt
} = require("../../scripts/base/record-base-mirror-deployment-receipt.cjs");
const {
  buildBaseMirrorDeploymentVerification
} = require("../../scripts/base/record-base-mirror-deployment-verification.cjs");
const {
  buildBaseMirrorDeploymentBundle
} = require("../../scripts/base/package-base-mirror-deployment.cjs");
const {
  buildBaseMirrorDeploymentSummary
} = require("../../scripts/base/export-base-mirror-deployment-summary.cjs");
const {
  buildBaseMirrorDeploymentConsumption
} = require("../../scripts/base/consume-base-mirror-deployment-summary.cjs");

const RELAY_OUTPUT_PATH = path.join(
  __dirname,
  "../../proving/out/starknet_l1_relay/harness_output.json"
);
const SUMMARY_PATH = path.join(
  __dirname,
  "../../proving/out/cairo_air_adapter_spike/summary.json"
);
const LOCAL_MANIFEST_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_manifest/local_regression_manifest.json"
);
const LOCAL_RUNNER_OUTPUT_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_runner/local_regression_runner_output.json"
);
const LOCAL_RECEIPT_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_receipt/local_regression_receipt.json"
);
const LOCAL_VERIFY_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_verify/local_regression_verification.json"
);
const LOCAL_PACKAGE_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_package/local_regression_bundle.json"
);
const LOCAL_EXPORT_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_export/local_regression_summary.json"
);
const LOCAL_CONSUME_PATH = path.join(
  __dirname,
  "../../proving/out/base_deploy_consume/local_regression_consumption.json"
);

function loadJson(jsonPath) {
  return JSON.parse(fs.readFileSync(jsonPath, "utf8"));
}

function asBigInt(value) {
  return BigInt(value);
}

function proofBlobForFact(factHigh, factLow) {
  return ethers.AbiCoder.defaultAbiCoder().encode(["uint256", "uint256"], [factHigh, factLow]);
}

describe("PhilBaseActionGate via production-shape mirrored Base fact state", function () {
  it("routes the canonical L1 fact through a production-shape messenger interface and uses mirrored Base-local state in the authorization path", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer] = await ethers.getSigners();

    const messaging = await deployContract(deployer, "MockStarknetMessaging");
    const trustAnchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
      await messaging.getAddress(),
      asBigInt(relayOutput.contract_address)
    ]);

    const factHigh = asBigInt(relayOutput.relayed_fact_high);
    const factLow = asBigInt(relayOutput.relayed_fact_low);
    await (
      await messaging.registerMessageFromL2(
        asBigInt(relayOutput.contract_address),
        await trustAnchor.getAddress(),
        [factHigh, factLow]
      )
    ).wait();
    await (await trustAnchor.consumeProofInputHashFactFromL2(factHigh, factLow)).wait();

    const {
      output: runnerOutput,
      baseCrossDomainMessenger,
      crossDomainMessengerAdapter,
      baseMirror,
      deploymentPlan,
      deploymentManifest
    } = await runLocalBaseMirrorDeployment({
      signer: deployer,
      networkName: "hardhat",
      outputPath: LOCAL_RUNNER_OUTPUT_PATH
    });
    const l1Messenger = await deployContract(deployer, "PhilL1ToBaseProofInputHashMessenger", [
      await trustAnchor.getAddress(),
      await crossDomainMessengerAdapter.getAddress()
    ]);

    await (await l1Messenger.relayProofInputHashFactToBase(await baseMirror.getAddress(), factHigh, factLow)).wait();

    const expectedMirrorMessage = baseMirror.interface.encodeFunctionData("mirrorProofInputHashFact", [
      factHigh,
      factLow
    ]);

    const verifier = await deployContract(deployer, "PhilBaseMirroredFactUnlockProofVerifier", [
      await baseMirror.getAddress()
    ]);
    const gate = await deployContract(deployer, "PhilBaseActionGate", [await verifier.getAddress()]);
    const consumer = await deployContract(deployer, "PhilAuthorizationConsumerMock");

    const consumerData = ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"));
    assert.equal(ethers.keccak256(consumerData), summary.publicInputs.consumerDataHash);

    const authorization = {
      consumer: await consumer.getAddress(),
      ownerCommitment: summary.publicInputs.ownerCommitment,
      actionHash: summary.publicInputs.actionHash,
      policyHash: summary.publicInputs.policyHash,
      nullifier: summary.publicInputs.nullifier,
      consumerDataHash: summary.publicInputs.consumerDataHash,
      expiry: BigInt(summary.publicInputs.expiry)
    };

    const proofPackage = {
      version: summary.version,
      proofType: summary.proofType,
      publicInputs: {
        ownerCommitment: summary.publicInputs.ownerCommitment,
        actionHash: summary.publicInputs.actionHash,
        policyHash: summary.publicInputs.policyHash,
        nullifier: summary.publicInputs.nullifier,
        consumerDataHash: summary.publicInputs.consumerDataHash,
        expiry: BigInt(summary.publicInputs.expiry)
      },
      proofInputHash: summary.proofInputHash,
      proofBlob: proofBlobForFact(factHigh, factLow)
    };

    const tx = await gate.verifyAndConsume(authorization, proofPackage, consumerData);
    await tx.wait();

    fs.mkdirSync(path.dirname(LOCAL_MANIFEST_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_MANIFEST_PATH, JSON.stringify(deploymentManifest, null, 2));
    const deploymentReceipt = buildBaseMirrorDeploymentReceipt({ runnerOutput });
    fs.mkdirSync(path.dirname(LOCAL_RECEIPT_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_RECEIPT_PATH, JSON.stringify(deploymentReceipt, null, 2));
    const deploymentVerification = await buildBaseMirrorDeploymentVerification({
      runnerOutput,
      deploymentReceipt
    });
    fs.mkdirSync(path.dirname(LOCAL_VERIFY_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_VERIFY_PATH, JSON.stringify(deploymentVerification, null, 2));
    const deploymentBundle = buildBaseMirrorDeploymentBundle({
      runnerOutput,
      deploymentReceipt,
      deploymentVerification
    });
    fs.mkdirSync(path.dirname(LOCAL_PACKAGE_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_PACKAGE_PATH, JSON.stringify(deploymentBundle, null, 2));
    const deploymentSummary = buildBaseMirrorDeploymentSummary({
      deploymentBundle
    });
    fs.mkdirSync(path.dirname(LOCAL_EXPORT_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_EXPORT_PATH, JSON.stringify(deploymentSummary, null, 2));
    const deploymentConsumption = buildBaseMirrorDeploymentConsumption({
      deploymentSummary
    });
    fs.mkdirSync(path.dirname(LOCAL_CONSUME_PATH), { recursive: true });
    fs.writeFileSync(LOCAL_CONSUME_PATH, JSON.stringify(deploymentConsumption, null, 2));

    assert.equal(
      BASE_MESSENGER_NETWORK_CONFIG.base.canonicalBaseMessengerAddress,
      CANONICAL_BASE_CROSS_DOMAIN_MESSENGER
    );
    assert.equal(
      BASE_MESSENGER_NETWORK_CONFIG.baseSepolia.canonicalBaseMessengerAddress,
      CANONICAL_BASE_CROSS_DOMAIN_MESSENGER
    );
    assert.equal(deploymentManifest.path, "base-proof-input-hash-mirror");
    assert.equal(
      deploymentManifest.deploymentPlan.adapter.constructorArgs[0],
      await baseCrossDomainMessenger.getAddress()
    );
    assert.equal(
      deploymentManifest.deploymentPlan.mirror.constructorArgs[1],
      await crossDomainMessengerAdapter.getAddress()
    );
    assert.equal(
      deploymentManifest.deployedAddresses.adapter,
      await crossDomainMessengerAdapter.getAddress()
    );
    assert.equal(deploymentManifest.deployedAddresses.mirror, await baseMirror.getAddress());
    assert.equal(await trustAnchor.anchoredProofInputHashFact(factHigh, factLow), true);
    assert.equal(await baseCrossDomainMessenger.lastTarget(), await baseMirror.getAddress());
    assert.equal(await baseCrossDomainMessenger.lastMessage(), expectedMirrorMessage);
    assert.equal(
      await baseCrossDomainMessenger.lastMinGasLimit(),
      BigInt(deploymentPlan.adapterMinGasLimit)
    );
    assert.equal(runnerOutput.deployArgSource, "scripts/base/assemble-base-messenger-deploy-args.cjs");
    assert.equal(runnerOutput.manifestSource, "scripts/base/record-base-mirror-deployment-manifest.cjs");
    assert.equal(runnerOutput.adapter.address, await crossDomainMessengerAdapter.getAddress());
    assert.equal(runnerOutput.mirror.address, await baseMirror.getAddress());
    assert.match(runnerOutput.baseCrossDomainMessenger.transactionHash, /^0x[0-9a-fA-F]{64}$/);
    assert.match(runnerOutput.adapter.transactionHash, /^0x[0-9a-fA-F]{64}$/);
    assert.match(runnerOutput.mirror.transactionHash, /^0x[0-9a-fA-F]{64}$/);
    assert.equal(runnerOutput.baseCrossDomainMessenger.blockNumber > 0, true);
    assert.equal(runnerOutput.adapter.blockNumber > 0, true);
    assert.equal(runnerOutput.mirror.blockNumber > 0, true);
    assert.equal(deploymentReceipt.path, "base-proof-input-hash-mirror-deployment-receipt");
    assert.equal(
      deploymentReceipt.deploymentReceipts.adapter.transactionHash,
      runnerOutput.adapter.transactionHash
    );
    assert.equal(
      deploymentReceipt.deploymentReceipts.mirror.blockNumber,
      runnerOutput.mirror.blockNumber
    );
    assert.equal(
      deploymentReceipt.deploymentManifest.deployedAddresses.mirror,
      await baseMirror.getAddress()
    );
    assert.equal(
      deploymentVerification.path,
      "base-proof-input-hash-mirror-deployment-verification"
    );
    assert.equal(
      deploymentVerification.deploymentVerification.baseCrossDomainMessenger.codeExists,
      true
    );
    assert.equal(
      deploymentVerification.deploymentVerification.adapter.runtimeBytecodeMatch,
      true
    );
    assert.equal(
      deploymentVerification.deploymentVerification.mirror.runtimeBytecodeMatch,
      true
    );
    assert.equal(
      deploymentVerification.deploymentVerification.adapter.transactionHash,
      runnerOutput.adapter.transactionHash
    );
    assert.equal(
      deploymentVerification.deploymentVerification.mirror.blockNumber,
      runnerOutput.mirror.blockNumber
    );
    assert.equal(
      deploymentBundle.path,
      "base-proof-input-hash-mirror-deployment-bundle"
    );
    assert.equal(
      deploymentBundle.payloadShape,
      "[fact_high, fact_low]"
    );
    assert.equal(
      deploymentBundle.runnerOutput.mirror.address,
      await baseMirror.getAddress()
    );
    assert.equal(
      deploymentBundle.deploymentReceipt.deploymentReceipts.adapter.transactionHash,
      runnerOutput.adapter.transactionHash
    );
    assert.equal(
      deploymentBundle.deploymentVerification.deploymentVerification.mirror.runtimeBytecodeMatch,
      true
    );
    assert.equal(
      deploymentSummary.path,
      "base-proof-input-hash-mirror-deployment-summary"
    );
    assert.equal(
      deploymentSummary.payloadShape,
      "[fact_high, fact_low]"
    );
    assert.equal(
      deploymentSummary.deployedContracts.mirror.address,
      await baseMirror.getAddress()
    );
    assert.equal(
      deploymentSummary.runtimeVerification.adapter.runtimeBytecodeMatch,
      true
    );
    assert.equal(
      deploymentSummary.deploymentPlan.adapterMinGasLimit,
      deploymentPlan.adapterMinGasLimit
    );
    assert.equal(
      deploymentConsumption.path,
      "base-proof-input-hash-mirror-deployment-consumption"
    );
    assert.equal(
      deploymentConsumption.payloadMarker,
      deploymentSummary.payloadShape
    );
    assert.deepEqual(
      deploymentConsumption.mirrorWriteShape,
      deploymentSummary.mirrorWriteShape
    );
    assert.equal(
      deploymentConsumption.operatorReadModel.mirrorAddress,
      await baseMirror.getAddress()
    );
    assert.equal(
      deploymentConsumption.validationChecks.runtimeVerificationAllPassed,
      true
    );
    assert.equal(await baseMirror.mirroredProofInputHashFact(factHigh, factLow), true);
    assert.equal(await baseMirror.latestFactHigh(), factHigh);
    assert.equal(await baseMirror.latestFactLow(), factLow);
    assert.equal(await gate.consumedNullifier(summary.publicInputs.nullifier), true);
    assert.equal(await consumer.consumeCount(), 1n);
    assert.equal(await consumer.lastNullifier(), summary.publicInputs.nullifier);
    assert.equal(await consumer.lastActionHash(), summary.publicInputs.actionHash);
    assert.equal(await consumer.lastConsumerData(), consumerData);
  });

  it("reverts when the Base-local mirror state has not been populated through the messenger seam", async function () {
    const relayOutput = loadJson(RELAY_OUTPUT_PATH);
    const summary = loadJson(SUMMARY_PATH);
    const [deployer] = await ethers.getSigners();

    const { crossDomainMessengerAdapter, baseMirror } = await runLocalBaseMirrorDeployment({
      signer: deployer,
      networkName: "hardhat"
    });
    const verifier = await deployContract(deployer, "PhilBaseMirroredFactUnlockProofVerifier", [
      await baseMirror.getAddress()
    ]);
    const gate = await deployContract(deployer, "PhilBaseActionGate", [await verifier.getAddress()]);
    const consumer = await deployContract(deployer, "PhilAuthorizationConsumerMock");

    const factHigh = asBigInt(relayOutput.relayed_fact_high);
    const factLow = asBigInt(relayOutput.relayed_fact_low);
    const proofPackage = {
      version: summary.version,
      proofType: summary.proofType,
      publicInputs: {
        ownerCommitment: summary.publicInputs.ownerCommitment,
        actionHash: summary.publicInputs.actionHash,
        policyHash: summary.publicInputs.policyHash,
        nullifier: summary.publicInputs.nullifier,
        consumerDataHash: summary.publicInputs.consumerDataHash,
        expiry: BigInt(summary.publicInputs.expiry)
      },
      proofInputHash: summary.proofInputHash,
      proofBlob: proofBlobForFact(factHigh, factLow)
    };
    const authorization = {
      consumer: await consumer.getAddress(),
      ownerCommitment: summary.publicInputs.ownerCommitment,
      actionHash: summary.publicInputs.actionHash,
      policyHash: summary.publicInputs.policyHash,
      nullifier: summary.publicInputs.nullifier,
      consumerDataHash: summary.publicInputs.consumerDataHash,
      expiry: BigInt(summary.publicInputs.expiry)
    };

    await expectRevert(
      () =>
        gate.verifyAndConsume(
          authorization,
          proofPackage,
          ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"))
        ),
      "expected missing Base-local mirrored fact to revert"
    );
  });
});
