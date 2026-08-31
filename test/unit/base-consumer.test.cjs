const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");
const { ethers } = hre;

const { deployContract, expectRevert } = require("../helpers/context.cjs");

const RELAY_OUTPUT_PATH = path.join(
  __dirname,
  "../../proving/out/starknet_l1_relay/harness_output.json"
);
const SUMMARY_PATH = path.join(
  __dirname,
  "../../proving/out/cairo_air_adapter_spike/summary.json"
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

describe("PhilBaseActionGate via anchored L1 fact verifier", function () {
  it("reads the canonical L1 fact, preserves the exact two-felt payload, and maps it into the Base authorization path", async function () {
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

    const verifier = await deployContract(deployer, "PhilL1FactUnlockProofVerifier", [await trustAnchor.getAddress()]);
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

    assert.equal(await trustAnchor.anchoredProofInputHashFact(factHigh, factLow), true);
    assert.equal(await gate.consumedNullifier(summary.publicInputs.nullifier), true);
    assert.equal(await consumer.consumeCount(), 1n);
    assert.equal(await consumer.lastNullifier(), summary.publicInputs.nullifier);
    assert.equal(await consumer.lastActionHash(), summary.publicInputs.actionHash);
    assert.equal(await consumer.lastConsumerData(), consumerData);
  });

  it("reverts when the proof blob does not carry the exact anchored two-felt payload", async function () {
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

    const verifier = await deployContract(deployer, "PhilL1FactUnlockProofVerifier", [await trustAnchor.getAddress()]);
    const gate = await deployContract(deployer, "PhilBaseActionGate", [await verifier.getAddress()]);
    const consumer = await deployContract(deployer, "PhilAuthorizationConsumerMock");

    const authorization = {
      consumer: await consumer.getAddress(),
      ownerCommitment: summary.publicInputs.ownerCommitment,
      actionHash: summary.publicInputs.actionHash,
      policyHash: summary.publicInputs.policyHash,
      nullifier: summary.publicInputs.nullifier,
      consumerDataHash: summary.publicInputs.consumerDataHash,
      expiry: BigInt(summary.publicInputs.expiry)
    };

    const badProofPackage = {
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
      proofBlob: proofBlobForFact(factHigh, factLow + 1n)
    };

    await expectRevert(
      () =>
        gate.verifyAndConsume(
          authorization,
          badProofPackage,
          ethers.hexlify(ethers.toUtf8Bytes("phase3.4-consumer-data"))
        ),
      "expected mismatched anchored fact payload to revert"
    );
  });
});
