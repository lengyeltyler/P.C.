const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const hre = require("hardhat");

const { deployContract, expectRevert } = require("../helpers/context.cjs");

const RELAY_OUTPUT_PATH = path.join(
  __dirname,
  "../../proving/out/starknet_l1_relay/harness_output.json"
);

function loadRelayOutput() {
  return JSON.parse(fs.readFileSync(RELAY_OUTPUT_PATH, "utf8"));
}

function asBigInt(value) {
  return BigInt(value);
}

describe("PhilL1ProofInputHashAnchor", function () {
  it("consumes the authentic Starknet-forwarded payload and records the exact two-felt fact unchanged", async function () {
    const relayOutput = loadRelayOutput();
    assert.equal(relayOutput.syscalls.SendMessageToL1, 1, "acceptance source must include one L2->L1 message");

    const [deployer] = await hre.ethers.getSigners();
    const messaging = await deployContract(deployer, "MockStarknetMessaging");

    const sourceL2Verifier = asBigInt(relayOutput.contract_address);
    const factHigh = asBigInt(relayOutput.relayed_fact_high);
    const factLow = asBigInt(relayOutput.relayed_fact_low);
    const trustAnchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
      await messaging.getAddress(),
      sourceL2Verifier
    ]);

    const payload = [factHigh, factLow];
    await (await messaging.registerMessageFromL2(sourceL2Verifier, await trustAnchor.getAddress(), payload)).wait();

    const expectedMessageHash = await messaging.l2ToL1MessageHash(
      sourceL2Verifier,
      await trustAnchor.getAddress(),
      payload
    );
    assert.equal(await messaging.messageCount(expectedMessageHash), 1n);

    const tx = await trustAnchor.consumeProofInputHashFactFromL2(factHigh, factLow);
    const receipt = await tx.wait();

    assert.equal(await messaging.messageCount(expectedMessageHash), 0n);
    assert.equal(await trustAnchor.anchoredProofInputHashFact(factHigh, factLow), true);
    assert.equal(await trustAnchor.latestFactHigh(), factHigh);
    assert.equal(await trustAnchor.latestFactLow(), factLow);

    const anchoredEvent = receipt.logs
      .map((log) => {
        try {
          return trustAnchor.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find(Boolean);

    assert.equal(anchoredEvent?.name, "ProofInputHashFactAnchored");
    assert.equal(anchoredEvent.args.sourceL2Verifier, sourceL2Verifier);
    assert.equal(anchoredEvent.args.factHigh, factHigh);
    assert.equal(anchoredEvent.args.factLow, factLow);
  });

  it("reverts when the Starknet payload has not been registered for this trust-anchor boundary", async function () {
    const relayOutput = loadRelayOutput();
    const [deployer] = await hre.ethers.getSigners();
    const messaging = await deployContract(deployer, "MockStarknetMessaging");
    const trustAnchor = await deployContract(deployer, "PhilL1ProofInputHashAnchor", [
      await messaging.getAddress(),
      asBigInt(relayOutput.contract_address)
    ]);

    await expectRevert(
      () =>
        trustAnchor.consumeProofInputHashFactFromL2(
          asBigInt(relayOutput.relayed_fact_high),
          asBigInt(relayOutput.relayed_fact_low)
        ),
      "expected missing Starknet L2->L1 message to revert"
    );
  });
});
