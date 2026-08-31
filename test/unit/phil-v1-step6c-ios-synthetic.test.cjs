const assert = require("node:assert/strict");
const { ethers } = require("hardhat");

const {
  auth,
  deployStep6CFixture,
  buildRequestForNonce
} = require("../helpers/phil-v1-step6c-fixture.cjs");

describe("Phil V1 Step 6C synthetic iPhone-side derivation", function () {
  it("derives every displayed field from admitted records and raw calldata", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 20n,
      sessionLabel: "ios-display"
    });
    const p = built.request.humanPresentation;
    assert.equal(p.applicationNameHash, f.catalog.entries[0].displayTextHash);
    assert.equal(p.networkLabelHash, f.catalog.entries[1].displayTextHash);
    assert.equal(p.accountLabelHash, f.catalog.entries[2].displayTextHash);
    assert.equal(p.targetLabelHash, f.catalog.entries[3].displayTextHash);
    assert.equal(p.actionLabelHash, f.catalog.entries[4].displayTextHash);
    assert.equal(p.parametersHash, built.request.actionHash);
    assert.equal(p.parameterSummaryHash, auth.derivePhilRoutineParameterSummaryHashV1(built.targetCalldata));
    assert.equal(p.targetRuntimeCodeHash, f.targetCodeHash);
    assert.equal(p.externalNetwork, false);
    assert.equal(p.productionAuthority, false);
    assert.equal(p.meaningfulAssets, false);
  });

  it("does not relabel the disclosed synthetic key as Secure Enclave or user-presence evidence", async function () {
    const f = await deployStep6CFixture();
    assert.equal(f.enrollment.secureEnclaveBacked, false);
    assert.equal(f.enrollment.userPresenceRequired, false);
    assert.equal(f.enrollment.status, 1);
    assert.notEqual(f.enrollment.signatureSuiteId, ethers.id("phil-signature-p256-sha256-v1"));
  });

  it("rejects selector, value, boolean, trailing-byte, summary, and signing-digest substitution", async function () {
    const f = await deployStep6CFixture();
    const built = await buildRequestForNonce(f, {
      nonceSequence: 0,
      shouldRevert: false,
      issuedAt: BigInt(f.policy.validAfter) + 20n,
      sessionLabel: "ios-negative"
    });
    const raw = ethers.getBytes(built.targetCalldata);
    for (const mutation of [
      ethers.hexlify(Uint8Array.from(raw, (value, index) => index === 0 ? value ^ 1 : value)),
      ethers.hexlify(Uint8Array.from(raw, (value, index) => index === 4 ? value ^ 1 : value)),
      `${built.targetCalldata.slice(0, -64)}${"2".padStart(64, "0")}`,
      `${built.targetCalldata}00`
    ]) assert.throws(() => auth.derivePhilRoutineParameterSummaryHashV1(mutation));
    assert.throws(() => auth.createPhilRoutineAuthorizationResponseV1({
      request: built.request,
      signature: `0x${"01".repeat(64)}`
    }), (error) => /SIGNATURE|SCALAR/.test(error.code));
  });
});
