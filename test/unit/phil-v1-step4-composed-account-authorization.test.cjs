const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { p256 } = require("@noble/curves/p256");
const { getBytes } = require("ethers");
const {
  PHIL_STEP4_REFERENCE_RECEIPT_V1_HASH,
  createPhilStep4ReferenceReceiptV1,
  derivePhilStep4ReferenceReceiptDigestV1
} = require("../../apps/phil-device-sdk/src/composedAccountAuthorizationV1.ts");
const {
  derivePhilAuthorizationEnvelopeDigestV1
} = require("../../apps/phil-device-sdk/src/authorizationEnvelopeV1.ts");
const {
  derivePhilDeviceApprovalDigestV1
} = require("../../apps/phil-device-sdk/src/deviceApprovalV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const PROJECT = path.join(REPO_ROOT, "starknet/phil-v1-step4-account-gate");
const vector = JSON.parse(
  fs.readFileSync(path.join(PROJECT, "fixtures/canonical-vector.json"), "utf8")
);

describe("Phil V1 Step 4 composed account authorization", function () {
  it("matches the deterministic envelope, approval, signature, and receipt fixture", function () {
    assert.equal(
      derivePhilAuthorizationEnvelopeDigestV1(vector.envelope),
      vector.authorizationEnvelopeDigest
    );
    assert.equal(
      derivePhilDeviceApprovalDigestV1(vector.approval),
      vector.deviceApprovalDigest
    );
    assert.equal(
      p256.verify(
        {
          r: BigInt(vector.approval.signatureR),
          s: BigInt(vector.approval.signatureS)
        },
        getBytes(vector.deviceApprovalDigest),
        getBytes(vector.devicePublicKey.bytes),
        { lowS: true }
      ),
      true
    );
    assert.equal(
      derivePhilStep4ReferenceReceiptDigestV1({
        authorizationEnvelopeDigest: vector.authorizationEnvelopeDigest,
        rootProofNullifier: vector.envelope.rootProofNullifier,
        deviceApprovalDigest: vector.deviceApprovalDigest,
        accountNonce: vector.accountConfiguration.nextNonce,
        receiptSequence: vector.expectedAuthorizationState.receiptCount
      }),
      vector.expectedReceiptDigest
    );

    const receipt = createPhilStep4ReferenceReceiptV1({
      authorizationEnvelopeDigest: vector.authorizationEnvelopeDigest,
      rootProofNullifier: vector.envelope.rootProofNullifier,
      deviceApprovalDigest: vector.deviceApprovalDigest,
      accountNonce: vector.accountConfiguration.nextNonce,
      receiptSequence: vector.expectedAuthorizationState.receiptCount
    });
    assert.equal(receipt.receiptDigest, vector.expectedReceiptDigest);
    assert.equal(receipt.productionAuthority, false);
    assert.equal(receipt.networkActivity, false);
    assert.match(PHIL_STEP4_REFERENCE_RECEIPT_V1_HASH, /^0x[0-9a-f]{64}$/);
  });

  it("binds the receipt independently to every composed authority and replay value", function () {
    const canonical = {
      authorizationEnvelopeDigest: vector.authorizationEnvelopeDigest,
      rootProofNullifier: vector.envelope.rootProofNullifier,
      deviceApprovalDigest: vector.deviceApprovalDigest,
      accountNonce: vector.accountConfiguration.nextNonce,
      receiptSequence: vector.expectedAuthorizationState.receiptCount
    };
    for (const [field, value] of [
      ["authorizationEnvelopeDigest", `0x${"11".repeat(32)}`],
      ["rootProofNullifier", `0x${"22".repeat(32)}`],
      ["deviceApprovalDigest", `0x${"33".repeat(32)}`],
      ["accountNonce", "12"],
      ["receiptSequence", "2"]
    ]) {
      assert.notEqual(
        derivePhilStep4ReferenceReceiptDigestV1({ ...canonical, [field]: value }),
        vector.expectedReceiptDigest,
        `${field} was not receipt-bound`
      );
    }
  });

  it("has no runtime, RPC, deployment, transaction, signer, device, or STWO reachability", function () {
    const receiptSource = fs.readFileSync(
      path.join(REPO_ROOT, "apps/phil-device-sdk/src/composedAccountAuthorizationV1.ts"),
      "utf8"
    );
    const contractSource = fs.readFileSync(
      path.join(PROJECT, "src/composed_account_gate.cairo"),
      "utf8"
    );
    const contractTestSource = fs.readFileSync(
      path.join(PROJECT, "tests/composed_account_gate_test.cairo"),
      "utf8"
    );
    assert.doesNotMatch(receiptSource, /from\s+["']\.\/runtime\//);
    assert.doesNotMatch(
      `${receiptSource}\n${contractSource}`,
      /starknet\.js|ethers\.Wallet|fetch\s*\(|XMLHttpRequest|WebSocket|STWO|stwo|deploy_syscall|replace_class_syscall|call_contract_syscall/
    );
    assert.match(contractSource, /LibraryDispatcher/);
    assert.doesNotMatch(
      contractSource,
      /pub root_verifier_class_hash|root_verifier_class_hash:\s*starknet::ClassHash|self\.root_verifier_class_hash/
    );
    assert.match(
      contractSource,
      /class_hash: accepted_step3_verifier_class_hash\(\)/
    );
    assert.match(contractSource, /approval\.approval_nonce != 0/);
    assert.match(contractSource, /approval\.approved_at != 0/);
    assert.match(contractSource, /approval\.approval_expires_at != 0/);
    assert.match(contractSource, /is_valid_device_public_key\(config\.device_public_key_x/);
    assert.match(contractSource, /is_valid_initial_account_nonce\(config\.next_nonce\)/);
    assert.match(
      contractSource,
      /reference_action_value <= policy_max_value/
    );
    assert.match(
      contractSource,
      /reference_action_fee <= policy_max_fee/
    );
    assert.match(
      contractSource,
      /assert_reference_action_policy_ceilings\(\s*config\.reference_action_value,\s*config\.policy_max_value,\s*config\.reference_action_fee,\s*config\.policy_max_fee,/s
    );
    assert.match(
      contractTestSource,
      /fn action_value_above_policy_ceiling_executes_exact_constructor_rejection\(\)/
    );
    assert.match(
      contractTestSource,
      /fn action_fee_above_policy_ceiling_executes_exact_constructor_rejection\(\)/
    );
  });
});
