const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

describe("O.21.2 Device Vault signing-purpose review", function () {
  it("defines an explicit local-proof-gated Ethereum Sepolia signing purpose", function () {
    const source = fs.readFileSync(path.resolve(
      "apps/phil-device-sdk/src/runtime/deviceVaultEcdsaCustody.ts"
    ), "utf8");
    assert.ok(source.includes('"erc4337_owner_validator_local_alpha"'));
    assert.ok(source.includes('"erc4337_owner_validator_base_sepolia_beta"'));
    assert.ok(source.includes(
      '"ethereum_sepolia_local_proof_gated_v1_signing"'
    ));
    assert.ok(source.includes("signing_purpose_chain_mismatch"));
  });

  it("keeps signing in the Runtime main process and exposes no submission path", function () {
    const host = fs.readFileSync(path.resolve(
      "apps/philcore-desktop/src/main/runtime-host.cjs"
    ), "utf8");
    const preload = fs.readFileSync(path.resolve(
      "apps/philcore-desktop/src/preload/preload.cjs"
    ), "utf8");
    const signingWorkflow = fs.readFileSync(path.resolve(
      "apps/philcore-desktop/src/main/sepolia-user-operation-signing-workflow.cjs"
    ), "utf8");
    assert.ok(host.includes("finalizeSepoliaSignedArtifact"));
    assert.ok(signingWorkflow.includes("createDeviceVaultEcdsaValidatorSigner"));
    assert.ok(signingWorkflow.includes("signLocalProofGatedUserOperation"));
    assert.equal(host.includes("requestSepoliaUserOperationSubmission"), false);
    assert.equal(preload.includes("submitSepolia"), false);
    assert.equal(preload.includes("privateKey"), false);
    assert.equal(preload.includes("signBoundDigest"), false);
  });
});
