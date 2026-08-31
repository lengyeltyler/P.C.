const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { describe, it } = require("mocha");

const { validateConfig } = require("../../scripts/starknet/validate-starknet-publication-config.cjs");

const root = path.resolve(__dirname, "../..");

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8"));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function codes(result) {
  return result.issues.map((issue) => issue.code);
}

describe("Starknet publication configuration boundary", function () {
  const readiness = readJson("config/starknet-publication-readiness.json");
  const validConfig = readJson("config/starknet-publication-config.local.json");

  it("accepts the local predeployment profile bound to the reproducible artifacts", function () {
    const result = validateConfig(validConfig, readiness);
    assert.equal(result.ok, true, JSON.stringify(result.issues, null, 2));
    assert.equal(result.summary.profileId, "local_devnet");
    assert.equal(result.summary.productionApproved, false);
    assert.equal(result.summary.publicationContractAddress, null);
  });

  it("rejects stale artifact hashes", function () {
    const config = clone(validConfig);
    config.artifactBinding.sierraSha256 = "00";
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("artifact_hash_mismatch"));
  });

  it("rejects wrong ABI or entrypoint binding", function () {
    const config = clone(validConfig);
    config.artifactBinding.entrypoint = "verify_proof_input_hash_slice";
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("entrypoint_mismatch"));
  });

  it("rejects unsupported proof type", function () {
    const config = clone(validConfig);
    config.publication.proofType = "unsupported-proof";
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("unsupported_proof_type"));
  });

  it("rejects wrong message shape and high/low ordering", function () {
    const config = clone(validConfig);
    config.publication.messageShape.expectedFactPayload.reverse();
    config.publication.messageShape.l2ToL1PayloadOrdering = ["fact_low", "fact_high"];
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("fact_payload_mismatch"));
    assert.ok(codes(result).includes("high_low_order_mismatch"));
  });

  it("rejects zero L1 recipients", function () {
    const config = clone(validConfig);
    config.l1RecipientBinding.configuredL1RecipientAddress = "0x0";
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("zero_l1_recipient"));
  });

  it("allows unresolved publication address only while preparation remains disabled", function () {
    const config = clone(validConfig);
    config.networkProfiles.local_devnet.usableForTransactionPreparation = true;
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("preparation_enabled_without_deployment"));
    assert.ok(codes(result).includes("preparation_enabled_without_l2_sender"));
  });

  it("rejects enabled mainnet without accepted deployment data", function () {
    const config = clone(validConfig);
    config.networkProfiles.starknet_mainnet.enabled = true;
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("mainnet_enabled"));
  });

  it("rejects secret-shaped fields anywhere in the config", function () {
    const config = clone(validConfig);
    config.accountCallerModel.privateKey = "do-not-store";
    const result = validateConfig(config, readiness);
    assert.equal(result.ok, false);
    assert.ok(codes(result).includes("secret_field_present"));
  });

  it("rejects malformed config files through the CLI", function () {
    const config = clone(validConfig);
    config.artifactBinding.compiledClassSha256 = "bad";
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-starknet-config-"));
    const file = path.join(dir, "bad-config.json");
    fs.writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`);
    const result = require("node:child_process").spawnSync(
      "node",
      [
        "scripts/starknet/validate-starknet-publication-config.cjs",
        "--config",
        file
      ],
      {
        cwd: root,
        encoding: "utf8"
      }
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /artifact_hash_mismatch/);
  });
});
