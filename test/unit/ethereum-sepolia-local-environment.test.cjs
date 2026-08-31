const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { keccak256, toUtf8Bytes } = require("ethers");

const {
  LOCAL_ENV_FILENAME,
  SAMPLEPHIL_VALIDATOR_ADDRESS,
  loadSepoliaLocalEnvironment,
  readCanonicalDesktopIdentityBinding,
  validateCanonicalIdentityBinding,
  validateSepoliaLocalEnvironment
} = require("../../scripts/ethereum-sepolia/local-environment.cjs");
const {
  LOCAL_PROOF_GATED_VALIDATOR_KEY_BINDING_DOMAIN,
  createRestrictedSepoliaReadOnlyClient,
  deriveLocalProofGatedValidatorKeyIdBinding,
  runLocalProofGatedPreparationPreflight
} = require("../../apps/phil-device-sdk/src/runtime/localProofGatedDeploymentPreparation.ts");

const DEPLOYER = "0x17f2F9f2e0aaf90768c0f26579fba5043Ef0C903";
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const OWNER = `0x${"ab".repeat(32)}`;
const KEY_ID = "validator_key_3c5b2ebebc4f3f3b";
const SALT = `0x${"12".repeat(32)}`;

function values(overrides = {}) {
  return {
    PHILCORE_SEPOLIA_RPC_URL: "https://rpc.example.test/redacted-key",
    PHILCORE_SEPOLIA_DEPLOYER_ADDRESS: DEPLOYER,
    PHILCORE_SEPOLIA_DEPLOYER_NONCE: "37",
    PHILCORE_SEPOLIA_VALIDATOR_ADDRESS: VALIDATOR,
    PHILCORE_SEPOLIA_OWNER_COMMITMENT: OWNER,
    PHILCORE_SEPOLIA_VALIDATOR_KEY_ID: KEY_ID,
    PHILCORE_SEPOLIA_ACCOUNT_SALT: SALT,
    PHILCORE_SEPOLIA_BUNDLER_URL: "",
    ...overrides
  };
}

function writeFixture(root, envValues = values(), identities) {
  const envPath = path.join(root, LOCAL_ENV_FILENAME);
  fs.writeFileSync(
    envPath,
    Object.entries(envValues).map(([key, value]) => `${key}="${value}"`).join("\n") + "\n",
    { mode: 0o600 }
  );
  const indexPath = path.join(root, "identity-index.json");
  fs.writeFileSync(indexPath, JSON.stringify({
    identities: identities ?? [{
      identityId: "identity_canonical",
      label: "My Phil",
      ownerCommitment: OWNER,
      validatorPublicAddress: VALIDATOR,
      validatorKeyReferenceId: KEY_ID,
      validatorStatus: "available",
      status: "locked",
      createdAt: "2026-07-25T18:25:59.195Z"
    }]
  }));
  return { envPath, indexPath };
}

describe("O.20 Ethereum Sepolia local environment", function () {
  it("permits only the exact optional O.23R selectors and keeps them out of public values", function () {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o23r-"));
    const o23rValues = values({
      PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY: "11".repeat(32),
      PHILCORE_SEPOLIA_FUNDING_ADDRESS:
        "0x3000000000000000000000000000000000000003",
      PHILCORE_SEPOLIA_FUNDING_PRIVATE_KEY: "22".repeat(32)
    });
    const { indexPath } = writeFixture(root, o23rValues);
    const environment = {};
    const loaded = loadSepoliaLocalEnvironment({
      root,
      indexPath,
      environment,
      includeO23rSensitiveSelectors: true
    });
    assert.equal(
      loaded.o23rSensitiveSelectorsConfigured
        .PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY,
      true
    );
    assert.equal(
      loaded.values.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY,
      undefined
    );
    assert.equal(
      environment.PHILCORE_SEPOLIA_DEPLOYER_PRIVATE_KEY,
      "11".repeat(32)
    );
    const invalid = validateSepoliaLocalEnvironment({
      ...o23rValues,
      PHILCORE_SEPOLIA_OTHER_PRIVATE_KEY: "33".repeat(32)
    });
    assert.equal(invalid.valid, false);
    assert.ok(invalid.errors.includes(
      "unexpected_field:PHILCORE_SEPOLIA_OTHER_PRIVATE_KEY"
    ));
    assert.ok(invalid.errors.includes(
      "forbidden_field:PHILCORE_SEPOLIA_OTHER_PRIVATE_KEY"
    ));
  });

  it("loads only the exact 0600 local filename and preserves its account salt", function () {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o20-"));
    const { envPath, indexPath } = writeFixture(root);
    const environment = { PHILCORE_SEPOLIA_ACCOUNT_SALT: `0x${"ff".repeat(32)}` };
    const loaded = loadSepoliaLocalEnvironment({ root, indexPath, environment });
    assert.equal(path.basename(loaded.path), ".env.sepolia.local");
    assert.equal(loaded.permissions, "0600");
    assert.equal(loaded.values.PHILCORE_SEPOLIA_ACCOUNT_SALT, SALT);
    assert.equal(environment.PHILCORE_SEPOLIA_ACCOUNT_SALT, SALT);
    assert.equal(loaded.processEnvironmentPrecedence, false);
    assert.equal(fs.statSync(envPath).mode & 0o777, 0o600);
  });

  it("fails closed when the exact local file is not private to the user", function () {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o20-"));
    const { envPath, indexPath } = writeFixture(root);
    fs.chmodSync(envPath, 0o644);
    assert.throws(
      () => loadSepoliaLocalEnvironment({ root, indexPath, environment: {} }),
      /SEPOLIA_LOCAL_ENV_PERMISSIONS_INVALID/
    );
  });

  it("keeps the real local environment path excluded by the repository rule", function () {
    const root = path.resolve(__dirname, "../..");
    const result = spawnSync("git", ["check-ignore", "-q", ".env.sepolia.local"], {
      cwd: root
    });
    assert.equal(result.status, 0);
  });

  it("rejects placeholders, missing bindings, invalid salts, secret fields, and approvals", function () {
    for (const [override, expected] of [
      [{ PHILCORE_SEPOLIA_OWNER_COMMITMENT: undefined }, "missing_field:PHILCORE_SEPOLIA_OWNER_COMMITMENT"],
      [{ PHILCORE_SEPOLIA_VALIDATOR_KEY_ID: undefined }, "missing_field:PHILCORE_SEPOLIA_VALIDATOR_KEY_ID"],
      [{ PHILCORE_SEPOLIA_ACCOUNT_SALT: "0x1234" }, "account_salt_invalid"],
      [{ PHILCORE_SEPOLIA_RPC_URL: "https://rpc.example.test/0xPASTE_KEY" }, "rpc_url_invalid"],
      [{ PHILCORE_PRIVATE_KEY: "forbidden" }, "forbidden_field:PHILCORE_PRIVATE_KEY"],
      [{ PHILCORE_SEPOLIA_FUNDING_APPROVED: "1" }, "forbidden_field:PHILCORE_SEPOLIA_FUNDING_APPROVED"]
    ]) {
      const candidate = values();
      for (const [key, value] of Object.entries(override)) {
        if (value === undefined) delete candidate[key];
        else candidate[key] = value;
      }
      assert.ok(validateSepoliaLocalEnvironment(candidate).errors.includes(expected), expected);
    }
  });

  it("rejects the SamplePhil validator and deployer/validator role collision", function () {
    assert.ok(validateSepoliaLocalEnvironment(values({
      PHILCORE_SEPOLIA_VALIDATOR_ADDRESS: SAMPLEPHIL_VALIDATOR_ADDRESS
    })).errors.includes("samplephil_validator_not_canonical"));
    assert.ok(validateSepoliaLocalEnvironment(values({
      PHILCORE_SEPOLIA_VALIDATOR_ADDRESS: DEPLOYER
    })).errors.includes("deployer_validator_role_collision"));
  });

  it("selects one complete canonical record and rejects cross-identity composition", function () {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "philcore-o20-"));
    const { indexPath } = writeFixture(root);
    const identity = readCanonicalDesktopIdentityBinding({ indexPath });
    assert.equal(identity.validatorAddress, VALIDATOR);
    assert.equal(identity.ownerCommitment, OWNER);
    assert.equal(identity.validatorKeyId, KEY_ID);
    assert.equal(validateCanonicalIdentityBinding(values(), identity).valid, true);
    assert.ok(validateCanonicalIdentityBinding(values({
      PHILCORE_SEPOLIA_OWNER_COMMITMENT: `0x${"cd".repeat(32)}`
    }), identity).errors.includes("canonical_owner_commitment_mismatch"));
  });

  it("derives one stable domain-separated bytes32 contract binding from the canonical key ID", function () {
    const expected = keccak256(toUtf8Bytes(
      `${LOCAL_PROOF_GATED_VALIDATOR_KEY_BINDING_DOMAIN}:${KEY_ID}`
    ));
    assert.equal(deriveLocalProofGatedValidatorKeyIdBinding(KEY_ID), expected);
    assert.throws(
      () => deriveLocalProofGatedValidatorKeyIdBinding(VALIDATOR),
      /validator_key_reference_id_invalid/
    );
  });

  it("checks the live pending nonce after chain verification and fails on mismatch without mutation", async function () {
    const calls = [];
    const client = createRestrictedSepoliaReadOnlyClient({
      url: "https://rpc.example.test/redacted",
      transport: {
        async request(method, params) {
          calls.push(method);
          if (method === "eth_chainId") return "0xaa36a7";
          if (method === "eth_blockNumber") return "0x1";
          if (method === "eth_getCode") return String(params[0]).toLowerCase().endsWith("da032")
            ? "0x6000"
            : "0x";
          if (method === "eth_getBalance") return "0x0";
          if (method === "eth_call") return `0x${"0".repeat(64)}`;
          if (method === "eth_gasPrice") return "0x1";
          if (method === "eth_getTransactionCount") return "0x25";
          throw new Error(`unexpected:${method}`);
        }
      }
    });
    const result = await runLocalProofGatedPreparationPreflight({
      client,
      deployer: { address: DEPLOYER, configuredPendingNonce: "0" },
      validatorAddress: VALIDATOR
    });
    assert.equal(calls[0], "eth_chainId");
    assert.equal(result.status, "READ_ONLY_PREFLIGHT_FAILED");
    assert.equal(result.deployer.observedPendingNonce, "37");
    assert.equal(result.deployer.nonceMatched, false);
    assert.ok(result.errors.includes("deployer_pending_nonce_mismatch"));
    assert.ok(!calls.some((method) => method.startsWith("eth_send")));
    assert.equal(result.publicMutationOccurred, false);
  });

  it("generates cryptographically random bytes32-compatible salts", function () {
    const first = `0x${crypto.randomBytes(32).toString("hex")}`;
    const second = `0x${crypto.randomBytes(32).toString("hex")}`;
    assert.match(first, /^0x[0-9a-f]{64}$/);
    assert.notEqual(first, second);
  });
});
