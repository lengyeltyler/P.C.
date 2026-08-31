require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { getBytes } = require("ethers");
const hre = require("hardhat");

const { ethers, network } = hre;
const {
  PHILCORE_NATIVE_IPHONE_ROLE1,
  buildPhilCoreNativeIPhoneDescriptor,
  computePhilCoreNativeIPhoneFactorCommitment,
  normalizePhilCoreNativeIPhoneDescriptor
} = require("../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
const {
  buildO43NativeIPhoneFixturePackage
} = require("../../scripts/cryptography/generate-o43-native-iphone-fixtures.cjs");

const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_PATH = path.join(
  ROOT,
  "config/cryptography/O43_NATIVE_IPHONE_RECOVERY_FIXTURES.json"
);
const fixtures = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));

function request() {
  return { ...fixtures.request };
}

async function signerFor(address) {
  await network.provider.send("hardhat_impersonateAccount", [address]);
  return ethers.getSigner(address);
}

async function expectRejected(promise, label) {
  try {
    await promise;
  } catch {
    return;
  }
  assert.fail(`${label}: expected rejection`);
}

describe("O.43 native iPhone Role 1", function () {
  let verifier;

  before(async function () {
    verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
  });

  async function verify(envelope, override = {}) {
    const bound = { ...request(), ...override };
    const signer = await signerFor(bound.account);
    return verifier.connect(signer).verifyAuthority.staticCall(bound, envelope);
  }

  it("keeps the deterministic package current and free of production secrets", function () {
    const expected = `${JSON.stringify(
      buildO43NativeIPhoneFixturePackage(),
      (_key, value) => typeof value === "bigint" ? value.toString() : value,
      2
    )}\n`;
    assert.equal(fs.readFileSync(FIXTURE_PATH, "utf8"), expected);
    assert.equal(fixtures.classification, "DETERMINISTIC_SYNTHETIC_TEST_ONLY");
    assert.equal(fixtures.publicMutationCount, 0);
    assert.equal(fixtures.secretsCommitted, false);
    assert.equal(fixtures.productionCredentialCreated, false);
    assert.equal(fixtures.productionSignatureCommitted, false);
    assert.deepEqual(fixtures.validBitmaps, [3, 5, 6]);
    assert.deepEqual(
      fixtures.validPairs.map((pair) => pair.roles),
      [[0, 1], [0, 2], [1, 2]]
    );
    assert.equal(JSON.stringify(fixtures).includes("privateScalar"), false);
  });

  it("accepts native Role 1 in both exact 2-of-3 pairs", async function () {
    for (const pair of fixtures.validPairs) {
      const result = await verify(pair.envelope);
      assert.equal(result, await verifier.SUCCESS_MAGIC(), `bitmap ${pair.bitmap}`);
    }
    assert.equal(fixtures.validPairs[0].nativeEvidenceBytes, 640);
    assert.equal(fixtures.validPairs[2].nativeEvidenceBytes, 640);
  });

  it("preserves the outer V2 authority envelope and existing account version", function () {
    assert.equal(fixtures.outerAuthorityTransportChanged, false);
    assert.equal(fixtures.request.accountVersionId,
      "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f");
    assert.equal(fixtures.role, 1);
    assert.equal(fixtures.verifierKind, 4);
    assert.equal(fixtures.descriptorVersion, 1);
    assert.equal(
      PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity,
      "PHILCORE_IOS_NATIVE_ROLE1_V1|B342738S82|com.philcore.ios.companion.localalpha"
    );
  });

  it("rejects wrong account, recovery epoch, public key signature, and context", async function () {
    const valid = fixtures.validPairs.find((pair) => pair.bitmap === 6).envelope;
    await expectRejected(
      verify(valid, { account: "0x0000000000000000000000000000000000004301" }),
      "wrong account"
    );
    await expectRejected(
      verify(valid, { recoveryEpoch: 2 }),
      "wrong recovery epoch"
    );
    const bytes = getBytes(valid);
    bytes[bytes.length - 1] ^= 1;
    await expectRejected(
      verify(`0x${Buffer.from(bytes).toString("hex")}`),
      "changed signature"
    );
    await expectRejected(
      verify(valid, { recoveryConfigHash: `0x${"99".repeat(32)}` }),
      "wrong recovery configuration"
    );
  });

  it("fails closed on simulator, software-key, app, team, bundle, generation, and approval substitutions", function () {
    const descriptor = fixtures.factors.nativeIPhone.descriptor;
    const cases = [
      { ...descriptor, simulatorCredential: true },
      { ...descriptor, secureEnclaveRequired: false },
      { ...descriptor, applicationIdentityHash: `0x${"11".repeat(32)}` },
      { ...descriptor, applicationIdentityHash: `0x${"12".repeat(32)}` },
      { ...descriptor, applicationIdentityHash: `0x${"13".repeat(32)}` },
      { ...descriptor, credentialGeneration: 0 },
      { ...descriptor, localApprovalPolicyHash: `0x${"00".repeat(32)}` },
      { ...descriptor, role: 0 },
      { ...descriptor, verifierKind: 1 }
    ];
    for (const candidate of cases) {
      assert.throws(
        () => normalizePhilCoreNativeIPhoneDescriptor(candidate),
        /simulator|secure_enclave|must_be_nonzero|unsupported/
      );
    }
    const wrongKey = buildPhilCoreNativeIPhoneDescriptor({
      qx: `0x${"21".repeat(32)}`,
      qy: `0x${"22".repeat(32)}`,
      credentialIdentifierCommitment: descriptor.credentialIdentifierCommitment,
      deviceCustodyCommitment: descriptor.deviceCustodyCommitment,
      generation: 1
    });
    assert.notEqual(
      computePhilCoreNativeIPhoneFactorCommitment(wrongKey),
      fixtures.factors.nativeIPhone.factorCommitment
    );
  });

  it("records optional App Attest without making recovery online-dependent", function () {
    assert.equal(
      fixtures.appAttest,
      "DEFERRED_OPTIONAL_ENROLLMENT_ATTESTATION"
    );
    assert.equal(
      fixtures.factors.nativeIPhone.descriptor.appAttestCommitment,
      `0x${"00".repeat(32)}`
    );
  });

  it("changes only verifier bytecode among retained V2 sources", async function () {
    assert.equal(
      await verifier.VERIFIER_VERSION_ID(),
      ethers.id("philcore-v2-native-iphone-recovery-static-authority-verifier-v3")
    );
    const accountSource = fs.readFileSync(
      path.join(ROOT, "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol"),
      "utf8"
    );
    const factorySource = fs.readFileSync(
      path.join(ROOT, "contracts/base/erc4337/v2/PhilCoreV2MinimalAccountFactoryV2.sol"),
      "utf8"
    );
    assert.equal(accountSource.includes("NATIVE_DEVICE_P256"), false);
    assert.equal(factorySource.includes("NATIVE_DEVICE_P256"), false);
  });
});
