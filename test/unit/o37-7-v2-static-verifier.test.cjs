const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const {
  concat,
  dataSlice,
  getBytes,
  keccak256,
  toUtf8Bytes
} = require("ethers");
const hre = require("hardhat");

const { ethers, network } = hre;
const ROOT = path.resolve(__dirname, "../..");
const O372 = JSON.parse(fs.readFileSync(
  path.join(
    ROOT,
    "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
  )
));
const O374 = JSON.parse(fs.readFileSync(
  path.join(
    ROOT,
    "config/cryptography/O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
  )
));
const EVIDENCE = JSON.parse(fs.readFileSync(
  path.join(
    ROOT,
    "config/solidity/O37_7_STATIC_VERIFIER_IMPLEMENTATION_EVIDENCE.json"
  )
));

const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const HISTORICAL_ACCOUNT_VERSION_ID =
  "0x21fa156a27ec1e135fd05d69d2e37b6243327f63e37eac2f40783ba9a652fbb7";
const FQN =
  "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol:" +
  "PhilCoreV2StaticAuthorityVerifier";

function normalValidatorRequest() {
  const fixture = O372.validAuthorizationFixture;
  const header = fixture.intent.header;
  const validator = fixture.validatorAuthorizationInput;
  return {
    actionType: Number(header.actionType),
    account: header.account,
    chainId: header.chainId,
    entryPoint: header.entryPoint,
    accountVersionId: HISTORICAL_ACCOUNT_VERSION_ID,
    securityModelId: header.securityModelId,
    authorizedIntentHash: fixture.authorizedIntentHash,
    userOpHash: fixture.userOperationHash,
    validator: validator.validator,
    validatorKeyIdBinding: validator.validatorKeyIdBinding,
    validatorEpoch: validator.validatorEpoch,
    recoveryEpoch: validator.recoveryEpoch,
    recoveryConfigHash: ZERO_BYTES32,
    requestId: ZERO_BYTES32,
    validAfter: header.validAfter,
    validUntil: header.validUntil,
    proposedValidatorCommitment: ZERO_BYTES32,
    proposedRecoveryConfigHash: ZERO_BYTES32,
    proposedRecoveryEpoch: 0,
    primaryDeviceCommitment: ZERO_BYTES32,
    hardwareSecurityKeyCommitment: ZERO_BYTES32,
    recoveryFactorCommitment: ZERO_BYTES32
  };
}

function recoveryRequest(validFixture) {
  const recovery = validFixture.recoveryEvidence;
  const context = recovery.context;
  const validatorEnvelope =
    validFixture.validatorEnvelope ||
    O374.valid.validatorPlusPrimaryAndHardwareConfigRotation.validatorEnvelope;
  const descriptor = recovery.firstEvidence.descriptor;
  return {
    actionType: Number(context.actionType),
    account: context.account,
    chainId: context.chainId,
    entryPoint: context.entryPoint,
    accountVersionId: descriptor.accountVersionId,
    securityModelId: descriptor.securityModelId,
    authorizedIntentHash: context.authorizedIntentHash,
    userOpHash: context.userOperationHash,
    validator: validatorEnvelope.validator,
    validatorKeyIdBinding: validatorEnvelope.validatorKeyIdBinding,
    validatorEpoch: context.validatorEpoch,
    recoveryEpoch: context.recoveryEpoch,
    recoveryConfigHash: context.currentRecoveryConfigHash,
    requestId: context.requestId,
    validAfter: context.validAfter,
    validUntil: context.validUntil,
    proposedValidatorCommitment: context.proposedValidatorCommitment,
    proposedRecoveryConfigHash: context.proposedRecoveryConfigHash,
    proposedRecoveryEpoch: context.proposedRecoveryEpoch,
    primaryDeviceCommitment: context.primaryDeviceCommitment,
    hardwareSecurityKeyCommitment: context.hardwareSecurityKeyCommitment,
    recoveryFactorCommitment: context.recoveryFactorCommitment
  };
}

function changeLastByte(value) {
  const bytes = getBytes(value);
  bytes[bytes.length - 1] ^= 1;
  return `0x${Buffer.from(bytes).toString("hex")}`;
}

function sha256(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function executableOpcodes(bytecode) {
  const bytes = getBytes(bytecode);
  const metadataLength =
    (bytes[bytes.length - 2] << 8) | bytes[bytes.length - 1];
  const executableLength = bytes.length - metadataLength - 2;
  assert.ok(executableLength > 0, "invalid Solidity metadata length");
  const opcodes = [];
  for (let index = 0; index < executableLength; index += 1) {
    const opcode = bytes[index];
    opcodes.push(opcode);
    if (opcode >= 0x60 && opcode <= 0x7f) {
      index += opcode - 0x5f;
    }
  }
  const dataSeparator = opcodes.lastIndexOf(0xfe);
  assert.ok(dataSeparator >= 0, "missing compiler data separator");
  return opcodes.slice(0, dataSeparator + 1);
}

async function signerFor(address) {
  await network.provider.send("hardhat_impersonateAccount", [address]);
  return ethers.getSigner(address);
}

async function expectRejected(promise, label) {
  try {
    await promise;
  } catch (error) {
    assert.notEqual(error, undefined, label);
    return;
  }
  assert.fail(`${label}: expected verifier rejection`);
}

describe("O.37.7 V2 static authority verifier", function () {
  let verifier;

  before(async function () {
    const artifact = await hre.artifacts.readArtifact(FQN);
    const [deployer] = await ethers.getSigners();
    const factory = new ethers.ContractFactory(
      artifact.abi,
      artifact.bytecode,
      deployer
    );
    verifier = await factory.deploy();
    await verifier.waitForDeployment();
  });

  async function verifyAsRequestAccount(request, envelope) {
    const signer = await signerFor(request.account);
    return verifier.connect(signer).verifyAuthority.staticCall(
      request,
      envelope
    );
  }

  it("accepts the unchanged O.37.2/O.37.4 validator fixture", async function () {
    const request = normalValidatorRequest();
    const result = await verifyAsRequestAccount(
      request,
      O374.valid.normalValidatorExecution.encodedSignature
    );
    assert.equal(result, await verifier.SUCCESS_MAGIC());
  });

  it("rejects the historical V2 recovery fixture after the O.39 version boundary", async function () {
    const valid = O374.valid.recoveryConfigCancellation;
    await expectRejected(
      verifyAsRequestAccount(
        recoveryRequest(valid),
        valid.encodedSignature
      ),
      "historical descriptor version"
    );
  });

  for (const fixtureName of [
    "validatorPlusPrimaryAndHardwareConfigRotation",
    "validatorPlusPrimaryAndRecoveryFactorRotation"
  ]) {
    it(`rejects the historical combined fixture after O.39: ${fixtureName}`, async function () {
      const valid = O374.valid[fixtureName];
      await expectRejected(
        verifyAsRequestAccount(
          recoveryRequest(valid),
          valid.encodedSignature
        ),
        "historical configuration version"
      );
    });
  }

  it("rejects a wrong validator signer and malformed evidence", async function () {
    const request = normalValidatorRequest();
    for (const id of ["wrong_signer", "high_s"]) {
      const fixture = O372.validatorSignatureFixtures.invalid.find(
        (candidate) => candidate.id === id
      );
      await expectRejected(
        verifyAsRequestAccount(request, fixture.encodedEnvelope),
        id
      );
    }
    await expectRejected(
      verifyAsRequestAccount(request, "0x1234"),
      "malformed envelope"
    );
  });

  it("rejects modified digest, chain, account, and epoch bindings", async function () {
    const valid = O374.valid.normalValidatorExecution.encodedSignature;
    const modifiedDigest = {
      ...normalValidatorRequest(),
      userOpHash: changeLastByte(normalValidatorRequest().userOpHash)
    };
    const wrongChain = {
      ...normalValidatorRequest(),
      chainId: "31338"
    };
    const wrongAccount = {
      ...normalValidatorRequest(),
      account: "0x00000000000000000000000000000000000F3703"
    };
    const wrongEpoch = {
      ...normalValidatorRequest(),
      validatorEpoch: 4
    };
    const wrongRecoveryEpoch = {
      ...normalValidatorRequest(),
      recoveryEpoch: 3
    };
    for (const [label, request] of [
      ["modified digest", modifiedDigest],
      ["wrong chain", wrongChain],
      ["wrong account", wrongAccount],
      ["wrong validator epoch", wrongEpoch],
      ["wrong recovery epoch", wrongRecoveryEpoch]
    ]) {
      await expectRejected(
        verifyAsRequestAccount(request, valid),
        label
      );
    }
  });

  it("rejects invalid bitmap, duplicate factors, reordered roles, and altered membership", async function () {
    const request = recoveryRequest(
      O374.valid.validatorPlusPrimaryAndHardwareConfigRotation
    );
    for (const id of [
      "wrong_bitmap",
      "duplicate_factor",
      "wrong_role_order",
      "altered_commitment"
    ]) {
      const fixture = O374.invalid.find((candidate) => candidate.id === id);
      await expectRejected(
        verifyAsRequestAccount(request, fixture.encodedEnvelope),
        id
      );
    }
  });

  it("rejects truncated, extended, and reordered combined evidence", async function () {
    const valid =
      O374.valid.validatorPlusPrimaryAndHardwareConfigRotation;
    const request = recoveryRequest(valid);
    const truncated = dataSlice(
      valid.encodedSignature,
      0,
      getBytes(valid.encodedSignature).length - 1
    );
    const extended = concat([valid.encodedSignature, "0x00"]);
    const reordered = O374.invalid.find(
      (fixture) => fixture.id === "reordered_outer_fields"
    ).encodedEnvelope;
    for (const [label, envelope] of [
      ["truncated", truncated],
      ["extended", extended],
      ["reordered", reordered]
    ]) {
      await expectRejected(
        verifyAsRequestAccount(request, envelope),
        label
      );
    }
  });

  it("rejects caller substitution before evaluating authority", async function () {
    const request = normalValidatorRequest();
    const [unboundCaller] = await ethers.getSigners();
    await expectRejected(
      verifier.connect(unboundCaller).verifyAuthority.staticCall(
        request,
        O374.valid.normalValidatorExecution.encodedSignature
      ),
      "caller account mismatch"
    );
  });

  it("has the superseding O.43 version identity, compatible success magic, ABI, and empty storage", async function () {
    assert.equal(
      await verifier.VERIFIER_VERSION_ID(),
      "0xde11c6ee24a54ab8efdc492bab9d294b5312fae953d3d12c7dec52e29a24719a"
    );
    assert.equal(
      await verifier.SUCCESS_MAGIC(),
      dataSlice(
        keccak256(toUtf8Bytes(
          "PHILCORE_V2_STATIC_AUTHORITY_VERIFIER_V1_SUCCESS"
        )),
        0,
        4
      )
    );
    const buildInfo = await hre.artifacts.getBuildInfo(FQN);
    const contract = buildInfo.output.contracts[
      "contracts/base/erc4337/v2/PhilCoreV2StaticAuthorityVerifier.sol"
    ].PhilCoreV2StaticAuthorityVerifier;
    assert.deepEqual(contract.storageLayout.storage, []);
    const functions = contract.abi
      .filter((entry) => entry.type === "function");
    assert.deepEqual(
      functions.map((entry) => entry.name).sort(),
      ["SUCCESS_MAGIC", "VERIFIER_VERSION_ID", "verifyAuthority"]
    );
    assert.equal(
      functions.find((entry) => entry.name === "verifyAuthority")
        .stateMutability,
      "view"
    );
  });

  it("fits the hard runtime budget and contains no state-changing opcode", async function () {
    const artifact = await hre.artifacts.readArtifact(
      "PhilCoreV2StaticAuthorityVerifier"
    );
    const runtimeBytes = getBytes(artifact.deployedBytecode).length;
    assert.ok(runtimeBytes <= 20480, `${runtimeBytes} > 20480`);
    assert.notEqual(runtimeBytes, EVIDENCE.implementation.runtimeBytecodeBytes);
    assert.notEqual(
      keccak256(artifact.deployedBytecode),
      EVIDENCE.implementation.runtimeBytecodeKeccak256
    );
    assert.notEqual(
      getBytes(artifact.bytecode).length,
      EVIDENCE.implementation.creationBytecodeBytes
    );
    assert.notEqual(
      keccak256(artifact.bytecode),
      EVIDENCE.implementation.creationBytecodeKeccak256
    );
    assert.equal(
      sha256(
        "contracts/base/erc4337/v2/" +
        "IPhilCoreV2StaticAuthorityVerifier.sol"
      ),
      EVIDENCE.implementation.interfaceSourceSha256
    );
    assert.notEqual(
      sha256(
        "contracts/base/erc4337/v2/" +
        "PhilCoreV2StaticAuthorityVerifier.sol"
      ),
      EVIDENCE.implementation.contractSourceSha256
    );
    assert.equal(
      sha256(
        "contracts/base/erc4337/" +
        "PhilCore4337LocalProofAccountV1.sol"
      ),
      EVIDENCE.baseline.v1AccountSourceSha256
    );
    assert.equal(
      sha256(
        "contracts/base/erc4337/" +
        "PhilCore4337LocalProofAccountFactoryV1.sol"
      ),
      EVIDENCE.baseline.v1FactorySourceSha256
    );
    assert.equal(
      sha256(
        "config/cryptography/" +
        "O37_4_V2_AUTHORITY_TRANSPORT_TEST_VECTORS.json"
      ),
      EVIDENCE.baseline.o37_4FixtureSha256
    );
    const opcodes = executableOpcodes(artifact.deployedBytecode);
    for (const [forbidden, opcode] of Object.entries({
      SSTORE: 0x55,
      SLOAD: 0x54,
      TLOAD: 0x5c,
      TSTORE: 0x5d,
      CREATE: 0xf0,
      CREATE2: 0xf5,
      CALL: 0xf1,
      DELEGATECALL: 0xf4,
      CALLCODE: 0xf2,
      SELFDESTRUCT: 0xff,
      LOG0: 0xa0,
      LOG1: 0xa1,
      LOG2: 0xa2,
      LOG3: 0xa3,
      LOG4: 0xa4
    })) {
      assert.equal(opcodes.includes(opcode), false, forbidden);
    }
    assert.equal(opcodes.includes(0xfa), true, "STATICCALL");
  });
});
