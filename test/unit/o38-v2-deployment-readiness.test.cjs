const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { ethers, network } = require("hardhat");

const ROOT = path.resolve(__dirname, "../..");
const PREPARATION_SCRIPT = path.join(
  ROOT,
  "scripts/ethereum-sepolia/prepare-o38-v2-deployment.cjs"
);
const TEMPLATE_PATH = path.join(
  ROOT,
  "config/ethereum-sepolia/O38_V2_DEPLOYMENT_CANDIDATE_TEMPLATE.json"
);
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
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const HISTORICAL_ACCOUNT_VERSION_ID =
  "0x21fa156a27ec1e135fd05d69d2e37b6243327f63e37eac2f40783ba9a652fbb7";
const RECOVERY_CONFIGURATION_TYPEHASH = ethers.id(
  "PhilCoreV2RecoveryConfigurationV2(uint8 configurationVersion,uint8 threshold,bytes32 primaryDeviceCommitment,bytes32 hardwareSecurityKeyCommitment,bytes32 recoveryFactorCommitment)"
);
const abi = ethers.AbiCoder.defaultAbiCoder();

function runPreparation(arguments_, environment = {}) {
  return childProcess.spawnSync(
    process.execPath,
    [PREPARATION_SCRIPT, ...arguments_],
    {
      cwd: ROOT,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        NODE_PATH: process.env.NODE_PATH,
        ...environment
      }
    }
  );
}

function temporaryInput(mutator) {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "philcore-o38-test-")
  );
  const input = JSON.parse(fs.readFileSync(TEMPLATE_PATH));
  mutator(input);
  const file = path.join(directory, "input.json");
  fs.writeFileSync(file, `${JSON.stringify(input, null, 2)}\n`, {
    mode: 0o600
  });
  return file;
}

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

async function expectRejected(promise, label) {
  try {
    await promise;
  } catch {
    return;
  }
  assert.fail(`${label}: expected rejection`);
}

function deterministicBytes(seed, length) {
  let state = BigInt(seed) || 1n;
  const bytes = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13n;
    state ^= state >> 7n;
    state ^= state << 17n;
    bytes[index] = Number(state & 0xffn);
  }
  return `0x${bytes.toString("hex")}`;
}

describe("O.38 V2 deployment readiness guards and properties", function () {
  it("fails closed because O.39 superseded the frozen O.38 artifact hashes", function () {
    const result = runPreparation([]);
    assert.notEqual(result.status, 0);
    assert.match(
      result.stderr,
      /O38_INITIALIZATION_MISMATCH:artifact:verifierRuntimeKeccak256/
    );
  });

  it("fails closed for chain, artifact, initialization, and broadcast mutations", function () {
    const wrongChain = temporaryInput((input) => {
      input.chainId = "1";
    });
    let result = runPreparation(["--input", wrongChain]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /O38_WRONG_CHAIN/);

    const artifactMismatch = temporaryInput((input) => {
      input.artifactExpectations.accountRuntimeKeccak256 = ZERO_BYTES32;
    });
    result = runPreparation(["--input", artifactMismatch]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /O38_INITIALIZATION_MISMATCH:artifact/);

    const initializationMismatch = temporaryInput((input) => {
      input.initialization.ownerCommitment = ethers.id("wrong-owner");
      input.initialization.factoryBinding =
        "0x0000000000000000000000000000000000003801";
      input.futureFactoryAddress =
        "0x0000000000000000000000000000000000003801";
      input.futureVerifierAddress =
        "0x0000000000000000000000000000000000003802";
      input.confirmationTarget =
        "0x0000000000000000000000000000000000003803";
      input.initialization.confirmationTarget = input.confirmationTarget;
      input.userSalt = ethers.id("o38-test-salt");
      input.deploymentGasCeiling = 9_000_000;
      const commitments = [
        ethers.id("o38-primary"),
        ethers.id("o38-hardware"),
        ethers.id("o38-independent")
      ];
      [
        input.initialization.primaryDeviceRecoveryCommitment,
        input.initialization.hardwareSecurityKeyCommitment,
        input.initialization.independentRecoveryFactorCommitment
      ] = commitments;
      input.initialization.recoveryConfigurationHash = ethers.keccak256(
        abi.encode(
          ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
          [RECOVERY_CONFIGURATION_TYPEHASH, 2, 2, ...commitments]
        )
      );
    });
    result = runPreparation([
      "--input",
      initializationMismatch,
      "--require-ready"
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /O38_INITIALIZATION_MISMATCH:artifact/);

    result = runPreparation(["--broadcast"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /O38_PUBLIC_MUTATION_APPROVAL_REQUIRED/);
    result = runPreparation(
      ["--broadcast"],
      {
        PHILCORE_O38_PUBLIC_MUTATION_APPROVED:
          "O38_EXACT_PUBLIC_MUTATION_APPROVED"
      }
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /O38_BROADCAST_PATH_NOT_IMPLEMENTED/);
  });

  it("rejects 128 deterministic arbitrary envelope lengths and contents", async function () {
    const [deployer] = await ethers.getSigners();
    const Verifier = await ethers.getContractFactory(
      "PhilCoreV2StaticAuthorityVerifier",
      deployer
    );
    const verifier = await Verifier.deploy();
    const request = normalValidatorRequest();
    await network.provider.send("hardhat_impersonateAccount", [request.account]);
    const account = await ethers.getSigner(request.account);
    for (let seed = 1; seed <= 128; seed += 1) {
      const length = (seed * 73) % 1025;
      await expectRejected(
        verifier.connect(account).verifyAuthority.staticCall(
          request,
          deterministicBytes(seed, length)
        ),
        `seed=${seed},length=${length}`
      );
    }
  });

  it("rejects mixed/unknown actions and canonical truncation or extension", async function () {
    const [deployer] = await ethers.getSigners();
    const Verifier = await ethers.getContractFactory(
      "PhilCoreV2StaticAuthorityVerifier",
      deployer
    );
    const verifier = await Verifier.deploy();
    const request = normalValidatorRequest();
    await network.provider.send("hardhat_impersonateAccount", [request.account]);
    const account = await ethers.getSigner(request.account);
    const valid = O374.valid.normalValidatorExecution.encodedSignature;
    for (const actionType of [0, 3, 4, 5, 12, 127, 255]) {
      await expectRejected(
        verifier.connect(account).verifyAuthority.staticCall(
          { ...request, actionType },
          valid
        ),
        `actionType=${actionType}`
      );
    }
    for (let bytes = 1; bytes <= 32; bytes += 1) {
      await expectRejected(
        verifier.connect(account).verifyAuthority.staticCall(
          request,
          `0x${valid.slice(2, -bytes * 2)}`
        ),
        `truncated=${bytes}`
      );
      await expectRejected(
        verifier.connect(account).verifyAuthority.staticCall(
          request,
          `${valid}${"00".repeat(bytes)}`
        ),
        `extended=${bytes}`
      );
    }
  });

  it("keeps deployment preparation free of RPC, signing, and send methods", function () {
    const source = fs.readFileSync(PREPARATION_SCRIPT, "utf8");
    for (const forbidden of [
      "JsonRpcProvider",
      "Wallet",
      "signTransaction",
      "sendTransaction",
      "eth_sendRawTransaction",
      "eth_sendUserOperation",
      ".env.sepolia.local"
    ]) {
      assert.equal(source.includes(forbidden), false, forbidden);
    }
  });
});
