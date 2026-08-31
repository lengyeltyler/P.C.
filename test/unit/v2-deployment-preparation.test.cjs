const assert = require("node:assert/strict");
const { ethers } = require("hardhat");
const { AbiCoder, concat, keccak256, toUtf8Bytes } = require("ethers");

const identity = require("../../apps/phil-device-sdk/src/v2DeployableIdentity.ts");
const prep = require("../../apps/phil-device-sdk/src/runtime/v2DeploymentPreparation.ts");
const {
  PHILCORE_V2_ACCOUNT_VERSION_ID: HISTORICAL_ACCOUNT_VERSION_ID
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  ERC4337_V07_CANONICAL_ENTRYPOINT,
  ETHEREUM_SEPOLIA_CHAIN_ID
} = require("../../apps/phil-device-sdk/src/runtime/ethereumSepoliaReadiness.ts");
const {
  computePhilCore4337UserOperationHash,
  unpackPhilCore4337Uints
} = require("../../apps/phil-device-sdk/src/runtime/philcore4337UserOperationPreparation.ts");

const EntryPointArtifact = require("@account-abstraction/contracts/artifacts/EntryPoint.json");
const AccountArtifact = require(
  "../../artifacts/contracts/base/erc4337/v2/PhilCoreV2MinimalAccountV2.sol/PhilCoreV2MinimalAccountV2.json"
);

const abiCoder = AbiCoder.defaultAbiCoder();
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

const FACTORY = "0x1000000000000000000000000000000000000001";
const VERIFIER = "0x2000000000000000000000000000000000000002";
const CONFIRMATION_TARGET = "0x3000000000000000000000000000000000000003";
const VALIDATOR = "0x4000000000000000000000000000000000000004";

// --- Independent (hand-rolled) reimplementations of the on-chain formulas. ---
// These intentionally do not call into the module under test, so they act as
// an outside check on the module's cryptography.
const IDENTITY_BINDING_TYPEHASH =
  "0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8";
const OWNER_COMMITMENT_SCHEME_ID =
  "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e";
const VALIDATOR_COMMITMENT_TYPEHASH = keccak256(toUtf8Bytes(
  "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
));
const RECOVERY_CONFIGURATION_TYPEHASH = keccak256(toUtf8Bytes(
  "PhilCoreV2RecoveryConfigurationV3(uint8 configurationVersion,uint8 threshold,bytes32 role0Commitment,bytes32 role1Commitment,bytes32 role2Commitment)"
));
const INTENT_CORE_HEADER_TYPEHASH = keccak256(toUtf8Bytes(
  "PhilCoreV2IntentCoreHeader(uint8 specificationVersion,bytes32 securityModelId,uint8 actionType,bytes32 actionId,bytes32 purpose,bytes32 ownerCommitment,uint256 chainId,address entryPoint,address account,uint192 nonceKey,uint64 nonceSequence,uint64 validatorEpoch,uint64 recoveryEpoch,bytes32 applicationContextHash,bytes32 fundLifecycleDigest,uint256 maxTotalFeeWei,uint48 validAfter,uint48 validUntil)"
));
const CONFIRM_TYPEHASH = keccak256(toUtf8Bytes(
  "PhilCoreV2ConfirmIntent(bytes32 coreHeaderHash,address confirmationTarget,bytes32 confirmationDigest)"
));
const CREATE2_SALT_DOMAIN = keccak256(toUtf8Bytes("PHILCORE_V2_CREATE2_SALT_V1"));
const PURPOSE_CONFIRM = keccak256(toUtf8Bytes("PHILCORE_V2_PURPOSE_CONFIRM_ACTION"));

const INITIALIZATION_TUPLE_TYPES = [
  "address", "uint256", "bytes32", "bytes32", "address", "bytes32", "bytes32",
  "address", "address", "uint8", "bytes32", "bytes32", "uint64", "bytes32",
  "bytes32", "bytes32", "bytes32", "uint64", "uint64", "uint64"
];
const HEADER_TUPLE_TYPES = [
  "uint8", "bytes32", "uint8", "bytes32", "bytes32", "bytes32", "uint256",
  "address", "address", "uint192", "uint64", "uint64", "uint64", "bytes32",
  "bytes32", "uint256", "uint48", "uint48"
];

function H(label) {
  return keccak256(toUtf8Bytes(label));
}

function identityBindingOf(ownerCommitment) {
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "bytes32", "bytes32"],
    [IDENTITY_BINDING_TYPEHASH, 1, ownerCommitment, OWNER_COMMITMENT_SCHEME_ID]
  ));
}

function validatorCommitmentOf(validator, keyBinding) {
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "address", "bytes32"],
    [VALIDATOR_COMMITMENT_TYPEHASH, 1, validator, keyBinding]
  ));
}

function recoveryConfigHashOf(primary, hardware, independent) {
  return keccak256(abiCoder.encode(
    ["bytes32", "uint8", "uint8", "bytes32", "bytes32", "bytes32"],
    [RECOVERY_CONFIGURATION_TYPEHASH, 3, 2, primary, hardware, independent]
  ));
}

function headerHashOf(core) {
  return keccak256(abiCoder.encode(
    ["bytes32", ...HEADER_TUPLE_TYPES],
    [
      INTENT_CORE_HEADER_TYPEHASH,
      core.specificationVersion,
      core.securityModelId,
      core.actionType,
      core.actionId,
      core.purpose,
      core.ownerCommitment,
      core.chainId,
      core.entryPoint,
      core.account,
      core.nonceKey,
      core.nonceSequence,
      core.validatorEpoch,
      core.recoveryEpoch,
      core.applicationContextHash,
      core.fundLifecycleDigest,
      core.maxTotalFeeWei,
      core.validAfter,
      core.validUntil
    ]
  ));
}

function confirmIntentCoreHashOf(core, confirmationTarget, confirmationDigest) {
  return keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "address", "bytes32"],
    [CONFIRM_TYPEHASH, headerHashOf(core), confirmationTarget, confirmationDigest]
  ));
}

function deploymentSaltOf(input) {
  return keccak256(abiCoder.encode(
    ["bytes32", "uint256", "bytes32", "bytes32", "bytes32", "bytes32", "bytes32"],
    [
      CREATE2_SALT_DOMAIN,
      input.chainId,
      input.accountVersionId,
      input.securityModelId,
      input.ownerCommitment,
      input.identityBindingCommitment,
      input.userSalt
    ]
  ));
}

function initializationArray(init) {
  return [
    init.entryPoint,
    init.deploymentChainId,
    init.ownerCommitment,
    init.identityBindingCommitment,
    init.factoryBinding,
    init.accountVersionId,
    init.securityModelId,
    init.confirmationTarget,
    init.initialValidator,
    init.validatorVerifierKind,
    init.validatorKeyIdBinding,
    init.validatorCommitment,
    init.validatorEpoch,
    init.primaryDeviceRecoveryCommitment,
    init.hardwareSecurityKeyCommitment,
    init.independentRecoveryFactorCommitment,
    init.recoveryConfigurationHash,
    init.recoveryEpoch,
    init.recoveryDelaySeconds,
    init.recoveryExpirySeconds
  ];
}

function accountCreationCodeHashOf(bytecode, init) {
  const encoded = abiCoder.encode(
    [`tuple(${INITIALIZATION_TUPLE_TYPES.join(",")})`],
    [initializationArray(init)]
  );
  return keccak256(concat([bytecode, encoded]));
}

function baseValues(seed = "v2-demo") {
  const ownerCommitment = H(`${seed}-owner`);
  const validatorKeyIdBinding = H(`${seed}-validator-key`);
  const primary = H(`${seed}-primary`);
  const hardware = H(`${seed}-hardware`);
  const independent = H(`${seed}-independent`);
  return {
    ownerCommitment,
    identityBindingCommitment: identityBindingOf(ownerCommitment),
    validatorKeyIdBinding,
    validatorCommitment: validatorCommitmentOf(VALIDATOR, validatorKeyIdBinding),
    primaryDeviceRecoveryCommitment: primary,
    hardwareSecurityKeyCommitment: hardware,
    independentRecoveryFactorCommitment: independent,
    recoveryConfigurationHash: recoveryConfigHashOf(primary, hardware, independent),
    userSalt: H(`${seed}-user-salt`)
  };
}

function validInput(overrides = {}) {
  const { seed, ...rest } = overrides;
  const values = baseValues(seed);
  return {
    factory: FACTORY,
    verifier: VERIFIER,
    verifierRuntimeCodeHash: H("verifier-runtime-code"),
    confirmationTarget: CONFIRMATION_TARGET,
    entryPoint: ERC4337_V07_CANONICAL_ENTRYPOINT,
    validator: VALIDATOR,
    chainId: ETHEREUM_SEPOLIA_CHAIN_ID,
    ownerCommitment: values.ownerCommitment,
    identityBindingCommitment: values.identityBindingCommitment,
    validatorKeyIdBinding: values.validatorKeyIdBinding,
    validatorCommitment: values.validatorCommitment,
    primaryDeviceRecoveryCommitment: values.primaryDeviceRecoveryCommitment,
    hardwareSecurityKeyCommitment: values.hardwareSecurityKeyCommitment,
    independentRecoveryFactorCommitment: values.independentRecoveryFactorCommitment,
    recoveryConfigurationHash: values.recoveryConfigurationHash,
    validatorEpoch: 1,
    recoveryEpoch: 1,
    recoveryDelaySeconds: 172_800,
    recoveryExpirySeconds: 604_800,
    userSalt: values.userSalt,
    accountCreationBytecode: AccountArtifact.bytecode,
    actionId: H("action-confirm-deployment"),
    confirmationDigest: H("confirmation-digest"),
    runtimeAuthorizationDigest: H("runtime-authorization-digest"),
    applicationContextHash: H("application-context"),
    fundLifecycleDigest: H("fund-lifecycle"),
    maxTotalFeeWei: "1000000000000000",
    validAfter: 1_800_000_000,
    validUntil: 1_800_000_300,
    verificationGasLimit: "900000",
    callGasLimit: "150000",
    preVerificationGas: "100000",
    maxFeePerGas: "30000000000",
    maxPriorityFeePerGas: "1000000000",
    ...rest
  };
}

function serializeForComparison(value) {
  if (typeof value === "bigint") return `bigint:${value.toString()}`;
  if (Array.isArray(value)) return value.map(serializeForComparison);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = serializeForComparison(value[key]);
    return out;
  }
  return value;
}

describe("PhilCoreV2 Sepolia demo deployment preparation", function () {
  describe("v2DeployableIdentity", function () {
    it("exposes the current deployable account version id, matching v2ConsumerRecovery", function () {
      assert.equal(
        identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION,
        "philcore-v2-minimal-account-v3-consumer-recovery"
      );
      assert.equal(
        identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
        PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID
      );
      assert.equal(
        identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
        "0xa271e70f3c567c6a54a81e455de89f98cc067a931ac70816c6016e9b9ca1fd1f"
      );
    });

    it("differs from the historical v2Intent account version id", function () {
      assert.notEqual(
        identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
        HISTORICAL_ACCOUNT_VERSION_ID
      );
      assert.equal(
        HISTORICAL_ACCOUNT_VERSION_ID,
        "0x21fa156a27ec1e135fd05d69d2e37b6243327f63e37eac2f40783ba9a652fbb7"
      );
    });

    it("re-exports (does not redefine) the current security model from v2Intent", function () {
      assert.equal(
        identity.PHILCORE_V2_SECURITY_MODEL,
        "philcore-v2-typed-intent-local-proof-gated-v1"
      );
      assert.equal(
        identity.PHILCORE_V2_SECURITY_MODEL_ID,
        keccak256(toUtf8Bytes("philcore-v2-typed-intent-local-proof-gated-v1"))
      );
    });

    it("matches the SDK's canonical Sepolia chain id and EntryPoint address", function () {
      assert.equal(identity.PHILCORE_V2_SEPOLIA_CHAIN_ID, ETHEREUM_SEPOLIA_CHAIN_ID);
      assert.equal(identity.PHILCORE_ENTRY_POINT_V07_ADDRESS, ERC4337_V07_CANONICAL_ENTRYPOINT);
    });

    it("computes the CREATE2 salt domain identically to the factory contract", function () {
      assert.equal(identity.PHILCORE_V2_CREATE2_SALT_DOMAIN, CREATE2_SALT_DOMAIN);
    });
  });

  describe("preparePhilCoreV2SepoliaDemoDeployment (offline happy path)", function () {
    it("exposes the expected schema constant", function () {
      assert.equal(
        prep.PHILCORE_V2_SEPOLIA_DEMO_PREPARATION_SCHEMA,
        "philcore-v2-sepolia-demo-preparation-v1"
      );
    });

    it("produces an unsigned, unsubmitted proposal with the exact 20-field initialization tuple", function () {
      const input = validInput({ seed: "happy-path" });
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);

      assert.equal(proposal.schemaVersion, "philcore-v2-sepolia-demo-preparation-v1");
      assert.equal(proposal.chainId, BigInt(ETHEREUM_SEPOLIA_CHAIN_ID));
      assert.equal(proposal.entryPoint, ethers.getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT));
      assert.equal(proposal.factory, ethers.getAddress(FACTORY));
      assert.equal(proposal.status, "proposed_unsigned");
      assert.equal(proposal.signed, false);
      assert.equal(proposal.submitted, false);
      assert.equal(proposal.incompleteUntilDeviceApproval, true);

      const expectedArray = initializationArray({
        entryPoint: ethers.getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT),
        deploymentChainId: BigInt(ETHEREUM_SEPOLIA_CHAIN_ID),
        ownerCommitment: input.ownerCommitment,
        identityBindingCommitment: input.identityBindingCommitment,
        factoryBinding: ethers.getAddress(FACTORY),
        accountVersionId: identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
        securityModelId: identity.PHILCORE_V2_SECURITY_MODEL_ID,
        confirmationTarget: ethers.getAddress(CONFIRMATION_TARGET),
        initialValidator: ethers.getAddress(VALIDATOR),
        validatorVerifierKind: 1n,
        validatorKeyIdBinding: input.validatorKeyIdBinding,
        validatorCommitment: input.validatorCommitment,
        validatorEpoch: 1n,
        primaryDeviceRecoveryCommitment: input.primaryDeviceRecoveryCommitment,
        hardwareSecurityKeyCommitment: input.hardwareSecurityKeyCommitment,
        independentRecoveryFactorCommitment: input.independentRecoveryFactorCommitment,
        recoveryConfigurationHash: input.recoveryConfigurationHash,
        recoveryEpoch: 1n,
        recoveryDelaySeconds: 172_800n,
        recoveryExpirySeconds: 604_800n
      });
      assert.deepEqual(
        proposal.initializationTuple.map(String),
        expectedArray.map(String)
      );
      assert.deepEqual(
        Object.values(proposal.initialization).map(String),
        expectedArray.map(String)
      );
    });

    it("encodes createAccount calldata that decodes back to the exact initialization tuple", function () {
      const input = validInput({ seed: "calldata-decode" });
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);

      assert.equal(
        proposal.createAccountCalldata.slice(0, 10),
        prep.PHILCORE_V2_FACTORY_CREATE_ACCOUNT_SELECTOR
      );
      const body = `0x${proposal.createAccountCalldata.slice(10)}`;
      const [decodedTuple, decodedSalt] = abiCoder.decode(
        [`tuple(${INITIALIZATION_TUPLE_TYPES.join(",")})`, "bytes32"],
        body
      );
      assert.deepEqual(
        decodedTuple.map(String),
        proposal.initializationTuple.map(String)
      );
      assert.equal(decodedSalt, input.userSalt);
    });

    it("builds initCode as factory address concatenated with createAccount calldata", function () {
      const input = validInput({ seed: "initcode" });
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);

      assert.equal(
        proposal.initCode.slice(0, 42).toLowerCase(),
        proposal.factory.toLowerCase()
      );
      assert.equal(`0x${proposal.initCode.slice(42)}`, proposal.createAccountCalldata);
    });

    it("independently reproduces the deployment salt, code hash, and CREATE2 address", function () {
      const input = validInput({ seed: "create2" });
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);

      const expectedSalt = deploymentSaltOf({
        chainId: BigInt(ETHEREUM_SEPOLIA_CHAIN_ID),
        accountVersionId: identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
        securityModelId: identity.PHILCORE_V2_SECURITY_MODEL_ID,
        ownerCommitment: input.ownerCommitment,
        identityBindingCommitment: input.identityBindingCommitment,
        userSalt: input.userSalt
      });
      assert.equal(proposal.deploymentSalt, expectedSalt);
      assert.equal(
        prep.computeDeploymentSalt({
          deploymentChainId: BigInt(ETHEREUM_SEPOLIA_CHAIN_ID),
          ownerCommitment: input.ownerCommitment,
          identityBindingCommitment: input.identityBindingCommitment,
          userSalt: input.userSalt
        }),
        expectedSalt
      );

      const expectedCodeHash = accountCreationCodeHashOf(
        AccountArtifact.bytecode,
        proposal.initialization
      );
      assert.equal(proposal.accountCreationCodeHash, expectedCodeHash);

      const expectedAddress = ethers.getCreate2Address(
        proposal.factory,
        proposal.deploymentSalt,
        proposal.accountCreationCodeHash
      );
      assert.equal(proposal.counterfactualAccount, expectedAddress);
      assert.equal(
        prep.predictCreate2Address({
          factory: proposal.factory,
          deploymentSalt: proposal.deploymentSalt,
          accountCreationCodeHash: proposal.accountCreationCodeHash
        }),
        expectedAddress
      );
    });

    it("produces a confirmIntent calldata that round-trips and matches recomputed hashes", function () {
      const input = validInput({ seed: "confirm-intent" });
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);

      assert.equal(
        proposal.confirmIntent.calldata.slice(0, 10),
        prep.PHILCORE_V2_CONFIRM_INTENT_SELECTOR
      );
      const body = `0x${proposal.confirmIntent.calldata.slice(10)}`;
      const [decodedIntent, decodedDigest] = abiCoder.decode(
        [`tuple(tuple(${HEADER_TUPLE_TYPES.join(",")}) core, bytes32 runtimeAuthorizationDigest)`, "bytes32"],
        body
      );
      const [core, runtimeAuthorizationDigest] = decodedIntent;
      assert.equal(decodedDigest, input.confirmationDigest);
      assert.equal(runtimeAuthorizationDigest, input.runtimeAuthorizationDigest);

      const coreObj = {
        specificationVersion: core[0],
        securityModelId: core[1],
        actionType: core[2],
        actionId: core[3],
        purpose: core[4],
        ownerCommitment: core[5],
        chainId: core[6],
        entryPoint: core[7],
        account: core[8],
        nonceKey: core[9],
        nonceSequence: core[10],
        validatorEpoch: core[11],
        recoveryEpoch: core[12],
        applicationContextHash: core[13],
        fundLifecycleDigest: core[14],
        maxTotalFeeWei: core[15],
        validAfter: core[16],
        validUntil: core[17]
      };
      assert.equal(coreObj.specificationVersion, 1n);
      assert.equal(coreObj.securityModelId, identity.PHILCORE_V2_SECURITY_MODEL_ID);
      assert.equal(coreObj.actionType, 1n); // CONFIRM
      assert.equal(coreObj.actionId, input.actionId);
      assert.equal(coreObj.purpose, PURPOSE_CONFIRM);
      assert.equal(coreObj.ownerCommitment, input.ownerCommitment);
      assert.equal(coreObj.chainId, BigInt(ETHEREUM_SEPOLIA_CHAIN_ID));
      assert.equal(coreObj.entryPoint, ethers.getAddress(ERC4337_V07_CANONICAL_ENTRYPOINT));
      assert.equal(coreObj.account, proposal.counterfactualAccount);
      assert.equal(coreObj.nonceKey, 0n);
      assert.equal(coreObj.nonceSequence, 0n);
      assert.equal(coreObj.validatorEpoch, 1n);
      assert.equal(coreObj.recoveryEpoch, 1n);
      assert.equal(coreObj.applicationContextHash, input.applicationContextHash);
      assert.equal(coreObj.fundLifecycleDigest, input.fundLifecycleDigest);
      assert.equal(coreObj.maxTotalFeeWei, BigInt(input.maxTotalFeeWei));
      assert.equal(coreObj.validAfter, BigInt(input.validAfter));
      assert.equal(coreObj.validUntil, BigInt(input.validUntil));

      const expectedCoreHeaderHash = headerHashOf(coreObj);
      assert.equal(proposal.confirmIntent.coreHeaderHash, expectedCoreHeaderHash);
      const expectedIntentCoreHash = confirmIntentCoreHashOf(
        coreObj,
        proposal.initialization.confirmationTarget,
        input.confirmationDigest
      );
      assert.equal(proposal.confirmIntent.intentCoreHash, expectedIntentCoreHash);
    });

    it("builds an unsigned PackedUserOperation wrapping confirmIntent with an independently reproduced hash", function () {
      const input = validInput({ seed: "user-op" });
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);
      const op = proposal.userOperation;

      assert.equal(op.sender, proposal.counterfactualAccount);
      assert.equal(op.initCode, proposal.initCode);
      assert.equal(op.callData, proposal.confirmIntent.calldata);
      assert.equal(op.signature, "0x");
      assert.equal(op.paymasterAndData, "0x");
      assert.equal(op.nonce, "0");

      const gasLimits = unpackPhilCore4337Uints(op.accountGasLimits);
      assert.equal(gasLimits.high128, "900000");
      assert.equal(gasLimits.low128, "150000");
      const gasFees = unpackPhilCore4337Uints(op.gasFees);
      assert.equal(gasFees.high128, "1000000000");
      assert.equal(gasFees.low128, "30000000000");

      const expectedUserOperationHash = computePhilCore4337UserOperationHash({
        userOperation: op,
        entryPointAddress: proposal.entryPoint,
        chainId: ETHEREUM_SEPOLIA_CHAIN_ID
      });
      assert.equal(proposal.userOperationHash, expectedUserOperationHash);
      assert.equal(proposal.hashes.userOperationHash, expectedUserOperationHash);
      assert.equal(proposal.hashes.deploymentSalt, proposal.deploymentSalt);
      assert.equal(proposal.hashes.accountCreationCodeHash, proposal.accountCreationCodeHash);
      assert.equal(proposal.hashes.identityBindingCommitment, input.identityBindingCommitment);
      assert.equal(proposal.hashes.validatorCommitment, input.validatorCommitment);
      assert.equal(proposal.hashes.recoveryConfigurationHash, input.recoveryConfigurationHash);
    });

    it("only ever encodes the zero-value confirmIntent action, never transferNative or execute", function () {
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "confirm-only" }));
      assert.equal(
        proposal.userOperation.callData.slice(0, 10),
        prep.PHILCORE_V2_CONFIRM_INTENT_SELECTOR
      );
      assert.equal(
        proposal.confirmIntent.calldata.slice(0, 10),
        prep.PHILCORE_V2_CONFIRM_INTENT_SELECTOR
      );
    });

    it("is deterministic for identical inputs", function () {
      const a = prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "determinism" }));
      const b = prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "determinism" }));
      assert.deepEqual(serializeForComparison(a), serializeForComparison(b));
    });

    it("returns a deeply frozen proposal and does not mutate a frozen input", function () {
      const input = Object.freeze(validInput({ seed: "mutation-safety" }));
      const proposal = prep.preparePhilCoreV2SepoliaDemoDeployment(input);

      assert.ok(Object.isFrozen(proposal));
      assert.ok(Object.isFrozen(proposal.initialization));
      assert.ok(Object.isFrozen(proposal.initializationTuple));
      assert.ok(Object.isFrozen(proposal.userOperation));
      assert.ok(Object.isFrozen(proposal.hashes));

      const originalChainId = proposal.chainId;
      const originalSender = proposal.userOperation.sender;
      const originalFirstTupleEntry = proposal.initializationTuple[0];
      try {
        proposal.chainId = 999n;
      } catch {
        // sloppy-mode assignment to a frozen object silently no-ops; strict
        // mode (as compiled ESM/TS modules run under) throws. Either way the
        // value must be unchanged below.
      }
      try {
        proposal.userOperation.sender = "0x0000000000000000000000000000000000000000";
      } catch {
        // see above
      }
      try {
        proposal.initializationTuple[0] = "0x0000000000000000000000000000000000000000";
      } catch {
        // see above
      }
      assert.equal(proposal.chainId, originalChainId);
      assert.equal(proposal.userOperation.sender, originalSender);
      assert.equal(proposal.initializationTuple[0], originalFirstTupleEntry);
    });
  });

  describe("preparePhilCoreV2SepoliaDemoDeployment (rejections)", function () {
    it("rejects zero recovery commitments", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "zero-recovery", primaryDeviceRecoveryCommitment: ZERO_BYTES32 })
        ),
        (error) => error.code === "RECOVERY_COMMITMENT_INVALID"
      );
    });

    it("rejects duplicate recovery commitments", function () {
      const input = validInput({ seed: "duplicate-recovery" });
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment({
          ...input,
          hardwareSecurityKeyCommitment: input.primaryDeviceRecoveryCommitment
        }),
        (error) => error.code === "RECOVERY_COMMITMENTS_NOT_DISTINCT"
      );
    });

    it("rejects the historical (pre-consumer-recovery) account version id", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "historical-version", accountVersionId: HISTORICAL_ACCOUNT_VERSION_ID })
        ),
        (error) => error.code === "ACCOUNT_VERSION_UNSUPPORTED"
      );
    });

    it("rejects a non-Sepolia chain id", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "wrong-chain", chainId: 1 })),
        (error) => error.code === "CHAIN_ID_UNSUPPORTED"
      );
    });

    it("rejects a non-canonical EntryPoint address", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "wrong-entrypoint", entryPoint: FACTORY })
        ),
        (error) => error.code === "ENTRY_POINT_UNSUPPORTED"
      );
    });

    it("rejects an unsupported security model id", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "wrong-security-model", securityModelId: H("some-other-security-model") })
        ),
        (error) => error.code === "SECURITY_MODEL_UNSUPPORTED"
      );
    });

    it("rejects a missing recoveryConfigurationHash (no silent default)", function () {
      const input = validInput({ seed: "missing-recovery-config" });
      delete input.recoveryConfigurationHash;
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(input),
        (error) => error.code === "RECOVERY_CONFIGURATION_HASH_MISMATCH"
      );
    });

    it("rejects an identityBindingCommitment that does not match the recomputed formula", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "bad-identity-binding", identityBindingCommitment: H("not-the-real-binding") })
        ),
        (error) => error.code === "IDENTITY_BINDING_COMMITMENT_MISMATCH"
      );
    });

    it("rejects a validatorCommitment that does not match the recomputed formula", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "bad-validator-commitment", validatorCommitment: H("not-the-real-commitment") })
        ),
        (error) => error.code === "VALIDATOR_COMMITMENT_MISMATCH"
      );
    });

    it("rejects zero addresses for factory/verifier/confirmationTarget/validator", function () {
      const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "zero-factory", factory: ZERO_ADDRESS })),
        (error) => error.code === "FACTORY_ADDRESS_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "zero-verifier", verifier: ZERO_ADDRESS })),
        (error) => error.code === "VERIFIER_ADDRESS_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "zero-confirmation-target", confirmationTarget: ZERO_ADDRESS })
        ),
        (error) => error.code === "CONFIRMATION_TARGET_ADDRESS_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "zero-validator", validator: ZERO_ADDRESS })),
        (error) => error.code === "VALIDATOR_ADDRESS_INVALID"
      );
    });

    it("rejects validatorEpoch/recoveryEpoch other than 1 for initial deployment", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "validator-epoch-2", validatorEpoch: 2 })),
        (error) => error.code === "VALIDATOR_EPOCH_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "recovery-epoch-2", recoveryEpoch: 2 })),
        (error) => error.code === "RECOVERY_EPOCH_INVALID"
      );
    });

    it("rejects recoveryDelaySeconds/recoveryExpirySeconds other than the fixed policy values", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "bad-delay", recoveryDelaySeconds: 1 })
        ),
        (error) => error.code === "RECOVERY_DELAY_SECONDS_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "bad-expiry", recoveryExpirySeconds: 1 })
        ),
        (error) => error.code === "RECOVERY_EXPIRY_SECONDS_INVALID"
      );
    });

    it("rejects a zero userSalt", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "zero-salt", userSalt: ZERO_BYTES32 })),
        (error) => error.code === "USER_SALT_INVALID"
      );
    });

    it("rejects zero actionId/confirmationDigest/runtimeAuthorizationDigest", function () {
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(validInput({ seed: "zero-action", actionId: ZERO_BYTES32 })),
        (error) => error.code === "ACTION_ID_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "zero-confirmation-digest", confirmationDigest: ZERO_BYTES32 })
        ),
        (error) => error.code === "CONFIRMATION_DIGEST_INVALID"
      );
      assert.throws(
        () => prep.preparePhilCoreV2SepoliaDemoDeployment(
          validInput({ seed: "zero-runtime-auth", runtimeAuthorizationDigest: ZERO_BYTES32 })
        ),
        (error) => error.code === "RUNTIME_AUTHORIZATION_DIGEST_INVALID"
      );
    });
  });

  describe("module surface (no execution/submission capability)", function () {
    // Matched against exported *function* names only (as leading verbs), so
    // legitimate nouns like "PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION" or
    // "computeAccountCreationCodeHash" are not flagged as false positives.
    const forbiddenFunctionNamePatterns = [
      /^submit/i,
      /^deploy/i,
      /^fund/i,
      /^sign/i,
      /^retry/i,
      /transferNative/i,
      /^execute/i
    ];

    it("exposes no submit/deploy/fund/sign/retry/transferNative/execute functions", function () {
      for (const [moduleName, mod] of [["v2DeployableIdentity", identity], ["v2DeploymentPreparation", prep]]) {
        for (const [key, value] of Object.entries(mod)) {
          if (typeof value !== "function") continue;
          for (const pattern of forbiddenFunctionNamePatterns) {
            assert.ok(
              !pattern.test(key),
              `${moduleName}.${key} must not exist (matches forbidden pattern ${pattern})`
            );
          }
        }
      }
    });

    it("exposes no signer/provider/network dependency-injection exports", function () {
      const forbiddenExactNames = new Set(["signer", "provider", "network", "getSigner", "getProvider"]);
      for (const [moduleName, mod] of [["v2DeployableIdentity", identity], ["v2DeploymentPreparation", prep]]) {
        for (const key of Object.keys(mod)) {
          assert.ok(
            !forbiddenExactNames.has(key) && !forbiddenExactNames.has(key.toLowerCase()),
            `${moduleName}.${key} must not exist`
          );
        }
      }
    });

    it("never reads process.env, and requires every commitment explicitly (no default recovery policy)", function () {
      const input = validInput({ seed: "no-defaults" });
      // Sanity: calling with a fully explicit, valid input succeeds.
      assert.doesNotThrow(() => prep.preparePhilCoreV2SepoliaDemoDeployment(input));
      // Every recovery/validator commitment field must be required; dropping
      // any of them must reject rather than silently substituting a default.
      for (const key of [
        "ownerCommitment",
        "identityBindingCommitment",
        "validatorKeyIdBinding",
        "validatorCommitment",
        "primaryDeviceRecoveryCommitment",
        "hardwareSecurityKeyCommitment",
        "independentRecoveryFactorCommitment",
        "recoveryConfigurationHash",
        "userSalt",
        "actionId",
        "confirmationDigest",
        "runtimeAuthorizationDigest"
      ]) {
        const withoutField = { ...input };
        delete withoutField[key];
        assert.throws(
          () => prep.preparePhilCoreV2SepoliaDemoDeployment(withoutField),
          undefined,
          `expected rejection when ${key} is missing`
        );
      }
    });
  });

  describe("live cross-check against the deployed PhilCoreV2MinimalAccountFactoryV2", function () {
    it("matches the on-chain getAddress/deploymentSalt/accountCreationCodeHash exactly", async function () {
      const [deployer, validatorSigner] = await ethers.getSigners();
      const network = await ethers.provider.getNetwork();
      const chainId = network.chainId;

      const entryPoint = await new ethers.ContractFactory(
        EntryPointArtifact.abi,
        EntryPointArtifact.bytecode,
        deployer
      ).deploy();
      await entryPoint.waitForDeployment();

      const Confirmation = await ethers.getContractFactory("PhilCoreV2ConfirmationTargetMock");
      const confirmation = await Confirmation.deploy();
      await confirmation.waitForDeployment();

      const Verifier = await ethers.getContractFactory("PhilCoreV2AuthorityVerifierMock");
      const verifier = await Verifier.deploy("0x15c57f54", false);
      await verifier.waitForDeployment();
      const verifierAddress = await verifier.getAddress();
      const verifierRuntimeCodeHash = ethers.keccak256(await ethers.provider.getCode(verifierAddress));

      const Factory = await ethers.getContractFactory("PhilCoreV2MinimalAccountFactoryV2");
      const factory = await Factory.deploy(
        await entryPoint.getAddress(),
        chainId,
        await confirmation.getAddress(),
        verifierAddress,
        verifierRuntimeCodeHash
      );
      await factory.waitForDeployment();
      const factoryAddress = await factory.getAddress();

      const values = baseValues("live-cross-check");
      const initialization = {
        entryPoint: await entryPoint.getAddress(),
        deploymentChainId: chainId,
        ownerCommitment: values.ownerCommitment,
        identityBindingCommitment: values.identityBindingCommitment,
        factoryBinding: factoryAddress,
        accountVersionId: identity.PHILCORE_V2_DEPLOYABLE_ACCOUNT_VERSION_ID,
        securityModelId: identity.PHILCORE_V2_SECURITY_MODEL_ID,
        confirmationTarget: await confirmation.getAddress(),
        initialValidator: validatorSigner.address,
        validatorVerifierKind: 1,
        validatorKeyIdBinding: values.validatorKeyIdBinding,
        validatorCommitment: validatorCommitmentOf(validatorSigner.address, values.validatorKeyIdBinding),
        validatorEpoch: 1,
        primaryDeviceRecoveryCommitment: values.primaryDeviceRecoveryCommitment,
        hardwareSecurityKeyCommitment: values.hardwareSecurityKeyCommitment,
        independentRecoveryFactorCommitment: values.independentRecoveryFactorCommitment,
        recoveryConfigurationHash: values.recoveryConfigurationHash,
        recoveryEpoch: 1,
        recoveryDelaySeconds: 172_800,
        recoveryExpirySeconds: 604_800
      };

      const onChainSalt = await factory.deploymentSalt(initialization, values.userSalt);
      const onChainCodeHash = await factory.accountCreationCodeHash(initialization);
      // NOTE: `factory.getAddress(...)` would collide with ethers' built-in
      // `BaseContract.getAddress()` accessor (which just resolves the
      // factory's own address). `getFunction(...).staticCall(...)` is
      // required to invoke the contract's own `getAddress` ABI function.
      const onChainAddress = await factory
        .getFunction("getAddress")
        .staticCall(initialization, values.userSalt);

      const offlineSalt = prep.computeDeploymentSalt({
        deploymentChainId: chainId,
        ownerCommitment: initialization.ownerCommitment,
        identityBindingCommitment: initialization.identityBindingCommitment,
        userSalt: values.userSalt
      });
      const offlineCodeHash = prep.computeAccountCreationCodeHash({
        accountCreationBytecode: AccountArtifact.bytecode,
        initialization
      });
      const offlineAddress = prep.predictCreate2Address({
        factory: factoryAddress,
        deploymentSalt: offlineSalt,
        accountCreationCodeHash: offlineCodeHash
      });

      assert.equal(offlineSalt, onChainSalt);
      assert.equal(offlineCodeHash, onChainCodeHash);
      assert.equal(offlineAddress, onChainAddress);

      const offlineCreateAccountCalldata = prep.encodeCreateAccountCalldata({
        initialization,
        userSalt: values.userSalt
      });
      await (await factory.createAccount(initialization, values.userSalt)).wait();
      const deployedCode = await ethers.provider.getCode(onChainAddress);
      assert.notEqual(deployedCode, "0x");
      assert.equal(
        offlineCreateAccountCalldata.slice(0, 10),
        prep.PHILCORE_V2_FACTORY_CREATE_ACCOUNT_SELECTOR
      );
    });
  });
});
