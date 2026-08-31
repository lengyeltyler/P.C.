require("tsx/cjs");

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const {
  AbiCoder,
  id,
  keccak256,
  toUtf8Bytes
} = require("ethers");

const {
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_PURPOSE,
  PHILCORE_V2_SECURITY_MODEL_ID,
  PHILCORE_V2_TYPE,
  PHILCORE_V2_TYPEHASH,
  composePhilCoreV2Nonce,
  computePhilCoreV2ApplicationContextHash,
  computePhilCoreV2DomainSeparator,
  computePhilCoreV2FundLifecycleDigest,
  computePhilCoreV2IntentCoreHash,
  decomposePhilCoreV2Nonce,
  encodePhilCoreV2Intent
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_AUTHORIZATION_TYPE,
  PHILCORE_V2_AUTHORIZATION_TYPEHASH,
  PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION,
  PHILCORE_V2_RECOVERY_FACTOR_BITMAP,
  PHILCORE_V2_RECOVERY_FACTOR_ROLE,
  PHILCORE_V2_RECOVERY_THRESHOLD,
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY,
  PHILCORE_V2_VALIDATOR_VERIFIER_KIND,
  assertPhilCoreV2AuthorityEpoch,
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2CombinedCancellationDigest,
  computePhilCoreV2ConfigRotationDigest,
  computePhilCoreV2ProofBindingHash,
  computePhilCoreV2RecoveryConfigurationHash,
  computePhilCoreV2RecoveryFactorCommitment,
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2RuntimeAuthorizationDigest,
  computePhilCoreV2ValidatorCommitment,
  computePhilCoreV2ValidatorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  buildO32VectorPackage,
  stringify
} = require("../../scripts/cryptography/generate-o32-v2-vectors.cjs");

const abiCoder = AbiCoder.defaultAbiCoder();
const H = (value) => keccak256(toUtf8Bytes(value));
const ROOT = path.resolve(__dirname, "../..");
const VECTOR_PATH = path.join(
  ROOT,
  "config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json"
);

const ACCOUNT = "0x1000000000000000000000000000000000000001";
const ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const RECIPIENT = "0x2000000000000000000000000000000000000002";
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const VALIDATOR_KEY_ID_BINDING =
  "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809";

function applicationContext() {
  return {
    applicationIdHash: H("o32:application"),
    originHash: H("o32:origin"),
    sessionIdHash: H("o32:session"),
    capabilityGrantIdHash: H("o32:capability"),
    policyDecisionIdHash: H("o32:policy")
  };
}

function fundLifecycle() {
  return {
    lifecycleSchemaHash: H("philcore-test-fund-lifecycle-v1"),
    account: ACCOUNT,
    asset: "0x0000000000000000000000000000000000000000",
    tokenId: 0n,
    maximumFundingOrHolding: 10_000_000n,
    maximumStranded: 1_000n,
    residualRecipient: RECIPIENT,
    expectedPostOperationBalance: 9_000_000n,
    expectedFinalBalance: 0n,
    releaseRouteHash: H("o32:release-route"),
    simulationEvidenceHash: H("o32:simulation")
  };
}

function nativeIntent(overrides = {}) {
  const base = {
    header: {
      specificationVersion: PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      actionType: PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER,
      actionId: H("o32:action:1"),
      purpose: PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      ownerCommitment: H("o32:owner-commitment"),
      chainId: 11155111n,
      entryPoint: ENTRYPOINT,
      account: ACCOUNT,
      nonceKey: PHILCORE_V2_NONCE_KEY.ORDINARY,
      nonceSequence: 7n,
      validatorEpoch: 3n,
      recoveryEpoch: 2n,
      applicationContextHash:
        computePhilCoreV2ApplicationContextHash(applicationContext()),
      fundLifecycleDigest:
        computePhilCoreV2FundLifecycleDigest(fundLifecycle()),
      maxTotalFeeWei: 5_000_000_000_000n,
      validAfter: 1_800_000_000n,
      validUntil: 1_800_000_300n
    },
    payload: {
      kind: "NATIVE_TRANSFER",
      recipient: RECIPIENT,
      amountWei: 1_234_567n
    }
  };
  return {
    ...base,
    ...overrides,
    header: { ...base.header, ...(overrides.header ?? {}) },
    payload: { ...base.payload, ...(overrides.payload ?? {}) }
  };
}

function proofBinding(overrides = {}) {
  return {
    proofTypeHash: H("stwo-unlock-keccak-v1"),
    proofInputHash: H("o32:proof-input"),
    proofArtifactDigest: H("o32:proof-artifact"),
    nullifier: H("o32:nullifier"),
    ...overrides
  };
}

function runtimeAuthorization(intentCoreHash, overrides = {}) {
  const proofBindingHash = computePhilCoreV2ProofBindingHash(proofBinding());
  return {
    intentCoreHash,
    proofBindingHash,
    policyDecisionHash: H("o32:runtime-policy-decision"),
    approvalEvidenceHash: H("o32:approval-evidence"),
    userPresenceEvidenceHash: H("o32:user-presence-evidence"),
    ...overrides
  };
}

function authorizationChain(intent = nativeIntent(), overrides = {}) {
  const intentCoreHash = computePhilCoreV2IntentCoreHash(intent);
  const runtimeInput = runtimeAuthorization(
    intentCoreHash,
    overrides.runtimeAuthorization
  );
  const runtimeAuthorizationDigest =
    computePhilCoreV2RuntimeAuthorizationDigest(runtimeInput);
  const authorizedIntentHash = computePhilCoreV2AuthorizedIntentHash({
    intentCoreHash,
    runtimeAuthorizationDigest
  });
  const validator = {
    authorizedIntentHash,
    userOperationHash: H("o32:user-operation-hash-binding"),
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
    validatorEpoch: intent.header.validatorEpoch,
    recoveryEpoch: intent.header.recoveryEpoch,
    ...overrides.validator
  };
  const domain = {
    chainId: intent.header.chainId,
    account: intent.header.account,
    ...overrides.domain
  };
  return {
    intentCoreHash,
    proofBindingHash: runtimeInput.proofBindingHash,
    runtimeAuthorizationDigest,
    authorizedIntentHash,
    validator: computePhilCoreV2ValidatorDigest(domain, validator)
  };
}

function recoveryFactor(role, overrides = {}) {
  const webauthn = role !== PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR;
  return {
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    role,
    verifierKind: webauthn
      ? PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256
      : PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1,
    publicVerificationMaterialHash: H(`o32:factor-public-material:${role}`),
    rpIdHash: webauthn ? H("philcore.test") : `0x${"00".repeat(32)}`,
    originPolicyHash: webauthn
      ? H("https://philcore.test")
      : `0x${"00".repeat(32)}`,
    userVerificationPolicy: webauthn
      ? PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED
      : PHILCORE_V2_USER_VERIFICATION_POLICY.NOT_APPLICABLE,
    credentialGeneration: 1n,
    ...overrides
  };
}

function recoveryConfiguration(overrides = {}) {
  return {
    configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION,
    threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
    primaryDeviceCommitment: computePhilCoreV2RecoveryFactorCommitment(
      recoveryFactor(PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE)
    ),
    hardwareSecurityKeyCommitment:
      computePhilCoreV2RecoveryFactorCommitment(
        recoveryFactor(PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY)
      ),
    recoveryFactorCommitment: computePhilCoreV2RecoveryFactorCommitment(
      recoveryFactor(PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR)
    ),
    ...overrides
  };
}

describe("O.32 V2 cryptographic foundation", function () {
  describe("intent core encoding and hashing", function () {
    it("locks exact type strings and their keccak256 type hashes", function () {
      for (const [name, value] of Object.entries(PHILCORE_V2_TYPE)) {
        assert.equal(PHILCORE_V2_TYPEHASH[name], id(value), name);
      }
      assert.match(PHILCORE_V2_TYPE.INTENT_CORE_HEADER, /uint192 nonceKey/);
      assert.match(PHILCORE_V2_TYPE.INTENT_CORE_HEADER, /uint64 validatorEpoch/);
      assert.match(PHILCORE_V2_TYPE.INTENT_CORE_HEADER, /uint64 recoveryEpoch/);
    });

    it("uses exact ABI encoding and an independently reproduced native-transfer hash", function () {
      const input = nativeIntent();
      const encoded = encodePhilCoreV2Intent(input);
      const expectedHeaderEncoding = abiCoder.encode(
        [
          "bytes32",
          "uint8",
          "bytes32",
          "uint8",
          "bytes32",
          "bytes32",
          "bytes32",
          "uint256",
          "address",
          "address",
          "uint192",
          "uint64",
          "uint64",
          "uint64",
          "bytes32",
          "bytes32",
          "uint256",
          "uint48",
          "uint48"
        ],
        [
          PHILCORE_V2_TYPEHASH.INTENT_CORE_HEADER,
          input.header.specificationVersion,
          input.header.securityModelId,
          input.header.actionType,
          input.header.actionId,
          input.header.purpose,
          input.header.ownerCommitment,
          input.header.chainId,
          input.header.entryPoint,
          input.header.account,
          input.header.nonceKey,
          input.header.nonceSequence,
          input.header.validatorEpoch,
          input.header.recoveryEpoch,
          input.header.applicationContextHash,
          input.header.fundLifecycleDigest,
          input.header.maxTotalFeeWei,
          input.header.validAfter,
          input.header.validUntil
        ]
      );
      const expectedHeaderHash = keccak256(expectedHeaderEncoding);
      const expectedActionEncoding = abiCoder.encode(
        ["bytes32", "bytes32", "address", "uint256"],
        [
          PHILCORE_V2_TYPEHASH.NATIVE_TRANSFER,
          expectedHeaderHash,
          input.payload.recipient,
          input.payload.amountWei
        ]
      );
      assert.equal(encoded.coreHeaderEncoding, expectedHeaderEncoding);
      assert.equal(encoded.coreHeaderHash, expectedHeaderHash);
      assert.equal(encoded.actionEncoding, expectedActionEncoding);
      assert.equal(encoded.intentCoreHash, keccak256(expectedActionEncoding));
    });

    it("changes the hash for amount, recipient, chain, account, expiry, and nonce", function () {
      const canonical = computePhilCoreV2IntentCoreHash(nativeIntent());
      const mutations = [
        nativeIntent({ payload: { amountWei: 1_234_568n } }),
        nativeIntent({
          payload: {
            recipient: "0x3000000000000000000000000000000000000003"
          }
        }),
        nativeIntent({ header: { chainId: 1n } }),
        nativeIntent({
          header: {
            account: "0x4000000000000000000000000000000000000004"
          }
        }),
        nativeIntent({ header: { validUntil: 1_800_000_301n } }),
        nativeIntent({ header: { nonceSequence: 8n } })
      ];
      for (const mutation of mutations) {
        assert.notEqual(computePhilCoreV2IntentCoreHash(mutation), canonical);
      }
    });

    it("rejects wrong versions, purposes, lanes, payload types, and ambiguous validity", function () {
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          header: { specificationVersion: 2 }
        })),
        /specificationVersion_unsupported/
      );
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          header: { securityModelId: H("wrong") }
        })),
        /securityModelId_unsupported/
      );
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          header: { purpose: PHILCORE_V2_PURPOSE.REQUEST_RECOVERY }
        })),
        /purpose_not_allowed/
      );
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          header: { nonceKey: PHILCORE_V2_NONCE_KEY.RECOVERY }
        })),
        /nonceKey_not_allowed/
      );
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          payload: {
            kind: "ERC20_TRANSFER",
            token: "0x5000000000000000000000000000000000000005",
            recipient: RECIPIENT,
            amount: 1n
          }
        })),
        /payload_actionType_mismatch/
      );
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          header: { validUntil: 1_800_000_000n }
        })),
        /validity_range_invalid/
      );
      assert.throws(
        () => computePhilCoreV2IntentCoreHash(nativeIntent({
          header: { validUntil: 1_800_000_601n }
        })),
        /validity_lifetime_exceeded/
      );
    });

    it("hashes application and lifecycle contexts without optional serialization", function () {
      const context = applicationContext();
      const lifecycle = fundLifecycle();
      const contextHash = computePhilCoreV2ApplicationContextHash(context);
      const lifecycleHash = computePhilCoreV2FundLifecycleDigest(lifecycle);
      assert.equal(contextHash.length, 66);
      assert.equal(lifecycleHash.length, 66);
      assert.notEqual(
        computePhilCoreV2ApplicationContextHash({
          ...context,
          sessionIdHash: H("o32:other-session")
        }),
        contextHash
      );
      assert.notEqual(
        computePhilCoreV2FundLifecycleDigest({
          ...lifecycle,
          maximumStranded: 1001n
        }),
        lifecycleHash
      );
      assert.throws(
        () => computePhilCoreV2FundLifecycleDigest({
          ...lifecycle,
          maximumStranded: lifecycle.maximumFundingOrHolding + 1n
        }),
        /maximumStranded_exceeds/
      );
    });

    it("uses a standard account-and-chain EIP-712 domain", function () {
      const first = computePhilCoreV2DomainSeparator({
        chainId: 11155111n,
        account: ACCOUNT
      });
      assert.notEqual(
        computePhilCoreV2DomainSeparator({ chainId: 1n, account: ACCOUNT }),
        first
      );
      assert.notEqual(
        computePhilCoreV2DomainSeparator({
          chainId: 11155111n,
          account: "0x4000000000000000000000000000000000000004"
        }),
        first
      );
    });

    it("canonically encodes every fixed V2 action schema", function () {
      const base = nativeIntent();
      const factorCommitments = recoveryConfiguration();
      const cases = [
        [
          PHILCORE_V2_ACTION_TYPE.CONFIRM,
          PHILCORE_V2_NONCE_KEY.ORDINARY,
          PHILCORE_V2_PURPOSE.CONFIRM_ACTION,
          "CONFIRM",
          {
            kind: "CONFIRM",
            confirmationTarget: RECIPIENT,
            confirmationDigest: H("o32:confirmation")
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER,
          PHILCORE_V2_NONCE_KEY.ORDINARY,
          PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
          "NATIVE_TRANSFER",
          base.payload
        ],
        [
          PHILCORE_V2_ACTION_TYPE.ERC20_TRANSFER,
          PHILCORE_V2_NONCE_KEY.ORDINARY,
          PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
          "ERC20_TRANSFER",
          {
            kind: "ERC20_TRANSFER",
            token: "0x5000000000000000000000000000000000000005",
            recipient: RECIPIENT,
            amount: 5n
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.ERC721_SAFE_TRANSFER,
          PHILCORE_V2_NONCE_KEY.ORDINARY,
          PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
          "ERC721_SAFE_TRANSFER",
          {
            kind: "ERC721_SAFE_TRANSFER",
            token: "0x5000000000000000000000000000000000000005",
            recipient: RECIPIENT,
            tokenId: 7n,
            receiverDataHash: H("o32:erc721-data")
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.ERC1155_SAFE_TRANSFER,
          PHILCORE_V2_NONCE_KEY.ORDINARY,
          PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
          "ERC1155_SAFE_TRANSFER",
          {
            kind: "ERC1155_SAFE_TRANSFER",
            token: "0x5000000000000000000000000000000000000005",
            recipient: RECIPIENT,
            tokenId: 8n,
            amount: 9n,
            receiverDataHash: H("o32:erc1155-data")
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.ENTRYPOINT_DEPOSIT_WITHDRAWAL,
          PHILCORE_V2_NONCE_KEY.ORDINARY,
          PHILCORE_V2_PURPOSE.WITHDRAW_DEPOSIT,
          "ENTRYPOINT_DEPOSIT_WITHDRAWAL",
          {
            kind: "ENTRYPOINT_DEPOSIT_WITHDRAWAL",
            recipient: RECIPIENT,
            amountWei: 10n
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.VALIDATOR_ROTATION,
          PHILCORE_V2_NONCE_KEY.MAINTENANCE,
          PHILCORE_V2_PURPOSE.ROTATE_VALIDATOR,
          "VALIDATOR_ROTATION",
          {
            kind: "VALIDATOR_ROTATION",
            proposedValidator:
              "0x6000000000000000000000000000000000000006",
            proposedValidatorKeyIdBinding: H("o32:new-validator"),
            proposedValidatorEpoch: 4n
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
          PHILCORE_V2_NONCE_KEY.RECOVERY,
          PHILCORE_V2_PURPOSE.REQUEST_RECOVERY,
          "RECOVERY_REQUEST",
          {
            kind: "RECOVERY_REQUEST",
            proposedValidator:
              "0x6000000000000000000000000000000000000006",
            proposedValidatorKeyIdBinding: H("o32:recovered-validator"),
            proposedValidatorEpoch: 4n,
            recoveryRequestSalt: H("o32:recovery-request")
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL,
          PHILCORE_V2_NONCE_KEY.RECOVERY,
          PHILCORE_V2_PURPOSE.CANCEL_RECOVERY,
          "RECOVERY_CANCEL",
          {
            kind: "RECOVERY_CANCEL",
            recoveryRequestId: H("o32:recovery-request-id")
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
          PHILCORE_V2_NONCE_KEY.RECOVERY,
          PHILCORE_V2_PURPOSE.ROTATE_RECOVERY_CONFIG,
          "RECOVERY_CONFIG_ROTATION_REQUEST",
          {
            kind: "RECOVERY_CONFIG_ROTATION_REQUEST",
            proposedRecoveryConfigHash: H("o32:new-recovery-config"),
            proposedPrimaryDeviceCommitment:
              factorCommitments.primaryDeviceCommitment,
            proposedHardwareSecurityKeyCommitment:
              factorCommitments.hardwareSecurityKeyCommitment,
            proposedRecoveryFactorCommitment:
              factorCommitments.recoveryFactorCommitment,
            proposedRecoveryEpoch: 3n
          }
        ],
        [
          PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_CANCEL,
          PHILCORE_V2_NONCE_KEY.RECOVERY,
          PHILCORE_V2_PURPOSE.CANCEL_RECOVERY_CONFIG_ROTATION,
          "RECOVERY_CONFIG_ROTATION_CANCEL",
          {
            kind: "RECOVERY_CONFIG_ROTATION_CANCEL",
            recoveryConfigRotationRequestId:
              H("o32:recovery-config-rotation-id")
          }
        ]
      ];

      const hashes = new Set();
      for (const [actionType, nonceKey, purpose, typeName, payload] of cases) {
        const encoded = encodePhilCoreV2Intent(nativeIntent({
          header: {
            actionType,
            nonceKey,
            purpose,
            validUntil: actionType >= PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST
              ? 1_800_003_600n
              : 1_800_000_300n
          },
          payload
        }));
        assert.equal(
          encoded.actionEncoding.slice(0, 66),
          PHILCORE_V2_TYPEHASH[typeName]
        );
        hashes.add(encoded.intentCoreHash);
      }
      assert.equal(hashes.size, cases.length);
    });

    it("rejects skipped validator or recovery epochs in transition intents", function () {
      assert.throws(
        () => encodePhilCoreV2Intent(nativeIntent({
          header: {
            actionType: PHILCORE_V2_ACTION_TYPE.VALIDATOR_ROTATION,
            nonceKey: PHILCORE_V2_NONCE_KEY.MAINTENANCE,
            purpose: PHILCORE_V2_PURPOSE.ROTATE_VALIDATOR
          },
          payload: {
            kind: "VALIDATOR_ROTATION",
            proposedValidator:
              "0x6000000000000000000000000000000000000006",
            proposedValidatorKeyIdBinding: H("o32:new-validator"),
            proposedValidatorEpoch: 5n
          }
        })),
        /proposedValidatorEpoch_must_equal_current_plus_one/
      );
      assert.throws(
        () => encodePhilCoreV2Intent(nativeIntent({
          header: {
            actionType:
              PHILCORE_V2_ACTION_TYPE.RECOVERY_CONFIG_ROTATION_REQUEST,
            nonceKey: PHILCORE_V2_NONCE_KEY.RECOVERY,
            purpose: PHILCORE_V2_PURPOSE.ROTATE_RECOVERY_CONFIG,
            validUntil: 1_800_003_600n
          },
          payload: {
            kind: "RECOVERY_CONFIG_ROTATION_REQUEST",
            proposedRecoveryConfigHash: H("o32:new-recovery-config"),
            proposedPrimaryDeviceCommitment: H("o32:primary"),
            proposedHardwareSecurityKeyCommitment: H("o32:hardware"),
            proposedRecoveryFactorCommitment: H("o32:recovery"),
            proposedRecoveryEpoch: 4n
          }
        })),
        /proposedRecoveryEpoch_must_equal_current_plus_one/
      );
    });
  });

  describe("nonce composition", function () {
    it("round-trips ERC-4337 keyed nonces without overlap", function () {
      for (const key of [
        PHILCORE_V2_NONCE_KEY.ORDINARY,
        PHILCORE_V2_NONCE_KEY.MAINTENANCE,
        PHILCORE_V2_NONCE_KEY.RECOVERY
      ]) {
        const nonce = composePhilCoreV2Nonce({ key, sequence: 42n });
        assert.deepEqual(decomposePhilCoreV2Nonce(nonce), {
          key,
          sequence: 42n
        });
      }
      assert.notEqual(
        composePhilCoreV2Nonce({ key: 0n, sequence: 1n }),
        composePhilCoreV2Nonce({ key: 1n, sequence: 1n })
      );
    });
  });

  describe("Runtime authorization and validator binding", function () {
    it("locks exact authorization type hashes", function () {
      for (const [name, value] of Object.entries(PHILCORE_V2_AUTHORIZATION_TYPE)) {
        assert.equal(PHILCORE_V2_AUTHORIZATION_TYPEHASH[name], id(value), name);
      }
    });

    it("builds a noncircular intent -> Runtime -> authorized intent -> validator chain", function () {
      const chain = authorizationChain();
      for (const value of [
        chain.intentCoreHash,
        chain.proofBindingHash,
        chain.runtimeAuthorizationDigest,
        chain.authorizedIntentHash,
        chain.validator.structHash,
        chain.validator.domainSeparator,
        chain.validator.digest
      ]) {
        assert.match(value, /^0x[0-9a-f]{64}$/);
      }
      assert.notEqual(chain.intentCoreHash, chain.runtimeAuthorizationDigest);
      assert.notEqual(
        chain.runtimeAuthorizationDigest,
        chain.authorizedIntentHash
      );
      assert.notEqual(chain.authorizedIntentHash, chain.validator.digest);
    });

    it("binds proof, policy, approval, and presence into Runtime authorization", function () {
      const base = authorizationChain();
      for (const mutation of [
        { proofBindingHash: H("other-proof") },
        { policyDecisionHash: H("other-policy") },
        { approvalEvidenceHash: H("other-approval") },
        { userPresenceEvidenceHash: H("other-presence") }
      ]) {
        const changed = authorizationChain(
          nativeIntent(),
          { runtimeAuthorization: mutation }
        );
        assert.notEqual(
          changed.runtimeAuthorizationDigest,
          base.runtimeAuthorizationDigest
        );
        assert.notEqual(changed.validator.digest, base.validator.digest);
      }
    });

    it("binds the UserOperation hash, validator, key ID, and both epochs", function () {
      const base = authorizationChain();
      const mutations = [
        { userOperationHash: H("another-user-operation") },
        {
          validator: "0x6000000000000000000000000000000000000006"
        },
        { validatorKeyIdBinding: H("another-validator-key-id") },
        { validatorEpoch: 4n },
        { recoveryEpoch: 3n }
      ];
      for (const validator of mutations) {
        assert.notEqual(
          authorizationChain(nativeIntent(), { validator }).validator.digest,
          base.validator.digest
        );
      }
    });

    it("transitively binds EntryPoint and directly domain-binds account and chain", function () {
      const base = authorizationChain();
      const wrongEntryPoint = authorizationChain(nativeIntent({
        header: {
          entryPoint: "0x7000000000000000000000000000000000000007"
        }
      }));
      const wrongAccount = authorizationChain(nativeIntent({
        header: {
          account: "0x4000000000000000000000000000000000000004"
        }
      }));
      const wrongChain = authorizationChain(nativeIntent({
        header: { chainId: 1n }
      }));
      assert.notEqual(wrongEntryPoint.validator.digest, base.validator.digest);
      assert.notEqual(wrongAccount.validator.digest, base.validator.digest);
      assert.notEqual(wrongChain.validator.digest, base.validator.digest);
    });

    it("creates only a validator commitment and rejects unsupported verifier kinds", function () {
      const commitment = computePhilCoreV2ValidatorCommitment({
        verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
        validator: VALIDATOR,
        validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING
      });
      assert.match(commitment, /^0x[0-9a-f]{64}$/);
      assert.throws(
        () => computePhilCoreV2ValidatorCommitment({
          verifierKind: 2,
          validator: VALIDATOR,
          validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING
        }),
        /validatorVerifierKind_unsupported/
      );
    });
  });

  describe("recovery commitments and epoch replay protection", function () {
    it("creates distinct role-bound commitments and one exact 2-of-3 configuration", function () {
      const configuration = recoveryConfiguration();
      const commitments = [
        configuration.primaryDeviceCommitment,
        configuration.hardwareSecurityKeyCommitment,
        configuration.recoveryFactorCommitment
      ];
      assert.equal(new Set(commitments).size, 3);
      const configurationHash =
        computePhilCoreV2RecoveryConfigurationHash(configuration);
      assert.match(configurationHash, /^0x[0-9a-f]{64}$/);
      assert.throws(
        () => computePhilCoreV2RecoveryConfigurationHash({
          ...configuration,
          recoveryFactorCommitment: configuration.primaryDeviceCommitment
        }),
        /commitments_must_be_unique/
      );
      assert.throws(
        () => computePhilCoreV2RecoveryConfigurationHash({
          ...configuration,
          threshold: 1
        }),
        /threshold_must_equal_two/
      );
    });

    it("binds factor role, verifier, public-material hash, policy, and generation", function () {
      const baseInput = recoveryFactor(
        PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE
      );
      const base = computePhilCoreV2RecoveryFactorCommitment(baseInput);
      for (const mutation of [
        {
          role: PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY
        },
        {
          publicVerificationMaterialHash: H("different-factor-material")
        },
        { originPolicyHash: H("different-origin-policy") },
        { credentialGeneration: 2n }
      ]) {
        assert.notEqual(
          computePhilCoreV2RecoveryFactorCommitment({
            ...baseInput,
            ...mutation
          }),
          base
        );
      }
      assert.throws(
        () => computePhilCoreV2RecoveryFactorCommitment({
          ...baseInput,
          rpIdHash: `0x${"00".repeat(32)}`
        }),
        /webauthn_policy_hashes_required/
      );
    });

    it("accepts only exact two-role bitmaps and binds the recovery epoch", function () {
      const chain = authorizationChain();
      const configurationHash =
        computePhilCoreV2RecoveryConfigurationHash(recoveryConfiguration());
      const domain = { chainId: 11155111n, account: ACCOUNT };
      const input = {
        authorizedIntentHash: chain.authorizedIntentHash,
        userOperationHash: H("o32:recovery-user-operation-binding"),
        recoveryConfigHash: configurationHash,
        recoveryEpoch: 2n,
        factorBitmap:
          PHILCORE_V2_RECOVERY_FACTOR_BITMAP.HARDWARE_AND_RECOVERY
      };
      const base = computePhilCoreV2RecoveryFactorDigest(domain, input);
      assert.notEqual(
        computePhilCoreV2RecoveryFactorDigest(domain, {
          ...input,
          recoveryEpoch: 3n
        }).digest,
        base.digest
      );
      for (const invalid of [1, 2, 4, 7]) {
        assert.throws(
          () => computePhilCoreV2RecoveryFactorDigest(domain, {
            ...input,
            factorBitmap: invalid
          }),
          /exactly_two_roles/
        );
      }
    });

    it("domain-separates threshold recovery, combined cancellation, and config rotation", function () {
      const chain = authorizationChain();
      const recoveryConfigHash =
        computePhilCoreV2RecoveryConfigurationHash(recoveryConfiguration());
      const domain = { chainId: 11155111n, account: ACCOUNT };
      const common = {
        authorizedIntentHash: chain.authorizedIntentHash,
        userOperationHash: H("o32:recovery-user-operation-binding"),
        validator: VALIDATOR,
        validatorEpoch: 3n,
        recoveryConfigHash,
        recoveryEpoch: 2n,
        factorBitmap:
          PHILCORE_V2_RECOVERY_FACTOR_BITMAP.HARDWARE_AND_RECOVERY
      };
      const recovery = computePhilCoreV2RecoveryFactorDigest(domain, common);
      const cancellation =
        computePhilCoreV2CombinedCancellationDigest(domain, common);
      const rotation = computePhilCoreV2ConfigRotationDigest(domain, {
        ...common,
        proposedRecoveryConfigHash: H("o32:proposed-recovery-config"),
        proposedRecoveryEpoch: 3n
      });
      assert.equal(new Set([
        recovery.digest,
        cancellation.digest,
        rotation.digest
      ]).size, 3);
      assert.throws(
        () => computePhilCoreV2ConfigRotationDigest(domain, {
          ...common,
          proposedRecoveryConfigHash: H("o32:proposed-recovery-config"),
          proposedRecoveryEpoch: 4n
        }),
        /current_plus_one/
      );
    });

    it("rejects stale and future validator or recovery epochs", function () {
      assert.equal(assertPhilCoreV2AuthorityEpoch({
        currentValidatorEpoch: 3n,
        currentRecoveryEpoch: 2n,
        suppliedValidatorEpoch: 3n,
        suppliedRecoveryEpoch: 2n
      }), true);
      for (const [field, value, error] of [
        ["suppliedValidatorEpoch", 2n, /validator_epoch_stale/],
        ["suppliedValidatorEpoch", 4n, /validator_epoch_future/],
        ["suppliedRecoveryEpoch", 1n, /recovery_epoch_stale/],
        ["suppliedRecoveryEpoch", 3n, /recovery_epoch_future/]
      ]) {
        assert.throws(
          () => assertPhilCoreV2AuthorityEpoch({
            currentValidatorEpoch: 3n,
            currentRecoveryEpoch: 2n,
            suppliedValidatorEpoch: 3n,
            suppliedRecoveryEpoch: 2n,
            [field]: value
          }),
          error
        );
      }
    });
  });

  describe("deterministic compatibility package", function () {
    it("is byte-for-byte current with the implementation", function () {
      const expected = stringify(buildO32VectorPackage());
      assert.equal(fs.readFileSync(VECTOR_PATH, "utf8"), expected);
      assert.doesNotThrow(() => childProcess.execFileSync(
        process.execPath,
        [
          path.join(
            ROOT,
            "scripts/cryptography/generate-o32-v2-vectors.cjs"
          ),
          "--check"
        ],
        {
          cwd: ROOT,
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"]
        }
      ));
    });

    it("locks all requested mutation and replay cases", function () {
      const vectors = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
      assert.equal(vectors.fixtureOnly, true);
      assert.equal(vectors.publicMutationCount, 0);
      assert.equal(vectors.canonicalModel.canonicalEncoding, "abi.encode");
      assert.equal(vectors.canonicalModel.packedEncodingAllowed, false);
      assert.equal(vectors.canonicalModel.personalSignAllowed, false);
      assert.equal(
        vectors.canonicalModel.arbitraryTypedDataApiExposed,
        false
      );

      const mutationIds = new Set(
        vectors.intentMutationVectors.map((vector) => vector.id)
      );
      for (const id of [
        "modified_amount",
        "modified_recipient",
        "modified_chain",
        "modified_account",
        "modified_expiry",
        "modified_nonce",
        "old_validator_epoch",
        "old_recovery_epoch"
      ]) {
        assert.equal(mutationIds.has(id), true, id);
      }
      for (const vector of vectors.intentMutationVectors) {
        assert.equal(vector.matchesValidIntentCoreHash, false, vector.id);
      }
      assert.equal(
        vectors.replayVectors.reusedNonce.expectedRuntimeResult,
        "REJECT_ALREADY_CONSUMED_ENTRYPOINT_NONCE"
      );
      assert.equal(
        vectors.replayVectors.reusedNonce.matchesOriginalHash,
        true
      );
      assert.equal(
        vectors.replayVectors.oldValidatorEpoch
          .matchesValidIntentCoreHash,
        false
      );
      assert.equal(
        vectors.replayVectors.oldRecoveryEpoch
          .matchesValidIntentCoreHash,
        false
      );
      assert.equal(
        vectors.replayVectors.wrongAccount.matchesValidIntentCoreHash,
        false
      );
      assert.equal(
        vectors.replayVectors.wrongChain.matchesValidIntentCoreHash,
        false
      );
    });

    it("contains commitment-only recovery fixtures and no authority artifacts", function () {
      const vectors = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
      assert.equal(
        vectors.recovery.invalidFactorCommitment
          .matchesRegisteredCommitment,
        false
      );
      assert.equal(
        vectors.recovery.staleRecoveryEpoch.matchesCurrentEpochDigest,
        false
      );
      assert.equal(
        new Set(Object.values(vectors.recovery.factorCommitments)).size,
        3
      );
      assert.deepEqual(
        Object.values(vectors.securityBoundary),
        Object.values(vectors.securityBoundary).map(() => false)
      );

      const {
        securityBoundary: _securityBoundary,
        ...artifactWithoutBoundaryDeclarations
      } = vectors;
      const serialized = JSON.stringify(artifactWithoutBoundaryDeclarations);
      for (const prohibited of [
        "phil_secret",
        "privateKey",
        "rawTransaction",
        "credential-bearing",
        "https://eth-",
        "/v2/"
      ]) {
        assert.equal(serialized.includes(prohibited), false, prohibited);
      }
    });
  });
});
