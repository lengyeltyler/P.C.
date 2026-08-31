require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const { ethers } = require("hardhat");
const EntryPointArtifact = require(
  "@account-abstraction/contracts/artifacts/EntryPoint.json"
);
const mod = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS,
  PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE,
  PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
  PHILCORE_V2_CONSUMER_SYNC_CLASS,
  computePhilCoreV2ConsumerRecoveryIndependenceBinding,
  computePhilCoreV2ConsumerRecoveryFactorCommitment,
  computePhilCoreV2Secp256k1PublicMaterialHash,
  validatePhilCoreV2ConsumerRecoveryRotation,
  validatePhilCoreV2ConsumerRecoveryProfile,
  validatePhilCoreV2ConsumerRecoveryFactorPolicy
} = mod;
const {
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  buildConsumerRecoveryWebAuthnFactorDescriptor,
  consumerRecoveryRegistrationPolicy,
  enrollOfflineRecoveryFactor,
  finalizeConsumerRecoveryWebAuthnEnrollment,
  inspectOfflineRecoveryExport
} = require(
  "../../apps/phil-device-sdk/src/runtime/consumerRecoveryEnrollment.ts"
);
const {
  buildO39ConsumerRecoveryFixturePackage
} = require(
  "../../scripts/cryptography/generate-o39-consumer-recovery-fixtures.cjs"
);

const ROOT = path.resolve(__dirname, "../..");
const FIXTURE_PATH = path.join(
  ROOT,
  "config/cryptography/O39_CONSUMER_RECOVERY_FIXTURES.json"
);
const fixtures = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));

function stringify(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function factors(profile) {
  return [
    {
      descriptor: profile.factors.primary.descriptor,
      independence: profile.factors.primary.independence
    },
    {
      descriptor: profile.factors.secondary.descriptor,
      independence: profile.factors.secondary.independence
    },
    {
      descriptor: profile.factors.offline.descriptor,
      independence: profile.factors.offline.independence,
      signer: profile.factors.offline.signer
    }
  ];
}

function clone(value) {
  return structuredClone(value);
}

function rebind(factor) {
  factor.descriptor.independenceBindingHash =
    computePhilCoreV2ConsumerRecoveryIndependenceBinding(factor.independence);
}

function spkiFromFixture(factor) {
  const prefix = ethers.getBytes(
    "0x3059301306072a8648ce3d020106082a8648ce3d03010703420004"
  );
  return ethers.hexlify(ethers.concat([prefix, factor.qx, factor.qy]));
}

function baseObservationWithoutStore() {
  const primary = fixtures.profiles.standard.factors.primary;
  return {
    role: 0,
    authenticatorClass:
      PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
    registrationVerified: true,
    productionVerified: true,
    userPresent: true,
    userVerified: true,
    credentialPublicKeySpki: spkiFromFixture(primary),
    credentialId: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    rpId: "recovery.philcore.example",
    origin: "https://recovery.philcore.example",
    backupEligible: false,
    backupState: false,
    attestationVerified: true,
    enrollmentCeremonyHash: ethers.id("O39:TEST:CEREMONY"),
    attestationEvidenceHash: ethers.id("O39:TEST:ATTESTATION"),
    custodyDomainCommitment: ethers.id("O39:TEST:CUSTODY"),
    credentialGeneration: 1n
  };
}

describe("O.39 consumer recovery model", function () {
  it("keeps the committed fixture package deterministic and secret-free", function () {
    assert.equal(
      fs.readFileSync(FIXTURE_PATH, "utf8"),
      stringify(buildO39ConsumerRecoveryFixturePackage())
    );
    assert.equal(fixtures.classification, "DETERMINISTIC_SYNTHETIC_TEST_ONLY");
    assert.equal(fixtures.publicMutationCount, 0);
    assert.equal(fixtures.secretsCommitted, false);
    assert.equal(fixtures.productionCredentialIdsCommitted, false);
    assert.equal(fixtures.productionSignaturesCommitted, false);
    const serialized = JSON.stringify(fixtures);
    assert.doesNotMatch(serialized, /privateScalar|privateKey|recoveryCode/);
  });

  it("freezes Standard and Enhanced profiles with exact 2-of-3 pairs", function () {
    for (const [name, profile] of Object.entries(fixtures.profiles)) {
      const validated = validatePhilCoreV2ConsumerRecoveryProfile({
        factors: factors(profile),
        executionValidator: profile.request.validator
      });
      assert.equal(validated.profile, name.toUpperCase());
      assert.equal(validated.recoveryConfigurationHash,
        profile.recoveryConfigurationHash);
      assert.deepEqual(profile.validPairs.map((pair) => pair.bitmap), [3, 5, 6]);
      assert.deepEqual(profile.validPairs.map((pair) => pair.roles),
        [[0, 1], [0, 2], [1, 2]]);
    }
  });

  it("initializes actual local accounts with both reviewed profile configurations", async function () {
    const [deployer, validator] = await ethers.getSigners();
    const entryPoint = await new ethers.ContractFactory(
      EntryPointArtifact.abi,
      EntryPointArtifact.bytecode,
      deployer
    ).deploy();
    await entryPoint.waitForDeployment();
    const confirmationTarget = await (
      await ethers.getContractFactory("PhilCoreV2ConfirmationTargetMock")
    ).deploy();
    await confirmationTarget.waitForDeployment();
    const verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
    const verifierHash = ethers.keccak256(
      await ethers.provider.getCode(await verifier.getAddress())
    );
    const factory = await (
      await ethers.getContractFactory("PhilCoreV2MinimalAccountFactoryV2")
    ).deploy(
      await entryPoint.getAddress(),
      31337,
      await confirmationTarget.getAddress(),
      await verifier.getAddress(),
      verifierHash
    );
    await factory.waitForDeployment();
    const abi = ethers.AbiCoder.defaultAbiCoder();
    const identityTypehash =
      "0x57f4660c20a425b4f07312eeeab81e83fc44cba5db3e7cc2fb8e1ef5d2d7afd8";
    const ownerScheme =
      "0xb891af6798d5e37aec3e66cdefd59ef16f633d0c539efd12ebfcf30d3cad6c4e";
    const validatorTypehash = ethers.id(
      "PhilCoreV2ValidatorCommitment(uint8 verifierKind,address validator,bytes32 validatorKeyIdBinding)"
    );
    for (const profile of Object.values(fixtures.profiles)) {
      const ownerCommitment = ethers.id(`O39:${profile.profile}:OWNER`);
      const validatorKeyIdBinding =
        ethers.id(`O39:${profile.profile}:VALIDATOR_KEY`);
      const roleCommitments = [
        profile.factors.primary.factorCommitment,
        profile.factors.secondary.factorCommitment,
        profile.factors.offline.factorCommitment
      ];
      const initialization = {
        entryPoint: await entryPoint.getAddress(),
        deploymentChainId: 31337,
        ownerCommitment,
        identityBindingCommitment: ethers.keccak256(abi.encode(
          ["bytes32", "uint8", "bytes32", "bytes32"],
          [identityTypehash, 1, ownerCommitment, ownerScheme]
        )),
        factoryBinding: await factory.getAddress(),
        accountVersionId: profile.request.accountVersionId,
        securityModelId: profile.request.securityModelId,
        confirmationTarget: await confirmationTarget.getAddress(),
        initialValidator: validator.address,
        validatorVerifierKind: 1,
        validatorKeyIdBinding,
        validatorCommitment: ethers.keccak256(abi.encode(
          ["bytes32", "uint8", "address", "bytes32"],
          [validatorTypehash, 1, validator.address, validatorKeyIdBinding]
        )),
        validatorEpoch: 1,
        primaryDeviceRecoveryCommitment: roleCommitments[0],
        hardwareSecurityKeyCommitment: roleCommitments[1],
        independentRecoveryFactorCommitment: roleCommitments[2],
        recoveryConfigurationHash: profile.recoveryConfigurationHash,
        recoveryEpoch: 1,
        recoveryDelaySeconds: 172800,
        recoveryExpirySeconds: 604800
      };
      const userSalt = ethers.id(`O39:${profile.profile}:USER_SALT`);
      const predicted = await factory.getFunction("getAddress").staticCall(
        initialization,
        userSalt
      );
      await (await factory.createAccount(initialization, userSalt)).wait();
      const account = await ethers.getContractAt(
        "PhilCoreV2MinimalAccountV2",
        predicted
      );
      const state = await account.accountSecurityState();
      assert.equal(state[7], profile.recoveryConfigurationHash);
      assert.deepEqual([...state.slice(8, 11)], roleCommitments);
    }
  });

  it("builds role-specific registration policy without profile ambiguity", function () {
    assert.equal(consumerRecoveryRegistrationPolicy({
      role: 0,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE
    }).authenticatorAttachment, "platform");
    assert.equal(consumerRecoveryRegistrationPolicy({
      role: 1,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.SECONDARY_PLATFORM_DEVICE
    }).authenticatorAttachment, "platform");
    assert.equal(consumerRecoveryRegistrationPolicy({
      role: 1,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY
    }).authenticatorAttachment, "cross-platform");
    assert.throws(() => consumerRecoveryRegistrationPolicy({
      role: 0,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY
    }), /role_authenticator_class_invalid/);
  });

  it("finalizes a verified device-bound WebAuthn enrollment behind secure storage", function () {
    const primary = fixtures.profiles.standard.factors.primary;
    let stored;
    const result = finalizeConsumerRecoveryWebAuthnEnrollment({
      role: 0,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
      registrationVerified: true,
      productionVerified: true,
      userPresent: true,
      userVerified: true,
      credentialPublicKeySpki: spkiFromFixture(primary),
      credentialId: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
      rpId: "recovery.philcore.example",
      origin: "https://recovery.philcore.example",
      backupEligible: false,
      backupState: false,
      attestationVerified: true,
      enrollmentCeremonyHash: ethers.id("O39:TEST:CEREMONY"),
      attestationEvidenceHash: ethers.id("O39:TEST:ATTESTATION"),
      custodyDomainCommitment: ethers.id("O39:TEST:CUSTODY"),
      credentialGeneration: 1n,
      storeCredentialId(input) {
        stored = input;
        return "secure-recovery-credential:role0:generation1";
      }
    });
    assert.equal(result.deployable, true);
    assert.equal(result.secureStorageReference,
      "secure-recovery-credential:role0:generation1");
    assert.equal(stored.credentialId.byteLength, 32);
    assert.equal("credentialId" in result, false);
    assert.match(result.warnings[0], /cannot prove separate/);
  });

  it("rejects synced, backup-eligible, malformed, or unverified enrollment", function () {
    const primary = fixtures.profiles.standard.factors.primary;
    const base = {
      role: 0,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
      registrationVerified: true,
      productionVerified: true,
      userPresent: true,
      userVerified: true,
      credentialPublicKeySpki: spkiFromFixture(primary),
      credentialId: new Uint8Array(32).fill(7),
      rpId: "recovery.philcore.example",
      origin: "https://recovery.philcore.example",
      backupEligible: false,
      backupState: false,
      attestationVerified: true,
      enrollmentCeremonyHash: ethers.id("O39:TEST:CEREMONY"),
      attestationEvidenceHash: ethers.id("O39:TEST:ATTESTATION"),
      custodyDomainCommitment: ethers.id("O39:TEST:CUSTODY"),
      credentialGeneration: 1n,
      storeCredentialId: () => "secure:test"
    };
    for (const mutation of [
      { backupEligible: true },
      { backupState: true }
    ]) {
      assert.throws(
        () => finalizeConsumerRecoveryWebAuthnEnrollment({
          ...base,
          ...mutation
        }),
        /synced_or_backup_eligible/
      );
    }
    assert.throws(
      () => finalizeConsumerRecoveryWebAuthnEnrollment({
        ...base,
        productionVerified: false
      }),
      /not_production_verified/
    );
    assert.throws(
      () => finalizeConsumerRecoveryWebAuthnEnrollment({
        ...base,
        credentialId: new Uint8Array(8)
      }),
      /credential_id_too_short/
    );
  });

  it("builds the canonical factor descriptor as a pure, non-durable extraction", function () {
    assert.equal(typeof buildConsumerRecoveryWebAuthnFactorDescriptor, "function");

    const observation = baseObservationWithoutStore();
    const built = buildConsumerRecoveryWebAuthnFactorDescriptor(observation);

    assert.deepEqual(Object.keys(built), [
      "factor",
      "commitmentInput",
      "credentialIdHash"
    ]);
    assert.equal("deployable" in built, false);
    assert.equal("secureStorageReference" in built, false);
    assert.equal("cryptographicallyEnforced" in built, false);
    assert.equal("locallyObserved" in built, false);
    assert.equal("userAttested" in built, false);
    assert.equal("warnings" in built, false);
    assert.equal("commitment" in built, false);
    assert.equal("credentialId" in built, false);
    assert.equal("credentialId" in built.factor.descriptor, false);
    assert.equal("credentialId" in built.commitmentInput, false);

    assert.equal(Object.isFrozen(built), true);
    assert.equal(Object.isFrozen(built.factor), true);

    let storeCredentialIdReads = 0;
    const hostileObservation = { ...observation };
    Object.defineProperty(hostileObservation, "storeCredentialId", {
      enumerable: true,
      configurable: true,
      get() {
        storeCredentialIdReads += 1;
        throw new Error("storeCredentialId must never be read by the builder");
      }
    });
    const builtFromHostile = buildConsumerRecoveryWebAuthnFactorDescriptor(
      hostileObservation
    );
    assert.equal(storeCredentialIdReads, 0);
    assert.deepEqual(builtFromHostile.commitmentInput, built.commitmentInput);
  });

  it("builder and finalizer produce byte-identical factor, descriptor, independence, and canonical commitment", function () {
    const observation = baseObservationWithoutStore();
    const built = buildConsumerRecoveryWebAuthnFactorDescriptor(observation);

    let stored;
    const finalized = finalizeConsumerRecoveryWebAuthnEnrollment({
      ...observation,
      storeCredentialId(input) {
        stored = input;
        return "secure-recovery-credential:role0:generation1";
      }
    });

    assert.deepEqual(built.factor, finalized.factor);
    assert.deepEqual(built.commitmentInput, finalized.commitmentInput);
    assert.deepEqual(built.factor.independence, finalized.factor.independence);
    assert.equal(built.credentialIdHash, finalized.credentialIdHash);
    assert.equal(
      computePhilCoreV2ConsumerRecoveryFactorCommitment(built.commitmentInput),
      computePhilCoreV2ConsumerRecoveryFactorCommitment(finalized.commitmentInput)
    );
    assert.equal(stored.credentialId.byteLength, observation.credentialId.byteLength);
    assert.notEqual(stored.credentialId, observation.credentialId);
    assert.deepEqual([...stored.credentialId], [...observation.credentialId]);
  });

  it("calls storage exactly once on success and never on pre-storage validation failure", function () {
    const observation = baseObservationWithoutStore();
    let calls = 0;
    finalizeConsumerRecoveryWebAuthnEnrollment({
      ...observation,
      storeCredentialId() {
        calls += 1;
        return "secure:once";
      }
    });
    assert.equal(calls, 1);

    let invalidCalls = 0;
    assert.throws(
      () => finalizeConsumerRecoveryWebAuthnEnrollment({
        ...observation,
        backupEligible: true,
        storeCredentialId() {
          invalidCalls += 1;
          return "secure:should-not-be-reached";
        }
      }),
      /synced_or_backup_eligible/
    );
    assert.equal(invalidCalls, 0);
  });

  it("preserves every existing finalizer claim, key, and deployability behavior unchanged", function () {
    const observation = baseObservationWithoutStore();
    let stored;
    const result = finalizeConsumerRecoveryWebAuthnEnrollment({
      ...observation,
      storeCredentialId(input) {
        stored = input;
        return "secure-recovery-credential:role0:generation1";
      }
    });
    assert.deepEqual(Object.keys(result), [
      "deployable",
      "factor",
      "commitmentInput",
      "credentialIdHash",
      "secureStorageReference",
      "cryptographicallyEnforced",
      "locallyObserved",
      "userAttested",
      "warnings"
    ]);
    assert.equal(result.deployable, true);
    assert.equal(result.secureStorageReference,
      "secure-recovery-credential:role0:generation1");
    assert.equal(stored.credentialId.byteLength, 32);
    assert.equal("credentialId" in result, false);
    assert.deepEqual(result.cryptographicallyEnforced, [
      "distinct credential public material and identifier commitment",
      "RP ID, origin policy, role, account/security version and generation",
      "user verification, device-bound backup flags and descriptor commitment"
    ]);
    assert.deepEqual(result.locallyObserved, [
      "platform attachment",
      "backup eligibility and backup state were both false",
      "approved attestation evidence was verified"
    ]);
    assert.deepEqual(result.userAttested, [
      "custody domain is independently controlled",
      "credential is not restored from the primary cloud or password-manager domain"
    ]);
    assert.match(result.warnings[0], /cannot prove separate/);
    assert.equal(Object.isFrozen(result), true);
    assert.equal(Object.isFrozen(result.factor), true);
  });

  it("derives the narrative attachment exclusively from the builder's canonical descriptor, with no post-builder authenticatorClass read", function () {
    const base = baseObservationWithoutStore();
    const { authenticatorClass: droppedAuthenticatorClass, ...rest } = base;
    void droppedAuthenticatorClass;

    let reads = 0;
    let calls = 0;
    const observation = {
      ...rest,
      storeCredentialId() {
        calls += 1;
        return "secure:attachment-consistency";
      }
    };
    Object.defineProperty(observation, "authenticatorClass", {
      enumerable: true,
      configurable: true,
      get() {
        reads += 1;
        if (reads > 4) {
          throw new Error("authenticatorClass must not be read a fifth time");
        }
        return PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE;
      }
    });

    const result = finalizeConsumerRecoveryWebAuthnEnrollment(observation);

    assert.equal(reads, 4);
    assert.equal(calls, 1);
    assert.equal(
      result.commitmentInput.authenticatorAttachmentPolicy,
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED
    );
    assert.equal(
      result.commitmentInput.attestationPolicy,
      PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
    );
    assert.equal(result.locallyObserved[0], "platform attachment");
  });

  it("locallyObserved attachment always agrees with the canonical descriptor's attachment policy", function () {
    const platformResult = finalizeConsumerRecoveryWebAuthnEnrollment({
      ...baseObservationWithoutStore(),
      storeCredentialId: () => "secure:platform-consistency"
    });
    assert.equal(
      platformResult.commitmentInput.authenticatorAttachmentPolicy,
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED
    );
    assert.equal(platformResult.locallyObserved[0], "platform attachment");

    const hardwareResult = finalizeConsumerRecoveryWebAuthnEnrollment({
      ...baseObservationWithoutStore(),
      role: 1,
      authenticatorClass:
        PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.EXTERNAL_HARDWARE_KEY,
      storeCredentialId: () => "secure:hardware-consistency"
    });
    assert.equal(
      hardwareResult.commitmentInput.authenticatorAttachmentPolicy,
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED
    );
    assert.equal(hardwareResult.locallyObserved[0], "cross-platform attachment");
  });

  it("creates, checks, and checksum-protects an offline export without vault retention", function () {
    const result = enrollOfflineRecoveryFactor({
      randomBytes: () => Uint8Array.from(
        { length: 32 },
        (_, index) => index + 17
      ),
      custodyDomainCommitment: ethers.id("O39:OFFLINE:CUSTODY"),
      enrollmentCeremonyHash: ethers.id("O39:OFFLINE:CEREMONY"),
      credentialGeneration: 1n,
      executionValidator: fixtures.profiles.standard.request.validator
    });
    assert.equal(result.normalDeviceVaultStoragePermitted, false);
    assert.equal(result.restorationCheck.matched, true);
    assert.deepEqual(
      inspectOfflineRecoveryExport(result.export.recoveryCode),
      {
        signer: result.signer,
        publicVerificationMaterialHash:
          result.restorationCheck.publicVerificationMaterialHash
      }
    );
    const corrupted = `${result.export.recoveryCode.slice(0, -1)}A`;
    assert.throws(
      () => inspectOfflineRecoveryExport(corrupted),
      /checksum_invalid/
    );
    assert.match(result.export.warning, /normal device backups/);
  });

  describe("validatePhilCoreV2ConsumerRecoveryFactorPolicy (shared per-role policy validator)", function () {
    const DESCRIPTOR_KEYS = [
      "descriptorVersion", "accountVersionId", "securityModelId",
      "recoveryDomainId", "role", "verifierKind",
      "publicVerificationMaterialHash", "credentialIdHash", "rpIdHash",
      "originPolicyHash", "independenceBindingHash", "userVerificationPolicy",
      "backupPolicy", "authenticatorAttachmentPolicy", "attestationPolicy",
      "credentialGeneration"
    ];
    const INDEPENDENCE_KEYS = [
      "bindingVersion", "role", "authenticatorClass", "synchronizationClass",
      "independenceAssurance", "credentialIdHash", "enrollmentCeremonyHash",
      "attestationEvidenceHash", "custodyDomainCommitment", "credentialGeneration"
    ];

    function validFactor(role) {
      return clone(factors(fixtures.profiles.standard))[role];
    }

    function hardwareRole1Factor() {
      return clone(factors(fixtures.profiles.enhanced))[1];
    }

    it("exports exactly one new runtime value, with no other export change", function () {
      const actual = Object.keys(mod).sort();
      const expected = [
        "PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS",
        "PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE",
        "PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION",
        "PHILCORE_V2_CONSUMER_RECOVERY_ACCOUNT_VERSION_ID",
        "PHILCORE_V2_CONSUMER_RECOVERY_CONFIGURATION_VERSION",
        "PHILCORE_V2_CONSUMER_RECOVERY_DESCRIPTOR_VERSION",
        "PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN",
        "PHILCORE_V2_CONSUMER_RECOVERY_DOMAIN_ID",
        "PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION",
        "PHILCORE_V2_CONSUMER_RECOVERY_PROFILE",
        "PHILCORE_V2_CONSUMER_RECOVERY_ROLE",
        "PHILCORE_V2_CONSUMER_RECOVERY_TYPE",
        "PHILCORE_V2_CONSUMER_RECOVERY_TYPEHASH",
        "PHILCORE_V2_CONSUMER_SYNC_CLASS",
        "computePhilCoreV2ConsumerRecoveryConfigurationHash",
        "computePhilCoreV2ConsumerRecoveryFactorCommitment",
        "computePhilCoreV2ConsumerRecoveryIndependenceBinding",
        "computePhilCoreV2Secp256k1PublicMaterialHash",
        "computePhilCoreV2WebAuthnPublicMaterialHash",
        "validatePhilCoreV2ConsumerRecoveryFactorPolicy",
        "validatePhilCoreV2ConsumerRecoveryProfile",
        "validatePhilCoreV2ConsumerRecoveryRotation"
      ].sort();
      assert.deepEqual(actual, expected);
      assert.equal(typeof validatePhilCoreV2ConsumerRecoveryFactorPolicy, "function");
    });

    it("succeeds directly for valid Role 0, both accepted Role 1 variants, and valid Role 2", function () {
      const role0 = validatePhilCoreV2ConsumerRecoveryFactorPolicy(validFactor(0), 0);
      assert.equal(role0.factorCommitment.length, 66);
      const role1Platform = validatePhilCoreV2ConsumerRecoveryFactorPolicy(validFactor(1), 1);
      assert.equal(role1Platform.factorCommitment.length, 66);
      const role1Hardware = validatePhilCoreV2ConsumerRecoveryFactorPolicy(hardwareRole1Factor(), 1);
      assert.equal(role1Hardware.factorCommitment.length, 66);
      const role2 = validatePhilCoreV2ConsumerRecoveryFactorPolicy(validFactor(2), 2);
      assert.equal(role2.factorCommitment.length, 66);
      assert.equal(role2.factor.signer, fixtures.profiles.standard.factors.offline.signer);
    });

    it("rejects a WebAuthn factor whose descriptor.credentialIdHash diverges from independence.credentialIdHash", function () {
      const profile = fixtures.profiles.standard;
      const divergent = clone(factors(profile));
      // Change only descriptor.credentialIdHash to a different valid,
      // nonzero, lowercase bytes32 -- independence.credentialIdHash, the
      // recomputed independence binding, and every other policy field
      // remain valid.
      divergent[0].descriptor.credentialIdHash =
        ethers.id("O39:DIVERGENT:DESCRIPTOR:CREDENTIAL_ID").toLowerCase();
      assert.notEqual(
        divergent[0].descriptor.credentialIdHash,
        divergent[0].independence.credentialIdHash
      );
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryProfile({
          factors: divergent,
          executionValidator: profile.request.validator
        }),
        /descriptor_independence_credential_id_hash_mismatch/
      );
    });

    it("rejects a descriptor/independence credentialIdHash divergence directly for Role 0, Role 1, and Role 2", function () {
      for (const role of [0, 1, 2]) {
        const factor = role === 1 ? hardwareRole1Factor() : validFactor(role);
        factor.descriptor.credentialIdHash =
          ethers.id(`O39:DIVERGENT:ROLE:${role}`).toLowerCase();
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, role),
          /descriptor_independence_credential_id_hash_mismatch/
        );
      }
    });

    it("rejects expectedRole outside 0|1|2 before any factor property is read", function () {
      let read = false;
      const hostileFactor = new Proxy({}, {
        ownKeys() { read = true; return []; },
        get() { read = true; return undefined; },
        has() { read = true; return false; }
      });
      for (const bad of [3, -1, 1.5, "0", 0n, null, undefined, NaN]) {
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(hostileFactor, bad),
          /recovery_factor_expected_role_invalid/
        );
      }
      assert.equal(read, false);
    });

    it("rejects a non-object, null, or array factor", function () {
      for (const bad of [null, [], "x", 1, undefined]) {
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(bad, 0),
          /recovery_factor_input_invalid/
        );
      }
    });

    it("rejects an extra enumerable, non-enumerable, or symbol key on the factor", function () {
      const withExtra = { ...validFactor(0), extra: 1 };
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(withExtra, 0),
        /recovery_factor_input_invalid/
      );
      const withHidden = { ...validFactor(0) };
      Object.defineProperty(withHidden, "hidden", { value: 1, enumerable: false, configurable: true });
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(withHidden, 0),
        /recovery_factor_input_invalid/
      );
      const withSymbol = { ...validFactor(0) };
      withSymbol[Symbol("extra")] = 1;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(withSymbol, 0),
        /recovery_factor_input_invalid/
      );
    });

    it("rejects a missing or inherited-only descriptor/independence", function () {
      const missingDescriptor = { independence: validFactor(0).independence };
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(missingDescriptor, 0),
        /recovery_factor_input_invalid/
      );
      const proto = { descriptor: validFactor(0).descriptor };
      const inherited = Object.assign(
        Object.create(proto),
        { independence: validFactor(0).independence }
      );
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(inherited, 0),
        /recovery_factor_input_invalid/
      );
    });

    it("rejects extra, missing, and inherited-only descriptor and independence keys", function () {
      const extraDescriptor = validFactor(0);
      extraDescriptor.descriptor = { ...extraDescriptor.descriptor, extra: 1 };
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(extraDescriptor, 0),
        /recovery_factor_descriptor_input_invalid/
      );

      const missingDescriptorKey = validFactor(0);
      delete missingDescriptorKey.descriptor.role;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(missingDescriptorKey, 0),
        /recovery_factor_descriptor_input_invalid/
      );

      const inheritedDescriptorKey = validFactor(0);
      const descriptorProto = { role: 0 };
      inheritedDescriptorKey.descriptor =
        Object.assign(Object.create(descriptorProto), inheritedDescriptorKey.descriptor);
      delete inheritedDescriptorKey.descriptor.role;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(inheritedDescriptorKey, 0),
        /recovery_factor_descriptor_input_invalid/
      );

      const extraIndependence = validFactor(0);
      extraIndependence.independence = { ...extraIndependence.independence, extra: 1 };
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(extraIndependence, 0),
        /recovery_factor_independence_input_invalid/
      );

      const missingIndependenceKey = validFactor(0);
      delete missingIndependenceKey.independence.role;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(missingIndependenceKey, 0),
        /recovery_factor_independence_input_invalid/
      );
    });

    it("rejects explicit undefined for a required descriptor/independence field", function () {
      const factor = validFactor(0);
      factor.descriptor.role = undefined;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0)
      );
    });

    it("forbids a signer property for Roles 0 and 1, including explicit undefined", function () {
      for (const role of [0, 1]) {
        const factor = role === 1 ? hardwareRole1Factor() : validFactor(role);
        factor.signer = "0x0000000000000000000000000000000000003922";
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, role),
          /webauthn_recovery_factor_signer_forbidden/
        );
        const withUndefined = role === 1 ? hardwareRole1Factor() : validFactor(role);
        withUndefined.signer = undefined;
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(withUndefined, role),
          /webauthn_recovery_factor_signer_forbidden/
        );
      }
    });

    it("Role 2: rejects missing, malformed, non-canonical, and zero signer", function () {
      const missing = validFactor(2);
      delete missing.signer;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(missing, 2),
        /offline_recovery_signer_required/
      );

      const malformed = validFactor(2);
      malformed.signer = "not-an-address";
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(malformed, 2),
        /offline_recovery_signer_invalid/
      );

      const lower = validFactor(2);
      const lowerCased = lower.signer.toLowerCase();
      assert.notEqual(lowerCased, lower.signer);
      lower.signer = lowerCased;
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(lower, 2),
        /offline_recovery_signer_invalid/
      );

      const zero = validFactor(2);
      zero.signer = "0x0000000000000000000000000000000000000000";
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(zero, 2),
        /offline_recovery_signer_invalid/
      );
    });

    it("Role 2: rejects a signer whose public-material hash does not match the descriptor", function () {
      const factor = validFactor(2);
      factor.signer = "0x1111111111111111111111111111111111111111";
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 2),
        /offline_recovery_signer_binding_invalid/
      );
    });

    it("rejects a throwing getter without leaking the raw thrown value, and reads it exactly once", function () {
      const factor = validFactor(0);
      const marker = { poison: "descriptor-getter-marker" };
      let reads = 0;
      Object.defineProperty(factor, "descriptor", {
        enumerable: true,
        configurable: true,
        get() {
          reads += 1;
          throw marker;
        }
      });
      let caught = null;
      try {
        validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
      } catch (error) {
        caught = error;
      }
      assert.equal(caught.message, "recovery_factor_descriptor_input_invalid");
      assert.notEqual(caught.cause, marker);
      assert.equal(Object.getOwnPropertyNames(caught).includes("cause"), false);
      assert.equal(reads, 1);
    });

    it("rejects an ownKeys enumeration trap that throws", function () {
      const factor = validFactor(0);
      const trap = new Proxy(factor.descriptor, {
        ownKeys() {
          throw new Error("enumeration hostile");
        }
      });
      const hostile = { ...factor, descriptor: trap };
      assert.throws(
        () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(hostile, 0),
        /recovery_factor_descriptor_input_invalid/
      );
    });

    it("contains a revoked Proxy at the factor, descriptor, and independence boundaries", function () {
      const { proxy: revokedFactor, revoke: revokeFactor } = Proxy.revocable({}, {});
      revokeFactor();
      assert.throws(() => validatePhilCoreV2ConsumerRecoveryFactorPolicy(revokedFactor, 0));

      const validDescriptor = validFactor(0).descriptor;
      const { proxy: revokedDescriptor, revoke: revokeDescriptor } = Proxy.revocable(validDescriptor, {});
      revokeDescriptor();
      const hostileDescriptor = { ...validFactor(0), descriptor: revokedDescriptor };
      assert.throws(() => validatePhilCoreV2ConsumerRecoveryFactorPolicy(hostileDescriptor, 0));

      const validIndependence = validFactor(0).independence;
      const { proxy: revokedIndependence, revoke: revokeIndependence } = Proxy.revocable(validIndependence, {});
      revokeIndependence();
      const hostileIndependence = { ...validFactor(0), independence: revokedIndependence };
      assert.throws(() => validatePhilCoreV2ConsumerRecoveryFactorPolicy(hostileIndependence, 0));
    });

    describe("own-property Proxy corrective pass", function () {
      // Constructs a hostile Proxy whose target is extensible and has ZERO
      // own properties for `keys` (every value is only reachable through the
      // target's prototype), while its `ownKeys` trap falsely reports `keys`
      // as if they were own. No `getOwnPropertyDescriptor` or `get` trap is
      // defined: the default Proxy behavior already reproduces the attack --
      // `Reflect.getOwnPropertyDescriptor(proxy, key)` correctly resolves to
      // `undefined` (the target genuinely has no own property), while an
      // ordinary `proxy[key]` read still resolves through the prototype
      // chain to the real, valid value. This is spec-legal: for an
      // extensible target with zero own properties, the `ownKeys` trap has
      // no invariant to violate by reporting arbitrary names.
      function fakeOwnKeysProxy(realObject, keys) {
        const proto = { ...realObject };
        const target = Object.create(proto);
        return new Proxy(target, {
          ownKeys() {
            return keys;
          }
        });
      }

      it("rejects a factor Proxy whose descriptor/independence are inherited-only but falsely reported as own by ownKeys", function () {
        const real = validFactor(0);
        const hostile = fakeOwnKeysProxy(real, ["descriptor", "independence"]);
        // Confirm the attack construction: ordinary reads resolve inherited
        // values, but the properties are genuinely not own.
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "descriptor"), undefined);
        assert.notEqual(hostile.descriptor, undefined);
        let caught = null;
        try {
          validatePhilCoreV2ConsumerRecoveryFactorPolicy(hostile, 0);
        } catch (error) {
          caught = error;
        }
        assert.ok(caught, "the inherited-only factor Proxy must be rejected, not accepted");
        assert.equal(caught.message, "recovery_factor_input_invalid");
      });

      it("rejects a descriptor Proxy whose 16 fields are inherited-only but falsely reported as own by ownKeys", function () {
        const real = validFactor(0);
        const hostileDescriptor = fakeOwnKeysProxy(real.descriptor, DESCRIPTOR_KEYS);
        for (const key of DESCRIPTOR_KEYS) {
          assert.deepEqual(Object.getOwnPropertyDescriptor(hostileDescriptor, key), undefined);
          assert.notEqual(hostileDescriptor[key], undefined);
        }
        const factor = { ...real, descriptor: hostileDescriptor };
        let caught = null;
        try {
          validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
        } catch (error) {
          caught = error;
        }
        assert.ok(caught, "the inherited-only descriptor Proxy must be rejected, not accepted");
        assert.equal(caught.message, "recovery_factor_descriptor_input_invalid");
      });

      it("rejects an independence Proxy whose 10 fields are inherited-only but falsely reported as own by ownKeys", function () {
        const real = validFactor(0);
        const hostileIndependence = fakeOwnKeysProxy(real.independence, INDEPENDENCE_KEYS);
        for (const key of INDEPENDENCE_KEYS) {
          assert.deepEqual(Object.getOwnPropertyDescriptor(hostileIndependence, key), undefined);
          assert.notEqual(hostileIndependence[key], undefined);
        }
        const factor = { ...real, independence: hostileIndependence };
        let caught = null;
        try {
          validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
        } catch (error) {
          caught = error;
        }
        assert.ok(caught, "the inherited-only independence Proxy must be rejected, not accepted");
        assert.equal(caught.message, "recovery_factor_independence_input_invalid");
      });

      it("rejects a genesis-style factor commitment being produced from an inherited-only descriptor (no commitment is ever returned)", function () {
        // Directly restates the independently confirmed finding: a
        // descriptor with all 16 fields inherited but falsely reported as
        // own by ownKeys must never reach factor-commitment computation.
        const real = validFactor(0);
        const hostileDescriptor = fakeOwnKeysProxy(real.descriptor, DESCRIPTOR_KEYS);
        const factor = { ...real, descriptor: hostileDescriptor };
        assert.throws(() => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0));
      });

      it("contains a getOwnPropertyDescriptor trap that throws a raw marker, without leaking it", function () {
        const real = validFactor(0);
        const marker = { poison: "getOwnPropertyDescriptor-marker" };
        const hostileDescriptor = new Proxy(real.descriptor, {
          getOwnPropertyDescriptor() {
            throw marker;
          }
        });
        const factor = { ...real, descriptor: hostileDescriptor };
        let caught = null;
        try {
          validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
        } catch (error) {
          caught = error;
        }
        assert.equal(caught.message, "recovery_factor_descriptor_input_invalid");
        assert.notEqual(caught.cause, marker);
        assert.equal(Object.getOwnPropertyNames(caught).includes("cause"), false);
      });

      it("contains a revoked Proxy specifically during own-property-descriptor inspection", function () {
        const real = validFactor(0);
        const { proxy: revokedDescriptor, revoke } = Proxy.revocable(real.descriptor, {});
        // ownKeys succeeds once (before revocation) is not representative;
        // revoke immediately so every subsequent operation, including
        // getOwnPropertyDescriptor, throws a raw TypeError from the engine.
        revoke();
        const factor = { ...real, descriptor: revokedDescriptor };
        let caught = null;
        try {
          validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
        } catch (error) {
          caught = error;
        }
        assert.equal(caught.message, "recovery_factor_descriptor_input_invalid");
      });

      it("a genuine non-enumerable own data property remains valid", function () {
        const factor = validFactor(0);
        const roleValue = factor.descriptor.role;
        delete factor.descriptor.role;
        Object.defineProperty(factor.descriptor, "role", {
          value: roleValue,
          enumerable: false,
          configurable: true,
          writable: true
        });
        const result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
        assert.equal(BigInt(result.factor.descriptor.role), BigInt(roleValue));
      });

      it("a genuine own accessor property is read exactly once", function () {
        const factor = validFactor(0);
        const generationValue = factor.descriptor.credentialGeneration;
        delete factor.descriptor.credentialGeneration;
        let reads = 0;
        Object.defineProperty(factor.descriptor, "credentialGeneration", {
          enumerable: true,
          configurable: true,
          get() {
            reads += 1;
            return generationValue;
          }
        });
        const result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
        assert.equal(
          BigInt(result.factor.descriptor.credentialGeneration),
          BigInt(generationValue)
        );
        assert.equal(reads, 1);
      });

      it("rejects an own accessor property with no getter (set-only)", function () {
        const factor = validFactor(0);
        delete factor.descriptor.role;
        Object.defineProperty(factor.descriptor, "role", {
          enumerable: true,
          configurable: true,
          set() {}
        });
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0),
          /recovery_factor_descriptor_input_invalid/
        );
      });

      it("rejects a key whose getOwnPropertyDescriptor trap explicitly reports undefined despite ownKeys reporting it", function () {
        const real = validFactor(0);
        const hostileDescriptor = new Proxy(real.descriptor, {
          getOwnPropertyDescriptor(target, key) {
            if (key === "role") return undefined;
            return Reflect.getOwnPropertyDescriptor(target, key);
          }
        });
        const factor = { ...real, descriptor: hostileDescriptor };
        assert.throws(
          () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0),
          /recovery_factor_descriptor_input_invalid/
        );
      });

      it("Role 2: rejects a signer name fabricated by ownKeys but not genuinely own", function () {
        const real = validFactor(2);
        // descriptor/independence are genuine own properties of the target
        // (so the factor-level exact-key check passes for them); only
        // "signer" is inherited-only, reachable via the prototype, while
        // the ownKeys trap falsely reports it as own alongside the other
        // two genuine keys.
        const proto = { signer: real.signer };
        const target = Object.create(proto);
        target.descriptor = real.descriptor;
        target.independence = real.independence;
        const hostile = new Proxy(target, {
          ownKeys() {
            return ["descriptor", "independence", "signer"];
          }
        });
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "descriptor"), Object.getOwnPropertyDescriptor(target, "descriptor"));
        assert.deepEqual(Object.getOwnPropertyDescriptor(hostile, "signer"), undefined);
        assert.notEqual(hostile.signer, undefined);
        let caught = null;
        try {
          validatePhilCoreV2ConsumerRecoveryFactorPolicy(hostile, 2);
        } catch (error) {
          caught = error;
        }
        assert.equal(caught.message, "offline_recovery_signer_required");
      });

      it("Roles 0/1: a genuinely present signer own property is rejected without invoking its getter", function () {
        for (const role of [0, 1]) {
          const factor = role === 1 ? hardwareRole1Factor() : validFactor(role);
          let reads = 0;
          Object.defineProperty(factor, "signer", {
            enumerable: true,
            configurable: true,
            get() {
              reads += 1;
              return "0x0000000000000000000000000000000000003922";
            }
          });
          assert.throws(
            () => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, role),
            /webauthn_recovery_factor_signer_forbidden/
          );
          assert.equal(reads, 0, "a forbidden signer's getter must never be invoked");
        }
      });

      it("does not inspect .code, .name, or .message on a hostile thrown value at the descriptor boundary", function () {
        const factor = validFactor(0);
        let codeReads = 0;
        let nameReads = 0;
        let messageReads = 0;
        const hostileThrown = {
          get code() { codeReads += 1; return "FAKE"; },
          get name() { nameReads += 1; return "FakeError"; },
          get message() { messageReads += 1; return "fake message"; }
        };
        Object.defineProperty(factor, "descriptor", {
          enumerable: true,
          configurable: true,
          get() {
            throw hostileThrown;
          }
        });
        assert.throws(() => validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0));
        assert.equal(codeReads, 0);
        assert.equal(nameReads, 0);
        assert.equal(messageReads, 0);
      });
    });

    it("reads each caller-owned descriptor and independence field exactly once", function () {
      const factor = validFactor(0);
      const descriptorReads = {};
      for (const key of DESCRIPTOR_KEYS) {
        const value = factor.descriptor[key];
        descriptorReads[key] = 0;
        Object.defineProperty(factor.descriptor, key, {
          enumerable: true,
          configurable: true,
          get() {
            descriptorReads[key] += 1;
            return value;
          }
        });
      }
      const independenceReads = {};
      for (const key of INDEPENDENCE_KEYS) {
        const value = factor.independence[key];
        independenceReads[key] = 0;
        Object.defineProperty(factor.independence, key, {
          enumerable: true,
          configurable: true,
          get() {
            independenceReads[key] += 1;
            return value;
          }
        });
      }
      validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
      for (const key of DESCRIPTOR_KEYS) {
        assert.equal(descriptorReads[key], 1, `descriptor.${key} must be read exactly once`);
      }
      for (const key of INDEPENDENCE_KEYS) {
        assert.equal(independenceReads[key], 1, `independence.${key} must be read exactly once`);
      }
    });

    it("a property-changing second read on the caller's object cannot alter the returned snapshot", function () {
      const factor = validFactor(0);
      const originalCredentialGeneration = factor.descriptor.credentialGeneration;
      let readCount = 0;
      Object.defineProperty(factor.descriptor, "credentialGeneration", {
        enumerable: true,
        configurable: true,
        get() {
          readCount += 1;
          return readCount === 1 ? originalCredentialGeneration : 99;
        }
      });
      const result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
      assert.equal(
        BigInt(result.factor.descriptor.credentialGeneration),
        BigInt(originalCredentialGeneration)
      );
    });

    it("returns a deeply frozen factor, descriptor, independence, and result object", function () {
      const result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(validFactor(0), 0);
      assert.equal(Object.isFrozen(result), true);
      assert.equal(Object.isFrozen(result.factor), true);
      assert.equal(Object.isFrozen(result.factor.descriptor), true);
      assert.equal(Object.isFrozen(result.factor.independence), true);
    });

    it("mutating the caller's factor object after validation cannot mutate the returned result", function () {
      const factor = validFactor(0);
      const result = validatePhilCoreV2ConsumerRecoveryFactorPolicy(factor, 0);
      const before = result.factor.descriptor.role;
      factor.descriptor.role = 99;
      factor.independence.role = 99;
      assert.equal(result.factor.descriptor.role, before);
    });

    it("the profile validator never rereads a caller-owned factor after shared per-role validation", function () {
      const profile = fixtures.profiles.standard;
      const built = clone(factors(profile));
      let descriptorReads = 0;
      const hostileFactor = {
        get descriptor() {
          descriptorReads += 1;
          return built[0].descriptor;
        },
        independence: built[0].independence
      };
      const result = validatePhilCoreV2ConsumerRecoveryProfile({
        factors: [hostileFactor, built[1], built[2]],
        executionValidator: profile.request.validator
      });
      assert.equal(descriptorReads, 1);
      assert.equal(Object.isFrozen(result), true);
      assert.equal(Object.isFrozen(result.descriptors), true);
      assert.equal(Object.isFrozen(result.commitments), true);
      assert.equal(Object.isFrozen(result.warnings), true);
    });
  });

  it("rejects each independence and authority alias failure closed", function () {
    const profile = fixtures.profiles.standard;
    const validators = profile.request.validator;
    const cases = [];

    const duplicateCredential = clone(factors(profile));
    duplicateCredential[1].independence.credentialIdHash =
      duplicateCredential[0].independence.credentialIdHash;
    duplicateCredential[1].descriptor.credentialIdHash =
      duplicateCredential[0].descriptor.credentialIdHash;
    rebind(duplicateCredential[1]);
    cases.push([duplicateCredential, /credential_must_be_distinct/]);

    const duplicatePublic = clone(factors(profile));
    duplicatePublic[1].descriptor.publicVerificationMaterialHash =
      duplicatePublic[0].descriptor.publicVerificationMaterialHash;
    cases.push([duplicatePublic, /public_material_must_be_unique/]);

    const duplicateCustody = clone(factors(profile));
    duplicateCustody[1].independence.custodyDomainCommitment =
      duplicateCustody[0].independence.custodyDomainCommitment;
    rebind(duplicateCustody[1]);
    cases.push([duplicateCustody, /custody_domains_must_be_unique/]);

    const roleSubstitution = clone(factors(profile));
    roleSubstitution[1].independence.role = 0;
    rebind(roleSubstitution[1]);
    cases.push([roleSubstitution, /role_or_independence_binding_invalid/]);

    const stale = clone(factors(profile));
    stale[1].descriptor.credentialGeneration = 0;
    cases.push([stale, /role_or_independence_binding_invalid|generation/]);

    const invalidClass = clone(factors(profile));
    invalidClass[1].independence.authenticatorClass =
      PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE;
    rebind(invalidClass[1]);
    cases.push([invalidClass, /classification_invalid/]);

    const synced = clone(factors(profile));
    synced[1].independence.synchronizationClass =
      PHILCORE_V2_CONSUMER_SYNC_CLASS.SYNCED_MULTI_DEVICE;
    rebind(synced[1]);
    cases.push([synced, /webauthn_recovery_factor_policy_invalid/]);

    const degraded = clone(factors(profile));
    degraded[1].independence.independenceAssurance =
      PHILCORE_V2_CONSUMER_INDEPENDENCE_ASSURANCE.DEGRADED_UNVERIFIED;
    rebind(degraded[1]);
    cases.push([degraded, /degraded_independence_not_deployable/]);

    const alteredBinding = clone(factors(profile));
    alteredBinding[1].descriptor.independenceBindingHash =
      ethers.id("O39:ALTERED");
    cases.push([alteredBinding, /role_or_independence_binding_invalid/]);

    for (const [candidate, expected] of cases) {
      assert.throws(() => validatePhilCoreV2ConsumerRecoveryProfile({
        factors: candidate,
        executionValidator: validators
      }), expected);
    }

    // The Role 2 signer/public-material binding check now runs inside the
    // shared per-factor validator, before the profile-level alias check can
    // be reached, so the public-material hash must also be rebound to the
    // aliasing signer -- otherwise offline_recovery_signer_binding_invalid
    // fires first, which is a distinct, earlier-in-precedence defect.
    const validatorAlias = clone(factors(profile));
    validatorAlias[2].signer = validators;
    validatorAlias[2].descriptor.publicVerificationMaterialHash =
      computePhilCoreV2Secp256k1PublicMaterialHash({ signer: validators });
    assert.throws(() => validatePhilCoreV2ConsumerRecoveryProfile({
      factors: validatorAlias,
      executionValidator: validators
    }), /execution_validator_cannot_be_recovery_factor/);
  });

  it("requires exact one-role replacement and strict generation increments", function () {
    const profile = fixtures.profiles.standard;
    for (const changedRole of [0, 1, 2]) {
      const current = clone(factors(profile));
      const proposed = clone(current);
      proposed[changedRole].descriptor.credentialGeneration = 2;
      proposed[changedRole].independence.credentialGeneration = 2;
      proposed[changedRole].independence.enrollmentCeremonyHash =
        ethers.id(`O39:ROTATION:${changedRole}`);
      if (changedRole < 2) {
        proposed[changedRole].descriptor.credentialIdHash =
          ethers.id(`O39:ROTATED:CREDENTIAL:${changedRole}`);
        proposed[changedRole].independence.credentialIdHash =
          proposed[changedRole].descriptor.credentialIdHash;
        proposed[changedRole].descriptor.publicVerificationMaterialHash =
          ethers.id(`O39:ROTATED:PUBLIC:${changedRole}`);
      } else {
        proposed[changedRole].signer =
          "0x0000000000000000000000000000000000003922";
        const {
          computePhilCoreV2Secp256k1PublicMaterialHash
        } = require(
          "../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts"
        );
        proposed[changedRole].descriptor.publicVerificationMaterialHash =
          computePhilCoreV2Secp256k1PublicMaterialHash({
            signer: proposed[changedRole].signer
          });
      }
      rebind(proposed[changedRole]);
      const rotation = validatePhilCoreV2ConsumerRecoveryRotation({
        current,
        proposed,
        executionValidator: profile.request.validator
      });
      assert.equal(rotation.changedRole, changedRole);
      assert.notEqual(
        rotation.currentRecoveryConfigurationHash,
        rotation.proposedRecoveryConfigurationHash
      );
      assert.equal(
        computePhilCoreV2ConsumerRecoveryFactorCommitment(
          proposed[changedRole].descriptor
        ).length,
        66
      );
    }

    const stale = clone(factors(profile));
    stale[1].descriptor.credentialIdHash = ethers.id("O39:STALE:ROTATION");
    stale[1].independence.credentialIdHash =
      stale[1].descriptor.credentialIdHash;
    rebind(stale[1]);
    assert.throws(() => validatePhilCoreV2ConsumerRecoveryRotation({
      current: factors(profile),
      proposed: stale,
      executionValidator: profile.request.validator
    }), /generation_invalid/);
  });

  it("accepts all six exact 2-of-3 fixture envelopes in the static verifier", async function () {
    const verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
    const account = fixtures.profiles.standard.request.account;
    await ethers.provider.send("hardhat_setBalance", [
      account,
      "0x1000000000000000000"
    ]);
    await ethers.provider.send("hardhat_impersonateAccount", [account]);
    const caller = await ethers.getSigner(account);
    let accepted = 0;
    try {
      for (const profile of Object.values(fixtures.profiles)) {
        for (const pair of profile.validPairs) {
          assert.equal(
            await verifier.connect(caller).verifyAuthority(
              profile.request,
              pair.envelope
            ),
            "0x15c57f54"
          );
          accepted += 1;
        }
      }
    } finally {
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [account]);
    }
    assert.equal(accepted, 6);
  });

  it("rejects wrong account, chain, version, epoch, bitmap, and truncated evidence", async function () {
    const verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
    const profile = fixtures.profiles.standard;
    const account = profile.request.account;
    await ethers.provider.send("hardhat_setBalance", [
      account,
      "0x1000000000000000000"
    ]);
    await ethers.provider.send("hardhat_impersonateAccount", [account]);
    const caller = await ethers.getSigner(account);
    try {
      for (const request of [
        { ...profile.request, account:
          "0x0000000000000000000000000000000000003901" },
        { ...profile.request, chainId: "31338" },
        { ...profile.request, accountVersionId: ethers.id("wrong-version") },
        { ...profile.request, recoveryEpoch: 2 }
      ]) {
        await assert.rejects(
          verifier.connect(caller).verifyAuthority(
            request,
            profile.validPairs[0].envelope
          )
        );
      }
      await assert.rejects(
        verifier.connect(caller).verifyAuthority(
          profile.request,
          `${profile.validPairs[0].envelope.slice(0, -64)}`
        )
      );
    } finally {
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [account]);
    }
  });

  it("rejects correctly signed wrong-origin, wrong-RP, and backup-flag evidence", async function () {
    const verifier = await (
      await ethers.getContractFactory("PhilCoreV2StaticAuthorityVerifier")
    ).deploy();
    await verifier.waitForDeployment();
    const profile = fixtures.profiles.standard;
    const account = profile.request.account;
    await ethers.provider.send("hardhat_setBalance", [
      account,
      "0x1000000000000000000"
    ]);
    await ethers.provider.send("hardhat_impersonateAccount", [account]);
    const caller = await ethers.getSigner(account);
    try {
      assert.deepEqual(
        profile.invalidEnvelopes.map((item) => item.id),
        [
          "wrong_origin",
          "wrong_rp_id",
          "backup_eligible_flag",
          "malformed_backup_state_without_eligibility"
        ]
      );
      for (const invalid of profile.invalidEnvelopes) {
        await assert.rejects(
          verifier.connect(caller).verifyAuthority(
            profile.request,
            invalid.envelope
          ),
          undefined,
          invalid.id
        );
      }
    } finally {
      await ethers.provider.send("hardhat_stopImpersonatingAccount", [account]);
    }
  });

  it("records every required invalid fixture classification", function () {
    assert.deepEqual(fixtures.invalidCases, [
      "same_credential_roles_0_1",
      "same_public_key_roles_0_1",
      "same_custody_domain",
      "role_substitution",
      "execution_validator_reused",
      "stale_generation",
      "invalid_authenticator_class",
      "prohibited_sync_state",
      "malformed_backup_flags",
      "altered_independence_commitment",
      "wrong_rp_id",
      "wrong_origin",
      "wrong_account",
      "wrong_chain",
      "wrong_version",
      "wrong_recovery_epoch"
    ]);
    assert.equal(p256.CURVE.n > 0n, true);
    assert.equal(
      PHILCORE_V2_CONSUMER_RECOVERY_INDEPENDENCE_VERSION,
      2
    );
  });
});
