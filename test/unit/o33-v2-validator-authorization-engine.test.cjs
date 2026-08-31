require("tsx/cjs");

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { keccak256, toUtf8Bytes } = require("ethers");

const {
  PHILCORE_V2_PURPOSE
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2RuntimeAuthorizationDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_AUTHORIZATION_FAILURE_CODES,
  verifyPhilCoreV2Authorization
} = require("../../apps/phil-device-sdk/src/v2AuthorizationEngine.ts");
const {
  beginPhilCoreV2Recovery,
  beginPhilCoreV2RecoveryConfigRotation,
  cancelPhilCoreV2Recovery,
  cancelPhilCoreV2RecoveryConfigRotation,
  consumePhilCoreV2AuthorizationLocally,
  createPhilCoreV2AuthorityEvidenceReference,
  createPhilCoreV2FixtureAuthorityVerifier,
  createPhilCoreV2ValidatorState,
  revokePhilCoreV2ValidatorLocally,
  rotatePhilCoreV2ValidatorState
} = require("../../apps/phil-device-sdk/src/v2Validator.ts");
const {
  buildO32VectorPackage
} = require("../../scripts/cryptography/generate-o32-v2-vectors.cjs");
const {
  buildO33VectorPackage,
  stringify
} = require("../../scripts/cryptography/generate-o33-validator-vectors.cjs");

const H = (value) => keccak256(toUtf8Bytes(value));
const ROOT = path.resolve(__dirname, "../..");
const VECTOR_PATH = path.join(
  ROOT,
  "config/cryptography/O33_V2_VALIDATOR_AUTHORIZATION_TEST_VECTORS.json"
);
const ACCOUNT = "0x1000000000000000000000000000000000000001";
const ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const VALIDATOR_KEY_ID_BINDING =
  "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809";

function state(overrides = {}) {
  return createPhilCoreV2ValidatorState({
    chainId: 11155111n,
    entryPoint: ENTRYPOINT,
    account: ACCOUNT,
    ownerCommitment: H("o33:owner"),
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
    validatorEpoch: 3n,
    recoveryEpoch: 2n,
    recoveryConfigHash: H("o33:recovery-config"),
    ...overrides
  });
}

function fixturePackage() {
  const vectors = buildO32VectorPackage();
  const evidenceReferenceHash = H("o33:validator-evidence-reference");
  const currentState = state({
    ownerCommitment: vectors.validIntent.input.header.ownerCommitment,
    recoveryConfigHash: vectors.recovery.recoveryConfigHash
  });
  const authorizationPackage = {
    intent: vectors.validIntent.input,
    declaredIntentCoreHash: vectors.validIntent.intentCoreHash,
    runtimeAuthorization: vectors.runtimeAuthorization.input,
    declaredRuntimeAuthorizationDigest:
      vectors.runtimeAuthorization.runtimeAuthorizationDigest,
    declaredAuthorizedIntentHash:
      vectors.runtimeAuthorization.authorizedIntentHash,
    userOperationHashBinding:
      vectors.publicFixtureBindings.userOperationHashBinding,
    authority: {
      authorityKind: "validator_signature",
      validator: VALIDATOR,
      validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
      validatorEpoch: "3",
      recoveryEpoch: "2",
      recoveryConfigHash: vectors.recovery.recoveryConfigHash,
      evidence: createPhilCoreV2AuthorityEvidenceReference({
        authorityKind: "validator_signature",
        evidenceReferenceHash,
        fixtureOnly: true
      }),
      declaredAuthorityDigest:
        vectors.validatorAuthorization.validatorDigest
    }
  };
  const verifier = createPhilCoreV2FixtureAuthorityVerifier({
    verifierId: "o33.fixture.validator",
    expectations: [{
      authorityKind: "validator_signature",
      digest: vectors.validatorAuthorization.validatorDigest,
      evidenceReferenceHash,
      chainId: currentState.chainId,
      account: currentState.account,
      validator: currentState.validator,
      validatorKeyIdBinding: currentState.validatorKeyIdBinding,
      validatorEpoch: currentState.validatorEpoch,
      recoveryEpoch: currentState.recoveryEpoch,
      recoveryConfigHash: currentState.recoveryConfigHash
    }]
  });
  return {
    vectors,
    state: currentState,
    authorizationPackage,
    verifier
  };
}

function recoveryFixturePackage(overrides = {}) {
  const vectors = buildO32VectorPackage();
  const intent = vectors.recovery.validRecovery.intent;
  const runtimeAuthorization = {
    ...vectors.runtimeAuthorization.input,
    intentCoreHash: vectors.recovery.validRecovery.intentCoreHash
  };
  const runtimeAuthorizationDigest =
    computePhilCoreV2RuntimeAuthorizationDigest(runtimeAuthorization);
  const authorizedIntentHash = computePhilCoreV2AuthorizedIntentHash({
    intentCoreHash: vectors.recovery.validRecovery.intentCoreHash,
    runtimeAuthorizationDigest
  });
  assert.equal(
    authorizedIntentHash,
    vectors.recovery.validRecovery.authorizedIntentHash
  );
  const evidenceReferenceHash = H("o33:recovery-evidence-reference");
  const currentState = state({
    ownerCommitment: intent.header.ownerCommitment,
    recoveryConfigHash: vectors.recovery.recoveryConfigHash,
    ...(overrides.state ?? {})
  });
  const authority = {
    authorityKind: "recovery_threshold",
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
    validatorEpoch: "3",
    recoveryEpoch: "2",
    recoveryConfigHash: vectors.recovery.recoveryConfigHash,
    factorBitmap:
      vectors.recovery.validRecovery.authorizationInput.factorBitmap,
    evidence: createPhilCoreV2AuthorityEvidenceReference({
      authorityKind: "recovery_threshold",
      evidenceReferenceHash,
      fixtureOnly: true
    }),
    declaredAuthorityDigest:
      vectors.recovery.validRecovery.recoveryFactorDigest,
    ...(overrides.authority ?? {})
  };
  const authorizationPackage = {
    intent,
    declaredIntentCoreHash:
      vectors.recovery.validRecovery.intentCoreHash,
    runtimeAuthorization,
    declaredRuntimeAuthorizationDigest: runtimeAuthorizationDigest,
    declaredAuthorizedIntentHash: authorizedIntentHash,
    userOperationHashBinding:
      vectors.recovery.validRecovery.authorizationInput.userOperationHash,
    authority,
    ...(overrides.authorizationPackage ?? {})
  };
  const verifier = createPhilCoreV2FixtureAuthorityVerifier({
    verifierId: "o33.fixture.recovery",
    expectations: [{
      authorityKind: "recovery_threshold",
      digest: vectors.recovery.validRecovery.recoveryFactorDigest,
      evidenceReferenceHash,
      chainId: currentState.chainId,
      account: currentState.account,
      validator: currentState.validator,
      validatorKeyIdBinding: currentState.validatorKeyIdBinding,
      validatorEpoch: currentState.validatorEpoch,
      recoveryEpoch: currentState.recoveryEpoch,
      recoveryConfigHash: currentState.recoveryConfigHash,
      factorBitmap:
        vectors.recovery.validRecovery.authorizationInput.factorBitmap
    }]
  });
  return {
    vectors,
    state: currentState,
    authorizationPackage,
    verifier
  };
}

async function verifyFixture(fixture, overrides = {}) {
  return verifyPhilCoreV2Authorization({
    state: fixture.state,
    authorizationPackage: fixture.authorizationPackage,
    currentTime: "1800000150",
    authorityVerifier: fixture.verifier,
    ...overrides
  });
}

describe("O.33 V2 validator and authorization engine", function () {
  describe("validator state and authority boundary", function () {
    it("creates a strict epoch-one-or-greater validator state", function () {
      const current = state();
      assert.equal(current.validatorEpoch, 3n);
      assert.equal(current.recoveryEpoch, 2n);
      assert.equal(current.validatorStatus, "active");
      assert.equal(current.recoveryState, "normal");
      assert.throws(
        () => state({ validatorEpoch: 0n }),
        /validatorEpoch_must_be_nonzero/
      );
      assert.throws(
        () => state({ recoveryEpoch: 0n }),
        /recoveryEpoch_must_be_nonzero/
      );
    });

    it("uses references only and never carries signature bytes into the engine", function () {
      const evidence = createPhilCoreV2AuthorityEvidenceReference({
        authorityKind: "validator_signature",
        evidenceReferenceHash: H("o33:fixture-evidence"),
        fixtureOnly: true
      });
      assert.equal(evidence.signatureBytesPresentToEngine, false);
      assert.equal(evidence.verificationFormat, "secp256k1-rsv-65-low-s-v1");
      assert.equal("signature" in evidence, false);
    });

    it("consumes exact digest and keyed nonce locally and rejects replay", function () {
      const digest = H("o33:authorization");
      const consumed = consumePhilCoreV2AuthorizationLocally({
        state: state(),
        authorizationDigest: digest,
        nonceKey: 0n,
        nonceSequence: 7n
      });
      assert.equal(consumed.consumedAuthorizationDigests.includes(digest), true);
      assert.throws(
        () => consumePhilCoreV2AuthorizationLocally({
          state: consumed,
          authorizationDigest: digest,
          nonceKey: 0n,
          nonceSequence: 8n
        }),
        /authorization_replay/
      );
      assert.throws(
        () => consumePhilCoreV2AuthorizationLocally({
          state: consumed,
          authorizationDigest: H("o33:different-authorization"),
          nonceKey: 0n,
          nonceSequence: 7n
        }),
        /nonce_replay/
      );
    });

    it("models recovery freezes and mutually exclusive recovery states", function () {
      const activeRecovery = beginPhilCoreV2Recovery(state());
      assert.equal(activeRecovery.recoveryState, "recovery_active");
      assert.throws(
        () => beginPhilCoreV2RecoveryConfigRotation(activeRecovery),
        /recovery_state_not_normal/
      );
      assert.equal(
        cancelPhilCoreV2Recovery(activeRecovery).recoveryState,
        "normal"
      );

      const activeConfig = beginPhilCoreV2RecoveryConfigRotation(state());
      assert.equal(
        activeConfig.recoveryState,
        "recovery_config_rotation_active"
      );
      assert.throws(
        () => beginPhilCoreV2Recovery(activeConfig),
        /recovery_state_not_normal/
      );
      assert.equal(
        cancelPhilCoreV2RecoveryConfigRotation(activeConfig).recoveryState,
        "normal"
      );
    });

    it("rotates epochs exactly and makes recovery completion increment both", function () {
      const normalRotation = rotatePhilCoreV2ValidatorState({
        state: state(),
        proposedValidator:
          "0x6000000000000000000000000000000000000006",
        proposedValidatorKeyIdBinding: H("o33:new-validator"),
        proposedValidatorEpoch: 4n,
        mode: "normal_rotation"
      });
      assert.equal(normalRotation.validatorEpoch, 4n);
      assert.equal(normalRotation.recoveryEpoch, 2n);
      assert.throws(
        () => rotatePhilCoreV2ValidatorState({
          state: state(),
          proposedValidator:
            "0x6000000000000000000000000000000000000006",
          proposedValidatorKeyIdBinding: H("o33:new-validator"),
          proposedValidatorEpoch: 5n,
          mode: "normal_rotation"
        }),
        /current_plus_one/
      );

      const recovered = rotatePhilCoreV2ValidatorState({
        state: beginPhilCoreV2Recovery(
          revokePhilCoreV2ValidatorLocally(state())
        ),
        proposedValidator:
          "0x6000000000000000000000000000000000000006",
        proposedValidatorKeyIdBinding: H("o33:recovered-validator"),
        proposedValidatorEpoch: 4n,
        proposedRecoveryEpoch: 3n,
        mode: "recovery_completion"
      });
      assert.equal(recovered.validatorStatus, "active");
      assert.equal(recovered.validatorEpoch, 4n);
      assert.equal(recovered.recoveryEpoch, 3n);
      assert.equal(recovered.recoveryState, "normal");
    });

    it("uses a deterministic fixture verifier without creating authority", async function () {
      const digest = H("o33:validator-digest");
      const evidenceReferenceHash = H("o33:fixture-evidence");
      const verifier = createPhilCoreV2FixtureAuthorityVerifier({
        verifierId: "o33.fixture.validator",
        expectations: [{
          authorityKind: "validator_signature",
          digest,
          evidenceReferenceHash,
          chainId: 11155111n,
          account: ACCOUNT,
          validator: VALIDATOR,
          validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
          validatorEpoch: 3n,
          recoveryEpoch: 2n,
          recoveryConfigHash: H("o33:recovery-config")
        }]
      });
      const result = await verifier.verify({
        authorityKind: "validator_signature",
        digest,
        evidence: createPhilCoreV2AuthorityEvidenceReference({
          authorityKind: "validator_signature",
          evidenceReferenceHash,
          fixtureOnly: true
        }),
        chainId: 11155111n,
        account: ACCOUNT,
        validator: VALIDATOR,
        validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
        validatorEpoch: 3n,
        recoveryEpoch: 2n,
        recoveryConfigHash: H("o33:recovery-config")
      });
      assert.equal(result.verified, true);
      assert.equal(result.signatureProduced, false);
      assert.equal(verifier.descriptor.acceptsGenericMessages, false);
      assert.equal(verifier.descriptor.createsSignatures, false);
    });
  });

  describe("authorization verification pipeline", function () {
    it("accepts the exact O.32 authorization chain without executing it", async function () {
      const fixture = fixturePackage();
      const result = await verifyFixture(fixture);
      assert.equal(result.accepted, true);
      assert.equal(
        result.intentCoreHash,
        fixture.vectors.validIntent.intentCoreHash
      );
      assert.equal(
        result.authorizedIntentHash,
        fixture.vectors.runtimeAuthorization.authorizedIntentHash
      );
      assert.equal(
        result.authorityDigest,
        fixture.vectors.validatorAuthorization.validatorDigest
      );
      assert.equal(result.authorizedStateTransition, "none");
      assert.equal(result.executionPerformed, false);
      assert.equal(result.signatureProduced, false);
      assert.equal(result.userOperationCreated, false);
      assert.equal(result.publicMutationCount, 0);
    });

    it("rejects amount, recipient, expiry, nonce, and purpose mutations", async function () {
      const mutations = [
        ["amount", (request) => {
          request.intent.payload.amountWei = "1234568";
        }],
        ["recipient", (request) => {
          request.intent.payload.recipient =
            "0x3000000000000000000000000000000000000003";
        }],
        ["expiry", (request) => {
          request.intent.header.validUntil = "1800000301";
        }],
        ["nonce", (request) => {
          request.intent.header.nonceSequence = "8";
        }],
        ["purpose", (request) => {
          request.intent.header.purpose =
            PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL;
        }]
      ];
      for (const [name, mutate] of mutations) {
        const fixture = fixturePackage();
        mutate(fixture.authorizationPackage);
        const result = await verifyFixture(fixture);
        assert.equal(result.accepted, false, name);
        assert.equal(result.code, "INTENT_HASH_MISMATCH", name);
      }
    });

    it("rejects wrong chain, account, EntryPoint, and owner commitment explicitly", async function () {
      const cases = [
        ["chainId", "1", "CHAIN_MISMATCH"],
        [
          "account",
          "0x4000000000000000000000000000000000000004",
          "ACCOUNT_MISMATCH"
        ],
        [
          "entryPoint",
          "0x7000000000000000000000000000000000000007",
          "ENTRYPOINT_MISMATCH"
        ],
        ["ownerCommitment", H("o33:wrong-owner"), "OWNER_COMMITMENT_MISMATCH"]
      ];
      for (const [field, value, code] of cases) {
        const fixture = fixturePackage();
        fixture.authorizationPackage.intent.header[field] = value;
        const result = await verifyFixture(fixture);
        assert.equal(result.accepted, false, field);
        assert.equal(result.code, code, field);
      }
    });

    it("rejects changed Runtime evidence at the Runtime boundary", async function () {
      const fixture = fixturePackage();
      fixture.authorizationPackage.runtimeAuthorization.policyDecisionHash =
        H("o33:changed-policy");
      const result = await verifyFixture(fixture);
      assert.equal(result.accepted, false);
      assert.equal(
        result.code,
        "RUNTIME_AUTHORIZATION_DIGEST_MISMATCH"
      );
      assert.equal(result.stage, "runtime");
    });

    it("rejects wrong validator, key ID, old/future epochs, and stale recovery", async function () {
      const cases = [
        [
          "validator",
          "0x6000000000000000000000000000000000000006",
          "VALIDATOR_MISMATCH"
        ],
        [
          "validatorKeyIdBinding",
          H("o33:wrong-validator-key"),
          "VALIDATOR_KEY_ID_MISMATCH"
        ],
        ["validatorEpoch", "2", "VALIDATOR_EPOCH_STALE"],
        ["validatorEpoch", "4", "VALIDATOR_EPOCH_FUTURE"],
        ["recoveryEpoch", "1", "RECOVERY_EPOCH_STALE"],
        ["recoveryEpoch", "3", "RECOVERY_EPOCH_FUTURE"],
        [
          "recoveryConfigHash",
          H("o33:wrong-recovery-config"),
          "RECOVERY_CONFIG_MISMATCH"
        ]
      ];
      for (const [field, value, code] of cases) {
        const fixture = fixturePackage();
        fixture.authorizationPackage.authority[field] = value;
        const result = await verifyFixture(fixture);
        assert.equal(result.accepted, false, field);
        assert.equal(result.code, code, field);
      }
    });

    it("rejects stale or future epochs in the intent before authority verification", async function () {
      const cases = [
        ["validatorEpoch", "2", "VALIDATOR_EPOCH_STALE"],
        ["validatorEpoch", "4", "VALIDATOR_EPOCH_FUTURE"],
        ["recoveryEpoch", "1", "RECOVERY_EPOCH_STALE"],
        ["recoveryEpoch", "3", "RECOVERY_EPOCH_FUTURE"]
      ];
      for (const [field, value, code] of cases) {
        const fixture = fixturePackage();
        fixture.authorizationPackage.intent.header[field] = value;
        const result = await verifyFixture(fixture);
        assert.equal(result.accepted, false, field);
        assert.equal(result.code, code, field);
        assert.equal(result.stage, "intent", field);
      }
    });

    it("rejects expired, not-yet-valid, missing, malformed, and wrong authority", async function () {
      const expired = fixturePackage();
      assert.equal(
        (await verifyFixture(expired, { currentTime: "1800000301" })).code,
        "AUTHORIZATION_EXPIRED"
      );
      const early = fixturePackage();
      assert.equal(
        (await verifyFixture(early, { currentTime: "1799999999" })).code,
        "AUTHORIZATION_NOT_YET_VALID"
      );
      const missing = fixturePackage();
      delete missing.authorizationPackage.authority;
      assert.equal(
        (await verifyFixture(missing)).code,
        "AUTHORITY_MISSING"
      );
      const wrongEvidence = fixturePackage();
      wrongEvidence.authorizationPackage.authority.evidence =
        createPhilCoreV2AuthorityEvidenceReference({
          authorityKind: "validator_signature",
          evidenceReferenceHash: H("o33:wrong-evidence"),
          fixtureOnly: true
        });
      assert.equal(
        (await verifyFixture(wrongEvidence)).code,
        "SIGNATURE_INVALID"
      );
      const malformed = fixturePackage();
      malformed.authorizationPackage.authority.evidence = {
        ...malformed.authorizationPackage.authority.evidence,
        format: "wrong-format"
      };
      assert.equal(
        (await verifyFixture(malformed)).code,
        "AUTHORITY_EVIDENCE_MALFORMED"
      );
    });

    it("rejects a verifier that can sign, accepts generic messages, or misreports identity", async function () {
      for (const descriptorMutation of [
        { acceptsGenericMessages: true },
        { createsSignatures: true },
        { requiresIntentBoundDigest: false }
      ]) {
        const fixture = fixturePackage();
        const unsafe = {
          ...fixture.verifier,
          descriptor: {
            ...fixture.verifier.descriptor,
            ...descriptorMutation
          }
        };
        const result = await verifyFixture(fixture, {
          authorityVerifier: unsafe
        });
        assert.equal(result.code, "AUTHORITY_VERIFIER_UNSAFE");
      }

      const fixture = fixturePackage();
      const misreporting = {
        descriptor: fixture.verifier.descriptor,
        async verify() {
          return {
            verified: true,
            classification: "fixture_authority_verified",
            verifierId: "o33.different.verifier",
            signatureProduced: false
          };
        }
      };
      assert.equal(
        (await verifyFixture(fixture, {
          authorityVerifier: misreporting
        })).code,
        "AUTHORITY_VERIFIER_UNSAFE"
      );
    });

    it("rejects reused authority digest and reused keyed nonce", async function () {
      const fixture = fixturePackage();
      const digest = fixture.authorizationPackage.authority
        .declaredAuthorityDigest;
      const digestReplay = {
        ...fixture.state,
        consumedAuthorizationDigests: [digest]
      };
      assert.equal(
        (await verifyFixture(fixture, { state: digestReplay })).code,
        "AUTHORIZATION_REPLAY"
      );

      const nonceReplay = consumePhilCoreV2AuthorizationLocally({
        state: fixture.state,
        authorizationDigest: H("o33:other-digest"),
        nonceKey: fixture.authorizationPackage.intent.header.nonceKey,
        nonceSequence:
          fixture.authorizationPackage.intent.header.nonceSequence
      });
      assert.equal(
        (await verifyFixture(fixture, { state: nonceReplay })).code,
        "NONCE_REPLAY"
      );
    });
  });

  describe("recovery interaction", function () {
    it("accepts exact 2-of-3 recovery authority only as a non-executable transition", async function () {
      const fixture = recoveryFixturePackage();
      const result = await verifyFixture(fixture);
      assert.equal(result.accepted, true);
      assert.equal(result.authorityKind, "recovery_threshold");
      assert.equal(result.authorizedStateTransition, "begin_recovery");
      assert.equal(result.executionPerformed, false);
      assert.equal(result.signatureProduced, false);
    });

    it("rejects one factor, an invalid combination, and a stale recovery epoch", async function () {
      const oneFactor = recoveryFixturePackage({
        authority: { factorBitmap: 0b001 }
      });
      assert.equal(
        (await verifyFixture(oneFactor)).code,
        "RECOVERY_THRESHOLD_NOT_MET"
      );

      const wrongCombination = recoveryFixturePackage({
        authority: { factorBitmap: 0b111 }
      });
      assert.equal(
        (await verifyFixture(wrongCombination)).code,
        "RECOVERY_FACTOR_BITMAP_INVALID"
      );

      const stale = recoveryFixturePackage({
        authority: { recoveryEpoch: "1" }
      });
      assert.equal(
        (await verifyFixture(stale)).code,
        "RECOVERY_EPOCH_STALE"
      );
    });

    it("rejects recovery authority for ordinary execution", async function () {
      const fixture = fixturePackage();
      fixture.authorizationPackage.authority.authorityKind =
        "recovery_threshold";
      fixture.authorizationPackage.authority.factorBitmap = 0b110;
      fixture.authorizationPackage.authority.evidence =
        createPhilCoreV2AuthorityEvidenceReference({
          authorityKind: "recovery_threshold",
          evidenceReferenceHash: H("o33:recovery-evidence"),
          fixtureOnly: true
        });
      const result = await verifyFixture(fixture);
      assert.equal(result.accepted, false);
      assert.equal(result.code, "AUTHORITY_KIND_MISMATCH");
    });

    it("freezes ordinary and maintenance actions during active recovery", async function () {
      const ordinary = fixturePackage();
      ordinary.state = beginPhilCoreV2Recovery(ordinary.state);
      assert.equal(
        (await verifyFixture(ordinary)).code,
        "ORDINARY_EXECUTION_FROZEN"
      );

      const maintenance = fixturePackage();
      maintenance.authorizationPackage.intent.header.actionType = 7;
      maintenance.authorizationPackage.intent.header.nonceKey = "1";
      maintenance.authorizationPackage.intent.header.purpose =
        PHILCORE_V2_PURPOSE.ROTATE_VALIDATOR;
      maintenance.authorizationPackage.intent.payload = {
        kind: "VALIDATOR_ROTATION",
        proposedValidator:
          "0x6000000000000000000000000000000000000006",
        proposedValidatorKeyIdBinding: H("o33:new-validator"),
        proposedValidatorEpoch: "4"
      };
      maintenance.state = beginPhilCoreV2Recovery(maintenance.state);
      assert.equal(
        (await verifyFixture(maintenance)).code,
        "MAINTENANCE_FROZEN"
      );
    });

    it("rejects a new recovery request while recovery is already active", async function () {
      const fixture = recoveryFixturePackage({
        state: { recoveryState: "recovery_active" }
      });
      assert.equal(
        (await verifyFixture(fixture)).code,
        "RECOVERY_ACTION_INVALID_FOR_STATE"
      );
    });

    it("rejects validator authority after local revocation while preserving recovery", async function () {
      const validatorFixture = fixturePackage();
      validatorFixture.state = revokePhilCoreV2ValidatorLocally(
        validatorFixture.state
      );
      assert.equal(
        (await verifyFixture(validatorFixture)).code,
        "VALIDATOR_REVOKED"
      );

      const recoveryFixture = recoveryFixturePackage({
        state: { validatorStatus: "revoked" }
      });
      assert.equal((await verifyFixture(recoveryFixture)).accepted, true);
    });
  });

  describe("deterministic O.33 vector package", function () {
    it("is byte-for-byte bound to O.32 and both O.33 modules", async function () {
      const expected = stringify(await buildO33VectorPackage());
      assert.equal(fs.readFileSync(VECTOR_PATH, "utf8"), expected);
      assert.doesNotThrow(() => childProcess.execFileSync(
        process.execPath,
        [
          path.join(
            ROOT,
            "scripts/cryptography/generate-o33-validator-vectors.cjs"
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

    it("contains every required mutation, replay, validator, and recovery case", function () {
      const vectors = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
      assert.equal(vectors.o32Compatibility.reproducedExactly, true);
      assert.equal(
        vectors.o32Compatibility.duplicateHashImplementationIntroduced,
        false
      );
      assert.deepEqual(
        vectors.failureCodes,
        PHILCORE_V2_AUTHORIZATION_FAILURE_CODES
      );
      const ids = new Set(
        vectors.invalidAuthorizationVectors.map((vector) => vector.id)
      );
      for (const id of [
        "modified_amount",
        "modified_recipient",
        "modified_chain",
        "modified_account",
        "modified_expiry",
        "modified_nonce",
        "modified_purpose",
        "wrong_validator",
        "wrong_validator_key_id",
        "old_validator_epoch",
        "old_recovery_epoch",
        "wrong_authority",
        "malformed_authority",
        "unsafe_verifier",
        "missing_authority",
        "reused_authority",
        "reused_nonce"
      ]) {
        assert.equal(ids.has(id), true, id);
      }
      for (const vector of vectors.invalidAuthorizationVectors) {
        assert.equal(vector.result.accepted, false, vector.id);
        assert.equal(vector.result.code, vector.expectedCode, vector.id);
      }
      assert.equal(
        vectors.recoveryVectors.validTwoOfThree.accepted,
        true
      );
      for (const id of [
        "oneFactorOnly",
        "wrongFactorCombination",
        "staleRecoveryEpoch",
        "ordinaryDuringRecoveryFreeze",
        "revokedValidator"
      ]) {
        assert.equal(
          vectors.recoveryVectors[id].result.code,
          vectors.recoveryVectors[id].expectedCode,
          id
        );
      }
    });

    it("contains no executable or private authority", function () {
      const vectors = JSON.parse(fs.readFileSync(VECTOR_PATH, "utf8"));
      assert.equal(vectors.publicMutationCount, 0);
      assert.equal(vectors.validAuthorization.result.executionPerformed, false);
      assert.equal(vectors.validAuthorization.result.signatureProduced, false);
      assert.equal(vectors.validAuthorization.result.userOperationCreated, false);
      assert.deepEqual(
        Object.values(vectors.securityBoundary),
        Object.values(vectors.securityBoundary).map(() => false)
      );
      const serialized = JSON.stringify(vectors);
      for (const prohibited of [
        "\"signature\":\"0x",
        "\"privateKey\":\"",
        "\"rawTransaction\":\"",
        "phil_secret",
        "credential-bearing",
        "/v2/"
      ]) {
        assert.equal(serialized.includes(prohibited), false, prohibited);
      }
    });
  });
});
