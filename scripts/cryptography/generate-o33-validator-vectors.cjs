require("tsx/cjs");

const crypto = require("node:crypto");
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
  consumePhilCoreV2AuthorizationLocally,
  createPhilCoreV2AuthorityEvidenceReference,
  createPhilCoreV2FixtureAuthorityVerifier,
  createPhilCoreV2ValidatorState,
  revokePhilCoreV2ValidatorLocally
} = require("../../apps/phil-device-sdk/src/v2Validator.ts");
const {
  buildO32VectorPackage
} = require("./generate-o32-v2-vectors.cjs");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O33_V2_VALIDATOR_AUTHORIZATION_TEST_VECTORS.json"
);
const SOURCE_HEAD_AT_PHASE_START =
  "5520d660b50e5db5be700061bd3e93ccff87a8a8";
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const VALIDATOR_KEY_ID =
  "validator_key_3c5b2ebebc4f3f3b";
const VALIDATOR_KEY_ID_BINDING =
  "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809";
const H = (value) => keccak256(toUtf8Bytes(value));

function sha256File(relativePath) {
  return crypto.createHash("sha256")
    .update(fs.readFileSync(path.join(ROOT, relativePath)))
    .digest("hex");
}

function stringify(value) {
  return `${JSON.stringify(
    value,
    (_key, item) => typeof item === "bigint" ? item.toString() : item,
    2
  )}\n`;
}

function baseFixture() {
  const vectors = buildO32VectorPackage();
  const evidenceReferenceHash = H("o33:validator-evidence-reference");
  const state = createPhilCoreV2ValidatorState({
    chainId: vectors.validIntent.input.header.chainId,
    entryPoint: vectors.validIntent.input.header.entryPoint,
    account: vectors.validIntent.input.header.account,
    ownerCommitment: vectors.validIntent.input.header.ownerCommitment,
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
    validatorEpoch: "3",
    recoveryEpoch: "2",
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
      chainId: state.chainId,
      account: state.account,
      validator: state.validator,
      validatorKeyIdBinding: state.validatorKeyIdBinding,
      validatorEpoch: state.validatorEpoch,
      recoveryEpoch: state.recoveryEpoch,
      recoveryConfigHash: state.recoveryConfigHash
    }]
  });
  return { vectors, state, authorizationPackage, verifier };
}

function recoveryFixture() {
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
  if (
    authorizedIntentHash
    !== vectors.recovery.validRecovery.authorizedIntentHash
  ) {
    throw new Error("O33_RECOVERY_O32_BINDING_MISMATCH");
  }
  const evidenceReferenceHash = H("o33:recovery-evidence-reference");
  const state = createPhilCoreV2ValidatorState({
    chainId: intent.header.chainId,
    entryPoint: intent.header.entryPoint,
    account: intent.header.account,
    ownerCommitment: intent.header.ownerCommitment,
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
    validatorEpoch: "3",
    recoveryEpoch: "2",
    recoveryConfigHash: vectors.recovery.recoveryConfigHash
  });
  const authorizationPackage = {
    intent,
    declaredIntentCoreHash:
      vectors.recovery.validRecovery.intentCoreHash,
    runtimeAuthorization,
    declaredRuntimeAuthorizationDigest: runtimeAuthorizationDigest,
    declaredAuthorizedIntentHash: authorizedIntentHash,
    userOperationHashBinding:
      vectors.recovery.validRecovery.authorizationInput.userOperationHash,
    authority: {
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
        vectors.recovery.validRecovery.recoveryFactorDigest
    }
  };
  const verifier = createPhilCoreV2FixtureAuthorityVerifier({
    verifierId: "o33.fixture.recovery",
    expectations: [{
      authorityKind: "recovery_threshold",
      digest: vectors.recovery.validRecovery.recoveryFactorDigest,
      evidenceReferenceHash,
      chainId: state.chainId,
      account: state.account,
      validator: state.validator,
      validatorKeyIdBinding: state.validatorKeyIdBinding,
      validatorEpoch: state.validatorEpoch,
      recoveryEpoch: state.recoveryEpoch,
      recoveryConfigHash: state.recoveryConfigHash,
      factorBitmap:
        vectors.recovery.validRecovery.authorizationInput.factorBitmap
    }]
  });
  return { vectors, state, authorizationPackage, verifier };
}

async function verify(fixture, overrides = {}) {
  return verifyPhilCoreV2Authorization({
    state: fixture.state,
    authorizationPackage: fixture.authorizationPackage,
    currentTime: "1800000150",
    authorityVerifier: fixture.verifier,
    ...overrides
  });
}

async function failureVector(id, expectedCode, mutate) {
  const fixture = baseFixture();
  await mutate(fixture);
  const result = await verify(fixture);
  if (result.accepted || result.code !== expectedCode) {
    throw new Error(`O33_VECTOR_RESULT_MISMATCH:${id}`);
  }
  return { id, expectedCode, result };
}

async function buildO33VectorPackage() {
  const base = baseFixture();
  const accepted = await verify(base);
  if (!accepted.accepted) throw new Error("O33_VALID_VECTOR_REJECTED");

  const failures = [
    await failureVector("modified_amount", "INTENT_HASH_MISMATCH", async (f) => {
      f.authorizationPackage.intent.payload.amountWei = "1234568";
    }),
    await failureVector("modified_recipient", "INTENT_HASH_MISMATCH", async (f) => {
      f.authorizationPackage.intent.payload.recipient =
        "0x3000000000000000000000000000000000000003";
    }),
    await failureVector("modified_chain", "CHAIN_MISMATCH", async (f) => {
      f.authorizationPackage.intent.header.chainId = "1";
    }),
    await failureVector("modified_account", "ACCOUNT_MISMATCH", async (f) => {
      f.authorizationPackage.intent.header.account =
        "0x4000000000000000000000000000000000000004";
    }),
    await failureVector("modified_expiry", "INTENT_HASH_MISMATCH", async (f) => {
      f.authorizationPackage.intent.header.validUntil = "1800000301";
    }),
    await failureVector("modified_nonce", "INTENT_HASH_MISMATCH", async (f) => {
      f.authorizationPackage.intent.header.nonceSequence = "8";
    }),
    await failureVector("modified_purpose", "INTENT_HASH_MISMATCH", async (f) => {
      f.authorizationPackage.intent.header.purpose =
        PHILCORE_V2_PURPOSE.RELEASE_RESIDUAL;
    }),
    await failureVector("wrong_validator", "VALIDATOR_MISMATCH", async (f) => {
      f.authorizationPackage.authority.validator =
        "0x6000000000000000000000000000000000000006";
    }),
    await failureVector(
      "wrong_validator_key_id",
      "VALIDATOR_KEY_ID_MISMATCH",
      async (f) => {
        f.authorizationPackage.authority.validatorKeyIdBinding =
          H("o33:wrong-validator-key");
      }
    ),
    await failureVector("old_validator_epoch", "VALIDATOR_EPOCH_STALE", async (f) => {
      f.authorizationPackage.authority.validatorEpoch = "2";
    }),
    await failureVector("old_recovery_epoch", "RECOVERY_EPOCH_STALE", async (f) => {
      f.authorizationPackage.authority.recoveryEpoch = "1";
    }),
    await failureVector("wrong_authority", "SIGNATURE_INVALID", async (f) => {
      f.authorizationPackage.authority.evidence =
        createPhilCoreV2AuthorityEvidenceReference({
          authorityKind: "validator_signature",
          evidenceReferenceHash: H("o33:wrong-authority"),
          fixtureOnly: true
        });
    }),
    await failureVector(
      "malformed_authority",
      "AUTHORITY_EVIDENCE_MALFORMED",
      async (f) => {
        f.authorizationPackage.authority.evidence = {
          ...f.authorizationPackage.authority.evidence,
          format: "malformed"
        };
      }
    ),
    await failureVector(
      "unsafe_verifier",
      "AUTHORITY_VERIFIER_UNSAFE",
      async (f) => {
        f.verifier = {
          ...f.verifier,
          descriptor: {
            ...f.verifier.descriptor,
            acceptsGenericMessages: true
          }
        };
      }
    ),
    await failureVector("missing_authority", "AUTHORITY_MISSING", async (f) => {
      delete f.authorizationPackage.authority;
    }),
    await failureVector("reused_authority", "AUTHORIZATION_REPLAY", async (f) => {
      f.state = createPhilCoreV2ValidatorState({
        ...f.state,
        consumedAuthorizationDigests: [
          f.authorizationPackage.authority.declaredAuthorityDigest
        ]
      });
    }),
    await failureVector("reused_nonce", "NONCE_REPLAY", async (f) => {
      f.state = consumePhilCoreV2AuthorizationLocally({
        state: f.state,
        authorizationDigest: H("o33:other-authorization"),
        nonceKey: f.authorizationPackage.intent.header.nonceKey,
        nonceSequence: f.authorizationPackage.intent.header.nonceSequence
      });
    })
  ];

  const recovery = recoveryFixture();
  const validRecovery = await verify(recovery);
  if (!validRecovery.accepted) throw new Error("O33_RECOVERY_VECTOR_REJECTED");

  const oneFactor = recoveryFixture();
  oneFactor.authorizationPackage.authority.factorBitmap = 0b001;
  const oneFactorResult = await verify(oneFactor);
  const wrongCombination = recoveryFixture();
  wrongCombination.authorizationPackage.authority.factorBitmap = 0b111;
  const wrongCombinationResult = await verify(wrongCombination);
  const staleRecovery = recoveryFixture();
  staleRecovery.authorizationPackage.authority.recoveryEpoch = "1";
  const staleRecoveryResult = await verify(staleRecovery);
  const frozenOrdinary = baseFixture();
  frozenOrdinary.state = beginPhilCoreV2Recovery(frozenOrdinary.state);
  const frozenOrdinaryResult = await verify(frozenOrdinary);
  const revokedValidator = baseFixture();
  revokedValidator.state =
    revokePhilCoreV2ValidatorLocally(revokedValidator.state);
  const revokedValidatorResult = await verify(revokedValidator);

  return {
    schemaVersion: "philcore-o33-validator-authorization-vectors-v1",
    phase: "O.33",
    canonicalPhaseName: "O.33 V2 Validator and Authorization Engine Prototype",
    classification: "VALIDATOR_AUTHORIZATION_ENGINE_PROTOTYPE_LOCAL_ONLY",
    sourceHeadAtPhaseStart: SOURCE_HEAD_AT_PHASE_START,
    fixtureOnly: true,
    publicMutationCount: 0,
    implementationBindings: {
      o32IntentModuleSha256:
        sha256File("apps/phil-device-sdk/src/v2Intent.ts"),
      o32AuthorizationModuleSha256:
        sha256File("apps/phil-device-sdk/src/v2Authorization.ts"),
      o32VectorPackageSha256:
        sha256File(
          "config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json"
        ),
      o33ValidatorModuleSha256:
        sha256File("apps/phil-device-sdk/src/v2Validator.ts"),
      o33AuthorizationEngineModuleSha256:
        sha256File("apps/phil-device-sdk/src/v2AuthorizationEngine.ts")
    },
    canonicalIdentity: {
      identityId: "identity_abab9766da60_24afd015",
      label: "My Phil",
      validator: VALIDATOR,
      validatorKeyId: VALIDATOR_KEY_ID,
      validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING
    },
    o32Compatibility: {
      reproducedExactly: true,
      intentCoreHash: base.vectors.validIntent.intentCoreHash,
      runtimeAuthorizationDigest:
        base.vectors.runtimeAuthorization.runtimeAuthorizationDigest,
      authorizedIntentHash:
        base.vectors.runtimeAuthorization.authorizedIntentHash,
      validatorDigest:
        base.vectors.validatorAuthorization.validatorDigest,
      duplicateHashImplementationIntroduced: false
    },
    validatorModel: {
      validatorIsWallet: false,
      validatorIsAdministrator: false,
      choosesActions: false,
      expandsPermissions: false,
      acceptsGenericMessages: false,
      receivesSignatureBytes: false,
      createsSignatures: false,
      verifierInterfaceRequired: true,
      minimumValidatorEpoch: "1",
      ordinaryNonceKey: "0",
      maintenanceNonceKey: "1",
      recoveryNonceKey: "2"
    },
    failureCodes: PHILCORE_V2_AUTHORIZATION_FAILURE_CODES,
    validAuthorization: {
      state: base.state,
      authorizationPackage: base.authorizationPackage,
      result: accepted
    },
    invalidAuthorizationVectors: failures,
    recoveryVectors: {
      validTwoOfThree: validRecovery,
      oneFactorOnly: {
        expectedCode: "RECOVERY_THRESHOLD_NOT_MET",
        result: oneFactorResult
      },
      wrongFactorCombination: {
        expectedCode: "RECOVERY_FACTOR_BITMAP_INVALID",
        result: wrongCombinationResult
      },
      staleRecoveryEpoch: {
        expectedCode: "RECOVERY_EPOCH_STALE",
        result: staleRecoveryResult
      },
      ordinaryDuringRecoveryFreeze: {
        expectedCode: "ORDINARY_EXECUTION_FROZEN",
        result: frozenOrdinaryResult
      },
      revokedValidator: {
        expectedCode: "VALIDATOR_REVOKED",
        result: revokedValidatorResult
      }
    },
    securityBoundary: {
      solidityImplemented: false,
      deployableBytecodeCreated: false,
      factoryImplemented: false,
      productionValidatorCreated: false,
      credentialEnrolled: false,
      privateKeyCreated: false,
      signatureCreated: false,
      signatureBytesStored: false,
      proofGenerated: false,
      userOperationCreated: false,
      transactionCreated: false,
      liveContractCalled: false,
      fundsMoved: false,
      publicMutationOccurred: false
    }
  };
}

async function main() {
  const output = stringify(await buildO33VectorPackage());
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT_PATH)) {
      throw new Error("O33_VECTOR_PACKAGE_MISSING");
    }
    if (fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O33_VECTOR_PACKAGE_STALE");
    }
    process.stdout.write("O.33 validator vector package is current\n");
    return;
  }
  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, output, { mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

module.exports = {
  buildO33VectorPackage,
  stringify
};

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : "O33_ERROR"}\n`);
    process.exitCode = 1;
  });
}
