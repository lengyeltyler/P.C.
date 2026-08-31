require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { keccak256, toUtf8Bytes } = require("ethers");

const {
  PHILCORE_V2_ACCOUNT_VERSION,
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_EIP712_NAME,
  PHILCORE_V2_EIP712_VERSION,
  PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_PURPOSE,
  PHILCORE_V2_PURPOSE_LABEL,
  PHILCORE_V2_SECURITY_MODEL,
  PHILCORE_V2_SECURITY_MODEL_ID,
  PHILCORE_V2_TYPE,
  PHILCORE_V2_TYPEHASH,
  composePhilCoreV2Nonce,
  computePhilCoreV2ApplicationContextHash,
  computePhilCoreV2FundLifecycleDigest,
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
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2ProofBindingHash,
  computePhilCoreV2RecoveryConfigurationHash,
  computePhilCoreV2RecoveryFactorCommitment,
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2RuntimeAuthorizationDigest,
  computePhilCoreV2ValidatorCommitment,
  computePhilCoreV2ValidatorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json"
);
const SOURCE_HEAD_AT_PHASE_START =
  "4f62f4ba7e5330e2253f308289fa1e75e320ce68";

const ACCOUNT = "0x1000000000000000000000000000000000000001";
const OTHER_ACCOUNT = "0x4000000000000000000000000000000000000004";
const ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const RECIPIENT = "0x2000000000000000000000000000000000000002";
const OTHER_RECIPIENT = "0x3000000000000000000000000000000000000003";
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const VALIDATOR_KEY_ID =
  "validator_key_3c5b2ebebc4f3f3b";
const VALIDATOR_KEY_ID_BINDING =
  "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809";

const H = (value) => keccak256(toUtf8Bytes(value));
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;

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

function applicationContextInput() {
  return {
    applicationIdHash: H("o32:application"),
    originHash: H("o32:origin"),
    sessionIdHash: H("o32:session"),
    capabilityGrantIdHash: H("o32:capability"),
    policyDecisionIdHash: H("o32:policy")
  };
}

function fundLifecycleInput() {
  return {
    lifecycleSchemaHash: H("philcore-test-fund-lifecycle-v1"),
    account: ACCOUNT,
    asset: "0x0000000000000000000000000000000000000000",
    tokenId: "0",
    maximumFundingOrHolding: "10000000",
    maximumStranded: "1000",
    residualRecipient: RECIPIENT,
    expectedPostOperationBalance: "9000000",
    expectedFinalBalance: "0",
    releaseRouteHash: H("o32:release-route"),
    simulationEvidenceHash: H("o32:simulation")
  };
}

function nativeIntent(overrides = {}) {
  const applicationContextHash =
    computePhilCoreV2ApplicationContextHash(applicationContextInput());
  const fundLifecycleDigest =
    computePhilCoreV2FundLifecycleDigest(fundLifecycleInput());
  const base = {
    header: {
      specificationVersion: PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      actionType: PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER,
      actionId: H("o32:action:1"),
      purpose: PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      ownerCommitment: H("o32:fixture-owner-commitment"),
      chainId: "11155111",
      entryPoint: ENTRYPOINT,
      account: ACCOUNT,
      nonceKey: PHILCORE_V2_NONCE_KEY.ORDINARY.toString(),
      nonceSequence: "7",
      validatorEpoch: "3",
      recoveryEpoch: "2",
      applicationContextHash,
      fundLifecycleDigest,
      maxTotalFeeWei: "5000000000000",
      validAfter: "1800000000",
      validUntil: "1800000300"
    },
    payload: {
      kind: "NATIVE_TRANSFER",
      recipient: RECIPIENT,
      amountWei: "1234567"
    }
  };
  return {
    ...base,
    ...overrides,
    header: { ...base.header, ...(overrides.header ?? {}) },
    payload: { ...base.payload, ...(overrides.payload ?? {}) }
  };
}

function recoveryIntent(recoveryConfigHash) {
  const base = nativeIntent();
  return {
    header: {
      ...base.header,
      actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
      actionId: H("o32:recovery-action:1"),
      purpose: PHILCORE_V2_PURPOSE.REQUEST_RECOVERY,
      nonceKey: PHILCORE_V2_NONCE_KEY.RECOVERY.toString(),
      nonceSequence: "2",
      validUntil: "1800003600"
    },
    payload: {
      kind: "RECOVERY_REQUEST",
      proposedValidator:
        "0x6000000000000000000000000000000000000006",
      proposedValidatorKeyIdBinding: H("o32:proposed-validator-key-id"),
      proposedValidatorEpoch: "4",
      recoveryRequestSalt: H(`o32:recovery-request:${recoveryConfigHash}`)
    }
  };
}

function proofBindingInput() {
  return {
    proofTypeHash: H("stwo-unlock-keccak-v1"),
    proofInputHash: H("o32:proof-input"),
    proofArtifactDigest: H("o32:proof-artifact"),
    nullifier: H("o32:nullifier")
  };
}

function runtimeInput(intentCoreHash) {
  return {
    intentCoreHash,
    proofBindingHash: computePhilCoreV2ProofBindingHash(proofBindingInput()),
    policyDecisionHash: H("o32:runtime-policy-decision"),
    approvalEvidenceHash: H("o32:approval-evidence"),
    userPresenceEvidenceHash: H("o32:user-presence-evidence")
  };
}

function authorizationChain(intent, userOperationHashBinding) {
  const encoded = encodePhilCoreV2Intent(intent);
  const runtime = runtimeInput(encoded.intentCoreHash);
  const runtimeAuthorizationDigest =
    computePhilCoreV2RuntimeAuthorizationDigest(runtime);
  const authorizedIntentHash = computePhilCoreV2AuthorizedIntentHash({
    intentCoreHash: encoded.intentCoreHash,
    runtimeAuthorizationDigest
  });
  const validatorInput = {
    authorizedIntentHash,
    userOperationHash: userOperationHashBinding,
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
    validatorEpoch: intent.header.validatorEpoch,
    recoveryEpoch: intent.header.recoveryEpoch
  };
  const validatorResult = computePhilCoreV2ValidatorDigest(
    { chainId: intent.header.chainId, account: intent.header.account },
    validatorInput
  );
  return {
    encoded,
    runtime,
    runtimeAuthorizationDigest,
    authorizedIntentHash,
    validatorInput,
    validatorResult
  };
}

function factor(role, overrides = {}) {
  const webauthn = role !== PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR;
  return {
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    role,
    verifierKind: webauthn
      ? PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256
      : PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1,
    publicVerificationMaterialHash: H(`o32:factor-public-material:${role}`),
    rpIdHash: webauthn ? H("philcore.test") : ZERO_BYTES32,
    originPolicyHash: webauthn
      ? H("https://philcore.test")
      : ZERO_BYTES32,
    userVerificationPolicy: webauthn
      ? PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED
      : PHILCORE_V2_USER_VERIFICATION_POLICY.NOT_APPLICABLE,
    credentialGeneration: "1",
    ...overrides
  };
}

function recoveryVectors() {
  const descriptors = {
    primaryDevice: factor(PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE),
    hardwareSecurityKey:
      factor(PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY),
    recoveryFactor: factor(PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR)
  };
  const commitments = {
    primaryDevice: computePhilCoreV2RecoveryFactorCommitment(
      descriptors.primaryDevice
    ),
    hardwareSecurityKey: computePhilCoreV2RecoveryFactorCommitment(
      descriptors.hardwareSecurityKey
    ),
    recoveryFactor: computePhilCoreV2RecoveryFactorCommitment(
      descriptors.recoveryFactor
    )
  };
  const configurationInput = {
    configurationVersion: PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION,
    threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
    primaryDeviceCommitment: commitments.primaryDevice,
    hardwareSecurityKeyCommitment: commitments.hardwareSecurityKey,
    recoveryFactorCommitment: commitments.recoveryFactor
  };
  const recoveryConfigHash =
    computePhilCoreV2RecoveryConfigurationHash(configurationInput);
  const recoveryChain = authorizationChain(
    recoveryIntent(recoveryConfigHash),
    H("o32:recovery-user-operation-hash-binding")
  );
  const recoveryAuthorizationInput = {
    authorizedIntentHash: recoveryChain.authorizedIntentHash,
    userOperationHash: H("o32:recovery-user-operation-hash-binding"),
    recoveryConfigHash,
    recoveryEpoch: "2",
    factorBitmap:
      PHILCORE_V2_RECOVERY_FACTOR_BITMAP.HARDWARE_AND_RECOVERY
  };
  const domain = { chainId: "11155111", account: ACCOUNT };
  const validDigest =
    computePhilCoreV2RecoveryFactorDigest(domain, recoveryAuthorizationInput);
  const staleEpochDigest =
    computePhilCoreV2RecoveryFactorDigest(domain, {
      ...recoveryAuthorizationInput,
      recoveryEpoch: "1"
    });
  const invalidFactorDescriptor = {
    ...descriptors.hardwareSecurityKey,
    publicVerificationMaterialHash: H("o32:wrong-hardware-factor-material")
  };
  const invalidFactorCommitment =
    computePhilCoreV2RecoveryFactorCommitment(invalidFactorDescriptor);

  return {
    factorDescriptors: descriptors,
    factorCommitments: commitments,
    configurationInput,
    recoveryConfigHash,
    validRecovery: {
      intent: recoveryIntent(recoveryConfigHash),
      intentCoreHash: recoveryChain.encoded.intentCoreHash,
      authorizedIntentHash: recoveryChain.authorizedIntentHash,
      authorizationInput: recoveryAuthorizationInput,
      domainSeparator: validDigest.domainSeparator,
      structHash: validDigest.structHash,
      recoveryFactorDigest: validDigest.digest
    },
    invalidFactorCommitment: {
      descriptor: invalidFactorDescriptor,
      commitment: invalidFactorCommitment,
      registeredCommitment: commitments.hardwareSecurityKey,
      matchesRegisteredCommitment: false
    },
    staleRecoveryEpoch: {
      suppliedRecoveryEpoch: "1",
      currentRecoveryEpoch: "2",
      structHash: staleEpochDigest.structHash,
      recoveryFactorDigest: staleEpochDigest.digest,
      matchesCurrentEpochDigest: false
    }
  };
}

function mutationVectors(baseIntent, baseHash) {
  const inputs = [
    ["modified_amount", nativeIntent({ payload: { amountWei: "1234568" } })],
    ["modified_recipient", nativeIntent({
      payload: { recipient: OTHER_RECIPIENT }
    })],
    ["modified_chain", nativeIntent({ header: { chainId: "1" } })],
    ["modified_account", nativeIntent({ header: { account: OTHER_ACCOUNT } })],
    ["modified_expiry", nativeIntent({
      header: { validUntil: "1800000301" }
    })],
    ["modified_nonce", nativeIntent({ header: { nonceSequence: "8" } })],
    ["old_validator_epoch", nativeIntent({
      header: { validatorEpoch: "2" }
    })],
    ["old_recovery_epoch", nativeIntent({
      header: { recoveryEpoch: "1" }
    })]
  ];
  return inputs.map(([id, intent]) => {
    const intentCoreHash = encodePhilCoreV2Intent(intent).intentCoreHash;
    return {
      id,
      changedFields: id.replace("modified_", "").replace("old_", ""),
      intentCoreHash,
      matchesValidIntentCoreHash: intentCoreHash === baseHash
    };
  });
}

function buildO32VectorPackage() {
  const validIntent = nativeIntent();
  const validUserOperationHashBinding =
    H("o32:user-operation-hash-binding-fixture-only");
  const chain = authorizationChain(
    validIntent,
    validUserOperationHashBinding
  );
  const recovery = recoveryVectors();
  const mutations = mutationVectors(validIntent, chain.encoded.intentCoreHash);
  const reusedNonce = encodePhilCoreV2Intent(nativeIntent());
  const validatorCommitment = computePhilCoreV2ValidatorCommitment({
    verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
    validator: VALIDATOR,
    validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING
  });

  return {
    schemaVersion: "philcore-o32-v2-cryptographic-test-vectors-v1",
    phase: "O.32",
    canonicalPhaseName:
      "O.32 V2 Cryptographic Foundation and Intent Verification Implementation",
    classification: "CRYPTOGRAPHIC_FOUNDATION_IMPLEMENTED_LOCAL_ONLY",
    sourceHeadAtPhaseStart: SOURCE_HEAD_AT_PHASE_START,
    fixtureOnly: true,
    publicMutationCount: 0,
    implementationBindings: {
      intentModule:
        "apps/phil-device-sdk/src/v2Intent.ts",
      intentModuleSha256:
        sha256File("apps/phil-device-sdk/src/v2Intent.ts"),
      authorizationModule:
        "apps/phil-device-sdk/src/v2Authorization.ts",
      authorizationModuleSha256:
        sha256File("apps/phil-device-sdk/src/v2Authorization.ts")
    },
    canonicalModel: {
      intentSpecificationVersion:
        PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
      accountVersion: PHILCORE_V2_ACCOUNT_VERSION,
      accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
      securityModel: PHILCORE_V2_SECURITY_MODEL,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      eip712Name: PHILCORE_V2_EIP712_NAME,
      eip712Version: PHILCORE_V2_EIP712_VERSION,
      canonicalEncoding: "abi.encode",
      packedEncodingAllowed: false,
      personalSignAllowed: false,
      arbitraryTypedDataApiExposed: false,
      intentTypeStrings: PHILCORE_V2_TYPE,
      intentTypeHashes: PHILCORE_V2_TYPEHASH,
      authorizationTypeStrings: PHILCORE_V2_AUTHORIZATION_TYPE,
      authorizationTypeHashes: PHILCORE_V2_AUTHORIZATION_TYPEHASH,
      purposeLabels: PHILCORE_V2_PURPOSE_LABEL,
      purposeHashes: PHILCORE_V2_PURPOSE
    },
    canonicalFieldOrder: {
      intentCoreHeader: [
        "specificationVersion",
        "securityModelId",
        "actionType",
        "actionId",
        "purpose",
        "ownerCommitment",
        "chainId",
        "entryPoint",
        "account",
        "nonceKey",
        "nonceSequence",
        "validatorEpoch",
        "recoveryEpoch",
        "applicationContextHash",
        "fundLifecycleDigest",
        "maxTotalFeeWei",
        "validAfter",
        "validUntil"
      ],
      runtimeAuthorization: [
        "intentCoreHash",
        "proofBindingHash",
        "policyDecisionHash",
        "approvalEvidenceHash",
        "userPresenceEvidenceHash"
      ],
      validatorAuthorization: [
        "authorizedIntentHash",
        "userOpHash",
        "validator",
        "validatorKeyIdBinding",
        "validatorEpoch",
        "recoveryEpoch"
      ]
    },
    publicFixtureBindings: {
      chainId: "11155111",
      entryPoint: ENTRYPOINT,
      account: ACCOUNT,
      recipient: RECIPIENT,
      validator: VALIDATOR,
      validatorKeyId: VALIDATOR_KEY_ID,
      validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
      userOperationHashBinding: validUserOperationHashBinding,
      userOperationCreated: false
    },
    applicationContext: {
      input: applicationContextInput(),
      hash: computePhilCoreV2ApplicationContextHash(applicationContextInput())
    },
    fundLifecycle: {
      input: fundLifecycleInput(),
      digest: computePhilCoreV2FundLifecycleDigest(fundLifecycleInput())
    },
    validIntent: {
      input: validIntent,
      keyedNonce: composePhilCoreV2Nonce({
        key: validIntent.header.nonceKey,
        sequence: validIntent.header.nonceSequence
      }).toString(),
      coreHeaderEncoding: chain.encoded.coreHeaderEncoding,
      coreHeaderHash: chain.encoded.coreHeaderHash,
      actionEncoding: chain.encoded.actionEncoding,
      intentCoreHash: chain.encoded.intentCoreHash
    },
    runtimeAuthorization: {
      proofBindingInput: proofBindingInput(),
      proofBindingHash: chain.runtime.proofBindingHash,
      input: chain.runtime,
      runtimeAuthorizationDigest: chain.runtimeAuthorizationDigest,
      authorizedIntentHash: chain.authorizedIntentHash
    },
    validatorAuthorization: {
      validatorCommitment,
      input: chain.validatorInput,
      domainSeparator: chain.validatorResult.domainSeparator,
      structHash: chain.validatorResult.structHash,
      validatorDigest: chain.validatorResult.digest
    },
    intentMutationVectors: mutations,
    replayVectors: {
      reusedNonce: {
        nonceKey: validIntent.header.nonceKey,
        nonceSequence: validIntent.header.nonceSequence,
        keyedNonce: composePhilCoreV2Nonce({
          key: validIntent.header.nonceKey,
          sequence: validIntent.header.nonceSequence
        }).toString(),
        intentCoreHash: reusedNonce.intentCoreHash,
        matchesOriginalHash:
          reusedNonce.intentCoreHash === chain.encoded.intentCoreHash,
        expectedRuntimeResult:
          "REJECT_ALREADY_CONSUMED_ENTRYPOINT_NONCE"
      },
      oldValidatorEpoch: mutations.find(
        (vector) => vector.id === "old_validator_epoch"
      ),
      oldRecoveryEpoch: mutations.find(
        (vector) => vector.id === "old_recovery_epoch"
      ),
      wrongAccount: mutations.find(
        (vector) => vector.id === "modified_account"
      ),
      wrongChain: mutations.find(
        (vector) => vector.id === "modified_chain"
      )
    },
    recovery,
    securityBoundary: {
      privateKeyCreated: false,
      signatureCreated: false,
      credentialEnrolled: false,
      proofGenerated: false,
      protectedWitnessUsed: false,
      userOperationCreated: false,
      userOperationSubmitted: false,
      transactionCreated: false,
      contractImplemented: false,
      deployableBytecodeCreated: false,
      liveContractCalled: false,
      fundsMoved: false,
      publicMutationOccurred: false
    }
  };
}

function main() {
  const output = stringify(buildO32VectorPackage());
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT_PATH)) {
      throw new Error("O32_VECTOR_PACKAGE_MISSING");
    }
    if (fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O32_VECTOR_PACKAGE_STALE");
    }
    process.stdout.write("O.32 cryptographic vector package is current\n");
    return;
  }
  fs.mkdirSync(path.dirname(OUTPUT_PATH), { recursive: true });
  fs.writeFileSync(OUTPUT_PATH, output, { mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

module.exports = {
  buildO32VectorPackage,
  stringify
};

if (require.main === module) main();

module.exports = {
  OUTPUT_PATH,
  buildO32VectorPackage,
  stringify
};
