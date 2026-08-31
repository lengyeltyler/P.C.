require("tsx/cjs");

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const {
  AbiCoder,
  SigningKey,
  computeAddress,
  concat,
  getBytes,
  hexlify,
  id,
  keccak256,
  sha256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");

const {
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_PURPOSE,
  PHILCORE_V2_SECURITY_MODEL_ID,
  composePhilCoreV2Nonce,
  computePhilCoreV2ApplicationContextHash,
  computePhilCoreV2FundLifecycleDigest,
  encodePhilCoreV2Intent
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  PHILCORE_V2_RECOVERY_FACTOR_BITMAP,
  PHILCORE_V2_RECOVERY_FACTOR_ROLE,
  PHILCORE_V2_RECOVERY_THRESHOLD,
  PHILCORE_V2_RECOVERY_VERIFIER_KIND,
  PHILCORE_V2_USER_VERIFICATION_POLICY,
  PHILCORE_V2_VALIDATOR_VERIFIER_KIND,
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2ProofBindingHash,
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2RuntimeAuthorizationDigest,
  computePhilCoreV2ValidatorCommitment,
  computePhilCoreV2ValidatorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_ATTESTATION_POLICY,
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_BACKUP_POLICY,
  PHILCORE_V2_RECOVERY_AUTHORITY_KIND,
  PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
  PHILCORE_V2_RECOVERY_DOMAIN_ID,
  PHILCORE_V2_RECOVERY_EVIDENCE_VERSION,
  PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
  PHILCORE_V2_ZERO_BYTES32,
  computePhilCoreV2RecoveryDescriptorCommitment,
  computePhilCoreV2RecoveryEvidenceContextHash,
  computePhilCoreV2RecoveryIndependenceBinding,
  computePhilCoreV2Secp256k1PublicMaterialHash,
  computePhilCoreV2WebAuthnPublicMaterialHash,
  validatePhilCoreV2RecoveryDescriptorSet
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
  PHILCORE_O37_2_FIXTURE_VERSION,
  PHILCORE_O37_2_P256_ORDER,
  PHILCORE_O37_2_SECP256K1_ORDER,
  buildPhilCoreO372WebAuthnClientData,
  computePhilCoreO372PackedUserOperationHash,
  computePhilCoreO372PackedUserOperationStructHash,
  computePhilCoreO372RpIdHash,
  computePhilCoreO372WebAuthnMessageHash,
  encodePhilCoreO372RecoveryEnvelope,
  encodePhilCoreO372Secp256k1Evidence,
  encodePhilCoreO372ValidatorEnvelope,
  encodePhilCoreO372WebAuthnEvidence,
  packPhilCoreO372Uint128Pair,
  verifyPhilCoreO372P256Signature,
  verifyPhilCoreO372ValidatorEnvelope
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O37_2_V2_DETERMINISTIC_CRYPTOGRAPHIC_FIXTURES.json"
);
const SOURCE_HEAD_AT_PHASE_START =
  "569fe5671cc82640a464f37a0c34efe8c1159bc6";
const abiCoder = AbiCoder.defaultAbiCoder();

const FIXTURE_CHAIN_ID = 31337n;
const FIXTURE_ENTRYPOINT =
  "0x00000000000000000000000000000000000F4337";
const FIXTURE_ACCOUNT =
  "0x00000000000000000000000000000000000F3702";
const FIXTURE_RECIPIENT =
  "0x00000000000000000000000000000000000F0002";
const WRONG_FIXTURE_ACCOUNT =
  "0x00000000000000000000000000000000000F3703";
const WRONG_FIXTURE_ENTRYPOINT =
  "0x00000000000000000000000000000000000F4338";
const FIXTURE_RP_ID = "o37-2.fixture.philcore.invalid";
const FIXTURE_ORIGIN = "https://o37-2.fixture.philcore.invalid";
const FIXTURE_VALIDATOR_KEY_ID = "fixture_validator_o37_2_v1";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const CORE_TUPLE =
  "tuple(uint8 specificationVersion,bytes32 securityModelId,uint8 actionType,bytes32 actionId,bytes32 purpose,bytes32 ownerCommitment,uint256 chainId,address entryPoint,address account,uint192 nonceKey,uint64 nonceSequence,uint64 validatorEpoch,uint64 recoveryEpoch,bytes32 applicationContextHash,bytes32 fundLifecycleDigest,uint256 maxTotalFeeWei,uint48 validAfter,uint48 validUntil)";
const AUTHORIZED_INTENT_TUPLE =
  `tuple(${CORE_TUPLE} core,bytes32 runtimeAuthorizationDigest)`;

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

function deterministicScalar(label, order) {
  const material = sha256(toUtf8Bytes(
    `PHILCORE_O37_2_TEST_FIXTURE_ONLY:${label}`
  ));
  const scalar = (BigInt(material) % (order - 1n)) + 1n;
  return zeroPadValue(toBeHex(scalar), 32);
}

function secpIdentity(label, keyId, generation) {
  const privateScalar = deterministicScalar(label, PHILCORE_O37_2_SECP256K1_ORDER);
  const signingKey = new SigningKey(privateScalar);
  return {
    classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
    privateScalar,
    signingKey,
    public: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      publicKey: signingKey.publicKey,
      compressedPublicKey: signingKey.compressedPublicKey,
      address: computeAddress(signingKey.publicKey),
      keyIdentifier: keyId,
      keyIdentifierBinding: H(
        `PHILCORE_O37_2_TEST_KEY_BINDING:${keyId}:${generation}`
      ),
      generation
    }
  };
}

function p256Identity(label, role, attachmentPolicy, attestationPolicy) {
  const privateScalar = deterministicScalar(label, PHILCORE_O37_2_P256_ORDER);
  const publicKey = p256.getPublicKey(getBytes(privateScalar), false);
  const qx = hexlify(publicKey.slice(1, 33));
  const qy = hexlify(publicKey.slice(33, 65));
  const credentialIdFixture = sha256(toUtf8Bytes(
    `PHILCORE_O37_2_PUBLIC_CREDENTIAL_ID_FIXTURE:${label}`
  ));
  const credentialIdHash = keccak256(credentialIdFixture);
  const independenceInput = {
    bindingVersion: 1,
    role,
    credentialIdHash,
    enrollmentCeremonyHash: H(`o37.2:${label}:synthetic-enrollment`),
    attestationEvidenceHash: H(`o37.2:${label}:synthetic-attestation`),
    custodyDomainId: H(`o37.2:${label}:isolated-custody-domain`)
  };
  const descriptor = {
    descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_DOMAIN_ID,
    role,
    verifierKind: PHILCORE_V2_RECOVERY_VERIFIER_KIND.WEBAUTHN_P256,
    publicVerificationMaterialHash:
      computePhilCoreV2WebAuthnPublicMaterialHash({ qx, qy }),
    credentialIdHash,
    rpIdHash: computePhilCoreO372RpIdHash(FIXTURE_RP_ID),
    originPolicyHash: H(`PHILCORE_O37_2_ORIGIN_POLICY:${FIXTURE_ORIGIN}`),
    independenceBindingHash:
      computePhilCoreV2RecoveryIndependenceBinding(independenceInput),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.USER_VERIFICATION_REQUIRED,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.SINGLE_DEVICE_REQUIRED,
    authenticatorAttachmentPolicy: attachmentPolicy,
    attestationPolicy,
    credentialGeneration: 1
  };
  return {
    classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
    privateScalar,
    public: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      role,
      qx,
      qy,
      credentialIdFixture,
      credentialIdHash,
      rpId: FIXTURE_RP_ID,
      rpIdHash: descriptor.rpIdHash,
      origin: FIXTURE_ORIGIN,
      originPolicyHash: descriptor.originPolicyHash,
      independenceInput,
      descriptor,
      factorCommitment:
        computePhilCoreV2RecoveryDescriptorCommitment(descriptor)
    }
  };
}

function recoverySecpIdentity() {
  const identity = secpIdentity(
    "independent-recovery-factor",
    "fixture_recovery_factor_o37_2_v1",
    1
  );
  const independenceInput = {
    bindingVersion: 1,
    role: PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR,
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    enrollmentCeremonyHash: H(
      "o37.2:recovery-factor:synthetic-enrollment"
    ),
    attestationEvidenceHash: PHILCORE_V2_ZERO_BYTES32,
    custodyDomainId: H(
      "o37.2:recovery-factor:isolated-custody-domain"
    )
  };
  const descriptor = {
    descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
    accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    recoveryDomainId: PHILCORE_V2_RECOVERY_DOMAIN_ID,
    role: PHILCORE_V2_RECOVERY_FACTOR_ROLE.RECOVERY_FACTOR,
    verifierKind:
      PHILCORE_V2_RECOVERY_VERIFIER_KIND.PURPOSE_BOUND_SECP256K1,
    publicVerificationMaterialHash:
      computePhilCoreV2Secp256k1PublicMaterialHash({
        signer: identity.public.address
      }),
    credentialIdHash: PHILCORE_V2_ZERO_BYTES32,
    rpIdHash: PHILCORE_V2_ZERO_BYTES32,
    originPolicyHash: PHILCORE_V2_ZERO_BYTES32,
    independenceBindingHash:
      computePhilCoreV2RecoveryIndependenceBinding(independenceInput),
    userVerificationPolicy:
      PHILCORE_V2_USER_VERIFICATION_POLICY.NOT_APPLICABLE,
    backupPolicy: PHILCORE_V2_BACKUP_POLICY.NOT_APPLICABLE,
    authenticatorAttachmentPolicy:
      PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.NOT_APPLICABLE,
    attestationPolicy: PHILCORE_V2_ATTESTATION_POLICY.NOT_APPLICABLE,
    credentialGeneration: 1
  };
  return {
    ...identity,
    public: {
      ...identity.public,
      independenceInput,
      descriptor,
      factorCommitment:
        computePhilCoreV2RecoveryDescriptorCommitment(descriptor)
    }
  };
}

function applicationContextInput(label) {
  return {
    applicationIdHash: H(`o37.2:${label}:application`),
    originHash: H(`o37.2:${label}:origin`),
    sessionIdHash: H(`o37.2:${label}:session`),
    capabilityGrantIdHash: H(`o37.2:${label}:capability`),
    policyDecisionIdHash: H(`o37.2:${label}:policy`)
  };
}

function fundLifecycleInput(label) {
  return {
    lifecycleSchemaHash: H("philcore-o37-2-test-fund-lifecycle-v1"),
    account: FIXTURE_ACCOUNT,
    asset: ZERO_ADDRESS,
    tokenId: 0,
    maximumFundingOrHolding: "1000000000000000",
    maximumStranded: "0",
    residualRecipient: FIXTURE_RECIPIENT,
    expectedPostOperationBalance: "999999999999000",
    expectedFinalBalance: "0",
    releaseRouteHash: H(`o37.2:${label}:release-route`),
    simulationEvidenceHash: H(`o37.2:${label}:simulation`)
  };
}

function coreHeader(actionType, purpose, nonceKey, nonceSequence, label) {
  return {
    specificationVersion: PHILCORE_V2_INTENT_SPECIFICATION_VERSION,
    securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
    actionType,
    actionId: H(`o37.2:${label}:action`),
    purpose,
    ownerCommitment: H("o37.2:isolated-fixture-owner-commitment"),
    chainId: FIXTURE_CHAIN_ID.toString(),
    entryPoint: FIXTURE_ENTRYPOINT,
    account: FIXTURE_ACCOUNT,
    nonceKey: nonceKey.toString(),
    nonceSequence: nonceSequence.toString(),
    validatorEpoch: "3",
    recoveryEpoch: "2",
    applicationContextHash:
      computePhilCoreV2ApplicationContextHash(applicationContextInput(label)),
    fundLifecycleDigest:
      computePhilCoreV2FundLifecycleDigest(fundLifecycleInput(label)),
    maxTotalFeeWei: "4000000000000000",
    validAfter: "1900000000",
    validUntil: actionType >= PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST
      ? "1900003600"
      : "1900000300"
  };
}

function authorizationChain(intent) {
  const encoded = encodePhilCoreV2Intent(intent);
  const proofBindingInput = {
    proofTypeHash: H("o37.2:fixture-proof-type-no-proof-created"),
    proofInputHash: H("o37.2:fixture-proof-input-no-witness"),
    proofArtifactDigest: H("o37.2:fixture-proof-artifact-no-proof"),
    nullifier: H(`o37.2:fixture-nullifier:${encoded.intentCoreHash}`)
  };
  const proofBindingHash =
    computePhilCoreV2ProofBindingHash(proofBindingInput);
  const runtimeAuthorizationInput = {
    intentCoreHash: encoded.intentCoreHash,
    proofBindingHash,
    policyDecisionHash: H("o37.2:fixture-policy-decision"),
    approvalEvidenceHash: H("o37.2:fixture-approval-evidence"),
    userPresenceEvidenceHash: H("o37.2:fixture-presence-evidence")
  };
  const runtimeAuthorizationDigest =
    computePhilCoreV2RuntimeAuthorizationDigest(runtimeAuthorizationInput);
  const authorizedIntentHash = computePhilCoreV2AuthorizedIntentHash({
    intentCoreHash: encoded.intentCoreHash,
    runtimeAuthorizationDigest
  });
  return {
    intent,
    intentCoreHash: encoded.intentCoreHash,
    proofBindingInput,
    proofBindingHash,
    runtimeAuthorizationInput,
    runtimeAuthorizationDigest,
    authorizedIntentHash
  };
}

function authorizedIntentValue(chain, runtimeDigestOverride) {
  return {
    core: chain.intent.header,
    runtimeAuthorizationDigest:
      runtimeDigestOverride ?? chain.runtimeAuthorizationDigest
  };
}

function encodeCallData(signature, types, values) {
  const selector = id(signature).slice(0, 10);
  return hexlify(concat([selector, abiCoder.encode(types, values)]));
}

function transferCallData(chain, runtimeDigestOverride) {
  const signature =
    "transferNative(((uint8,bytes32,uint8,bytes32,bytes32,bytes32,uint256,address,address,uint192,uint64,uint64,uint64,bytes32,bytes32,uint256,uint48,uint48),bytes32),address,uint256)";
  return {
    selector: id(signature).slice(0, 10),
    callData: encodeCallData(
      signature,
      [AUTHORIZED_INTENT_TUPLE, "address", "uint256"],
      [
        authorizedIntentValue(chain, runtimeDigestOverride),
        chain.intent.payload.recipient,
        chain.intent.payload.amountWei
      ]
    )
  };
}

function recoveryCallData(chain, proposed) {
  const signature =
    "requestRecovery(((uint8,bytes32,uint8,bytes32,bytes32,bytes32,uint256,address,address,uint192,uint64,uint64,uint64,bytes32,bytes32,uint256,uint48,uint48),bytes32),address,bytes32,bytes32,uint64,bytes32)";
  return {
    selector: id(signature).slice(0, 10),
    callData: encodeCallData(
      signature,
      [
        AUTHORIZED_INTENT_TUPLE,
        "address",
        "bytes32",
        "bytes32",
        "uint64",
        "bytes32"
      ],
      [
        authorizedIntentValue(chain),
        proposed.validator,
        proposed.keyIdentifierBinding,
        proposed.commitment,
        proposed.epoch,
        chain.intent.payload.recoveryRequestSalt
      ]
    )
  };
}

function basePackedUserOperation(callData, nonce) {
  return {
    sender: FIXTURE_ACCOUNT,
    nonce: nonce.toString(),
    initCode: "0x",
    callData,
    accountGasLimits: packPhilCoreO372Uint128Pair(1500000, 300000),
    preVerificationGas: "200000",
    gasFees: packPhilCoreO372Uint128Pair(1000000, 2000000000),
    paymasterAndData: "0x",
    signature: "0x"
  };
}

function signatureParts(signature) {
  return {
    r: signature.r,
    s: signature.s,
    v: signature.v
  };
}

function validatorEnvelope(validator, signature) {
  return {
    envelopeVersion: 1,
    authorityKind: 1,
    verifierKind: 1,
    validator: validator.public.address,
    validatorKeyIdBinding: validator.public.keyIdentifierBinding,
    validatorEpoch: 3,
    recoveryEpoch: 2,
    ...signatureParts(signature)
  };
}

function authenticatorData(rpIdHash, counter) {
  return hexlify(concat([
    rpIdHash,
    "0x05",
    zeroPadValue(toBeHex(counter), 4)
  ]));
}

function signWebAuthn(identity, challenge, counter) {
  const client = buildPhilCoreO372WebAuthnClientData({
    challenge,
    origin: FIXTURE_ORIGIN
  });
  const authData = authenticatorData(identity.public.rpIdHash, counter);
  const messageHash = computePhilCoreO372WebAuthnMessageHash({
    authenticatorData: authData,
    clientDataJSON: client.clientDataJSON
  });
  const signature = p256.sign(
    getBytes(messageHash),
    getBytes(identity.privateScalar),
    { lowS: true, prehash: false }
  );
  const result = {
    ...client,
    authenticatorData: authData,
    messageHash,
    r: zeroPadValue(toBeHex(signature.r), 32),
    s: zeroPadValue(toBeHex(signature.s), 32)
  };
  const verification = verifyPhilCoreO372P256Signature({
    messageHash,
    qx: identity.public.qx,
    qy: identity.public.qy,
    r: result.r,
    s: result.s
  });
  if (!verification.accepted) {
    throw new Error("O37_2_P256_FIXTURE_SIGNATURE_REJECTED");
  }
  return result;
}

function publicUserOperation(userOperation) {
  return {
    ...userOperation,
    nonce: userOperation.nonce.toString(),
    preVerificationGas: userOperation.preVerificationGas.toString()
  };
}

function mutatedLastByte(value) {
  const data = getBytes(value);
  data[data.length - 1] ^= 1;
  return hexlify(data);
}

function buildPackedUserOperationNegativeFixtures(valid, chain, validHash) {
  const mutations = [
    {
      id: "wrong_sender",
      changedFields: ["sender"],
      operation: { ...valid, sender: WRONG_FIXTURE_ACCOUNT },
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID
    },
    {
      id: "wrong_nonce_lane",
      changedFields: ["nonce"],
      operation: {
        ...valid,
        nonce: composePhilCoreV2Nonce({
          key: PHILCORE_V2_NONCE_KEY.MAINTENANCE,
          sequence: 1
        })
      },
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID
    },
    {
      id: "modified_call_data",
      changedFields: ["callData"],
      operation: { ...valid, callData: mutatedLastByte(valid.callData) },
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID
    },
    {
      id: "modified_fees",
      changedFields: ["gasFees"],
      operation: {
        ...valid,
        gasFees: packPhilCoreO372Uint128Pair(1000000, 2000000001)
      },
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID
    },
    {
      id: "modified_chain",
      changedFields: ["chainId"],
      operation: valid,
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID + 1n
    },
    {
      id: "modified_entrypoint",
      changedFields: ["entryPoint"],
      operation: valid,
      entryPoint: WRONG_FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID
    },
    {
      id: "modified_authorization_hash",
      changedFields: ["callData.authorizedIntent.runtimeAuthorizationDigest"],
      operation: {
        ...valid,
        callData: transferCallData(
          chain,
          H("o37.2:modified-runtime-authorization-digest")
        ).callData
      },
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID
    }
  ];
  return mutations.map((mutation) => {
    const userOperationHash = computePhilCoreO372PackedUserOperationHash(
      mutation.operation,
      mutation.entryPoint,
      mutation.chainId
    );
    if (userOperationHash === validHash) {
      throw new Error(`O37_2_USEROP_MUTATION_DID_NOT_CHANGE_HASH:${mutation.id}`);
    }
    return {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      id: mutation.id,
      changedFields: mutation.changedFields,
      entryPoint: mutation.entryPoint,
      chainId: mutation.chainId.toString(),
      operation: publicUserOperation(mutation.operation),
      userOperationHash,
      matchesValidUserOperationHash: false,
      expectedResult: "REJECTED"
    };
  });
}

function recoveryContext({
  bitmap,
  chain,
  userOperationHash,
  descriptorSet,
  proposedValidatorCommitment
}) {
  const commitments = descriptorSet.commitments;
  const selected = bitmap === 3
    ? [commitments[0], commitments[1]]
    : bitmap === 5
      ? [commitments[0], commitments[2]]
      : [commitments[1], commitments[2]];
  return {
    envelopeVersion: PHILCORE_V2_RECOVERY_EVIDENCE_VERSION,
    authorityKind: PHILCORE_V2_RECOVERY_AUTHORITY_KIND,
    actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
    factorBitmap: bitmap,
    account: FIXTURE_ACCOUNT,
    chainId: FIXTURE_CHAIN_ID,
    entryPoint: FIXTURE_ENTRYPOINT,
    authorizedIntentHash: chain.authorizedIntentHash,
    userOperationHash,
    requestId: chain.authorizedIntentHash,
    currentRecoveryConfigHash: descriptorSet.recoveryConfigHash,
    validatorEpoch: 3,
    recoveryEpoch: 2,
    validAfter: chain.intent.header.validAfter,
    validUntil: chain.intent.header.validUntil,
    recoveryDelaySeconds: PHILCORE_V2_RECOVERY_DELAY_SECONDS,
    recoveryExpirySeconds: PHILCORE_V2_RECOVERY_EXPIRY_SECONDS,
    proposedValidatorCommitment,
    proposedRecoveryConfigHash: PHILCORE_V2_ZERO_BYTES32,
    proposedRecoveryEpoch: 3,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2],
    firstFactorCommitment: selected[0],
    secondFactorCommitment: selected[1]
  };
}

function webAuthnEvidence(identity, signature) {
  return {
    descriptor: identity.public.descriptor,
    factorCommitment: identity.public.factorCommitment,
    qx: identity.public.qx,
    qy: identity.public.qy,
    r: signature.r,
    s: signature.s,
    challengeIndex: signature.challengeIndex,
    typeIndex: signature.typeIndex,
    authenticatorData: signature.authenticatorData,
    clientDataJSON: signature.clientDataJSON
  };
}

function buildO372FixturePackage() {
  const validator = secpIdentity(
    "execution-validator",
    FIXTURE_VALIDATOR_KEY_ID,
    1
  );
  const invalidValidator = secpIdentity(
    "invalid-execution-validator",
    "fixture_invalid_validator_o37_2_v1",
    1
  );
  const proposedValidator = secpIdentity(
    "proposed-recovery-validator",
    "fixture_proposed_validator_o37_2_v1",
    2
  );
  const primary = p256Identity(
    "primary-device",
    PHILCORE_V2_RECOVERY_FACTOR_ROLE.PRIMARY_DEVICE,
    PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
  );
  const hardware = p256Identity(
    "hardware-security-key",
    PHILCORE_V2_RECOVERY_FACTOR_ROLE.HARDWARE_SECURITY_KEY,
    PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.CROSS_PLATFORM_REQUIRED,
    PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_EXTERNAL_HARDWARE
  );
  const recovery = recoverySecpIdentity();

  const isolatedAddresses = [
    validator.public.address,
    invalidValidator.public.address,
    proposedValidator.public.address,
    recovery.public.address,
    FIXTURE_ACCOUNT,
    FIXTURE_ENTRYPOINT
  ];
  if (new Set(isolatedAddresses.map((value) => value.toLowerCase())).size
      !== isolatedAddresses.length) {
    throw new Error("O37_2_FIXTURE_IDENTITY_COLLISION");
  }

  const descriptors = [
    primary.public.descriptor,
    hardware.public.descriptor,
    recovery.public.descriptor
  ];
  const descriptorSet = validatePhilCoreV2RecoveryDescriptorSet(descriptors);
  const validatorCommitment = computePhilCoreV2ValidatorCommitment({
    verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
    validator: validator.public.address,
    validatorKeyIdBinding: validator.public.keyIdentifierBinding
  });

  const transferIntent = {
    header: coreHeader(
      PHILCORE_V2_ACTION_TYPE.NATIVE_TRANSFER,
      PHILCORE_V2_PURPOSE.TRANSFER_ASSET,
      PHILCORE_V2_NONCE_KEY.ORDINARY,
      1,
      "native-transfer"
    ),
    payload: {
      kind: "NATIVE_TRANSFER",
      recipient: FIXTURE_RECIPIENT,
      amountWei: "1000"
    }
  };
  const transferChain = authorizationChain(transferIntent);
  const transferCall = transferCallData(transferChain);
  const unsignedUserOperation = basePackedUserOperation(
    transferCall.callData,
    composePhilCoreV2Nonce({
      key: PHILCORE_V2_NONCE_KEY.ORDINARY,
      sequence: 1
    })
  );
  const userOperationStructHash =
    computePhilCoreO372PackedUserOperationStructHash(unsignedUserOperation);
  const userOperationHash = computePhilCoreO372PackedUserOperationHash(
    unsignedUserOperation,
    FIXTURE_ENTRYPOINT,
    FIXTURE_CHAIN_ID
  );
  const validatorAuthorizationInput = {
    authorizedIntentHash: transferChain.authorizedIntentHash,
    userOperationHash,
    validator: validator.public.address,
    validatorKeyIdBinding: validator.public.keyIdentifierBinding,
    validatorEpoch: 3,
    recoveryEpoch: 2
  };
  const validatorDigest = computePhilCoreV2ValidatorDigest(
    { chainId: FIXTURE_CHAIN_ID, account: FIXTURE_ACCOUNT },
    validatorAuthorizationInput
  );
  const validValidatorSignature =
    validator.signingKey.sign(validatorDigest.digest);
  const validEnvelope = validatorEnvelope(
    validator,
    validValidatorSignature
  );
  const encodedValidatorEnvelope =
    encodePhilCoreO372ValidatorEnvelope(validEnvelope);
  const finalUserOperation = {
    ...unsignedUserOperation,
    signature: encodedValidatorEnvelope
  };
  const finalHash = computePhilCoreO372PackedUserOperationHash(
    finalUserOperation,
    FIXTURE_ENTRYPOINT,
    FIXTURE_CHAIN_ID
  );
  if (finalHash !== userOperationHash) {
    throw new Error("O37_2_USEROP_SIGNATURE_CHANGED_HASH");
  }
  const validatorVerification = verifyPhilCoreO372ValidatorEnvelope({
    digest: validatorDigest.digest,
    envelope: validEnvelope,
    expectedValidator: validator.public.address,
    expectedKeyIdBinding: validator.public.keyIdentifierBinding,
    expectedValidatorEpoch: 3,
    expectedRecoveryEpoch: 2
  });
  if (!validatorVerification.accepted) {
    throw new Error("O37_2_VALIDATOR_SIGNATURE_REJECTED");
  }

  const invalidSignerSignature =
    invalidValidator.signingKey.sign(validatorDigest.digest);
  const invalidSignerEnvelope = validatorEnvelope(
    validator,
    invalidSignerSignature
  );
  const validS = BigInt(validValidatorSignature.s);
  const highS = PHILCORE_O37_2_SECP256K1_ORDER - validS;
  const highSEnvelope = {
    ...validEnvelope,
    s: zeroPadValue(toBeHex(highS), 32),
    v: validEnvelope.v === 27 ? 28 : 27
  };
  const signatureNegativeFixtures = [
    {
      id: "wrong_signer",
      envelope: invalidSignerEnvelope,
      digest: validatorDigest.digest,
      expectedCode: "VALIDATOR_SIGNATURE_INVALID"
    },
    {
      id: "zero_r",
      envelope: { ...validEnvelope, r: PHILCORE_V2_ZERO_BYTES32 },
      digest: validatorDigest.digest,
      expectedCode: "VALIDATOR_SIGNATURE_INVALID"
    },
    {
      id: "zero_s",
      envelope: { ...validEnvelope, s: PHILCORE_V2_ZERO_BYTES32 },
      digest: validatorDigest.digest,
      expectedCode: "VALIDATOR_SIGNATURE_INVALID"
    },
    {
      id: "invalid_v",
      envelope: { ...validEnvelope, v: 29 },
      digest: validatorDigest.digest,
      expectedCode: "VALIDATOR_SIGNATURE_INVALID"
    },
    {
      id: "high_s",
      envelope: highSEnvelope,
      digest: validatorDigest.digest,
      expectedCode: "VALIDATOR_SIGNATURE_MALLEABLE"
    },
    {
      id: "modified_digest",
      envelope: validEnvelope,
      digest: H("o37.2:modified-validator-digest"),
      expectedCode: "VALIDATOR_SIGNATURE_INVALID"
    }
  ].map((fixture) => {
    const result = verifyPhilCoreO372ValidatorEnvelope({
      digest: fixture.digest,
      envelope: fixture.envelope,
      expectedValidator: validator.public.address,
      expectedKeyIdBinding: validator.public.keyIdentifierBinding,
      expectedValidatorEpoch: 3,
      expectedRecoveryEpoch: 2
    });
    if (result.accepted || result.code !== fixture.expectedCode) {
      throw new Error(`O37_2_SIGNATURE_NEGATIVE_MISMATCH:${fixture.id}`);
    }
    return {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      id: fixture.id,
      digest: fixture.digest,
      envelope: fixture.envelope,
      encodedEnvelope: encodePhilCoreO372ValidatorEnvelope(fixture.envelope),
      expectedCode: fixture.expectedCode,
      expectedResult: "REJECTED"
    };
  });

  const userOperationNegativeFixtures =
    buildPackedUserOperationNegativeFixtures(
      finalUserOperation,
      transferChain,
      userOperationHash
    );

  const proposedValidatorCommitment = computePhilCoreV2ValidatorCommitment({
    verifierKind: PHILCORE_V2_VALIDATOR_VERIFIER_KIND.SECP256K1_ECDSA,
    validator: proposedValidator.public.address,
    validatorKeyIdBinding: proposedValidator.public.keyIdentifierBinding
  });
  const recoveryIntent = {
    header: coreHeader(
      PHILCORE_V2_ACTION_TYPE.RECOVERY_REQUEST,
      PHILCORE_V2_PURPOSE.REQUEST_RECOVERY,
      PHILCORE_V2_NONCE_KEY.RECOVERY,
      1,
      "recovery-request"
    ),
    payload: {
      kind: "RECOVERY_REQUEST",
      proposedValidator: proposedValidator.public.address,
      proposedValidatorKeyIdBinding:
        proposedValidator.public.keyIdentifierBinding,
      proposedValidatorEpoch: "4",
      recoveryRequestSalt: H("o37.2:recovery-request-salt")
    }
  };
  const recoveryChain = authorizationChain(recoveryIntent);
  const recoveryCall = recoveryCallData(recoveryChain, {
    validator: proposedValidator.public.address,
    keyIdentifierBinding: proposedValidator.public.keyIdentifierBinding,
    commitment: proposedValidatorCommitment,
    epoch: 4
  });
  const recoveryUserOperation = basePackedUserOperation(
    recoveryCall.callData,
    composePhilCoreV2Nonce({
      key: PHILCORE_V2_NONCE_KEY.RECOVERY,
      sequence: 1
    })
  );
  const recoveryUserOperationHash =
    computePhilCoreO372PackedUserOperationHash(
      recoveryUserOperation,
      FIXTURE_ENTRYPOINT,
      FIXTURE_CHAIN_ID
    );

  function recoveryPair(bitmap) {
    const context = recoveryContext({
      bitmap,
      chain: recoveryChain,
      userOperationHash: recoveryUserOperationHash,
      descriptorSet,
      proposedValidatorCommitment
    });
    const authorizationInput = {
      authorizedIntentHash: recoveryChain.authorizedIntentHash,
      userOperationHash: recoveryUserOperationHash,
      recoveryConfigHash: descriptorSet.recoveryConfigHash,
      recoveryEpoch: 2,
      factorBitmap: bitmap
    };
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: FIXTURE_CHAIN_ID, account: FIXTURE_ACCOUNT },
      authorizationInput
    );
    const primarySignature = signWebAuthn(primary, digest.digest, bitmap);
    const primaryEvidence = webAuthnEvidence(primary, primarySignature);
    const encodedPrimaryEvidence =
      encodePhilCoreO372WebAuthnEvidence(primaryEvidence);

    if (bitmap === PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE) {
      const hardwareSignature = signWebAuthn(
        hardware,
        digest.digest,
        bitmap + 1
      );
      const hardwareEvidence = webAuthnEvidence(
        hardware,
        hardwareSignature
      );
      const encodedHardwareEvidence =
        encodePhilCoreO372WebAuthnEvidence(hardwareEvidence);
      return {
        classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
        bitmap,
        authorizationInput,
        recoveryDigest: digest.digest,
        context,
        contextHash: computePhilCoreV2RecoveryEvidenceContextHash(context),
        firstEvidence: primaryEvidence,
        secondEvidence: hardwareEvidence,
        encodedFirstEvidence: encodedPrimaryEvidence,
        encodedSecondEvidence: encodedHardwareEvidence,
        encodedRecoveryEnvelope: encodePhilCoreO372RecoveryEnvelope({
          context,
          firstFactorEvidence: encodedPrimaryEvidence,
          secondFactorEvidence: encodedHardwareEvidence
        }),
        expectedResult: "ACCEPTED"
      };
    }

    const recoverySignature =
      recovery.signingKey.sign(digest.digest);
    const recoveryEvidence = {
      descriptor: recovery.public.descriptor,
      factorCommitment: recovery.public.factorCommitment,
      signer: recovery.public.address,
      ...signatureParts(recoverySignature)
    };
    const encodedRecoveryEvidence =
      encodePhilCoreO372Secp256k1Evidence(recoveryEvidence);
    return {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      bitmap,
      authorizationInput,
      recoveryDigest: digest.digest,
      context,
      contextHash: computePhilCoreV2RecoveryEvidenceContextHash(context),
      firstEvidence: primaryEvidence,
      secondEvidence: recoveryEvidence,
      encodedFirstEvidence: encodedPrimaryEvidence,
      encodedSecondEvidence: encodedRecoveryEvidence,
      encodedRecoveryEnvelope: encodePhilCoreO372RecoveryEnvelope({
        context,
        firstFactorEvidence: encodedPrimaryEvidence,
        secondFactorEvidence: encodedRecoveryEvidence
      }),
      expectedResult: "ACCEPTED"
    };
  }

  const primaryHardwareRecovery =
    recoveryPair(PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_HARDWARE);
  const primarySecpRecovery =
    recoveryPair(PHILCORE_V2_RECOVERY_FACTOR_BITMAP.PRIMARY_AND_RECOVERY);

  return {
    schemaVersion: "philcore-o37-2-deterministic-cryptographic-fixtures-v1",
    phase: "O.37.2",
    canonicalPhaseName:
      "O.37.2 V2 Deterministic Cryptographic Test Fixture Generation",
    classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
    fixtureVersion: PHILCORE_O37_2_FIXTURE_VERSION,
    sourceHeadAtPhaseStart: SOURCE_HEAD_AT_PHASE_START,
    publicMutationCount: 0,
    implementationBindings: {
      fixtureUtilitySha256: sha256File(
        "apps/phil-device-sdk/src/v2DeterministicFixtures.ts"
      ),
      intentSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2Intent.ts"
      ),
      authorizationSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2Authorization.ts"
      ),
      recoveryEvidenceSourceSha256: sha256File(
        "apps/phil-device-sdk/src/v2RecoveryEvidence.ts"
      ),
      o32VectorsSha256: sha256File(
        "config/cryptography/O32_V2_CRYPTOGRAPHIC_TEST_VECTORS.json"
      ),
      o33VectorsSha256: sha256File(
        "config/cryptography/O33_V2_VALIDATOR_AUTHORIZATION_TEST_VECTORS.json"
      ),
      o37_1VectorsSha256: sha256File(
        "config/cryptography/O37_1_V2_RECOVERY_EVIDENCE_TEST_VECTORS.json"
      ),
      accountAbstractionUserOperationLibSha256: sha256File(
        "node_modules/@account-abstraction/contracts/core/UserOperationLib.sol"
      )
    },
    fixtureDomain: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      chainId: FIXTURE_CHAIN_ID.toString(),
      entryPoint: FIXTURE_ENTRYPOINT,
      account: FIXTURE_ACCOUNT,
      ownerCommitment: transferIntent.header.ownerCommitment,
      rpId: FIXTURE_RP_ID,
      origin: FIXTURE_ORIGIN,
      liveNetwork: false
    },
    fixtureIdentities: {
      executionValidator: {
        ...validator.public,
        validatorCommitment
      },
      invalidValidator: invalidValidator.public,
      proposedRecoveryValidator: {
        ...proposedValidator.public,
        validatorCommitment: proposedValidatorCommitment
      },
      primaryDevice: primary.public,
      hardwareSecurityKey: hardware.public,
      independentRecoveryFactor: recovery.public
    },
    recoveryConfiguration: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      descriptorVersion: PHILCORE_V2_RECOVERY_DESCRIPTOR_VERSION,
      configurationVersion:
        PHILCORE_V2_RECOVERY_CONFIGURATION_VERSION_V2,
      threshold: PHILCORE_V2_RECOVERY_THRESHOLD,
      commitments: {
        primaryDevice: descriptorSet.commitments[0],
        hardwareSecurityKey: descriptorSet.commitments[1],
        recoveryFactor: descriptorSet.commitments[2]
      },
      recoveryConfigHash: descriptorSet.recoveryConfigHash
    },
    validAuthorizationFixture: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      intent: transferChain.intent,
      intentCoreHash: transferChain.intentCoreHash,
      proofBindingInput: transferChain.proofBindingInput,
      proofBindingHash: transferChain.proofBindingHash,
      runtimeAuthorizationInput: transferChain.runtimeAuthorizationInput,
      runtimeAuthorizationDigest: transferChain.runtimeAuthorizationDigest,
      authorizedIntentHash: transferChain.authorizedIntentHash,
      callSelector: transferCall.selector,
      callData: transferCall.callData,
      userOperationStructHash,
      userOperationHash,
      validatorAuthorizationInput,
      validatorStructHash: validatorDigest.structHash,
      validatorDigest: validatorDigest.digest,
      validatorEnvelope: validEnvelope,
      encodedValidatorEnvelope,
      recoveredValidator: validatorVerification.recoveredAddress,
      expectedResult: "ACCEPTED"
    },
    validatorSignatureFixtures: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      valid: {
        digest: validatorDigest.digest,
        r: validEnvelope.r,
        s: validEnvelope.s,
        v: validEnvelope.v,
        encodedEnvelope: encodedValidatorEnvelope,
        expectedResult: "ACCEPTED"
      },
      invalid: signatureNegativeFixtures
    },
    packedUserOperationFixtures: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      entryPoint: FIXTURE_ENTRYPOINT,
      chainId: FIXTURE_CHAIN_ID.toString(),
      valid: {
        operation: publicUserOperation(finalUserOperation),
        structHash: userOperationStructHash,
        userOperationHash,
        signatureExcludedFromHash: true,
        expectedResult: "ACCEPTED"
      },
      invalid: userOperationNegativeFixtures
    },
    recoveryAuthorizationFixtures: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      intent: recoveryChain.intent,
      intentCoreHash: recoveryChain.intentCoreHash,
      runtimeAuthorizationDigest:
        recoveryChain.runtimeAuthorizationDigest,
      authorizedIntentHash: recoveryChain.authorizedIntentHash,
      callSelector: recoveryCall.selector,
      callData: recoveryCall.callData,
      unsignedPackedUserOperation: publicUserOperation(recoveryUserOperation),
      userOperationHash: recoveryUserOperationHash,
      primaryAndHardware: primaryHardwareRecovery,
      primaryAndRecovery: primarySecpRecovery
    },
    mutationCoverage: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      validatorSignature: signatureNegativeFixtures.map(({ id }) => id),
      packedUserOperation: userOperationNegativeFixtures.map(({ id }) => id),
      recoveryDescriptorAndEvidence:
        "O37_1_V2_RECOVERY_EVIDENCE_TEST_VECTORS.json"
    },
    encodingRules: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      packedEncodingUsed: false,
      jsonCryptographicEncodingUsed: false,
      standardAbiEncodingUsed: true,
      validatorEnvelopeBytes: 320,
      packedUserOperationVersion: "ERC-4337-v0.7",
      paymasterAndDataEmpty: true,
      initCodeEmpty: true
    },
    securityBoundary: {
      classification: PHILCORE_O37_2_FIXTURE_CLASSIFICATION,
      canonicalIdentityUsed: false,
      canonicalValidatorUsed: false,
      deviceVaultUsed: false,
      environmentFileUsed: false,
      realCredentialCreated: false,
      privateScalarsCommitted: false,
      productionSignatureCreated: false,
      productionUserOperationCreated: false,
      userOperationSubmitted: false,
      solidityCreated: false,
      bytecodeCreated: false,
      deploymentPerformed: false,
      rpcUsed: false,
      fundsMoved: false,
      publicMutationOccurred: false
    }
  };
}

function main() {
  const checkOnly = process.argv.includes("--check");
  const output = stringify(buildO372FixturePackage());
  if (checkOnly) {
    if (!fs.existsSync(OUTPUT_PATH)) {
      throw new Error("O37_2_FIXTURE_PACKAGE_MISSING");
    }
    if (fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O37_2_FIXTURE_PACKAGE_STALE");
    }
    process.stdout.write("O.37.2 deterministic fixture package is current\n");
    return;
  }
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO372FixturePackage
};
