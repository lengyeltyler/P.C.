require("tsx/cjs");

const fs = require("node:fs");
const path = require("node:path");
const { p256 } = require("@noble/curves/p256");
const {
  AbiCoder,
  getBytes,
  id,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue
} = require("ethers");
const {
  PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY,
  PHILCORE_V2_ATTESTATION_POLICY
} = require("../../apps/phil-device-sdk/src/v2RecoveryEvidence.ts");
const {
  PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS,
  computePhilCoreV2ConsumerRecoveryConfigurationHash
} = require("../../apps/phil-device-sdk/src/v2ConsumerRecovery.ts");
const {
  computePhilCoreV2RecoveryFactorDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_NATIVE_IPHONE_EVIDENCE_TUPLE,
  PHILCORE_NATIVE_IPHONE_ROLE1,
  buildPhilCoreNativeIPhoneDescriptor,
  computePhilCoreNativeIPhoneFactorCommitment,
  encodePhilCoreNativeIPhoneEvidence
} = require("../../apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts");
const {
  PHILCORE_O37_2_P256_ORDER,
  encodePhilCoreO372RecoveryEnvelope
} = require("../../apps/phil-device-sdk/src/v2DeterministicFixtures.ts");
const {
  contextFor,
  deterministicScalar,
  offlineFactor,
  secpEvidence,
  webAuthnEvidence,
  webAuthnFactor
} = require("./generate-o39-consumer-recovery-fixtures.cjs");

const ROOT = path.resolve(__dirname, "../..");
const OUTPUT_PATH = path.join(
  ROOT,
  "config/cryptography/O43_NATIVE_IPHONE_RECOVERY_FIXTURES.json"
);
const H = (value) => keccak256(toUtf8Bytes(value));
const ZERO = `0x${"00".repeat(32)}`;

function nativeFactor() {
  const privateScalar = deterministicScalar(
    "O43:STANDARD:native-iphone",
    PHILCORE_O37_2_P256_ORDER
  );
  const publicKey = p256.getPublicKey(getBytes(privateScalar), false);
  const qx = `0x${Buffer.from(publicKey.slice(1, 33)).toString("hex")}`;
  const qy = `0x${Buffer.from(publicKey.slice(33, 65)).toString("hex")}`;
  const descriptor = buildPhilCoreNativeIPhoneDescriptor({
    qx,
    qy,
    credentialIdentifierCommitment: H("O43:NATIVE_IPHONE:CREDENTIAL_ID"),
    deviceCustodyCommitment: H("O43:NATIVE_IPHONE:DEVICE_CUSTODY"),
    generation: 1
  });
  return {
    privateScalar,
    qx,
    qy,
    descriptor,
    factorCommitment: computePhilCoreNativeIPhoneFactorCommitment(descriptor)
  };
}

function nativeEvidence(factor, digest, descriptor = factor.descriptor) {
  const signature = p256.sign(
    getBytes(digest),
    getBytes(factor.privateScalar),
    { lowS: true, prehash: false }
  );
  return encodePhilCoreNativeIPhoneEvidence({
    descriptor,
    factorCommitment:
      computePhilCoreNativeIPhoneFactorCommitment(descriptor),
    qx: factor.qx,
    qy: factor.qy,
    r: zeroPadValue(toBeHex(signature.r), 32),
    s: zeroPadValue(toBeHex(signature.s), 32)
  });
}

function buildO43NativeIPhoneFixturePackage() {
  const primary = webAuthnFactor(
    "STANDARD:primary",
    0,
    PHILCORE_V2_CONSUMER_AUTHENTICATOR_CLASS.PRIMARY_PLATFORM_DEVICE,
    PHILCORE_V2_AUTHENTICATOR_ATTACHMENT_POLICY.PLATFORM_REQUIRED,
    PHILCORE_V2_ATTESTATION_POLICY.VERIFIED_DEVICE_BOUND
  );
  const native = nativeFactor();
  const offline = offlineFactor("STANDARD");
  const commitments = [
    primary.factorCommitment,
    native.factorCommitment,
    offline.factorCommitment
  ];
  const recoveryConfigHash =
    computePhilCoreV2ConsumerRecoveryConfigurationHash(commitments);
  const request = {
    actionType: 8,
    account: "0x0000000000000000000000000000000000004300",
    chainId: "31337",
    entryPoint: "0x00000000000000000000000000000000000F4337",
    accountVersionId: native.descriptor.accountVersionId,
    securityModelId: native.descriptor.securityModelId,
    authorizedIntentHash: H("O43:AUTHORIZED_INTENT"),
    userOpHash: H("O43:USER_OPERATION"),
    validator: "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa",
    validatorKeyIdBinding: H("O43:VALIDATOR_KEY_ID_BINDING"),
    validatorEpoch: 1,
    recoveryEpoch: 1,
    recoveryConfigHash,
    requestId: H("O43:AUTHORIZED_INTENT"),
    validAfter: 1000,
    validUntil: 5000,
    proposedValidatorCommitment: H("O43:PROPOSED_VALIDATOR"),
    proposedRecoveryConfigHash: ZERO,
    proposedRecoveryEpoch: 2,
    primaryDeviceCommitment: commitments[0],
    hardwareSecurityKeyCommitment: commitments[1],
    recoveryFactorCommitment: commitments[2]
  };
  const validPairs = [3, 5, 6].map((bitmap, index) => {
    const digest = computePhilCoreV2RecoveryFactorDigest(
      { chainId: request.chainId, account: request.account },
      {
        authorizedIntentHash: request.authorizedIntentHash,
        userOperationHash: request.userOpHash,
        recoveryConfigHash,
        recoveryEpoch: request.recoveryEpoch,
        factorBitmap: bitmap
      }
    ).digest;
    const evidence = bitmap === 3
      ? [webAuthnEvidence(primary, digest, index + 1),
        nativeEvidence(native, digest)]
      : bitmap === 5
        ? [webAuthnEvidence(primary, digest, index + 1),
          secpEvidence(offline, digest)]
        : [nativeEvidence(native, digest), secpEvidence(offline, digest)];
    const envelope = encodePhilCoreO372RecoveryEnvelope({
      context: contextFor(request, commitments, bitmap),
      firstFactorEvidence: evidence[0],
      secondFactorEvidence: evidence[1]
    });
    return {
      bitmap,
      roles: bitmap === 3 ? [0, 1] : bitmap === 5 ? [0, 2] : [1, 2],
      digest,
      nativeEvidenceBytes:
        bitmap === 5 ? null : (getBytes(bitmap === 3 ? evidence[1] : evidence[0]).length),
      envelope
    };
  });
  const publicNative = { ...native };
  delete publicNative.privateScalar;
  return {
    phase: "O.43",
    classification: "DETERMINISTIC_SYNTHETIC_TEST_ONLY",
    publicMutationCount: 0,
    role: 1,
    verifierKind: 4,
    descriptorVersion: 1,
    descriptorTuple: PHILCORE_NATIVE_IPHONE_EVIDENCE_TUPLE,
    applicationIdentity: PHILCORE_NATIVE_IPHONE_ROLE1.applicationIdentity,
    appAttest: PHILCORE_NATIVE_IPHONE_ROLE1.appAttestStatus,
    outerAuthorityTransportChanged: false,
    exactThreshold: 2,
    validBitmaps: [3, 5, 6],
    request,
    recoveryConfigurationHash: recoveryConfigHash,
    factors: {
      primary: {
        qx: primary.qx,
        qy: primary.qy,
        descriptor: primary.descriptor,
        factorCommitment: primary.factorCommitment
      },
      nativeIPhone: publicNative,
      offline: {
        signer: offline.signer,
        descriptor: offline.descriptor,
        factorCommitment: offline.factorCommitment
      }
    },
    validPairs,
    negativeCases: [
      "invalid_application_identity",
      "wrong_team_id",
      "wrong_bundle_id",
      "wrong_p256_key",
      "wrong_generation",
      "wrong_account",
      "wrong_recovery_epoch",
      "simulator_credential_as_production",
      "software_key_where_secure_enclave_required",
      "missing_local_approval_binding",
      "pairing_transcript_substitution",
      "device_role_substitution"
    ],
    secretsCommitted: false,
    productionCredentialCreated: false,
    productionSignatureCommitted: false
  };
}

function main() {
  const output = `${JSON.stringify(
    buildO43NativeIPhoneFixturePackage(),
    (_key, value) => typeof value === "bigint" ? value.toString() : value,
    2
  )}\n`;
  if (process.argv.includes("--check")) {
    if (!fs.existsSync(OUTPUT_PATH) || fs.readFileSync(OUTPUT_PATH, "utf8") !== output) {
      throw new Error("O43_NATIVE_IPHONE_FIXTURES_STALE");
    }
    process.stdout.write("O.43 native iPhone fixtures are current\n");
    return;
  }
  fs.writeFileSync(OUTPUT_PATH, output, { encoding: "utf8", mode: 0o644 });
  process.stdout.write(`${path.relative(ROOT, OUTPUT_PATH)}\n`);
}

if (require.main === module) main();

module.exports = {
  buildO43NativeIPhoneFixturePackage,
  nativeEvidence,
  nativeFactor
};
