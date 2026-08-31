const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const { keccak256, toUtf8Bytes } = require("ethers");
const {
  PHIL_CRYPTO_SCHEME_IDS_V1: S,
  PHIL_CRYPTO_SCHEME_REGISTRY_V1,
  PHIL_CRYPTO_SECURITY_MODE_V1: MODE,
  PHIL_MIGRATION_CEREMONY_KIND_V1: CEREMONY,
  PHIL_NETWORK_ENFORCEMENT_V1: ENFORCEMENT,
  assessPhilPostQuantumClaimV1,
  createPhilCryptoMigrationCeremonyV1,
  createPhilCryptoPolicyBundleV1,
  createPhilCryptoTrustedStateV1,
  createPhilNetworkCryptoCapabilityV1,
  deriveUntrustedPhilCryptoPolicyBundleHashV1,
  validatePhilCryptoSchemeRegistryV1
} = require("../../apps/phil-device-sdk/src/postQuantumMigrationV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const SOURCE_PATH = path.join(REPO_ROOT, "apps/phil-device-sdk/src/postQuantumMigrationV1.ts");
const FIXTURE_PATH = path.join(REPO_ROOT, "config/cryptography/PHIL_V1_STEP5_PQ_MIGRATION_FIXTURE.json");
const MANIFEST_PATH = path.join(REPO_ROOT, "docs/reference/PHIL_V1_STEP5_ARTIFACT_MANIFEST.json");
const WRITE = process.argv.includes("--write");

function hashLabel(label) {
  return keccak256(toUtf8Bytes(label));
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const registry = validatePhilCryptoSchemeRegistryV1();
const capabilityAuthorityHash = hashLabel("phil-v1-step5-local-capability-authority-not-production");

const starknetSepolia = createPhilNetworkCryptoCapabilityV1({
  networkIdHash: hashLabel("SN_SEPOLIA"),
  registryEpoch: registry.registryEpoch,
  registryHash: registry.registryHash,
  capabilityEpoch: 1,
  accountModelHash: hashLabel("starknet-native-account-abstraction-step4-candidate"),
  enforcement: ENFORCEMENT.CONTRACT_CANDIDATE,
  maximumSecurityMode: MODE.CLASSICAL_ONLY,
  signatureSchemeIds: [S.P256_SHA256_SIGNATURE],
  proofSchemeIds: [S.NOIR_ULTRAHONK_KECCAK_STEP3],
  verifierSchemeIds: [S.STEP3_GARAGA_VERIFIER],
  authorizationPathAvailable: false,
  capabilityAuthorityHash,
  implementationBindingHash: hashLabel("phil-v1-step4-3377606d-local-candidate"),
  evidenceHash: hashLabel("phil-v1-step4-independent-review-accepted-local-no-deployment")
});

const starknetSepoliaEpoch2 = createPhilNetworkCryptoCapabilityV1({
  networkIdHash: starknetSepolia.networkIdHash,
  registryEpoch: registry.registryEpoch,
  registryHash: registry.registryHash,
  capabilityEpoch: 2,
  accountModelHash: starknetSepolia.accountModelHash,
  enforcement: ENFORCEMENT.CONTRACT_CANDIDATE,
  maximumSecurityMode: MODE.CLASSICAL_ONLY,
  signatureSchemeIds: [S.P256_SHA256_SIGNATURE],
  proofSchemeIds: [S.NOIR_ULTRAHONK_KECCAK_STEP3],
  verifierSchemeIds: [S.STEP3_GARAGA_VERIFIER],
  authorizationPathAvailable: false,
  capabilityAuthorityHash,
  implementationBindingHash: hashLabel("phil-v1-step5-synthetic-same-network-capability-epoch-2"),
  evidenceHash: hashLabel("synthetic-capability-migration-evidence-not-production")
});

const baseMainnet = createPhilNetworkCryptoCapabilityV1({
  networkIdHash: hashLabel("eip155:8453"),
  registryEpoch: registry.registryEpoch,
  registryHash: registry.registryHash,
  capabilityEpoch: 1,
  accountModelHash: hashLabel("erc-4337-smart-account-adapter-not-step5-verified"),
  enforcement: ENFORCEMENT.LOCAL_ONLY,
  maximumSecurityMode: MODE.CLASSICAL_ONLY,
  signatureSchemeIds: [S.SECP256K1_KECCAK256_SIGNATURE],
  proofSchemeIds: [],
  verifierSchemeIds: [],
  authorizationPathAvailable: false,
  capabilityAuthorityHash,
  implementationBindingHash: hashLabel("phil-base-local-preparation-only"),
  evidenceHash: hashLabel("no-step5-base-proof-verifier-or-network-enforcement-evidence")
});

function trustedState(networkCapability, policyEpoch, expectedPolicyHash) {
  return createPhilCryptoTrustedStateV1({
    registryEpoch: networkCapability.registryEpoch,
    registryHash: networkCapability.registryHash,
    networkIdHash: networkCapability.networkIdHash,
    capabilityAuthorityHash: networkCapability.capabilityAuthorityHash,
    greatestAcceptedCapabilityEpoch: networkCapability.capabilityEpoch,
    expectedCapabilityHash: networkCapability.capabilityHash,
    greatestAcceptedPolicyEpoch: policyEpoch,
    expectedPolicyHash
  });
}

function bundleDraft(networkCapability, policyEpoch, recoveryIndependenceLabel) {
  return {
    policyEpoch,
    securityMode: MODE.CLASSICAL_ONLY,
    signatureCombiner: "all",
    deviceSignatureSchemeIds: [S.P256_SHA256_SIGNATURE],
    validatorSignatureSchemeIds: [S.P256_SHA256_SIGNATURE],
    recoveryProtectionSchemeIds: [S.PAIRWISE_HKDF_AES256GCM_2OF3_RECOVERY],
    keyEstablishmentSchemeIds: [S.P256_ECIES_X963_SHA256_AESGCM],
    hashSchemeIds: [S.SHA256, S.KECCAK256],
    symmetricSchemeIds: [S.AES256_GCM],
    kdfSchemeIds: [S.HKDF_SHA256],
    proofSchemeId: S.NOIR_ULTRAHONK_KECCAK_STEP3,
    verifierSchemeId: S.STEP3_GARAGA_VERIFIER,
    networkCapability,
    recoveryIndependenceHash: hashLabel(recoveryIndependenceLabel)
  };
}

const currentBundleDraft = bundleDraft(starknetSepolia, 1, "phil-v1-step2-independent-2-of-3-key-unwrapping-policy-epoch-1");
const rotatedBundleDraft = bundleDraft(starknetSepoliaEpoch2, 2, "phil-v1-step2-independent-2-of-3-key-unwrapping-policy-epoch-2");
const currentTrustedState = trustedState(
  starknetSepolia,
  1,
  deriveUntrustedPhilCryptoPolicyBundleHashV1(currentBundleDraft)
);
const rotatedTrustedState = trustedState(
  starknetSepoliaEpoch2,
  2,
  deriveUntrustedPhilCryptoPolicyBundleHashV1(rotatedBundleDraft)
);
const baseTrustedState = trustedState(
  baseMainnet,
  1,
  hashLabel("phil-v1-step5-no-admitted-base-policy")
);
const currentBundle = createPhilCryptoPolicyBundleV1({
  ...currentBundleDraft,
  trustedState: currentTrustedState
});
const rotatedBundle = createPhilCryptoPolicyBundleV1({
  ...rotatedBundleDraft,
  trustedState: rotatedTrustedState
});
const rotationCeremony = createPhilCryptoMigrationCeremonyV1({
  ceremonyKind: CEREMONY.ROTATE_WITHIN_MODE,
  fromBundle: currentBundle,
  toBundle: rotatedBundle,
  fromNetworkCapability: starknetSepolia,
  toNetworkCapability: starknetSepoliaEpoch2,
  fromTrustedState: currentTrustedState,
  toTrustedState: rotatedTrustedState,
  fromDeviceEpoch: 1,
  toDeviceEpoch: 2,
  fromValidatorEpoch: 1,
  toValidatorEpoch: 2,
  fromRecoveryEpoch: 1,
  toRecoveryEpoch: 2,
  newKeySetHash: hashLabel("phil-v1-step5-disclosed-synthetic-rotated-key-set"),
  userApprovalDigest: hashLabel("phil-v1-step5-disclosed-synthetic-user-approval"),
  recoveryApprovalDigest: hashLabel("phil-v1-step5-disclosed-synthetic-recovery-approval"),
  independentReviewHash: hashLabel("phil-v1-step5-independent-review-required-not-yet-performed"),
  notBefore: 1800000000,
  expiresAt: 1800003600,
  emergencyFreeze: false
});

const fixture = {
  format: "phil-v1-step5-post-quantum-migration-fixture-v1",
  classification: "architecture-only-disclosed-synthetic-fixture",
  productionAuthority: false,
  networkActivity: false,
  physicalDeviceUsed: false,
  backendSelected: false,
  wholeSystemPostQuantum: false,
  registry,
  schemes: PHIL_CRYPTO_SCHEME_REGISTRY_V1,
  platformCapabilities: {
    appleSecureEnclave: {
      currentPhilDeviceSignatureSchemeIds: [S.P256_SHA256_SIGNATURE],
      documentedPostQuantumSignatureCandidateIds: [S.ML_DSA_65_SIGNATURE],
      documentedKeyEstablishmentCandidateIds: [S.ML_KEM_768, S.ML_KEM_1024],
      secureEnclaveMlDsaSigningDocumented: true,
      philMlDsaDeviceIntegrationVerified: false,
      philMlKemDeviceIntegrationVerified: false,
      postQuantumDeviceAuthorizationAvailable: false
    }
  },
  networkCapabilities: {
    starknetSepolia,
    syntheticStarknetSepoliaEpoch2: starknetSepoliaEpoch2,
    baseMainnet
  },
  trustedStates: {
    currentStarknet: currentTrustedState,
    syntheticRotatedStarknet: rotatedTrustedState,
    baseMainnet: baseTrustedState
  },
  currentPolicyBundle: currentBundle,
  syntheticRotationTargetBundle: rotatedBundle,
  syntheticRotationCeremony: rotationCeremony,
  currentClaimAssessment: assessPhilPostQuantumClaimV1({
    bundle: currentBundle,
    network: starknetSepolia,
    trustedState: currentTrustedState
  }),
  activationGates: [
    "admitted-and-independently-reviewed-pq-device-signature",
    "admitted-and-independently-reviewed-pq-key-establishment",
    "admitted-and-independently-reviewed-pq-proof-and-verifier",
    "network-enforced-hybrid-and-account-path",
    "recovery-ceremony-proves-independent-pq-rotation",
    "downgrade-and-retirement-tests-pass",
    "separate-publication-and-production-authorization"
  ]
};

const fixtureJson = canonicalJson(fixture);
const manifest = {
  format: "phil-v1-step5-artifact-manifest-v1",
  source: "apps/phil-device-sdk/src/postQuantumMigrationV1.ts",
  sourceSha256: sha256(fs.readFileSync(SOURCE_PATH)),
  fixture: "config/cryptography/PHIL_V1_STEP5_PQ_MIGRATION_FIXTURE.json",
  fixtureSha256: sha256(fixtureJson),
  registryHash: registry.registryHash,
  currentBundleHash: currentBundle.bundleHash,
  starknetCapabilityHash: starknetSepolia.capabilityHash,
  baseCapabilityHash: baseMainnet.capabilityHash,
  syntheticStarknetEpoch2CapabilityHash: starknetSepoliaEpoch2.capabilityHash,
  currentTrustedStateHash: currentTrustedState.trustedStateHash,
  rotatedTrustedStateHash: rotatedTrustedState.trustedStateHash,
  rotationCeremonyHash: rotationCeremony.ceremonyHash,
  standardsSnapshot: {
    asOf: "2026-08-22",
    fips203: "https://csrc.nist.gov/pubs/fips/203/final",
    fips204: "https://csrc.nist.gov/pubs/fips/204/final",
    fips205: "https://csrc.nist.gov/pubs/fips/205/final",
    nistTransitionDraft: "https://csrc.nist.gov/pubs/ir/8547/ipd",
    appleQuantumSecureWorkflows: "https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows",
    appleSecureEnclaveMlDsa65Signing: "https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa65/privatekey/signature%28for%3A%29",
    appleSecKeyEciesCofactorX963Sha256AesGcm: "https://developer.apple.com/documentation/security/seckeyalgorithm/eciesencryptioncofactorx963sha256aesgcm",
    starknetAccounts: "https://docs.starknet.io/learn/protocol/accounts",
    erc4337: "https://eips.ethereum.org/EIPS/eip-4337"
  }
};
const manifestJson = canonicalJson(manifest);

function writeOrCheck(filePath, expected) {
  if (WRITE) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, expected);
    return;
  }
  if (!fs.existsSync(filePath) || fs.readFileSync(filePath, "utf8") !== expected) {
    throw new Error(`${path.relative(REPO_ROOT, filePath)} is missing or stale`);
  }
}

writeOrCheck(FIXTURE_PATH, fixtureJson);
writeOrCheck(MANIFEST_PATH, manifestJson);
console.log(WRITE ? "wrote Step 5 artifacts" : "verified Step 5 artifacts");
