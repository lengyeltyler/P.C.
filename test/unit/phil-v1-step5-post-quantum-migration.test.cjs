const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { keccak256, toUtf8Bytes } = require("ethers");
const {
  PHIL_CRYPTO_SCHEME_IDS_V1: S,
  PHIL_CRYPTO_SCHEME_LABELS_V1,
  PHIL_CRYPTO_SCHEME_REGISTRY_V1,
  PHIL_CRYPTO_SECURITY_MODE_V1: MODE,
  PHIL_MIGRATION_CEREMONY_KIND_V1: CEREMONY,
  PHIL_NETWORK_ENFORCEMENT_V1: ENFORCEMENT,
  PHIL_QUANTUM_POSTURE_V1: Q,
  PHIL_SCHEME_EVIDENCE_LEVEL_V1: EVIDENCE,
  PHIL_SCHEME_LIFECYCLE_V1: LIFECYCLE,
  assessPhilPostQuantumClaimV1,
  createPhilCryptoMigrationCeremonyV1,
  createPhilCryptoPolicyBundleV1,
  createPhilCryptoTrustedStateV1,
  createPhilNetworkCryptoCapabilityV1,
  deriveUntrustedPhilCryptoPolicyBundleHashV1,
  derivePhilCryptoSchemeRegistryHashV1,
  getPhilCryptoSchemeRecordV1,
  validatePhilCryptoSchemeRegistryV1
} = require("../../apps/phil-device-sdk/src/postQuantumMigrationV1.ts");

const REPO_ROOT = path.resolve(__dirname, "../..");
const fixture = JSON.parse(fs.readFileSync(
  path.join(REPO_ROOT, "config/cryptography/PHIL_V1_STEP5_PQ_MIGRATION_FIXTURE.json"),
  "utf8"
));

function h(label) {
  return keccak256(toUtf8Bytes(label));
}

function expectCode(fn, code) {
  assert.throws(fn, (error) => error && error.code === code);
}

function currentBundleDraft(overrides = {}) {
  return {
    policyEpoch: 1,
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
    networkCapability: fixture.networkCapabilities.starknetSepolia,
    recoveryIndependenceHash: h("phil-v1-step2-independent-2-of-3-key-unwrapping-policy-epoch-1"),
    ...overrides
  };
}

function currentBundle(overrides = {}) {
  const { trustedState, ...draftOverrides } = overrides;
  const draft = currentBundleDraft(draftOverrides);
  return createPhilCryptoPolicyBundleV1({
    ...draft,
    trustedState: trustedState ?? stateFor(draft.networkCapability, draft.policyEpoch, {
      expectedPolicyHash: deriveUntrustedPhilCryptoPolicyBundleHashV1(draft)
    })
  });
}

function network(overrides = {}) {
  const registry = validatePhilCryptoSchemeRegistryV1();
  return createPhilNetworkCryptoCapabilityV1({
    networkIdHash: h("test-network"),
    registryEpoch: registry.registryEpoch,
    registryHash: registry.registryHash,
    capabilityEpoch: 1,
    accountModelHash: h("test-account-model"),
    enforcement: ENFORCEMENT.CONTRACT_CANDIDATE,
    maximumSecurityMode: MODE.CLASSICAL_ONLY,
    signatureSchemeIds: [S.P256_SHA256_SIGNATURE],
    proofSchemeIds: [S.NOIR_ULTRAHONK_KECCAK_STEP3],
    verifierSchemeIds: [S.STEP3_GARAGA_VERIFIER],
    authorizationPathAvailable: false,
    capabilityAuthorityHash: h("test-capability-authority"),
    implementationBindingHash: h("test-implementation"),
    evidenceHash: h("test-evidence"),
    ...overrides
  });
}

function stateFor(networkCapability, policyEpoch = 1, overrides = {}) {
  return createPhilCryptoTrustedStateV1({
    registryEpoch: networkCapability.registryEpoch,
    registryHash: networkCapability.registryHash,
    networkIdHash: networkCapability.networkIdHash,
    capabilityAuthorityHash: networkCapability.capabilityAuthorityHash,
    greatestAcceptedCapabilityEpoch: networkCapability.capabilityEpoch,
    expectedCapabilityHash: networkCapability.capabilityHash,
    greatestAcceptedPolicyEpoch: policyEpoch,
    expectedPolicyHash: h("test-expected-policy-placeholder"),
    ...overrides
  });
}

function rotationInput(overrides = {}) {
  return {
    ceremonyKind: CEREMONY.ROTATE_WITHIN_MODE,
    fromBundle: fixture.currentPolicyBundle,
    toBundle: fixture.syntheticRotationTargetBundle,
    fromNetworkCapability: fixture.networkCapabilities.starknetSepolia,
    toNetworkCapability: fixture.networkCapabilities.syntheticStarknetSepoliaEpoch2,
    fromTrustedState: fixture.trustedStates.currentStarknet,
    toTrustedState: fixture.trustedStates.syntheticRotatedStarknet,
    fromDeviceEpoch: 1,
    toDeviceEpoch: 2,
    fromValidatorEpoch: 1,
    toValidatorEpoch: 2,
    fromRecoveryEpoch: 1,
    toRecoveryEpoch: 2,
    newKeySetHash: h("phil-v1-step5-disclosed-synthetic-rotated-key-set"),
    userApprovalDigest: h("phil-v1-step5-disclosed-synthetic-user-approval"),
    recoveryApprovalDigest: h("phil-v1-step5-disclosed-synthetic-recovery-approval"),
    independentReviewHash: h("phil-v1-step5-independent-review-required-not-yet-performed"),
    notBefore: 1800000000,
    expiresAt: 1800003600,
    emergencyFreeze: false,
    ...overrides
  };
}

describe("Phil V1 Step 5 post-quantum migration architecture", function () {
  it("freezes unique label-derived scheme IDs and a deterministic registry hash", function () {
    const validation = validatePhilCryptoSchemeRegistryV1();
    assert.equal(validation.schemeCount, PHIL_CRYPTO_SCHEME_REGISTRY_V1.length);
    assert.equal(validation.registryHash, fixture.registry.registryHash);
    assert.equal(derivePhilCryptoSchemeRegistryHashV1(1), fixture.registry.registryHash);
    assert.equal(new Set(PHIL_CRYPTO_SCHEME_REGISTRY_V1.map((record) => record.schemeId)).size, validation.schemeCount);
    for (const [name, label] of Object.entries(PHIL_CRYPTO_SCHEME_LABELS_V1)) {
      assert.equal(S[name], h(label));
    }
  });

  it("keeps STWO forbidden and every unverified PQ primitive candidate-only", function () {
    const stwo = getPhilCryptoSchemeRecordV1(S.STWO_EXPERIMENTAL_QUARANTINED);
    assert.equal(stwo.lifecycle, LIFECYCLE.FORBIDDEN);
    assert.equal(stwo.retiredRegistryEpoch, "1");
    for (const schemeId of [S.ML_DSA_65_SIGNATURE, S.SLH_DSA_SHA2_128S_SIGNATURE, S.ML_KEM_768, S.ML_KEM_1024]) {
      const record = getPhilCryptoSchemeRecordV1(schemeId);
      assert.equal(record.quantumPosture, Q.QUANTUM_RESISTANT);
      assert.equal(record.lifecycle, LIFECYCLE.SPECIFIED_CANDIDATE);
    }
    assert.equal(getPhilCryptoSchemeRecordV1(S.ML_DSA_65_SIGNATURE).evidenceLevel, EVIDENCE.PLATFORM_DOCUMENTED);
    assert.equal(getPhilCryptoSchemeRecordV1(S.ML_KEM_768).evidenceLevel, EVIDENCE.PLATFORM_DOCUMENTED);
  });

  it("records Apple ML-DSA and ML-KEM as documented candidates, not admitted PQ authorization", function () {
    const apple = fixture.platformCapabilities.appleSecureEnclave;
    assert.deepEqual(apple.currentPhilDeviceSignatureSchemeIds, [S.P256_SHA256_SIGNATURE]);
    assert.deepEqual(apple.documentedKeyEstablishmentCandidateIds, [S.ML_KEM_768, S.ML_KEM_1024]);
    assert.deepEqual(apple.documentedPostQuantumSignatureCandidateIds, [S.ML_DSA_65_SIGNATURE]);
    assert.equal(apple.secureEnclaveMlDsaSigningDocumented, true);
    assert.equal(apple.philMlDsaDeviceIntegrationVerified, false);
    assert.equal(apple.philMlKemDeviceIntegrationVerified, false);
    assert.equal(apple.postQuantumDeviceAuthorizationAvailable, false);
  });

  it("caps the current Starknet and Base records at classical-only with no live path", function () {
    const { starknetSepolia, baseMainnet } = fixture.networkCapabilities;
    assert.equal(starknetSepolia.maximumSecurityMode, MODE.CLASSICAL_ONLY);
    assert.equal(starknetSepolia.enforcement, ENFORCEMENT.CONTRACT_CANDIDATE);
    assert.equal(starknetSepolia.authorizationPathAvailable, false);
    assert.equal(baseMainnet.maximumSecurityMode, MODE.CLASSICAL_ONLY);
    assert.equal(baseMainnet.enforcement, ENFORCEMENT.LOCAL_ONLY);
    assert.equal(baseMainnet.authorizationPathAvailable, false);
    assert.deepEqual(baseMainnet.proofSchemeIds, []);
    assert.deepEqual(baseMainnet.verifierSchemeIds, []);
    assert.equal(starknetSepolia.registryHash, fixture.registry.registryHash);
    assert.equal(baseMainnet.registryHash, fixture.registry.registryHash);
  });

  it("binds the complete registry and exact proof/verifier compatibility", function () {
    const verifier = getPhilCryptoSchemeRecordV1(S.STEP3_GARAGA_VERIFIER);
    assert.deepEqual(verifier.compatibleProofSchemeIds, [S.NOIR_ULTRAHONK_KECCAK_STEP3]);
    expectCode(
      () => network({ registryHash: h("substituted-registry") }),
      "PHIL_PQ_REGISTRY_TRUST_MISMATCH"
    );
    expectCode(
      () => network({ verifierSchemeIds: [S.TRANSPARENT_STARK_VERIFIER_RESERVED] }),
      "PHIL_PQ_PROOF_VERIFIER_INCOMPATIBLE"
    );
    assert.equal(
      getPhilCryptoSchemeRecordV1(S.P256_ECIES_X963_SHA256_AESGCM).implementationBindingHash,
      h("git-commit-fe583b6aef84a8636736b2041db2a56046a5972e:git-blob-78391d7e93bda3ab390134ec4eae6f380833b8cc:SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM")
    );
    assert.equal(
      getPhilCryptoSchemeRecordV1(S.SHA256).implementationBindingHash,
      h("git-blob-e59264255b0abdc51f488f5565e15dd6fd776088:apps/phil-device-sdk/src/v2NativeIPhoneRecovery.ts:ethers-sha256:sha256-package-lock-030f8a95dc90b91d939da1c8d7735553320b2b3c3f0a4e0f0fac54c8114dc3ec:ethers-6.17.0")
    );
    assert.equal(
      getPhilCryptoSchemeRecordV1(S.SECP256K1_KECCAK256_SIGNATURE).implementationBindingHash,
      h("git-blob-6da1f68e5a039c99245517fa647df0ac39a81c85:apps/phil-device-sdk/src/v2LocalCeremonyProtocol.ts:computePhilCoreV2LocalRole2CeremonyProofDigest+recoverCanonicalSecp256k1Signer:sha256-package-lock-030f8a95dc90b91d939da1c8d7735553320b2b3c3f0a4e0f0fac54c8114dc3ec:ethers-6.17.0")
    );
  });

  it("builds only the honest current classical bundle and claim", function () {
    const bundle = currentBundle();
    assert.equal(bundle.bundleHash, fixture.currentPolicyBundle.bundleHash);
    assert.deepEqual(
      bundle.recoveryProtectionSchemeIds,
      [S.PAIRWISE_HKDF_AES256GCM_2OF3_RECOVERY]
    );
    const claim = assessPhilPostQuantumClaimV1({
      bundle,
      network: fixture.networkCapabilities.starknetSepolia,
      trustedState: fixture.trustedStates.currentStarknet
    });
    assert.equal(claim.claim, "algorithm_agile_only");
    assert.equal(claim.wholeSystemPostQuantum, false);
    assert.match(claim.reasons.join("\n"), /quantum-vulnerable/);
    assert.match(claim.reasons.join("\n"), /not deployed/);
    expectCode(
      () => assessPhilPostQuantumClaimV1({
        bundle: { ...bundle, bundleHash: h("tampered-policy-bundle") },
        network: fixture.networkCapabilities.starknetSepolia,
        trustedState: fixture.trustedStates.currentStarknet
      }),
      "PHIL_PQ_POLICY_BUNDLE_HASH_MISMATCH"
    );
  });

  it("rejects OR combiners, duplicate schemes, wrong kinds, and forbidden schemes", function () {
    expectCode(() => currentBundle({ signatureCombiner: "any" }), "PHIL_PQ_SIGNATURE_OR_FORBIDDEN");
    expectCode(() => currentBundle({ hashSchemeIds: [S.SHA256, S.SHA256] }), "PHIL_PQ_SCHEME_SET_DUPLICATE");
    expectCode(() => currentBundle({ hashSchemeIds: [S.P256_SHA256_SIGNATURE] }), "PHIL_PQ_SCHEME_KIND_MISMATCH");
    expectCode(
      () => currentBundle({ recoveryProtectionSchemeIds: [S.P256_SHA256_SIGNATURE] }),
      "PHIL_PQ_SCHEME_KIND_MISMATCH"
    );
    expectCode(() => currentBundle({ proofSchemeId: S.STWO_EXPERIMENTAL_QUARANTINED }), "PHIL_PQ_SCHEME_NOT_ADMISSIBLE");
  });

  it("cannot activate candidate PQ algorithms or claim hybrid without admitted components", function () {
    expectCode(
      () => currentBundle({ keyEstablishmentSchemeIds: [S.ML_KEM_768] }),
      "PHIL_PQ_CANDIDATE_NOT_ACTIVATABLE"
    );
    expectCode(
      () => currentBundle({
        securityMode: MODE.HYBRID_AND,
        deviceSignatureSchemeIds: [S.P256_SHA256_SIGNATURE, S.ML_DSA_65_SIGNATURE],
        validatorSignatureSchemeIds: [S.P256_SHA256_SIGNATURE, S.ML_DSA_65_SIGNATURE],
        recoveryProtectionSchemeIds: [S.PAIRWISE_HKDF_AES256GCM_2OF3_RECOVERY],
        keyEstablishmentSchemeIds: [S.P256_ECIES_X963_SHA256_AESGCM, S.ML_KEM_768],
        proofSchemeId: S.TRANSPARENT_HASH_STARK_RESERVED,
        verifierSchemeId: S.TRANSPARENT_STARK_VERIFIER_RESERVED
      }),
      "PHIL_PQ_CANDIDATE_NOT_ACTIVATABLE"
    );
  });

  it("rejects network availability and hybrid/PQ overclaims", function () {
    expectCode(
      () => network({ authorizationPathAvailable: "false" }),
      "PHIL_PQ_INVALID_BOOLEAN"
    );
    expectCode(
      () => network({ authorizationPathAvailable: true }),
      "PHIL_PQ_NETWORK_PATH_OVERCLAIM"
    );
    expectCode(
      () => network({ maximumSecurityMode: MODE.HYBRID_AND }),
      "PHIL_PQ_NETWORK_MODE_OVERCLAIM"
    );
    expectCode(
      () => network({
        enforcement: ENFORCEMENT.NETWORK_ENFORCED,
        maximumSecurityMode: MODE.HYBRID_AND
      }),
      "PHIL_PQ_HYBRID_COMPONENTS_REQUIRED"
    );
    expectCode(
      () => currentBundle({
        networkCapability: fixture.networkCapabilities.baseMainnet,
        trustedState: fixture.trustedStates.baseMainnet
      }),
      "PHIL_PQ_NETWORK_SCHEME_UNSUPPORTED"
    );
    expectCode(
      () => currentBundle({
        networkCapability: {
          ...fixture.networkCapabilities.starknetSepolia,
          capabilityHash: h("tampered-network-capability")
        }
      }),
      "PHIL_PQ_NETWORK_CAPABILITY_HASH_MISMATCH"
    );
  });

  it("requires trusted provenance and exact capability and policy pins", function () {
    const currentNetwork = fixture.networkCapabilities.starknetSepolia;
    expectCode(
      () => currentBundle({
        trustedState: stateFor(currentNetwork, 1, {
          expectedCapabilityHash: h("untrusted-capability")
        })
      }),
      "PHIL_PQ_CAPABILITY_UNTRUSTED"
    );
    expectCode(
      () => currentBundle({
        trustedState: stateFor(currentNetwork, 1, {
          greatestAcceptedCapabilityEpoch: 2
        })
      }),
      "PHIL_PQ_CAPABILITY_STALE"
    );
    expectCode(
      () => currentBundle({
        trustedState: stateFor(currentNetwork, 2)
      }),
      "PHIL_PQ_POLICY_EPOCH_UNTRUSTED"
    );
    expectCode(
      () => currentBundle({
        trustedState: stateFor(currentNetwork, 1, {
          capabilityAuthorityHash: h("untrusted-authority")
        })
      }),
      "PHIL_PQ_CAPABILITY_PROVENANCE_MISMATCH"
    );
    expectCode(
      () => currentBundle({
        trustedState: {
          ...fixture.trustedStates.currentStarknet,
          trustedStateHash: h("tampered-trusted-state")
        }
      }),
      "PHIL_PQ_TRUSTED_STATE_HASH_MISMATCH"
    );
    expectCode(
      () => currentBundle({
        policyEpoch: 999,
        trustedState: fixture.trustedStates.currentStarknet
      }),
      "PHIL_PQ_POLICY_EPOCH_UNTRUSTED"
    );
    expectCode(
      () => currentBundle({
        recoveryIndependenceHash: h("unknown-same-epoch-policy"),
        trustedState: fixture.trustedStates.currentStarknet
      }),
      "PHIL_PQ_POLICY_UNTRUSTED"
    );
    expectCode(
      () => currentBundle({
        trustedState: {
          ...fixture.trustedStates.currentStarknet,
          formatVersionHash: h("forged-trusted-state-format")
        }
      }),
      "PHIL_PQ_TRUSTED_STATE_FORMAT_MISMATCH"
    );
  });

  it("binds a deterministic rotation ceremony and rejects epoch or freeze errors", function () {
    const ceremony = createPhilCryptoMigrationCeremonyV1(rotationInput());
    assert.equal(ceremony.ceremonyHash, fixture.syntheticRotationCeremony.ceremonyHash);
    assert.notEqual(ceremony.fromNetworkCapabilityHash, ceremony.toNetworkCapabilityHash);
    assert.equal(
      BigInt(fixture.networkCapabilities.syntheticStarknetSepoliaEpoch2.capabilityEpoch),
      BigInt(fixture.networkCapabilities.starknetSepolia.capabilityEpoch) + 1n
    );
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({ toDeviceEpoch: 3 })),
      "PHIL_PQ_AUTHORITY_EPOCH_TRANSITION"
    );
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({ emergencyFreeze: true })),
      "PHIL_PQ_EMERGENCY_FREEZE_REQUIRED"
    );
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({ emergencyFreeze: "false" })),
      "PHIL_PQ_INVALID_BOOLEAN"
    );
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({ expiresAt: 1799999999 })),
      "PHIL_PQ_CEREMONY_WINDOW_INVALID"
    );
  });

  it("requires a higher capability epoch for changed records and rejects capability rollback", function () {
    const oldCapability = fixture.networkCapabilities.starknetSepolia;
    const newerCapability = fixture.networkCapabilities.syntheticStarknetSepoliaEpoch2;
    const changedSameEpoch = createPhilNetworkCryptoCapabilityV1({
      networkIdHash: oldCapability.networkIdHash,
      registryEpoch: oldCapability.registryEpoch,
      registryHash: oldCapability.registryHash,
      capabilityEpoch: oldCapability.capabilityEpoch,
      accountModelHash: oldCapability.accountModelHash,
      enforcement: oldCapability.enforcement,
      maximumSecurityMode: oldCapability.maximumSecurityMode,
      signatureSchemeIds: oldCapability.signatureSchemeIds,
      proofSchemeIds: oldCapability.proofSchemeIds,
      verifierSchemeIds: oldCapability.verifierSchemeIds,
      authorizationPathAvailable: false,
      capabilityAuthorityHash: oldCapability.capabilityAuthorityHash,
      implementationBindingHash: h("changed-without-capability-epoch"),
      evidenceHash: h("changed-without-capability-epoch-evidence")
    });
    const changedDraft = currentBundleDraft({
      policyEpoch: 2,
      networkCapability: changedSameEpoch
    });
    const changedState = stateFor(changedSameEpoch, 2, {
      expectedPolicyHash: deriveUntrustedPhilCryptoPolicyBundleHashV1(changedDraft)
    });
    const changedBundle = currentBundle({
      policyEpoch: 2,
      networkCapability: changedSameEpoch,
      trustedState: changedState
    });
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({
        toBundle: changedBundle,
        toNetworkCapability: changedSameEpoch,
        toTrustedState: changedState
      })),
      "PHIL_PQ_CAPABILITY_EPOCH_TRANSITION"
    );

    const newerDraftAtPolicy1 = currentBundleDraft({
      policyEpoch: 1,
      networkCapability: newerCapability
    });
    const newerStateAtPolicy1 = stateFor(newerCapability, 1, {
      expectedPolicyHash: deriveUntrustedPhilCryptoPolicyBundleHashV1(newerDraftAtPolicy1)
    });
    const newerBundleAtPolicy1 = currentBundle({
      policyEpoch: 1,
      networkCapability: newerCapability,
      trustedState: newerStateAtPolicy1
    });
    const oldDraftAtPolicy2 = currentBundleDraft({
      policyEpoch: 2,
      networkCapability: oldCapability
    });
    const oldStateAtPolicy2 = stateFor(oldCapability, 2, {
      expectedPolicyHash: deriveUntrustedPhilCryptoPolicyBundleHashV1(oldDraftAtPolicy2)
    });
    const oldBundleAtPolicy2 = currentBundle({
      policyEpoch: 2,
      networkCapability: oldCapability,
      trustedState: oldStateAtPolicy2
    });
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({
        fromBundle: newerBundleAtPolicy1,
        toBundle: oldBundleAtPolicy2,
        fromNetworkCapability: newerCapability,
        toNetworkCapability: oldCapability,
        fromTrustedState: newerStateAtPolicy1,
        toTrustedState: oldStateAtPolicy2
      })),
      "PHIL_PQ_CAPABILITY_DOWNGRADE"
    );
  });

  it("rejects registry and security-mode downgrade transitions", function () {
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({
        fromBundle: { ...fixture.currentPolicyBundle, registryEpoch: "2" }
      })),
      "PHIL_PQ_REGISTRY_DOWNGRADE"
    );
    expectCode(
      () => createPhilCryptoMigrationCeremonyV1(rotationInput({
        fromBundle: { ...fixture.currentPolicyBundle, securityMode: MODE.HYBRID_AND }
      })),
      "PHIL_PQ_SECURITY_DOWNGRADE"
    );
  });

  it("contains no RPC, deployment, signer, device, secret, transaction, or STWO execution path", function () {
    const source = fs.readFileSync(
      path.join(REPO_ROOT, "apps/phil-device-sdk/src/postQuantumMigrationV1.ts"),
      "utf8"
    );
    assert.doesNotMatch(source, /fetch\s*\(|XMLHttpRequest|WebSocket|ethers\.Wallet|deploy_syscall|call_contract_syscall/);
    assert.doesNotMatch(source, /from\s+["']\.\/runtime\//);
    assert.match(source, /STWO_EXPERIMENTAL_QUARANTINED/);
    assert.match(source, /lifecycle: L\.FORBIDDEN/);
  });
});
