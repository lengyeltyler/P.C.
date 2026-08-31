require("tsx/cjs");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { keccak256, toUtf8Bytes } = require("ethers");

const {
  PHILCORE_V2_ACCOUNT_VERSION_ID,
  PHILCORE_V2_ACTION_TYPE,
  PHILCORE_V2_NONCE_KEY,
  PHILCORE_V2_PURPOSE,
  PHILCORE_V2_SECURITY_MODEL_ID,
  composePhilCoreV2Nonce,
  encodePhilCoreV2Intent
} = require("../../apps/phil-device-sdk/src/v2Intent.ts");
const {
  computePhilCoreV2AuthorizedIntentHash,
  computePhilCoreV2RecoveryFactorDigest,
  computePhilCoreV2RuntimeAuthorizationDigest
} = require("../../apps/phil-device-sdk/src/v2Authorization.ts");
const {
  PHILCORE_V2_ACCOUNT_FAILURE_CODES,
  PHILCORE_V2_RECOVERY_DELAY_SECONDS,
  applyPhilCoreV2AccountTransitionLocally,
  completePhilCoreV2RecoveryLocally,
  createPhilCoreV2AccountState,
  validatePhilCoreV2AccountOperation
} = require("../../apps/phil-device-sdk/src/v2AccountCore.ts");
const {
  createPhilCoreV2AuthorityEvidenceReference,
  createPhilCoreV2FixtureAuthorityVerifier
} = require("../../apps/phil-device-sdk/src/v2Validator.ts");
const {
  buildO32VectorPackage
} = require("../../scripts/cryptography/generate-o32-v2-vectors.cjs");

const H = (value) => keccak256(toUtf8Bytes(value));
const VALIDATOR = "0x1b41145742566Cf69621DA7e1D6F29609a8b1BDa";
const VALIDATOR_KEY_ID_BINDING =
  "0xb7bd562b139c95ebf020f445e6a3b3be82dfacf9e319d773b074da96e2b7b809";
const FACTORY = "0x3000000000000000000000000000000000000003";
const CONFIRMATION_TARGET =
  "0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7";
const NOW = 1800000150n;
const ROOT = path.resolve(__dirname, "../..");

function accountState(overrides = {}) {
  const vectors = buildO32VectorPackage();
  const base = {
    immutable: {
      chainId: vectors.publicFixtureBindings.chainId,
      entryPoint: vectors.publicFixtureBindings.entryPoint,
      account: vectors.publicFixtureBindings.account,
      ownerCommitment: vectors.validIntent.input.header.ownerCommitment,
      factoryBinding: FACTORY,
      accountVersionId: PHILCORE_V2_ACCOUNT_VERSION_ID,
      securityModelId: PHILCORE_V2_SECURITY_MODEL_ID,
      confirmationTarget: CONFIRMATION_TARGET,
      recoveryDelaySeconds: "172800",
      recoveryExpirySeconds: "604800"
    },
    validatorState: {
      chainId: vectors.publicFixtureBindings.chainId,
      entryPoint: vectors.publicFixtureBindings.entryPoint,
      account: vectors.publicFixtureBindings.account,
      ownerCommitment: vectors.validIntent.input.header.ownerCommitment,
      validator: VALIDATOR,
      validatorKeyIdBinding: VALIDATOR_KEY_ID_BINDING,
      validatorEpoch: "3",
      recoveryEpoch: "2",
      recoveryConfigHash: vectors.recovery.recoveryConfigHash
    },
    nonceSequences: {
      ordinary: "7",
      maintenance: "0",
      recovery: "2"
    },
    validatorCommitment: vectors.validatorAuthorization.validatorCommitment,
    securityConfigurationHash: vectors.recovery.recoveryConfigHash,
    primaryDeviceFactorCommitment:
      vectors.recovery.factorCommitments.primaryDevice,
    hardwareSecurityKeyCommitment:
      vectors.recovery.factorCommitments.hardwareSecurityKey,
    recoveryFactorCommitment:
      vectors.recovery.factorCommitments.recoveryFactor
  };
  return createPhilCoreV2AccountState({
    ...base,
    ...overrides,
    immutable: {
      ...base.immutable,
      ...(overrides.immutable ?? {})
    },
    validatorState: {
      ...base.validatorState,
      ...(overrides.validatorState ?? {})
    },
    nonceSequences: {
      ...base.nonceSequences,
      ...(overrides.nonceSequences ?? {})
    }
  });
}

function ordinaryFixture() {
  const vectors = buildO32VectorPackage();
  const evidenceReferenceHash = H("o34:validator-evidence-reference");
  const state = accountState();
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
    verifierId: "o34.fixture.validator",
    expectations: [{
      authorityKind: "validator_signature",
      digest: vectors.validatorAuthorization.validatorDigest,
      evidenceReferenceHash,
      chainId: state.validatorState.chainId,
      account: state.validatorState.account,
      validator: state.validatorState.validator,
      validatorKeyIdBinding: state.validatorState.validatorKeyIdBinding,
      validatorEpoch: state.validatorState.validatorEpoch,
      recoveryEpoch: state.validatorState.recoveryEpoch,
      recoveryConfigHash: state.validatorState.recoveryConfigHash
    }]
  });
  const fundLifecycleGate = {
    lifecycle: vectors.fundLifecycle.input,
    releasePathVerified: true,
    residualHandlingBound: true,
    finalStateVerificationRequired: true,
    separateReleaseAuthorizationRequired: true
  };
  return {
    vectors,
    state,
    authorizationPackage,
    verifier,
    fundLifecycleGate
  };
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
  const evidenceReferenceHash = H("o34:recovery-evidence-reference");
  const state = accountState();
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
    verifierId: "o34.fixture.recovery",
    expectations: [{
      authorityKind: "recovery_threshold",
      digest: vectors.recovery.validRecovery.recoveryFactorDigest,
      evidenceReferenceHash,
      chainId: state.validatorState.chainId,
      account: state.validatorState.account,
      validator: state.validatorState.validator,
      validatorKeyIdBinding: state.validatorState.validatorKeyIdBinding,
      validatorEpoch: state.validatorState.validatorEpoch,
      recoveryEpoch: state.validatorState.recoveryEpoch,
      recoveryConfigHash: state.validatorState.recoveryConfigHash,
      factorBitmap:
        vectors.recovery.validRecovery.authorizationInput.factorBitmap
    }]
  });
  return { vectors, state, authorizationPackage, verifier };
}

function cancellationFixture(activeState) {
  const vectors = buildO32VectorPackage();
  const intent = {
    header: {
      ...vectors.recovery.validRecovery.intent.header,
      actionType: PHILCORE_V2_ACTION_TYPE.RECOVERY_CANCEL,
      actionId: H("o34:recovery-cancel-action"),
      purpose: PHILCORE_V2_PURPOSE.CANCEL_RECOVERY,
      nonceSequence: "3"
    },
    payload: {
      kind: "RECOVERY_CANCEL",
      recoveryRequestId: activeState.pendingRecovery.requestId
    }
  };
  const encoded = encodePhilCoreV2Intent(intent);
  const runtimeAuthorization = {
    ...vectors.runtimeAuthorization.input,
    intentCoreHash: encoded.intentCoreHash
  };
  const runtimeAuthorizationDigest =
    computePhilCoreV2RuntimeAuthorizationDigest(runtimeAuthorization);
  const authorizedIntentHash = computePhilCoreV2AuthorizedIntentHash({
    intentCoreHash: encoded.intentCoreHash,
    runtimeAuthorizationDigest
  });
  const userOperationHashBinding = H("o34:recovery-cancel-userop-binding");
  const authorityDigest = computePhilCoreV2RecoveryFactorDigest(
    {
      chainId: activeState.immutable.chainId,
      account: activeState.immutable.account
    },
    {
      authorizedIntentHash,
      userOperationHash: userOperationHashBinding,
      recoveryConfigHash:
        activeState.validatorState.recoveryConfigHash,
      recoveryEpoch: activeState.validatorState.recoveryEpoch,
      factorBitmap: 6
    }
  ).digest;
  const evidenceReferenceHash = H("o34:recovery-cancel-evidence");
  const authorizationPackage = {
    intent,
    declaredIntentCoreHash: encoded.intentCoreHash,
    runtimeAuthorization,
    declaredRuntimeAuthorizationDigest: runtimeAuthorizationDigest,
    declaredAuthorizedIntentHash: authorizedIntentHash,
    userOperationHashBinding,
    authority: {
      authorityKind: "recovery_threshold",
      validator: activeState.validatorState.validator,
      validatorKeyIdBinding:
        activeState.validatorState.validatorKeyIdBinding,
      validatorEpoch: activeState.validatorState.validatorEpoch,
      recoveryEpoch: activeState.validatorState.recoveryEpoch,
      recoveryConfigHash:
        activeState.validatorState.recoveryConfigHash,
      factorBitmap: 6,
      evidence: createPhilCoreV2AuthorityEvidenceReference({
        authorityKind: "recovery_threshold",
        evidenceReferenceHash,
        fixtureOnly: true
      }),
      declaredAuthorityDigest: authorityDigest
    }
  };
  const verifier = createPhilCoreV2FixtureAuthorityVerifier({
    verifierId: "o34.fixture.recovery-cancel",
    expectations: [{
      authorityKind: "recovery_threshold",
      digest: authorityDigest,
      evidenceReferenceHash,
      chainId: activeState.validatorState.chainId,
      account: activeState.validatorState.account,
      validator: activeState.validatorState.validator,
      validatorKeyIdBinding:
        activeState.validatorState.validatorKeyIdBinding,
      validatorEpoch: activeState.validatorState.validatorEpoch,
      recoveryEpoch: activeState.validatorState.recoveryEpoch,
      recoveryConfigHash:
        activeState.validatorState.recoveryConfigHash,
      factorBitmap: 6
    }]
  });
  return {
    state: activeState,
    authorizationPackage,
    verifier
  };
}

function request(fixture, overrides = {}) {
  return {
    state: fixture.state,
    caller: fixture.state.immutable.entryPoint,
    keyedNonce: composePhilCoreV2Nonce({
      key: fixture.authorizationPackage.intent.header.nonceKey,
      sequence: fixture.authorizationPackage.intent.header.nonceSequence
    }),
    userOperationHashBinding:
      fixture.authorizationPackage.userOperationHashBinding,
    authorizationPackage: fixture.authorizationPackage,
    currentTime: NOW,
    authorityVerifier: fixture.verifier,
    ...(fixture.fundLifecycleGate
      ? { fundLifecycleGate: fixture.fundLifecycleGate }
      : {}),
    ...overrides
  };
}

function mutateIntent(fixture, header = {}, payload = {}) {
  return {
    ...fixture.authorizationPackage,
    intent: {
      header: {
        ...fixture.authorizationPackage.intent.header,
        ...header
      },
      payload: {
        ...fixture.authorizationPackage.intent.payload,
        ...payload
      }
    }
  };
}

describe("O.34 V2 account core", function () {
  it("fixes immutable security boundaries and exact coherent storage", function () {
    const state = accountState();
    assert.equal(state.immutable.upgradeable, false);
    assert.equal(state.immutable.administrator, null);
    assert.equal(state.immutable.upgradeKey, null);
    assert.equal(state.immutable.arbitraryExecutionEnabled, false);
    assert.equal(state.immutable.delegatecallEnabled, false);
    assert.equal(state.immutable.modulesEnabled, false);
    assert.equal(state.immutable.sessionKeysEnabled, false);
    assert.equal(state.immutable.paymastersEnabled, false);
    assert.equal(state.recoveryLifecycle, "NORMAL");
    assert.equal(state.publicMutationCount, 0);
    assert.throws(
      () => accountState({ validatorCommitment: H("wrong-validator") }),
      /validatorCommitment_state_mismatch/
    );
    assert.throws(
      () => accountState({ securityConfigurationHash: H("wrong-config") }),
      /securityConfigurationHash_state_mismatch/
    );
  });

  it("accepts exact O.32/O.33 authority without executing or moving value", async function () {
    const fixture = ordinaryFixture();
    const result = await validatePhilCoreV2AccountOperation(
      request(fixture)
    );
    assert.equal(result.accepted, true);
    assert.equal(result.action.kind, "NATIVE_TRANSFER");
    assert.equal(result.action.calldata, "0x");
    assert.equal(result.action.amountWei, 1234567n);
    assert.equal(result.fundLifecycleEnforced, true);
    assert.equal(result.executionPerformed, false);
    assert.equal(result.externalCallPerformed, false);
    assert.equal(result.fundsMoved, false);
    assert.equal(result.userOperationCreated, false);
    assert.equal(result.signatureProduced, false);
    assert.equal(result.publicMutationCount, 0);
  });

  it("applies only a local nonce/replay transition", async function () {
    const fixture = ordinaryFixture();
    const validation = await validatePhilCoreV2AccountOperation(
      request(fixture)
    );
    assert.equal(validation.accepted, true);
    const applied = applyPhilCoreV2AccountTransitionLocally({
      state: fixture.state,
      validation,
      currentTime: NOW
    });
    assert.equal(applied.state.nonceSequences.ordinary, 8n);
    assert.equal(
      applied.state.validatorState.consumedAuthorizationDigests.length,
      1
    );
    assert.equal(applied.fundsMoved, false);
    assert.equal(applied.externalCallPerformed, false);
    assert.equal(applied.publicMutationCount, 0);
    assert.throws(
      () => applyPhilCoreV2AccountTransitionLocally({
        state: fixture.state,
        validation,
        currentTime: NOW
      }),
      /validation_context_invalid/
    );
    const replay = await validatePhilCoreV2AccountOperation(
      request(fixture, { state: applied.state })
    );
    assert.deepEqual(
      { accepted: replay.accepted, code: replay.code },
      { accepted: false, code: "NONCE_STALE" }
    );
  });

  it("rejects copied and state-substituted local validation contexts", async function () {
    const fixture = ordinaryFixture();
    const validation = await validatePhilCoreV2AccountOperation(
      request(fixture)
    );
    assert.equal(validation.accepted, true);
    assert.throws(
      () => applyPhilCoreV2AccountTransitionLocally({
        state: fixture.state,
        validation: { ...validation },
        currentTime: NOW
      }),
      /validation_context_invalid/
    );
    assert.throws(
      () => applyPhilCoreV2AccountTransitionLocally({
        state: accountState({
          nonceSequences: { ordinary: "8" }
        }),
        validation,
        currentTime: NOW
      }),
      /validation_context_invalid/
    );
  });

  it("rejects changed recipient and amount through exact intent hashing", async function () {
    const fixture = ordinaryFixture();
    for (const payload of [
      { recipient: "0x4000000000000000000000000000000000000004" },
      { amountWei: "1234568" }
    ]) {
      const result = await validatePhilCoreV2AccountOperation(request(
        fixture,
        { authorizationPackage: mutateIntent(fixture, {}, payload) }
      ));
      assert.equal(result.accepted, false);
      assert.equal(result.code, "AUTHORIZATION_REJECTED");
      assert.equal(result.authorizationFailureCode, "INTENT_HASH_MISMATCH");
    }
  });

  it("rejects wrong chain, account, EntryPoint, purpose, and stale epoch", async function () {
    const cases = [
      [{ chainId: "1" }, "CHAIN_MISMATCH"],
      [{ account: "0x5000000000000000000000000000000000000005" }, "ACCOUNT_MISMATCH"],
      [{ entryPoint: "0x6000000000000000000000000000000000000006" }, "ENTRYPOINT_MISMATCH"],
      [{ purpose: PHILCORE_V2_PURPOSE.CONFIRM_ACTION }, "INTENT_INVALID"],
      [{ validatorEpoch: "2" }, "VALIDATOR_EPOCH_STALE"],
      [{ recoveryEpoch: "1" }, "RECOVERY_EPOCH_STALE"]
    ];
    for (const [header, expectedFailure] of cases) {
      const fixture = ordinaryFixture();
      const result = await validatePhilCoreV2AccountOperation(request(
        fixture,
        { authorizationPackage: mutateIntent(fixture, header) }
      ));
      assert.equal(result.accepted, false);
      assert.equal(result.code, "AUTHORIZATION_REJECTED");
      assert.equal(result.authorizationFailureCode, expectedFailure);
    }
  });

  it("rejects wrong validator and key binding", async function () {
    for (const authority of [
      { validator: "0x6000000000000000000000000000000000000006" },
      { validatorKeyIdBinding: H("wrong-key-binding") }
    ]) {
      const fixture = ordinaryFixture();
      const result = await validatePhilCoreV2AccountOperation(request(
        fixture,
        {
          authorizationPackage: {
            ...fixture.authorizationPackage,
            authority: {
              ...fixture.authorizationPackage.authority,
              ...authority
            }
          }
        }
      ));
      assert.equal(result.accepted, false);
      assert.equal(result.code, "AUTHORIZATION_REJECTED");
      assert.match(result.authorizationFailureCode, /VALIDATOR_/);
    }
  });

  it("rejects stale, future, wrong-lane, and mismatched envelope nonces", async function () {
    const fixture = ordinaryFixture();
    const cases = [
      [composePhilCoreV2Nonce({ key: 0, sequence: 6 }), "NONCE_STALE"],
      [composePhilCoreV2Nonce({ key: 0, sequence: 8 }), "NONCE_FUTURE"],
      [composePhilCoreV2Nonce({ key: 1, sequence: 0 }), "NONCE_ENVELOPE_MISMATCH"],
      [composePhilCoreV2Nonce({ key: 3, sequence: 0 }), "NONCE_KEY_UNSUPPORTED"]
    ];
    for (const [keyedNonce, expected] of cases) {
      const result = await validatePhilCoreV2AccountOperation(
        request(fixture, { keyedNonce })
      );
      assert.equal(result.accepted, false);
      assert.equal(result.code, expected);
    }
  });

  it("rejects wrong caller and UserOperation hash binding", async function () {
    const fixture = ordinaryFixture();
    const wrongCaller = await validatePhilCoreV2AccountOperation(request(
      fixture,
      { caller: "0x6000000000000000000000000000000000000006" }
    ));
    assert.equal(wrongCaller.code, "CALLER_NOT_ENTRYPOINT");
    const wrongHash = await validatePhilCoreV2AccountOperation(request(
      fixture,
      { userOperationHashBinding: H("different-user-operation") }
    ));
    assert.equal(wrongHash.code, "USER_OPERATION_BINDING_MISMATCH");
  });

  it("requires a complete exact fund lifecycle for value movement", async function () {
    const fixture = ordinaryFixture();
    const missing = await validatePhilCoreV2AccountOperation(request(
      fixture,
      { fundLifecycleGate: undefined }
    ));
    assert.equal(missing.code, "FUND_LIFECYCLE_REQUIRED");
    const unverified = await validatePhilCoreV2AccountOperation(request(
      fixture,
      {
        fundLifecycleGate: {
          ...fixture.fundLifecycleGate,
          releasePathVerified: false
        }
      }
    ));
    assert.equal(unverified.code, "RELEASE_PATH_UNVERIFIED");
    const changedRoute = await validatePhilCoreV2AccountOperation(request(
      fixture,
      {
        fundLifecycleGate: {
          ...fixture.fundLifecycleGate,
          lifecycle: {
            ...fixture.fundLifecycleGate.lifecycle,
            releaseRouteHash: H("changed-release-route")
          }
        }
      }
    ));
    assert.equal(changedRoute.code, "FUND_LIFECYCLE_MISMATCH");
  });

  it("rejects arbitrary calls, delegatecall, modules, sessions, and paymasters", async function () {
    const fixture = ordinaryFixture();
    for (const forbidden of [
      { arbitraryTarget: fixture.state.immutable.account },
      { arbitraryCalldata: "0x1234" },
      { delegatecall: true },
      { module: "fixture-module" },
      { sessionKey: "fixture-session-key" }
    ]) {
      const result = await validatePhilCoreV2AccountOperation(
        request(fixture, forbidden)
      );
      assert.equal(result.code, "UNRESTRICTED_EXECUTION_PROHIBITED");
    }
    const paymaster = await validatePhilCoreV2AccountOperation(
      request(fixture, { paymasterPresent: true })
    );
    assert.equal(paymaster.code, "PAYMASTER_PROHIBITED");
  });

  it("rejects EntryPoint deposit withdrawal as outside O.34 capability scope", async function () {
    const fixture = ordinaryFixture();
    const intent = mutateIntent(
      fixture,
      {
        actionType: PHILCORE_V2_ACTION_TYPE.ENTRYPOINT_DEPOSIT_WITHDRAWAL,
        purpose: PHILCORE_V2_PURPOSE.WITHDRAW_DEPOSIT
      },
      { kind: "ENTRYPOINT_DEPOSIT_WITHDRAWAL" }
    );
    const result = await validatePhilCoreV2AccountOperation(request(
      fixture,
      { authorizationPackage: intent }
    ));
    assert.equal(result.code, "ACTION_NOT_IMPLEMENTED");
  });

  it("accepts exact 2-of-3 recovery and rejects a single factor", async function () {
    const fixture = recoveryFixture();
    const accepted = await validatePhilCoreV2AccountOperation(
      request(fixture)
    );
    assert.equal(accepted.accepted, true);
    assert.equal(accepted.action.kind, "RECOVERY_REQUEST");
    const rejected = await validatePhilCoreV2AccountOperation(request(
      fixture,
      {
        authorizationPackage: {
          ...fixture.authorizationPackage,
          authority: {
            ...fixture.authorizationPackage.authority,
            factorBitmap: 1
          }
        }
      }
    ));
    assert.equal(rejected.accepted, false);
    assert.equal(rejected.code, "AUTHORIZATION_REJECTED");
    assert.equal(
      rejected.authorizationFailureCode,
      "RECOVERY_THRESHOLD_NOT_MET"
    );
  });

  it("freezes ordinary and maintenance lanes during active recovery", async function () {
    const recovery = recoveryFixture();
    const recoveryValidation = await validatePhilCoreV2AccountOperation(
      request(recovery)
    );
    assert.equal(recoveryValidation.accepted, true);
    const active = applyPhilCoreV2AccountTransitionLocally({
      state: recovery.state,
      validation: recoveryValidation,
      currentTime: NOW
    }).state;
    assert.equal(active.recoveryLifecycle, "RECOVERY_ACTIVE");
    assert.equal(active.validatorState.recoveryState, "recovery_active");
    assert.ok(active.pendingRecovery);

    const ordinary = ordinaryFixture();
    const frozen = await validatePhilCoreV2AccountOperation(request(
      ordinary,
      { state: active }
    ));
    assert.equal(frozen.code, "AUTHORIZATION_REJECTED");
    assert.equal(
      frozen.authorizationFailureCode,
      "ORDINARY_EXECUTION_FROZEN"
    );
  });

  it("completes only the exact delayed recovery with both epochs incremented", async function () {
    const fixture = recoveryFixture();
    const validation = await validatePhilCoreV2AccountOperation(
      request(fixture)
    );
    assert.equal(validation.accepted, true);
    const active = applyPhilCoreV2AccountTransitionLocally({
      state: fixture.state,
      validation,
      currentTime: NOW
    }).state;
    assert.throws(
      () => completePhilCoreV2RecoveryLocally({
        state: active,
        recoveryRequestId: active.pendingRecovery.requestId,
        currentTime: NOW + PHILCORE_V2_RECOVERY_DELAY_SECONDS - 1n
      }),
      /recovery_delay_not_elapsed/
    );
    assert.throws(
      () => completePhilCoreV2RecoveryLocally({
        state: active,
        recoveryRequestId: H("wrong-request"),
        currentTime: NOW + PHILCORE_V2_RECOVERY_DELAY_SECONDS
      }),
      /recovery_request_not_active/
    );
    const completed = completePhilCoreV2RecoveryLocally({
      state: active,
      recoveryRequestId: active.pendingRecovery.requestId,
      currentTime: NOW + PHILCORE_V2_RECOVERY_DELAY_SECONDS
    });
    assert.equal(completed.recoveryLifecycle, "RECOVERY_COMPLETED");
    assert.equal(completed.pendingRecovery, null);
    assert.equal(completed.validatorState.recoveryState, "normal");
    assert.equal(completed.validatorState.validatorEpoch, 4n);
    assert.equal(completed.validatorState.recoveryEpoch, 3n);
    assert.equal(
      completed.validatorState.validator,
      "0x6000000000000000000000000000000000000006"
    );
    assert.equal(completed.publicMutationCount, 0);
  });

  it("cancels only the exact active recovery and changes no epoch", async function () {
    const recovery = recoveryFixture();
    const recoveryValidation = await validatePhilCoreV2AccountOperation(
      request(recovery)
    );
    assert.equal(recoveryValidation.accepted, true);
    const active = applyPhilCoreV2AccountTransitionLocally({
      state: recovery.state,
      validation: recoveryValidation,
      currentTime: NOW
    }).state;
    const cancellation = cancellationFixture(active);
    const validation = await validatePhilCoreV2AccountOperation(
      request(cancellation)
    );
    assert.equal(validation.accepted, true);
    assert.equal(validation.action.kind, "RECOVERY_CANCEL");
    const cancelled = applyPhilCoreV2AccountTransitionLocally({
      state: active,
      validation,
      currentTime: NOW + 10n
    }).state;
    assert.equal(cancelled.recoveryLifecycle, "RECOVERY_CANCELLED");
    assert.equal(cancelled.pendingRecovery, null);
    assert.equal(cancelled.validatorState.recoveryState, "normal");
    assert.equal(cancelled.validatorState.validatorEpoch, 3n);
    assert.equal(cancelled.validatorState.recoveryEpoch, 2n);
    assert.equal(cancelled.nonceSequences.recovery, 4n);
  });

  it("rejects the retired validator-plus-factor cancellation authority", async function () {
    const recovery = recoveryFixture();
    const recoveryValidation = await validatePhilCoreV2AccountOperation(
      request(recovery)
    );
    assert.equal(recoveryValidation.accepted, true);
    const active = applyPhilCoreV2AccountTransitionLocally({
      state: recovery.state,
      validation: recoveryValidation,
      currentTime: NOW
    }).state;
    const cancellation = cancellationFixture(active);
    cancellation.authorizationPackage.authority.authorityKind =
      "combined_validator_recovery";

    const rejected = await validatePhilCoreV2AccountOperation(
      request(cancellation)
    );
    assert.equal(rejected.accepted, false);
    assert.equal(rejected.code, "AUTHORIZATION_REJECTED");
    assert.equal(
      rejected.authorizationFailureCode,
      "AUTHORITY_KIND_MISMATCH"
    );
  });

  it("publishes a stable complete rejection taxonomy", function () {
    assert.equal(
      new Set(PHILCORE_V2_ACCOUNT_FAILURE_CODES).size,
      PHILCORE_V2_ACCOUNT_FAILURE_CODES.length
    );
    assert.equal(
      PHILCORE_V2_ACCOUNT_FAILURE_CODES.includes(
        "UNRESTRICTED_EXECUTION_PROHIBITED"
      ),
      true
    );
  });

  it("documents and indexes the local-only O.34 boundary", function () {
    const architecture = fs.readFileSync(path.join(
      ROOT,
      "docs/reference/O34_V2_ACCOUNT_CORE_ARCHITECTURE.md"
    ), "utf8");
    const invariants = fs.readFileSync(path.join(
      ROOT,
      "docs/security/O34_V2_ACCOUNT_CORE_SECURITY_INVARIANTS.md"
    ), "utf8");
    const index = fs.readFileSync(
      path.join(ROOT, "docs/CANONICAL_DOCS.md"),
      "utf8"
    );
    const model = fs.readFileSync(path.join(
      ROOT,
      "docs/reference/LOCAL_PROOF_GATED_ACCOUNT_MODEL.md"
    ), "utf8");
    assert.match(architecture, /LOCAL_ACCOUNT_ENFORCEMENT_PROTOTYPE_COMPLETE/);
    assert.match(architecture, /no public mutation/i);
    assert.match(invariants, /single-factor recovery takeover/i);
    assert.match(invariants, /No UserOperation/i);
    assert.match(index, /O34_V2_ACCOUNT_CORE_ARCHITECTURE/);
    assert.match(index, /O34_V2_ACCOUNT_CORE_SECURITY_INVARIANTS/);
    assert.match(model, /O\.34 Account Core Enforcement Boundary/);
  });

  it("keeps the implementation free of network and submission capability", function () {
    const source = fs.readFileSync(path.join(
      ROOT,
      "apps/phil-device-sdk/src/v2AccountCore.ts"
    ), "utf8");
    for (const prohibited of [
      "JsonRpcProvider",
      "fetch(",
      "eth_sendUserOperation",
      "eth_sendRawTransaction",
      "sendTransaction(",
      "signTransaction(",
      "privateKey"
    ]) {
      assert.equal(source.includes(prohibited), false, prohibited);
    }
  });
});
