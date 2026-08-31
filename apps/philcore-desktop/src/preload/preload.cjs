const { contextBridge, ipcRenderer } = require("electron");
const { CHANNELS } = require("../shared/bridge-contract.cjs");

function invoke(channel, payload = {}) {
  return ipcRenderer.invoke(channel, payload);
}

contextBridge.exposeInMainWorld("philcore", Object.freeze({
  identity: Object.freeze({
    listLocal: () => invoke(CHANNELS.LIST_LOCAL_IDENTITIES),
    createLocal: (input) => invoke(CHANNELS.CREATE_LOCAL_IDENTITY, input),
    openLocal: (identityId) => invoke(CHANNELS.OPEN_LOCAL_IDENTITY, { identityId }),
    renameLocal: (label) => invoke(CHANNELS.RENAME_LOCAL_IDENTITY, { label }),
    getLockedSummary: () => invoke(CHANNELS.GET_LOCKED_SUMMARY),
    resetLocal: (input) => invoke(
      CHANNELS.RESET_LOCAL_IDENTITY,
      typeof input === "string" ? { confirmation: input } : input
    )
  }),
  session: Object.freeze({
    authenticateLocal: (passphrase) => invoke(CHANNELS.AUTHENTICATE_LOCAL, { passphrase }),
    unlockVault: () => invoke(CHANNELS.UNLOCK_VAULT),
    authenticateLocalFixture: () => invoke(CHANNELS.AUTHENTICATE_LOCAL_FIXTURE),
    lock: () => invoke(CHANNELS.LOCK_SESSION),
    getState: () => invoke(CHANNELS.GET_SESSION_STATE)
  }),
  platformAuth: Object.freeze({
    getAvailability: () => invoke(CHANNELS.GET_PLATFORM_AUTH_AVAILABILITY),
    getStatus: () => invoke(CHANNELS.GET_PLATFORM_AUTH_STATUS),
    getPolicy: () => invoke(CHANNELS.GET_PLATFORM_AUTH_POLICY),
    enroll: (passphrase, approvalArtifactId) => invoke(CHANNELS.ENROLL_PLATFORM_AUTH, { passphrase, approvalArtifactId }),
    unlock: () => invoke(CHANNELS.PLATFORM_UNLOCK),
    disable: (passphrase, approvalArtifactId, freshAuthenticationEvidenceId) => invoke(CHANNELS.DISABLE_PLATFORM_AUTH, { passphrase, approvalArtifactId, freshAuthenticationEvidenceId }),
    requireFreshAuthentication: (purpose, presentation) => invoke(CHANNELS.REQUIRE_FRESH_PLATFORM_AUTH, {
      purpose,
      presentationId: presentation?.presentationId,
      presentationDigest: presentation?.digest
    })
  }),
  approval: Object.freeze({
    createPresentation: (input) => invoke(CHANNELS.CREATE_APPROVAL_PRESENTATION, input),
    getPresentation: (presentationId) => invoke(CHANNELS.GET_APPROVAL_PRESENTATION, { presentationId }),
    respond: (presentationId, decision, typedConfirmation) => invoke(CHANNELS.RESPOND_APPROVAL, { presentationId, decision, typedConfirmation }),
    cancel: (presentationId) => invoke(CHANNELS.CANCEL_APPROVAL, { presentationId }),
    getStatus: () => invoke(CHANNELS.GET_APPROVAL_STATUS),
    consume: (input) => invoke(CHANNELS.CONSUME_APPROVAL, input),
    listHistory: () => invoke(CHANNELS.LIST_APPROVAL_HISTORY)
  }),
  vault: Object.freeze({
    getStatus: () => invoke(CHANNELS.GET_VAULT_STATUS),
    getProtectedView: (viewType) => invoke(CHANNELS.GET_PROTECTED_VIEW, { viewType })
  }),
  credentials: Object.freeze({
    listPublic: () => invoke(CHANNELS.LIST_PUBLIC_CREDENTIALS)
  }),
  validator: Object.freeze({
    getPublicStatus: () => invoke(CHANNELS.GET_VALIDATOR_STATUS)
  }),
  runtime: Object.freeze({
    getSnapshot: () => invoke(CHANNELS.GET_SNAPSHOT)
  }),
  authorization: Object.freeze({
    runLocalDemo: (input) => invoke(CHANNELS.RUN_LOCAL_AUTHORIZATION_DEMO, input),
    preflightLocalWorkflow: () => invoke(CHANNELS.PREFLIGHT_REAL_LOCAL_AUTHORIZATION_WORKFLOW),
    startLocalWorkflow: (input) => invoke(CHANNELS.START_REAL_LOCAL_AUTHORIZATION_WORKFLOW, input),
    getWorkflow: (workflowId) => invoke(CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_WORKFLOW, { workflowId }),
    requestFreshAuth: (workflowId) => invoke(CHANNELS.REQUEST_REAL_LOCAL_AUTHORIZATION_FRESH_AUTH, { workflowId }),
    respondToApproval: (input) => invoke(CHANNELS.RESPOND_REAL_LOCAL_AUTHORIZATION_APPROVAL, input),
    cancelWorkflow: (input) => invoke(
      CHANNELS.CANCEL_REAL_LOCAL_AUTHORIZATION_WORKFLOW,
      typeof input === "string" ? { workflowId: input } : input
    ),
    getResult: (workflowId) => invoke(CHANNELS.GET_REAL_LOCAL_AUTHORIZATION_RESULT, { workflowId })
  }),
  routineAuthorization: Object.freeze({
    baseline: () => invoke(CHANNELS.ROUTINE_AUTHORIZATION_BASELINE, {}),
    begin: (action = "record_harmless_value") => invoke(CHANNELS.ROUTINE_AUTHORIZATION_BEGIN, {
      typedApplicationIntent: { action }
    }),
    status: (requestId) => invoke(CHANNELS.ROUTINE_AUTHORIZATION_STATUS, { requestId }),
    cancel: (requestId) => invoke(CHANNELS.ROUTINE_AUTHORIZATION_CANCEL, { requestId }),
    deleteDisposableProfile: (confirmation) => invoke(
      CHANNELS.ROUTINE_AUTHORIZATION_DELETE_DISPOSABLE_PROFILE,
      { confirmation }
    )
  }),
  sepoliaMint: Object.freeze({
    begin: () => invoke(CHANNELS.SEPOLIA_MINT_BEGIN),
    status: (requestId) => invoke(CHANNELS.SEPOLIA_MINT_STATUS, { requestId }),
    cancel: (requestId) => invoke(CHANNELS.SEPOLIA_MINT_CANCEL, { requestId })
  }),
  recovery: Object.freeze({
    runLocalDemo: (scenario, input = {}) => invoke(CHANNELS.RUN_RECOVERY_DEMO, { scenario, ...input }),
    enrollment: Object.freeze({
      preflight: (input) => invoke(CHANNELS.RECOVERY_ENROLLMENT_PREFLIGHT, input),
      status: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_STATUS),
      beginCredential: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_CREDENTIAL),
      beginDisposableDiagnostic: () => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_BEGIN_DISPOSABLE_DIAGNOSTIC
      ),
      cancelDisposableDiagnostic: () => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_CANCEL_DISPOSABLE_DIAGNOSTIC
      ),
      verifyDisposableRegistration: (registration) => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_REGISTRATION,
        { registration }
      ),
      verifyDisposableAssertion: (assertion) => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_VERIFY_DISPOSABLE_ASSERTION,
        { assertion }
      ),
      beginHardwareFallback: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_HARDWARE_FALLBACK),
      storeCredential: (input) => invoke(CHANNELS.RECOVERY_ENROLLMENT_STORE_CREDENTIAL, input),
      beginPairing: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_BEGIN_PAIRING),
      beginIPhonePairing: () => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_BEGIN_IPHONE_PAIRING
      ),
      iPhonePairingStatus: () => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_IPHONE_PAIRING_STATUS
      ),
      cancelIPhonePairing: () => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_CANCEL_IPHONE_PAIRING
      ),
      acceptPairing: (encodedRequest, credential) => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_ACCEPT_PAIRING,
        { encodedRequest, credential }
      ),
      completePairing: (encodedResponse, custodyDomainCommitment) => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_COMPLETE_PAIRING,
        { encodedResponse, custodyDomainCommitment }
      ),
      generateOffline: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_GENERATE_OFFLINE),
      revealOffline: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_REVEAL_OFFLINE),
      confirmOfflineExport: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_CONFIRM_OFFLINE_EXPORT),
      restoreOffline: (restorationInput) => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_RESTORE_OFFLINE,
        { restorationInput }
      ),
      reviewIndependence: (input) => invoke(CHANNELS.RECOVERY_ENROLLMENT_REVIEW_INDEPENDENCE, input),
      complete: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_COMPLETE),
      cancel: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_CANCEL),
      listPublicFactors: () => invoke(CHANNELS.RECOVERY_ENROLLMENT_LIST_PUBLIC_FACTORS),
      deleteFactor: (reference) => invoke(CHANNELS.RECOVERY_ENROLLMENT_DELETE_FACTOR, { reference }),
      rotateFactor: (reference, replacement) => invoke(
        CHANNELS.RECOVERY_ENROLLMENT_ROTATE_FACTOR,
        { reference, replacement }
      )
    }),
    transport: Object.freeze({
      begin: (bitmap) => invoke(CHANNELS.RECOVERY_TRANSPORT_BEGIN, { bitmap }),
      status: () => invoke(CHANNELS.RECOVERY_TRANSPORT_STATUS),
      beginRole0Assertion: () => invoke(CHANNELS.RECOVERY_TRANSPORT_BEGIN_ROLE0_ASSERTION),
      submitRole0Assertion: (assertion) => invoke(
        CHANNELS.RECOVERY_TRANSPORT_SUBMIT_ROLE0_ASSERTION,
        { assertion }
      ),
      cancel: () => invoke(CHANNELS.RECOVERY_TRANSPORT_CANCEL)
    })
  }),
  audit: Object.freeze({
    list: () => invoke(CHANNELS.LIST_AUDIT_EVENTS)
  }),
  settings: Object.freeze({
    get: () => invoke(CHANNELS.GET_SETTINGS),
    update: (next) => invoke(CHANNELS.UPDATE_SETTINGS, next)
  }),
  diagnostics: Object.freeze({
    exportSanitized: () => invoke(CHANNELS.EXPORT_SANITIZED_DIAGNOSTICS),
    storage: () => invoke(CHANNELS.DIAGNOSE_STORAGE),
    identity: () => invoke(CHANNELS.DIAGNOSE_IDENTITY),
    vault: () => invoke(CHANNELS.DIAGNOSE_VAULT),
    platformAuth: () => invoke(CHANNELS.DIAGNOSE_PLATFORM_AUTH),
    keychain: () => invoke(CHANNELS.DIAGNOSE_KEYCHAIN),
    freshAuth: () => invoke(CHANNELS.DIAGNOSE_FRESH_AUTH)
  })
}));
