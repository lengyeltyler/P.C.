# PhilCore Technical Specification v1

## Accepted Step 1 Reconciliation

[Phil V1 Secure Identity Architecture](./PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
is the controlling exact contract for new V1 identity, recovery, authorization,
proof, adapter, and algorithm-agility implementation. The conceptual objects
below describe the current implementation baseline. Existing public root
fields, `ACTION_UNLOCK`, STWO proof fields, and Ethereum/Base objects remain
byte-stable compatibility or quarantined research surfaces and must not be
reinterpreted as the new architecture.

## 1. Technical Scope

Technical Specification v1 translates the accepted PhilCore architecture and functional specification into an engineering contract. It defines conceptual technical objects, interfaces, state machines, events, boundaries, and error categories needed to implement PhilCore without changing the accepted product model.

Source of truth:

- `docs/PHILCORE_CORE_BOUNDARY.md`
- `docs/PHILCORE_RUNTIME_LIFECYCLE.md`
- `docs/PHILCORE_FUNCTIONAL_SPEC_V1.md`
- `docs/PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md`

This specification covers:

- Runtime API conceptual interfaces
- Intent model
- Capability model
- User Session object
- Application manifest
- Adapter manifest
- Authorization package boundary
- Trust Manager boundary
- Device Vault boundary
- Audit event model
- Runtime state transitions
- Ethereum Net / Ethereum Adapter boundaries
- Error categories
- Event bus concepts
- Assurance levels
- Initial personas

This specification does not implement:

- new runtime code
- new contracts
- new proof schemas
- new mobile apps
- new browser extension
- new UI
- new multi-chain support
- AI permissions implementation

## 2. Core Technical Principles

- Applications create intents.
- Applications do not create authorizations.
- Applications call only PhilCore Runtime API.
- Runtime API is the sole application-facing interface.
- User Session coordinates runtime state but owns no secrets.
- Trust Manager evaluates trusted credentials/devices.
- Security Policy Engine evaluates whether an action is allowed.
- Authorization Engine creates bounded authorization packages only after approval.
- Proof System is invoked only when policy or adapter path requires it.
- Adapters execute approved packages only.
- Audit Log records security-relevant events.
- Device Vault protects local encrypted state.
- Identity Root remains `phil_secret -> identityRoot ->
  rootOwnerCommitment`, with existing `ownerCommitment` bytes retained as a
  compatibility alias; both derived root values are protected by default.
- Public relationships use pairwise scoped commitments.
- Device approval, identity/data recovery, and account authority use separate
  key classes and lifecycles.
- Routine capabilities and exceptional root proofs are distinct authorization
  classes; neither a proof nor device signature authorizes alone.
- All adapter actions bind the chain-agnostic authorization envelope.
- Algorithm and verifier identifiers are immutable and versioned.
- Ethereum Net is the first user-facing execution application.
- Ethereum Adapter is the first execution adapter.
- ERC-4337 Smart Accounts are the preferred Ethereum authority model.
- EOAs are compatibility paths.

## 3. Runtime API Interface

The PhilCore Runtime API is the sole application-facing interface into the Personal Security Operating System. Names below are conceptual and may later become TypeScript interfaces.

### `requestCapability`

Purpose: request a scoped application capability.

Caller: application.

Required inputs:

- `applicationId`
- `capabilityName`
- `scope`
- `requestedDuration`
- `reason`

Validation path:

- User Session
- Security Policy Engine
- Trust Manager when credential/device trust matters
- Audit Log

Possible outputs:

- granted capability
- scoped capability
- denial
- pending approval

Audit events:

- `capability_requested`
- `capability_granted`
- `capability_denied`
- `capability_revoked`

Failure cases:

- `runtime_locked`
- `session_expired`
- `policy_denied`
- `trust_denied`
- `unsupported_operation`

### `requestIntent`

Purpose: submit a user or application intent for evaluation.

Caller: application.

Required inputs:

- `requestingApplicationId`
- `intentType`
- `targetAdapter`
- `targetAccount`
- `targetResource`
- `payloadHash`
- `humanReadableSummary`
- `requestedCapabilities`
- `policyContext`

Validation path:

- User Session
- Security Policy Engine
- Trust Manager
- Audit Log

Possible outputs:

- created intent
- denied intent
- pending approval

Audit events:

- `intent_created`
- `intent_denied`

Failure cases:

- `invalid_intent`
- `capability_denied`
- `runtime_locked`
- `session_expired`

### `requestAuthorization`

Purpose: request bounded authorization for an approved intent.

Caller: Runtime API or approved application flow.

Required inputs:

- `intentId`
- `applicationId`
- `policyDecision`
- `trustDecision`
- `userApproval`
- `proofRequirement`

Validation path:

- Authorization Engine
- Security Policy Engine
- Trust Manager
- Proof System when required
- Audit Log

Possible outputs:

- authorization package
- denial
- proof-required response

Audit events:

- `authorization_requested`
- `authorization_created`
- `authorization_denied`

Failure cases:

- `policy_denied`
- `trust_denied`
- `proof_required`
- `proof_failed`
- `invalid_intent`

### `requestMessageSignature`

Purpose: request approval to sign a bounded message.

Caller: Ethereum Net or another future signing application.

Required inputs:

- `intentId`
- `applicationId`
- `targetAccount`
- `messageHash`
- `humanReadableSummary`
- `chainId`, when applicable

Validation path:

- Runtime API
- User Session
- Security Policy Engine
- Trust Manager
- Authorization Engine
- Adapter Layer
- Audit Log

Possible outputs:

- signed message result
- pending approval
- denial

Audit events:

- `intent_created`
- `authorization_created`
- `adapter_invocation_requested`
- `adapter_invocation_completed`
- `adapter_invocation_failed`

Failure cases:

- `capability_denied`
- `policy_denied`
- `trust_denied`
- `user_cancelled`
- `adapter_unavailable`

### `requestTransactionPreparation`

Purpose: prepare a transaction candidate without submitting it.

Caller: Ethereum Net.

Required inputs:

- `intentId`
- `targetAccount`
- `chainId`
- `to`
- `value`
- `payloadHash`
- `humanReadableSummary`

Validation path:

- Runtime API
- User Session
- Security Policy Engine
- Ethereum Adapter
- Audit Log

Possible outputs:

- prepared transaction
- estimated risk
- required approval level
- denial

Audit events:

- `intent_created`
- `adapter_invocation_requested`

Failure cases:

- `network_unavailable`
- `adapter_unavailable`
- `unsupported_operation`
- `invalid_intent`

### `requestTransactionSubmission`

Purpose: submit an approved transaction or user operation.

Caller: Ethereum Net.

Required inputs:

- `authorizationPackageId`
- `adapterExecutionPackage`
- `chainId`
- `targetAccount`
- `humanReadableSummary`

Validation path:

- Runtime API
- User Session
- Authorization Engine
- Ethereum Adapter
- Audit Log

Possible outputs:

- submitted transaction or UserOperation reference
- execution failure
- pending status

Audit events:

- `adapter_invocation_requested`
- `adapter_invocation_completed`
- `adapter_invocation_failed`

Failure cases:

- `invalid_authorization_package`
- `adapter_unavailable`
- `network_unavailable`
- `bundler_unavailable`
- `user_cancelled`

### `requestContractCall`

Purpose: request a bounded contract call.

Caller: Ethereum Net, NFT Manager App, or future application.

Required inputs:

- `intentId`
- `chainId`
- `targetAccount`
- `contractAddress`
- `callDataHash`
- `value`
- `humanReadableSummary`

Validation path:

- Runtime API
- Security Policy Engine
- Trust Manager
- Authorization Engine
- Proof System when required
- Ethereum Adapter
- Audit Log

Possible outputs:

- prepared contract call
- submitted contract call
- denial

Audit events:

- `intent_created`
- `authorization_created`
- `adapter_invocation_requested`
- `adapter_invocation_completed`

Failure cases:

- `policy_denied`
- `trust_denied`
- `proof_failed`
- `adapter_unavailable`
- `network_unavailable`

### `requestSmartAccountDeployment`

Purpose: deploy or initialize a PhilCore-controlled ERC-4337 Smart Account.

Caller: Ethereum Net.

Required inputs:

- `intentId`
- `chainId`
- `ownerCommitment`
- `deploymentSalt` or equivalent deployment context
- `policyContext`
- `humanReadableSummary`

Validation path:

- Runtime API
- User Session
- Security Policy Engine
- Trust Manager
- Authorization Engine
- Ethereum Adapter
- Audit Log

Possible outputs:

- deployment plan
- prepared UserOperation
- submitted UserOperation
- deployed Smart Account address
- denial

Audit events:

- `intent_created`
- `authorization_created`
- `adapter_invocation_requested`
- `adapter_invocation_completed`
- `adapter_invocation_failed`

Failure cases:

- `policy_denied`
- `trust_denied`
- `bundler_unavailable`
- `network_unavailable`
- `adapter_unavailable`

### `requestSessionKeyManagement`

Purpose: request creation, modification, or revocation of scoped session authority.

Caller: Ethereum Net or future application.

Required inputs:

- `intentId`
- `applicationId`
- `scope`
- `expiresAt`
- `constraints`
- `humanReadableSummary`

Validation path:

- Runtime API
- Security Policy Engine
- Trust Manager
- Authorization Engine
- Audit Log

Possible outputs:

- scoped session authority
- denial
- revocation result

Audit events:

- `intent_created`
- `capability_granted`
- `capability_revoked`

Failure cases:

- `policy_denied`
- `trust_denied`
- `unsupported_operation`
- `experimental_feature_disabled`

### `requestCredentialRotation`

Purpose: rotate from one trusted credential/device to another.

Caller: Recovery App, Settings, or Trust Manager-facing application flow.

Required inputs:

- `intentId`
- `oldCredentialId`
- `newCredentialDescriptor`
- `confirmation`
- `reason`

Validation path:

- Runtime API
- User Session
- Trust Manager
- Security Policy Engine
- Recovery Manager when applicable
- Audit Log

Possible outputs:

- rotation plan
- completed rotation
- denial
- anti-lockout warning

Audit events:

- `intent_created`
- `trust_credential_rotation_requested`
- `trust_credential_rotation_completed`

Failure cases:

- `trust_denied`
- `policy_denied`
- `recovery_required`
- `user_cancelled`

### `requestCredentialRevocation`

Purpose: revoke a trusted credential/device.

Caller: Recovery App, Settings, or Trust Manager-facing application flow.

Required inputs:

- `intentId`
- `credentialId`
- `confirmation`
- `reason`

Validation path:

- Runtime API
- Trust Manager
- Security Policy Engine
- Recovery Manager when applicable
- Audit Log

Possible outputs:

- revocation result
- denial
- anti-lockout warning

Audit events:

- `trust_credential_revocation_requested`
- `trust_credential_revoked`

Failure cases:

- `trust_denied`
- `policy_denied`
- `recovery_required`
- `user_cancelled`

### `requestEncryptedBackupExport`

Purpose: export an encrypted backup bundle.

Caller: Settings, Recovery App, or Audit Log App for audit-specific bundles.

Required inputs:

- `intentId`
- `backupType`
- `ownerCommitment`
- `encryptionContext`
- `humanReadableSummary`

Validation path:

- Runtime API
- Device Vault
- Security Policy Engine
- Trust Manager
- Audit Log

Possible outputs:

- encrypted backup bundle
- denial

Audit events:

- `encrypted_backup_export_requested`
- `encrypted_backup_exported`

Failure cases:

- `vault_unavailable`
- `policy_denied`
- `trust_denied`
- `user_cancelled`

### `requestRecoveryStart`

Purpose: begin recovery mode.

Caller: Recovery App.

Required inputs:

- `intentId`
- `ownerCommitment`
- `recoveryReason`
- `availableRecoveryFactors`

Validation path:

- Runtime API
- Recovery Manager
- Trust Manager
- Security Policy Engine
- Audit Log

Possible outputs:

- recovery session
- denial
- required recovery steps

Audit events:

- `recovery_started`

Failure cases:

- `trust_denied`
- `policy_denied`
- `vault_unavailable`

### `requestRecoveryApproval`

Purpose: approve or advance a recovery flow.

Caller: Recovery App.

Required inputs:

- `intentId`
- `recoveryId`
- `approvalFactor`
- `humanReadableSummary`

Validation path:

- Runtime API
- Recovery Manager
- Trust Manager
- Security Policy Engine
- Audit Log

Possible outputs:

- approved recovery step
- completed recovery
- denial

Audit events:

- `recovery_approved`
- `recovery_completed`

Failure cases:

- `recovery_required`
- `trust_denied`
- `policy_denied`
- `user_cancelled`

### `requestAuditReview`

Purpose: review, search, filter, export, or verify audit events.

Caller: Audit Log App.

Required inputs:

- `applicationId`
- `query`
- `filters`
- `exportRequest`, when applicable

Validation path:

- Runtime API
- Audit Log
- Security Policy Engine for sensitive exports
- Device Vault for encrypted data access

Possible outputs:

- audit event list
- redacted audit details
- encrypted audit bundle
- denial

Audit events:

- `audit_review_requested`
- `audit_export_requested`
- `audit_export_completed`

Failure cases:

- `runtime_locked`
- `vault_unavailable`
- `policy_denied`

### `requestScopedAgentPermission`

Purpose: future-only request for scoped AI or automation permission.

Caller: Future AI Permissions App.

Required inputs:

- `intentId`
- `agentId`
- `scope`
- `constraints`
- `expiresAt`
- `humanReadableSummary`

Validation path:

- Runtime API
- User Session
- Security Policy Engine
- Trust Manager
- Authorization Engine
- Audit Log

Possible outputs:

- scoped permission
- denial

Audit events:

- `future_ai_permission_requested`
- `future_ai_permission_granted`
- `future_ai_permission_revoked`

Failure cases:

- `experimental_feature_disabled`
- `policy_denied`
- `trust_denied`
- `unsupported_operation`

## 4. Intent Model

An Intent represents:

```text
The user wants to perform a bounded action.
```

An intent is not an authorization and cannot be executed directly.

Conceptual fields:

- `intentId`
- `createdAt`
- `expiresAt`
- `requestingApplicationId`
- `actorType`
- `intentType`
- `targetAdapter`
- `targetAccount`
- `targetResource`
- `chainId`, when applicable
- `value`, when applicable
- `payloadHash`
- `humanReadableSummary`
- `requestedCapabilities`
- `policyContext`
- `requiredTrustLevel`
- `proofRequirement`
- `status`
- `auditCorrelationId`

Intent statuses:

- `created`
- `pending_policy`
- `pending_trust`
- `pending_user_approval`
- `pending_proof`
- `approved`
- `denied`
- `expired`
- `cancelled`
- `submitted`
- `completed`
- `failed`

Status progression should be append-only in audit terms even if the current runtime object mutates its latest status.

## 5. Capability Model

A Capability is a scoped permission granted by PhilCore to an application.

Conceptual fields:

- `capabilityId`
- `capabilityName`
- `applicationId`
- `scope`
- `grantedAt`
- `expiresAt`
- `revokedAt`
- `status`
- `constraints`
- `auditPolicy`
- `requiredTrustLevel`
- `proofRequirement`

Capability statuses:

- `requested`
- `granted`
- `denied`
- `scoped`
- `expired`
- `revoked`

Examples:

Ethereum Net:

- `read_balance`
- `view_transactions`
- `view_nfts`
- `request_message_signature`
- `request_transaction_preparation`
- `request_transaction_submission`
- `request_contract_call`
- `request_smart_account_deployment`
- `request_session_key_management`

NFT Manager App:

- `view_nfts`
- `read_metadata`
- `request_mint_preparation`
- `request_mint_submission`
- `request_transfer_preparation`
- `request_transfer_submission`

Recovery App:

- `view_recovery_state`
- `request_recovery_start`
- `request_recovery_approval`
- `request_recovery_completion`
- `request_trust_credential_rotation`
- `request_trust_credential_revocation`

Audit Log App:

- `view_audit_events`
- `request_encrypted_audit_bundle_export`
- `request_audit_integrity_verification`

Future AI Permissions App:

- `request_scoped_permission`
- `draft_action`
- `request_user_approval`
- `request_limited_action_execution`
- `request_agent_permission_revocation`

## 6. User Session Model

User Session is runtime coordination state. It owns no secrets and references controlled runtime capabilities.

Conceptual fields:

- `sessionId`
- `ownerCommitment`
- `startedAt`
- `lastActiveAt`
- `lockState`
- `activeApplications`
- `activeCapabilities`
- `pendingIntents`
- `pendingApprovals`
- `currentPolicyMode`
- `trustStateSummary`
- `recoveryState`
- `timeoutPolicy`

Lock states:

- `locked`
- `partially_unlocked`
- `unlocked`
- `recovery_mode`
- `suspended`
- `expired`

User Session must not expose:

- `phil_secret`
- raw vault keys
- raw private keys
- unrestricted signing authority
- unrestricted adapter authority
- unrestricted wallet authority

## 7. Application Manifest

Every PhilCore application should declare a conceptual manifest.

Fields:

- `applicationId`
- `displayName`
- `version`
- `requestedCapabilities`
- `requiredAdapters`
- `supportedIntentTypes`
- `sensitiveSurfaces`
- `auditCategories`
- `defaultPolicyHints`
- `experimentalFlag`

Example: Ethereum Net

- `applicationId`: `ethereum_net`
- `requestedCapabilities`: balance reads, transaction preparation/submission, message signatures, contract calls, Smart Account deployment
- `requiredAdapters`: Ethereum Adapter
- `supportedIntentTypes`: Ethereum transaction, message signature, contract call, Smart Account deployment
- `experimentalFlag`: false for core local flows; true for features that rely on not-yet-production paths

Example: NFT Manager App

- requests NFT read, metadata, mint, and transfer capabilities
- requires Ethereum Adapter for Ethereum/Base NFTs

Example: Recovery App

- requests recovery and trust-management capabilities
- requires Recovery Manager and Trust Manager paths

Example: Audit Log App

- requests audit review and encrypted export capabilities
- requires Audit Log and Device Vault access through Runtime API

## 8. Adapter Manifest

Every adapter should declare a conceptual manifest.

Fields:

- `adapterId`
- `adapterType`
- `supportedNetworks`
- `supportedIntentTypes`
- `requiredCapabilities`
- `executionMethods`
- `riskLevel`
- `proofRequirements`
- `auditCategories`
- `productionReadiness`

Adapters are internal execution/protocol boundaries and do not define identity.

Example: Ethereum Adapter

- `adapterId`: `ethereum`
- `adapterType`: execution
- `supportedNetworks`: Ethereum-compatible networks; Base profile/config first
- `supportedIntentTypes`: transaction, message signature, contract call, Smart Account deployment
- `executionMethods`: ERC-4337 UserOperation, local no-send drills, future bundler submission
- `proofRequirements`: required where Base/proof fact path demands it

Example: Base profile/config

- profile/config under Ethereum Adapter
- not a separate adapter unless future complexity justifies it

Future Bitcoin Adapter and Future Solana Adapter:

- future-only
- no multi-chain implementation in v1

## 9. Authorization Package Boundary

An authorization package is a bounded runtime output produced after an intent passes policy, trust, user approval, and proof requirements where applicable.

Relationship:

```text
Intent
  -> policy decision
  -> trust decision
  -> user approval
  -> proof requirement
  -> Authorization package
  -> Adapter execution package
```

Adapters execute only approved adapter execution packages derived from authorization packages.

For Ethereum/Base, existing invariants are preserved:

- `ACTION_UNLOCK`
- `ownerCommitment`
- `actionHash`
- `policyHash`
- `nullifier`
- `consumerDataHash`
- `expiry`
- `proofInputHash`
- `proofType = "stwo-unlock-keccak-v1"`
- `[fact_high, fact_low]`

This specification does not change current proof or contract schemas.

## 10. Trust Manager Boundary

Trust Manager responsibilities:

- credential registry access through Device Vault
- active/revoked/pending/recovery-only/archived credential states
- trust evaluation
- credential rotation
- credential revocation
- recovery-only restrictions
- anti-lockout checks
- audit events

Trust Manager does not own `phil_secret`. It evaluates whether trusted credentials/devices can authorize runtime actions.

## 11. Device Vault Boundary

Device Vault responsibilities:

- encrypted local state
- vault metadata
- credential registry encrypted persistence
- backup import/export
- key lifecycle metadata
- owner binding
- integrity checks
- locked/unlocked behavior

Device Vault should not expose raw secrets to applications. Applications access vault-dependent operations only through PhilCore Runtime API and approved runtime paths.

## 12. Audit Event Model

Audit Event conceptual fields:

- `eventId`
- `timestamp`
- `eventType`
- `severity`
- `actorType`
- `applicationId`
- `sessionId`
- `intentId`
- `capabilityId`
- `adapterId`
- `ownerCommitment`
- `summary`
- `redactedDetails`
- `integrityLink`, future optional

Severity:

- `info`
- `notice`
- `warning`
- `critical`

Event categories:

- `runtime`
- `identity`
- `vault`
- `trust`
- `policy`
- `authorization`
- `proof`
- `adapter`
- `recovery`
- `application`
- `capability`
- `Ethereum`
- `future AI`

Audit events are local and encrypted by default where persisted.

## 13. Runtime State Transitions

First launch:

```text
no_identity -> runtime_initialized_locked -> identity_choice_pending
```

Identity creation:

```text
identity_choice_pending -> identity_creating -> vault_creating -> trust_bootstrap -> session_started
```

Unlock:

```text
locked -> unlock_requested -> trust_evaluated -> vault_unlocked -> session_unlocked
```

Lock:

```text
unlocked -> lock_requested -> sensitive_state_cleared -> locked
```

Suspend:

```text
unlocked -> suspend_requested -> sessions_paused -> suspended
```

Resume:

```text
suspended -> resume_requested -> trust_check -> unlocked | partially_unlocked
```

Timeout:

```text
unlocked -> inactive_timeout -> expired -> locked
```

Recovery start:

```text
unlocked_or_locked -> recovery_requested -> recovery_mode
```

Recovery approval:

```text
recovery_mode -> recovery_approval_pending -> recovery_approved
```

Recovery completion:

```text
recovery_approved -> trust_state_updated -> recovery_completed -> unlocked_or_locked
```

Application registration:

```text
application_discovered -> manifest_validated -> capabilities_requested -> application_registered
```

Capability grant/revocation:

```text
capability_requested -> policy_checked -> granted | denied | scoped
granted -> expired | revoked
```

Intent creation:

```text
intent_created -> pending_policy -> pending_trust -> pending_user_approval
```

Intent approval/denial:

```text
pending_user_approval -> approved | denied | cancelled | expired
```

Desktop protected-action approval projection:

```text
preparing -> awaiting_approval -> approved -> awaiting_user_presence -> executing -> completed
awaiting_approval -> rejected | cancelled | expired
awaiting_user_presence -> failed | cancelled
executing -> failed
```

Renderer state is a projection of Runtime state. The renderer may display a Runtime-generated presentation and send a decision for the exact digest, but it must not create an approval artifact, choose a target, mutate calldata, or hold reusable authority. Lock, restart, expiry, request mutation, and digest mismatch fail closed.

Proof-required action:

```text
approved -> pending_proof -> proof_generated | proof_failed
```

Adapter execution:

```text
authorization_created -> adapter_invocation_requested -> submitted -> completed | failed
```

Failure handling:

```text
any_pending_state -> failed | denied | cancelled | expired
```

## 14. Ethereum Net Technical Boundary

Ethereum Net is the user-facing Ethereum application.

It may:

- request Ethereum-related capabilities
- create Ethereum-related intents
- display approved Ethereum state
- request Smart Account deployment
- request transaction preparation
- request transaction submission
- request message signatures
- request contract calls

It must not:

- own private keys
- bypass Runtime API
- bypass policy/trust evaluation
- directly execute adapter calls
- become identity root

## 15. Ethereum Adapter Technical Boundary

Ethereum Adapter is the internal execution adapter.

It should handle:

- Ethereum/Base network configuration
- Base profile/config
- ERC-4337 UserOperation construction
- Smart Account deployment path
- Smart Account validation path
- bundler interaction
- Paymaster support where appropriate
- session artifacts
- proof fact payloads
- transaction receipts and execution status

It should not:

- define Phil identity
- receive `phil_secret`
- receive raw vault keys
- receive unrestricted signing authority
- treat EOAs as primary PhilCore authority

## 16. Error Categories

### `runtime_locked`

User-facing meaning: PhilCore is locked.

Technical meaning: User Session cannot grant sensitive capability while locked.

Audit severity: notice.

Expected recovery path: unlock PhilCore.

### `session_expired`

User-facing meaning: the active session timed out.

Technical meaning: User Session is expired and must be renewed.

Audit severity: notice.

Expected recovery path: re-unlock or resume session.

### `capability_denied`

User-facing meaning: the application is not allowed to do this.

Technical meaning: capability is missing, denied, expired, revoked, or insufficiently scoped.

Audit severity: notice or warning.

Expected recovery path: request capability or adjust policy.

### `policy_denied`

User-facing meaning: PhilCore policy blocked the action.

Technical meaning: Security Policy Engine denied the intent or authorization request.

Audit severity: warning.

Expected recovery path: review policy or request a different action.

### `trust_denied`

User-facing meaning: current device/credential trust is insufficient.

Technical meaning: Trust Manager denied the request.

Audit severity: warning.

Expected recovery path: use stronger credential, add trust, or recover.

### `user_cancelled`

User-facing meaning: the user cancelled the action.

Technical meaning: approval flow ended by user cancellation.

Audit severity: info.

Expected recovery path: restart intent if desired.

### `proof_required`

User-facing meaning: this action requires proof-backed authorization.

Technical meaning: Proof System must be invoked before authorization or execution.

Audit severity: notice.

Expected recovery path: generate or obtain required proof.

### `proof_failed`

User-facing meaning: required proof failed.

Technical meaning: proof generation, verification, or fact path failed.

Audit severity: warning or critical.

Expected recovery path: retry if safe, inspect proof path, or deny action.

### `adapter_unavailable`

User-facing meaning: execution adapter is unavailable.

Technical meaning: adapter cannot prepare or execute request.

Audit severity: warning.

Expected recovery path: retry later or use supported adapter path.

### `network_unavailable`

User-facing meaning: network is unavailable.

Technical meaning: adapter cannot reach required network.

Audit severity: notice.

Expected recovery path: reconnect or retry.

### `bundler_unavailable`

User-facing meaning: Smart Account submission service is unavailable.

Technical meaning: ERC-4337 bundler path cannot submit.

Audit severity: warning.

Expected recovery path: retry, switch endpoint, or hold pending.

### `vault_unavailable`

User-facing meaning: protected local state is unavailable.

Technical meaning: Device Vault cannot be loaded, unlocked, or authenticated.

Audit severity: critical when integrity-related.

Expected recovery path: unlock, restore backup, or enter recovery.

### `recovery_required`

User-facing meaning: recovery is required before continuing.

Technical meaning: ordinary trust path is unavailable or insufficient.

Audit severity: warning.

Expected recovery path: start or complete recovery.

### `invalid_intent`

User-facing meaning: the request is malformed or unsupported.

Technical meaning: intent object fails validation.

Audit severity: notice.

Expected recovery path: recreate intent with valid fields.

### `invalid_authorization_package`

User-facing meaning: authorization cannot be used.

Technical meaning: authorization package is malformed, expired, mismatched, or invalid.

Audit severity: warning.

Expected recovery path: recreate authorization from approved intent.

### `unsupported_operation`

User-facing meaning: PhilCore does not support this operation yet.

Technical meaning: requested operation is outside v1 support.

Audit severity: notice.

Expected recovery path: use supported flow.

### `experimental_feature_disabled`

User-facing meaning: experimental feature is disabled.

Technical meaning: feature flag or policy blocks the operation.

Audit severity: notice.

Expected recovery path: enable only in appropriate developer/experimental mode.

## 17. Event Bus Concepts

PhilCore may use a conceptual internal event bus to coordinate runtime services. This is not an implementation requirement yet.

Conceptual events:

- `runtime_started`
- `session_started`
- `session_locked`
- `session_unlocked`
- `identity_created`
- `vault_unlocked`
- `capability_requested`
- `capability_granted`
- `capability_denied`
- `intent_created`
- `intent_approved`
- `intent_denied`
- `authorization_created`
- `proof_requested`
- `proof_generated`
- `adapter_invocation_requested`
- `adapter_invocation_completed`
- `adapter_invocation_failed`
- `recovery_started`
- `recovery_completed`

Events should support audit correlation without exposing root secrets.

## 18. Assurance Levels

Assurance levels are conceptual policy inputs, not implemented policy code yet.

### Level 1 - Read-only / Low Risk

Examples:

- view balance
- view public Ethereum activity

### Level 2 - User Presence

Examples:

- unlock runtime
- view sensitive local settings

### Level 3 - User Verification

Examples:

- request message signature
- small transfer

### Level 4 - Strong Authorization

Examples:

- large transfer
- credential rotation
- Smart Account deployment
- encrypted backup export

### Level 5 - Recovery / Critical

Examples:

- recovery approval
- last credential revocation
- major policy change

## 19. Personas

### Everyday User

Primary needs:

- secure setup
- simple unlock
- Ethereum Net basics
- recovery confidence

Likely applications:

- Ethereum Net
- Recovery App
- Audit Log App
- Settings

Likely risk level:

- low to moderate, with occasional high-risk transfers.

Implications:

- defaults should be conservative
- developer mode hidden or off
- recovery prompts should be clear

### Power User

Primary needs:

- Smart Account control
- policy tuning
- multiple devices
- detailed audit

Likely applications:

- Ethereum Net
- NFT Manager App
- Audit Log App
- Settings

Likely risk level:

- moderate to high.

Implications:

- richer policy controls
- stronger trust options
- detailed audit review

### Developer

Primary needs:

- local fixtures
- no-send drills
- adapter diagnostics
- experimental feature testing

Likely applications:

- Ethereum Net
- Audit Log App
- Settings with developer mode

Likely risk level:

- high in test/dev contexts if confused with production.

Implications:

- developer mode must be clearly labeled
- test providers must be marked unsafe for production
- experimental paths must not weaken production identity

### Organization / Team

Primary needs:

- shared policy review
- controlled recovery
- audit export
- account administration

Likely applications:

- Ethereum Net
- Recovery App
- Audit Log App
- future organization policy tools

Likely risk level:

- high.

Implications:

- stronger assurance defaults
- careful recovery ceremonies
- encrypted audit export
- future multi-actor policy support

## 20. Non-Goals For v1

Technical Specification v1 does not attempt:

- multi-chain implementation
- AI-agent execution
- production mobile app
- production recovery ceremony
- remote policy server
- cloud custody
- seed-phrase-only identity model
- full post-quantum security claim
- direct control over existing MetaMask EOAs
- production mainnet launch without security review

## 21. Recommended First Implementation Milestone

Options:

A. Type-only/runtime-neutral SDK boundary index.

B. Runtime API skeleton types.

C. Intent and Capability TypeScript interfaces.

D. Documentation archive/index pass.

Recommendation: A. Type-only/runtime-neutral SDK boundary index.

Reasoning:

- It is the smallest behavior-preserving implementation step.
- It makes accepted architecture visible in the SDK without changing runtime behavior.
- It does not introduce new schemas, contracts, proof code, or execution paths.
- It can group existing exports under accepted product boundaries: Identity Root, Device Vault, Trust Manager, Authorization Engine, and Proof System.
- It creates a safe foundation for later TypeScript interfaces for Runtime API, Intent, Capability, User Session, manifests, and audit events.

The first implementation milestone should not change behavior. It should only expose existing code through a clearer architecture-aligned boundary.
