# PhilCore Runtime Lifecycle

## Accepted Step 1 Reconciliation

The exact V1 lifecycle boundaries are frozen in
[Phil V1 Secure Identity Architecture](./PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md).
It controls any conflict in this older conceptual lifecycle: the root and root
commitment are protected, public identities are scoped, identity/data recovery
is separate from account recovery, routine actions use narrow capabilities
plus device approval, and exceptional root operations additionally require an
admitted witness-hiding proof. Existing STWO and Ethereum/Base flows described
below are compatibility or quarantined research evidence until their later
ACP-0003 gates pass.

Step 1 made no runtime, schema, proof, device, or network change.

## 1. Product Frame

PhilCore is a Personal Security Operating System.

A running PhilCore instance starts from a private, user-owned identity root,
unlocks encrypted protected state, evaluates device trust and policy, issues
or evaluates scoped capabilities, and invokes isolated adapters without
exposing root or data-recovery secrets.

Ethereum/Base is the first real execution path. It is not the identity layer.

User-facing modules are applications. Chain, network, protocol, or execution-specific implementation modules are adapters.

Examples of applications:

- Ethereum Net
- NFT Manager App
- Recovery App
- Audit Log App
- Future AI Permissions App
- Future Bitcoin Wallet App
- Future Solana Wallet App

Examples of adapters:

- Ethereum Adapter
- Base profile/config under the Ethereum Adapter, unless a separate Base Adapter becomes justified later
- Future Bitcoin Adapter
- Future Solana Adapter
- Future AI/agent execution adapter, if needed

This document defines runtime behavior conceptually. It does not change application code, move modules, refactor files, change contracts, change proof code, change schemas, or alter behavior.

## 2. Runtime Boundary Diagram

```text
PhilCore Runtime
  -> User Session
      runtime coordination: active identity reference, vault state,
      trust state, capabilities, approvals, authorization sessions, timeouts

      -> Identity Layer
          -> Identity Root
              `phil_secret -> identityRoot -> ownerCommitment`
          -> Device Vault
              encrypted registry, key lifecycle, backups, local protected state
          -> Trust Manager
              credentials, devices, passkeys, hardware keys, recovery-only credentials

      -> Decision Layer
          -> Authorization Engine
              action requests, authorization packages, nullifiers, proof inputs
          -> Security Policy Engine
              local rules, credential strength, expiry, recovery constraints, app capabilities
          -> Proof System
              STARK/proof-backed authorization, proofInputHash, verified facts
          -> Recovery Manager
              recovery state, recovery credentials, stronger recovery flows

      -> Execution Layer
          -> Applications Layer
              -> Ethereum Net
              -> NFT Manager App
              -> Recovery App
              -> Audit Log App
              -> Future AI Permissions App
          -> PhilCore Runtime API
              controlled interface applications use to request PhilCore actions
          -> Adapter Layer
              -> Ethereum Adapter
                  -> Base profile/config
              -> Future Bitcoin Adapter
              -> Future Solana Adapter

      -> Audit Log
          encrypted local event history
```

Primary runtime flow:

```text
Application
  -> PhilCore Runtime API
  -> User Session
  -> Authorization Engine
  -> Security Policy Engine
  -> Trust Manager
  -> Proof System when required
  -> Adapter Layer
  -> Audit Log
```

User Session does not own secrets; it coordinates runtime state. Identity Root remains the identity boundary. Device Vault remains the protected storage boundary. Applications and adapters must not bypass PhilCore Runtime API, Authorization Engine, or Security Policy Engine for sensitive operations.

## 3. Runtime Layers

PhilCore has three runtime layers.

### Layer 1 - Identity Layer

Answers: "Who are you?"

Includes:

- Identity Root
- Device Vault
- Trust Manager

The Identity Layer establishes local user-owned identity, protects local secrets, and evaluates trusted credentials/devices. Ethereum/Base does not belong in this layer.

### Layer 2 - Decision Layer

Answers: "Should this happen?"

Includes:

- Authorization Engine
- Security Policy Engine
- Proof System
- Recovery Manager

The Decision Layer evaluates action requests, local policy, credential trust, recovery state, and proof requirements.

### Layer 3 - Execution Layer

Answers: "How does it happen?"

Includes:

- Applications Layer
- Adapter Layer
- Ethereum Net
- NFT Manager App
- Ethereum Adapter
- Base profile/config
- future applications
- future adapters

Ethereum/Base belongs in the Execution Layer, not the Identity Layer.

## 4. User Session

User Session is a runtime coordination boundary for an unlocked or partially unlocked PhilCore instance.

It may track:

- active identity
- vault unlock state
- trust state
- current policy mode
- active applications
- active capabilities
- pending approvals
- active authorization sessions
- lock/suspend timeout state

It must not own or expose:

- `phil_secret`
- raw vault keys
- raw private keys
- unrestricted signing authority
- unrestricted adapter authority

The Device Vault remains the protected storage boundary. Identity Root remains the identity boundary. User Session is runtime state only.

## 5. Capability Model

Applications request narrowly scoped capabilities from PhilCore. They do not receive broad authority.

Capabilities may be:

- granted
- denied
- scoped
- expired
- revoked
- audited

Sensitive capabilities must pass through Authorization Engine and Security Policy Engine. Trust Manager approval is required where credential/device trust matters. Proof-backed authorization is required where policy or adapter execution demands it.

Applications must never receive:

- `phil_secret`
- vault keys
- raw private keys
- unrestricted signing authority
- unrestricted wallet authority

Example Ethereum Net capabilities:

- `read_balance`
- `view_transactions`
- `view_nfts`
- `request_message_signature`
- `request_transaction_preparation`
- `request_transaction_submission`
- `request_contract_call`
- `request_smart_account_deployment`
- `request_session_key_management`

Example NFT Manager App capabilities:

- `view_nfts`
- `read_metadata`
- `request_mint_preparation`
- `request_mint_submission`
- `request_transfer_preparation`
- `request_transfer_submission`

Example Recovery App capabilities:

- `view_recovery_state`
- `request_recovery_start`
- `request_recovery_approval`
- `request_recovery_completion`
- `request_trust_credential_rotation`
- `request_trust_credential_revocation`

Example Audit Log App capabilities:

- `view_audit_events`
- `request_encrypted_audit_bundle_export`
- `request_audit_integrity_verification`

Example Future AI Permissions App capabilities:

- `request_scoped_permission`
- `draft_action`
- `request_user_approval`
- `request_limited_action_execution`
- `request_agent_permission_revocation`

## 6. Intent Model

Applications should not create authorizations. Applications create intents.

An Intent represents:

```text
The user wants to perform a bounded action.
```

Example flow:

```text
Ethereum Net
  -> Create Intent
  -> PhilCore Runtime API
  -> User Session
  -> Trust Manager
  -> Security Policy Engine
  -> Authorization Engine
  -> Proof System when required
  -> Execution Adapter
  -> Audit Log
```

Applications create intents. The Runtime API evaluates intents. Authorization Engine converts approved intents into bounded authorization packages. Adapters execute only approved authorization packages.

Future AI agents, automation, scheduled actions, delayed approvals, and delegated workflows should also produce intents rather than directly requesting execution.

## 7. PhilCore Runtime API

PhilCore Runtime API is the controlled interface applications use to request PhilCore actions.

The PhilCore Runtime API is the sole application-facing interface into the Personal Security Operating System.

Applications call the Runtime API. Applications should not call Trust Manager, Device Vault, Proof System, or Adapters directly for sensitive operations.

Applications should never communicate directly with:

- Device Vault
- Trust Manager
- Proof System
- Authorization Engine
- Security Policy Engine
- Recovery Manager
- Execution Adapters

except through the Runtime API.

The Runtime API routes requests through:

- User Session
- Authorization Engine
- Security Policy Engine
- Trust Manager
- Proof System when required
- Adapter Layer when execution is approved
- Audit Log

Conceptual request surfaces include:

- `requestCapability`
- `requestAuthorization`
- `requestSignature`
- `requestTransactionPreparation`
- `requestTransactionSubmission`
- `requestContractCall`
- `requestSmartAccountDeployment`
- `requestCredentialRotation`
- `requestCredentialRevocation`
- `requestEncryptedBackupExport`
- `requestRecoveryStart`
- `requestRecoveryApproval`
- `requestAuditReview`
- `requestScopedAgentPermission`, future only

These are conceptual API surfaces only. They should not be implemented yet as part of this architecture update.

The Runtime API must never expose:

- `phil_secret`
- raw vault keys
- raw private keys
- unrestricted signing authority
- unrestricted adapter authority
- unrestricted wallet authority

## 8. Boot Lifecycle

When PhilCore starts, it should:

1. Initialize the runtime shell without loading root secrets into application space.
2. Locate local vault metadata and encrypted registry records.
3. Load minimal public metadata such as known `ownerCommitment`, encrypted registry metadata, vault version, and application registrations.
4. Initialize Trust Manager in a locked or limited state.
5. Initialize Authorization Engine and Security Policy Engine with no sensitive capabilities granted yet.
6. Initialize Applications Layer with capability descriptors, not root access.
7. Initialize Adapter Layer with configuration only, such as Ethereum/Base network profiles, contract addresses, and local session settings.
8. Initialize Audit Log in encrypted or locked-read mode.

At boot, applications may render public or cached metadata that is safe to show before unlock. They should not receive `phil_secret`, raw private keys, vault keys, or decrypted credential registry state.

## 9. Unlock Lifecycle

Unlocking PhilCore means unlocking the Device Vault and making runtime identity authority available through controlled interfaces.

The unlock flow should:

1. Ask the user for the required local unlock factor.
2. Resolve or derive the vault encryption key through the configured key provider.
3. Decrypt and authenticate the encrypted vault/registry state.
4. Validate owner binding against the expected `ownerCommitment`.
5. Validate identity-root hash references where present.
6. Load credential, recovery, key lifecycle, and audit state into protected runtime memory.
7. Expose only controlled runtime capabilities to applications.

The Identity Root becomes available as authority, not as raw secret material.

Preserved invariant:

```text
phil_secret -> identityRoot -> ownerCommitment
```

`phil_secret` must not be handed to applications, adapters, logs, contracts, bridge payloads, backups in plaintext, or ordinary UI code. Applications should work with public identity metadata, capability handles, authorization results, and signed/proven action packages.

## 10. Trust Manager Lifecycle

Trust Manager is the accepted product-facing framing for credentials, devices, passkeys, and other trust-bearing authorization factors.

Trust Manager owns runtime trust state for:

- passkeys
- platform credentials
- hardware security keys
- local dev credentials
- future Secure Enclave credentials
- future mobile secure hardware credentials
- recovery-only credentials
- revoked or archived credentials

At runtime, Trust Manager should:

1. Load credential registry state from the unlocked Device Vault.
2. Classify credentials by status: active, pending, revoked, recovery-only, archived.
3. Evaluate which credentials may authorize ordinary actions.
4. Evaluate which credentials may participate only in recovery.
5. Track sign counters, device metadata, provider kind, and credential priority.
6. Support rotation as overlap, not destruction.
7. Require explicit confirmation for destructive actions.
8. Emit audit events for trust changes.

Active credentials may authorize ordinary actions. Recovery-only credentials are reserved for recovery flows. Revoked, archived, pending, and recovery-only credentials must not silently authorize ordinary application actions.

WebAuthn/passkey work remains preserved. WebAuthn credentials authorize Phil actions but do not become the Phil identity root.

## 11. Application Registration Lifecycle

Applications are user-facing modules that request capabilities from the runtime.

Examples:

- Ethereum Net
- NFT Manager App
- Recovery App
- Audit Log App
- Future AI Permissions App
- Future Bitcoin Wallet App
- Future Solana Wallet App

An application registration should declare:

- application id
- display name
- requested capabilities
- required adapters
- action types it may request
- policy constraints
- sensitive UI surfaces
- audit categories

Applications should request capabilities. They should not receive root secrets.

Applications must not:

- access `phil_secret`
- access raw vault keys
- access raw private keys
- bypass PhilCore Runtime API for sensitive operations
- bypass Authorization Engine
- bypass Security Policy Engine
- call adapters directly for sensitive execution
- mutate Trust Manager state without authorization
- export encrypted backups without policy approval

Applications receive capability handles and authorization APIs. The runtime decides whether a request is allowed.

## 12. Adapter Invocation Lifecycle

Adapters are internal execution/protocol boundaries used by applications.

The intended path is:

```text
Ethereum Net
  -> PhilCore Runtime API
  -> User Session
  -> Authorization Engine
  -> Security Policy Engine
  -> Proof System if required
  -> Ethereum Adapter
  -> Ethereum/Base execution
```

Applications should not call adapters directly for sensitive actions. They submit action requests to PhilCore Runtime API. The Runtime API routes through User Session, Authorization Engine, Security Policy Engine, Trust Manager, and Proof System as needed. Only after approval should an adapter receive the minimum execution package it needs.

In the Desktop Local Alpha, Home and Ethereum expose one normal **Test a protected action** path. This path uses the same Runtime operation as Developer diagnostics and remains a local-only proof of the lifecycle: request, trust, policy, digest-bound approval, fresh user presence where required, proof generation/verification, Device Vault signing, local ERC-4337 fixture execution, and audit projection. Developer mode is a diagnostic view over the same operation, not a bypass.

For Ethereum/Base, the adapter may handle:

- chain id
- Base profile/config
- contract addresses
- wallet/smart-account artifacts
- user operation construction
- signer payload digest handling
- bundler submission payloads
- proof fact payloads
- receipt and status data in future milestones

The adapter should not receive `phil_secret` or broad vault authority.

## 13. Authorization Request Lifecycle

A sensitive action should follow this general flow:

```text
Application request
  -> intent creation
  -> PhilCore Runtime API
  -> User Session
  -> action normalization
  -> policy evaluation
  -> trust evaluation
  -> user confirmation when required
  -> proof generation or proof fact check when required
  -> adapter execution package
  -> execution attempt
  -> audit event
```

Examples of sensitive actions:

- sending ETH
- minting an NFT
- signing a message
- adding a credential
- rotating a credential
- revoking a credential
- exporting an encrypted backup
- importing an encrypted backup
- approving future AI-agent permissions

The request should include:

- requesting application
- requested action
- target adapter, if any
- target account or resource
- value or data payload
- policy context
- expiry
- required credential strength
- recovery state constraints
- audit category

Authorization Engine should convert approved intents into bounded authorization results. For the current Ethereum/Base path, this includes the preserved `ACTION_UNLOCK` and `proofInputHash` shape where applicable.

## 14. Proof-Backed Authorization Lifecycle

Proof-backed authorization is required when the action must be backed by a cryptographic proof of the locked authorization statement or when an adapter/contract expects a verified `proofInputHash` fact.

Required:

- Base-side proof/fact-gated actions that consume the locked tuple.
- Actions that rely on `proofType = "stwo-unlock-keccak-v1"`.
- Actions that require a verified `proofInputHash` to be mirrored or anchored.

Optional:

- Local-only previews.
- Local dry-run/session construction.
- UI readiness checks.
- Some application-level policy checks before execution.

Not yet production-ready:

- Full public Starknet proof verification through a deployed verifier and live L1/Base bridge.
- Production trustless external proof relay.
- Direct Base verification of the frozen raw STWO proof boundary.
- Claims of full post-quantum security.

Preserved proof invariants:

- `ACTION_UNLOCK`
- public input tuple
- `proofInputHash`
- `proofBlob` artifact slot
- `proofType = "stwo-unlock-keccak-v1"`
- `[fact_high, fact_low]`
- current STARK/proof work

The Proof System supports PhilCore's authorization model. It is not the identity layer and not the whole product.

## 15. Lock/Suspend Lifecycle

When PhilCore locks, sleeps, times out, or closes, it should:

1. Stop granting new sensitive capabilities.
2. Clear decrypted vault plaintext from ordinary runtime access.
3. Clear transient authorization sessions.
4. Clear or invalidate proof witnesses and local signing payloads.
5. Keep only safe public metadata available.
6. Preserve encrypted vault state.
7. Persist audit events before lock when possible.
8. Require re-unlock before sensitive actions resume.

Applications may remain visible in a locked or limited mode, but they should not be able to invoke sensitive adapters, request root-derived authorizations, export backups, or mutate trust state until the runtime is unlocked again.

Adapters should treat lock as cancellation or suspension of pending sensitive execution unless an explicitly approved runtime policy says otherwise.

## 16. Recovery Lifecycle

Recovery mode is a runtime state, not a separate identity.

Recovery Manager should coordinate:

- recovery-pending state
- recovery approval
- recovery completion
- recovery-only credentials
- stronger-than-ordinary-authentication requirements
- anti-lockout warnings
- recovery audit events

Recovery mode should restrict ordinary application actions when necessary. For example, a Recovery App may be allowed to request recovery-specific capabilities, while Ethereum Net actions may be limited until recovery completes or is cancelled.

Recovery must not expose `phil_secret`. Recovery should preserve identity continuity:

```text
same Phil identity root
  -> updated trusted credentials
  -> continued controlled authorization
```

Current recovery is framework-first and local. Social recovery committees, production hardware recovery ceremonies, remote recovery services, and root rotation policies should not be implemented yet.

## 17. Audit Lifecycle

Audit Log should record local security-relevant events and encrypt them by default.

Events to record include:

- boot
- unlock success
- unlock failure
- lock/suspend
- vault load
- vault save
- vault tamper detection
- encrypted backup export
- encrypted backup import
- credential added
- credential rotated
- credential revoked
- credential archived
- credential marked recovery-only
- recovery started
- recovery approved
- recovery completed
- application registered
- capability requested
- capability denied
- intent created
- intent approved
- intent rejected
- sensitive authorization requested
- sensitive authorization approved
- sensitive authorization rejected
- proof requested
- proof generated
- proof verification/fact status observed
- adapter invocation requested
- adapter invocation submitted
- adapter invocation failed
- adapter invocation completed
- future AI permission requested
- future AI permission approved or revoked

Audit events may contain sensitive metadata. They should remain local and encrypted by default. The current audit model is immutable-style local state, not yet a tamper-proof replicated log, public record, or telemetry service.

The Audit Log App is user-facing. Audit persistence and event production are runtime/internal services.

## 18. Ethereum Authority Model

PhilCore's preferred Ethereum authority model is ERC-4337 Account Abstraction using PhilCore-controlled Smart Accounts.

Externally Owned Accounts are compatibility paths.

Existing EOAs may:

- connect to PhilCore
- be monitored
- fund PhilCore accounts
- migrate assets into PhilCore accounts
- participate in interoperability

PhilCore cannot become mandatory final authority over an ordinary EOA while that EOA's private key remains the controlling signer.

PhilCore-generated EOAs may exist for compatibility, but they should not become the preferred architecture.

PhilCore Smart Accounts are the primary long-term Ethereum account model. They should be capable of requiring PhilCore authorization before execution while preserving:

- `ACTION_UNLOCK`
- `proofInputHash`
- proof public input tuple
- proof-backed authorization semantics

The Ethereum Adapter should evolve around:

- ERC-4337 `UserOperation` construction
- Smart Account deployment
- Smart Account validation
- session handling
- bundler interaction
- Paymaster support where appropriate
- future modular validation
- Ethereum/Base execution

This authority model does not change existing proof, identity, schema, contract, or runtime invariants.

## 19. Ethereum-First Runtime Path

Ethereum is the first real execution environment because current repo work already includes:

- Base authorization contracts
- Base action gate
- mirrored proof-input-hash fact verifier
- L1 trust anchor
- L1-to-Base relay modeling
- mint-pass consumer
- unlock consumer
- wallet artifacts
- smart-account deploy/session artifacts
- local bundler stub
- local no-send deploy-session matrix
- local device-signing integration

Runtime framing:

```text
Ethereum Net
  -> PhilCore Runtime API
  -> User Session
  -> Authorization Engine
  -> Security Policy Engine
  -> Trust Manager
  -> Proof System when required
  -> Ethereum Adapter
      -> Base profile/config
      -> Base contracts
      -> smart-account/session flow
```

Ethereum Net is the user-facing application. Ethereum Adapter is the internal execution adapter. Ethereum/Base remains downstream of Phil identity. Ethereum accounts, EOAs, smart accounts, and wallet artifacts are controlled applications/modules under PhilCore. They are not the root Phil identity.

Base should remain a profile/config under Ethereum Adapter unless a separate Base Adapter becomes justified by complexity.

## 20. Runtime Platforms

PhilCore should be framed as a trusted security control surface on:

- native iOS
- native Android
- desktop
- browser extension

A Progressive Web App may be considered later only if the security model remains acceptable.

PhilCore is not a privileged operating-system overlay. It receives requests, evaluates trust and policy, authorizes actions, and invokes execution adapters.

## 21. Future Multi-Application / Multi-Adapter Path

Future applications can plug into PhilCore without changing Identity Root.

Possible future applications:

- Bitcoin Wallet App
- Solana Wallet App
- SSH Key App
- PGP Signing App
- Document Signing App
- AI Permissions App
- Recovery App
- Audit Log App
- NFT Manager App

Possible future adapters:

- Bitcoin Adapter
- Solana Adapter
- SSH Adapter
- PGP Adapter
- document signing adapter
- AI/agent execution adapter, if needed

The integration pattern should remain:

```text
Application
  -> Intent
  -> PhilCore Runtime API
  -> User Session
  -> Authorization Engine
  -> Security Policy Engine
  -> Trust Manager
  -> Proof System when required
  -> Adapter
```

Future adapters should not require changing:

- `phil_secret -> identityRoot -> ownerCommitment`
- Device Vault root model
- Trust Manager semantics
- Authorization Engine invariants
- Audit Log expectations

Multi-chain support should not be introduced yet. The current design should merely avoid making Identity Root depend on Ethereum/Base.

## 22. Recommended Smallest Next Code Milestone

The smallest next code milestone should be a no-behavior-change terminology and export-boundary pass.

Recommended milestone:

```text
Add a type-only/runtime-neutral SDK boundary index that groups existing exports under accepted product names.
```

Suggested groups:

- Identity Root
- Device Vault
- Trust Manager
- Authorization Engine
- Proof System

This milestone should not:

- move files
- refactor modules
- change runtime behavior
- change contracts
- change proof schemas
- change `ACTION_UNLOCK`
- change `proofInputHash`
- introduce multi-chain support
- implement applications
- implement new adapters
- implement AI permissions

The pass should be small enough that existing tests prove behavior is unchanged. It should primarily make the accepted architecture visible in code organization without changing how PhilCore works.
