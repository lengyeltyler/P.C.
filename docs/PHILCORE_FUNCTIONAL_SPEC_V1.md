# PhilCore Functional Specification v1

## Accepted Step 1 Reconciliation

The user-facing security model in
[Phil V1 Secure Identity Architecture](./PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
is accepted under ACP-0003. It controls conflicts in this earlier functional
description: the canonical root is private, each relationship receives a
scoped public identity, encrypted identity/data continuity is user-recoverable,
devices are replaceable approval factors, applications and agents receive
narrow capabilities, and networks are adapters rather than identity owners.

All implementation descriptions below remain current-state or compatibility
descriptions, not claims that Step 1 implemented the accepted target.

## 1. Product Goals

PhilCore is a Personal Security Operating System. From a user's perspective, PhilCore should make high-value digital actions safer, clearer, and more recoverable without forcing the user to manage raw secrets directly.

Primary goals:

- Give the user a private, device-first identity root that survives device
  replacement without becoming a device key.
- Protect identity continuity and user data with separate encrypted key
  classes and a portable recovery package.
- Let the user decide which devices, passkeys, and credentials are trusted.
- Make sensitive actions explicit, bounded, and auditable.
- Let applications create intents instead of directly controlling authority.
- Let PhilCore evaluate trust, policy, and proof requirements before execution.
- Make Ethereum usable through PhilCore-controlled Smart Accounts, with EOAs treated as compatibility paths.
- Preserve user-controlled identity/data recovery without exposing root
  secrets or conflating it with account-validator recovery.
- Give each network, app, credential relationship, persona, and agent a scoped
  public identity instead of one universal correlation handle.
- Prepare for future applications such as Bitcoin, Solana, SSH, PGP, document signing, and AI permissions without changing the identity model.

The user should understand PhilCore as the place where identity, trust, policy, authorization, recovery, and audit come together.

## 2. First Launch Experience

On first launch, no PhilCore identity exists.

The runtime should explain that PhilCore can create a local identity root on the user's device and protect it with local trust factors such as passkeys, device credentials, PINs, or hardware keys. It should make clear that PhilCore identity is not the same as an Ethereum wallet, an EOA, or a browser wallet account.

The user should be offered clear choices:

- Create a new PhilCore identity.
- Restore an existing PhilCore identity.
- Enter recovery for an existing identity.
- Explore in a limited mode if supported, without creating authority.

The runtime should ask only necessary questions:

- Is this a new identity or an existing one?
- Which local unlock method should protect this device?
- Should this device become a trusted device?
- Should an encrypted backup or recovery method be configured now or later?
- Should Ethereum Net be prepared now or skipped until later?

Internally, first launch initializes a locked runtime shell, prepares application registration metadata, and waits for the user to create, restore, or recover identity authority. No application receives root secrets. No adapter has execution authority before the runtime is initialized and the user has approved the relevant path.

The user should understand:

- PhilCore will protect a local identity root.
- Losing all trusted credentials may require recovery.
- Applications request permission; they do not receive unrestricted authority.
- Ethereum/Base is available as the first execution environment, but it does not define PhilCore identity.

## 3. Existing Identity

A user who already has a PhilCore identity should be able to restore, import, migrate, or recover depending on what material they possess.

Restore means the user has an encrypted backup or vault bundle and the required unlock/recovery material. PhilCore should authenticate the backup, verify that it belongs to the expected public identity anchor, and restore local runtime state without exposing root secrets to applications.

Import means the user brings in an encrypted PhilCore artifact, such as a vault backup, trust registry, or audit bundle. PhilCore should validate ownership, format, integrity, and policy before accepting it.

Migration means the user is moving PhilCore to a new device while still having access to an existing trusted device or credential. The experience should favor overlap: add the new device, verify it, make it trusted, then optionally retire the old device.

Recovery means ordinary trusted access is unavailable or insufficient. PhilCore should enter a restricted recovery mode, explain the consequences, require stronger recovery conditions, and limit unrelated application actions until recovery is completed or cancelled.

## 4. Identity Creation Flow

Identity creation should feel deliberate and understandable.

The flow should:

1. Explain that PhilCore will create a local identity root.
2. Ask the user to choose initial trust factors.
3. Create the local PhilCore identity.
4. Create the Device Vault.
5. Initialize Trust Manager with the first trusted credential or device.
6. Initialize Recovery Manager state.
7. Initialize Audit Log state.
8. Start a User Session.
9. Register default applications such as Ethereum Net, Recovery, Audit, and Settings.

What is created:

- A PhilCore identity rooted in `phil_secret -> identityRoot -> ownerCommitment`.
- A protected Device Vault.
- Initial Trust Manager state.
- Initial recovery state.
- Initial local audit history.
- A runtime session for the active identity.

Confirmations should occur before:

- Creating the identity root.
- Trusting the first credential/device.
- Creating or exporting encrypted backups.
- Enabling Ethereum Net account creation.
- Creating the first Smart Account.

The runtime becomes active only after the identity root exists, the vault is created and unlocked, and at least one valid trust path exists.

## 5. Unlock Flow

Normal unlock lets the user open PhilCore using an approved trust factor. After unlock, PhilCore starts or resumes a User Session, loads protected runtime state, and makes controlled capabilities available through the Runtime API.

Biometric unlock may be used when the platform credential is trusted and policy allows it. The user should understand whether biometric unlock is convenience unlock, high-assurance approval, or both.

Passkey unlock uses a registered credential to authenticate the user and authorize access to PhilCore runtime state.

PIN unlock may be allowed as a local factor, but sensitive actions may still require stronger trust depending on policy.

Hardware key unlock should require the physical key and any required user verification. Hardware keys may be ordinary trusted credentials or recovery-only credentials depending on how they were registered.

Recovery unlock is a restricted path. It should not behave like normal unlock. It should make recovery actions available while limiting unrelated sensitive actions.

Timeout unlock happens after sleep, inactivity, or explicit lock. The runtime should preserve safe public metadata but require re-unlock before sensitive actions continue.

Failed unlock should be clear and cautious. PhilCore should not reveal whether a secret was close to correct. Repeated failures may trigger delay, extra confirmation, reduced mode, or recovery guidance.

Read-only mode may be appropriate when the vault is locked but public metadata or locally cached non-sensitive state can be shown. In read-only mode, sensitive actions must remain unavailable.

## 6. Runtime Home

After unlock, PhilCore should present an active runtime state.

Expected applications and areas:

- Ethereum Net
- Recovery
- Audit
- Settings
- Future applications when installed or enabled

Runtime behavior:

- Applications are registered with requested capabilities.
- Applications create intents.
- PhilCore Runtime API evaluates intents.
- User Session tracks active state, capabilities, pending approvals, and timeouts.
- Trust Manager determines whether the active trust state is sufficient.
- Security Policy Engine determines whether the requested action is allowed.
- Authorization Engine creates bounded authorization packages only after approval.
- Adapters execute only approved packages.
- Audit Log records important events.

The runtime home is not a place where applications gain direct access to secrets. It is a control surface for requests, approvals, state, and review.

## 7. Ethereum Net Experience

Ethereum Net is the user-facing Ethereum application. Ethereum Adapter is the internal execution adapter. Base remains a profile/config under Ethereum Adapter unless future complexity justifies a separate Base Adapter.

Creating the first Smart Account:

- Ethereum Net creates an intent to deploy a PhilCore-controlled Smart Account.
- PhilCore Runtime API evaluates the intent.
- Security Policy Engine checks whether deployment is allowed.
- Trust Manager checks whether the current credential/device can approve deployment.
- Authorization Engine creates the bounded package needed for deployment.
- Ethereum Adapter prepares the ERC-4337 path.
- The user approves before any external submission.
- Audit Log records the request, approval, and result.

Connecting an existing wallet:

- Existing EOAs such as MetaMask may connect to PhilCore.
- They may be monitored, fund PhilCore accounts, migrate assets into PhilCore Smart Accounts, and participate in interoperability.
- PhilCore must explain that it cannot become final authority over an ordinary EOA while that EOA's private key remains the controlling signer.

Funding the Smart Account:

- Ethereum Net can show funding options.
- Funding may come from an external wallet, exchange withdrawal, bridge, or direct transfer.
- Funding actions should be treated as intents and audited where PhilCore participates.

Viewing balances:

- Viewing balances is a low-risk capability.
- It may be available without high-assurance approval, depending on privacy settings.

Sending ETH:

- Ethereum Net creates a send intent.
- The runtime evaluates recipient, amount, account, policy, trust state, and session state.
- Large or unusual transfers may require stronger approval.
- Proof-backed authorization may be required if the execution path demands it.
- Ethereum Adapter executes only after approval.
- Audit Log records the full lifecycle.

Receiving ETH:

- Receiving ETH should be simple and low-risk.
- Ethereum Net can expose receive addresses or Smart Account identifiers.
- The runtime may notify when funds arrive.

Signing messages:

- Ethereum Net creates a message-signature intent.
- PhilCore should show the meaning and risk of the message before approval.
- The request should be bounded to a specific message, account, application, and expiry where possible.

Session behavior:

- Sessions may allow repeated low-risk reads.
- Sensitive actions must not inherit broad signing authority.
- Session key management, if supported later, must be explicit, scoped, expired, revocable, and audited.

User approvals:

- Approvals should explain what action is being authorized.
- Approval should identify the application, account, target, amount or payload, policy result, and adapter path.

Intent creation:

- Ethereum Net creates intents, not authorizations.
- Approved intents may become bounded authorization packages.

Capability requests:

- Ethereum Net requests capabilities such as `read_balance`, `request_message_signature`, `request_transaction_preparation`, `request_transaction_submission`, `request_contract_call`, `request_smart_account_deployment`, and `request_session_key_management`.

Authorization:

- Authorization Engine creates bounded authorization packages only after the runtime approves the intent.

Execution:

- Ethereum Adapter executes approved packages.
- Ethereum Adapter does not define identity and does not receive root secrets.

Audit:

- Ethereum Net actions should be auditable from intent through result.

## 8. Trust Experience

Trust Manager is how users manage trusted devices, passkeys, and credentials.

Users should be able to:

- View trusted devices and credentials.
- Add a new device.
- Add a passkey.
- Add a hardware key.
- Mark a credential as recovery-only.
- Rotate from an old credential to a new one.
- Revoke a lost or compromised credential.
- Archive credentials no longer used.
- Understand which credentials can authorize ordinary actions.
- Understand which credentials are recovery-only.

Adding a device should require approval from an existing trusted path unless the identity is being created or recovered.

Adding a passkey should explain what the passkey can authorize.

Rotation should be overlap-first:

```text
old credential remains valid
-> new credential is added
-> new credential is verified
-> user optionally retires the old credential
```

Revocation should require explicit confirmation and warn if the user may lock themselves out.

Trust changes should always be audited.

## 9. Recovery Experience

Recovery is for cases such as:

- lost phone
- new phone
- replaced hardware
- lost passkey
- compromised credential
- failed ordinary unlock

Recovery should be clear, restricted, and stronger than ordinary authorization.

Lost phone:

- The user enters recovery on a new device or remaining trusted device.
- PhilCore explains what credentials are missing and what recovery options exist.
- Recovery-only credentials or approved recovery paths may be required.

New phone:

- If the old phone is still available, the preferred flow is migration, not emergency recovery.
- The user adds the new phone as trusted, verifies it, then optionally retires the old phone.

Replacing hardware:

- The user adds the replacement hardware key before removing the old one when possible.
- PhilCore warns before removing the last strong trust factor.

Recovery ceremony:

- Recovery starts in a restricted runtime state.
- Recovery requires stronger approval than ordinary actions.
- Recovery may include waiting periods, multiple factors, or future social/hardware ceremonies.

Recovery completion:

- New trust state becomes active.
- Recovery state is updated.
- The user is shown what changed.
- Audit Log records recovery start, approval, and completion.

Recovery restrictions:

- Ordinary Ethereum Net actions may be restricted during recovery.
- Exporting backups or changing policies may require extra confirmation.
- Recovery must never expose `phil_secret`.

## 10. Audit Experience

Audit lets the user understand what PhilCore did, what was requested, what was approved, and what failed.

Users should be able to:

- View events.
- Search events.
- Filter by application, intent, credential, adapter, policy, recovery, proof, or time.
- Export encrypted audit bundles.
- Verify audit bundle integrity.
- Review approvals.
- Understand why an action was denied.

Events should include:

- unlocks and failed unlocks
- credential additions, rotations, revocations, and recovery-only changes
- intents created, approved, rejected, or expired
- capability grants, denials, revocations, and expirations
- Ethereum Net actions
- proof requests and proof failures
- adapter execution attempts and failures
- recovery lifecycle events
- encrypted backup exports and imports

Audit data may be sensitive. It should be local and encrypted by default.

## 11. Settings Experience

Settings should expose conceptual controls, not raw implementation internals.

Security:

- unlock methods
- trust requirements
- timeout behavior
- high-risk action confirmations
- device trust state

Privacy:

- what public metadata is shown
- application visibility
- audit visibility
- network lookup preferences

Recovery:

- recovery status
- recovery-only credentials
- backup status
- recovery warnings

Ethereum:

- Ethereum Net status
- Smart Account status
- Base profile/config status
- connected EOAs
- funding and migration preferences

Applications:

- installed/enabled applications
- requested capabilities
- granted capabilities
- revoked capabilities

Policies:

- approval thresholds
- action limits
- session behavior
- capability expiry

Audit:

- audit retention
- encrypted export
- integrity verification

Developer mode:

- local fixtures
- test providers
- no-send session drills
- experimental proof/adapter diagnostics

Normal Desktop Alpha protected action:

- visible from Home and Ethereum without enabling Developer mode
- unavailable with no identity, while locked, or while another protected action is active
- explained as local-only with no real funds and no public transaction
- approved through an in-app Runtime-generated presentation, not a browser-native confirmation dialog
- bound to the displayed digest, expiry, identity, session, action, and local account
- one-time use only, with no reusable pending authority after lock, close, restart, rejection, cancellation, or expiry
- routed through the canonical Runtime trust, policy, approval, proof, Device Vault signing, local ERC-4337 fixture execution, and audit workflow

Experimental features:

- clearly labeled
- disabled by default where risk is unclear
- never allowed to weaken root identity or vault protections

## 12. Application Lifecycle

Applications interact with PhilCore through the Runtime API.

Register:

- The application declares its identity, requested capabilities, required adapters, action types, and audit categories.

Request capabilities:

- The application requests narrow capabilities.
- PhilCore may grant, deny, scope, expire, revoke, or audit them.

Create intents:

- The application creates intents when the user wants to do something.
- The application does not create authorizations.

Request authorization:

- The Runtime API evaluates the intent.
- User Session supplies active state.
- Trust Manager and Security Policy Engine evaluate the request.
- Authorization Engine creates bounded authorization only after approval.

Receive approval:

- The application receives an approved result or denial.
- Denials should explain the broad reason without leaking secrets.

Execute:

- Adapters execute approved authorization packages.
- Applications do not directly execute privileged actions.

Log results:

- The runtime records result, failure, denial, timeout, or cancellation.

Suspend:

- Application capabilities may be paused during lock, recovery, timeout, or policy changes.

Resume:

- Applications resume through Runtime API and User Session state.
- Sensitive actions may require re-approval.

Uninstall:

- The application loses capabilities.
- Related sessions are invalidated.
- Audit Log records uninstall and capability revocation.

## 13. Daily Usage

A typical day using PhilCore:

1. The user unlocks PhilCore.
2. User Session begins or resumes.
3. Ethereum Net shows balances and recent activity.
4. The user receives ETH; PhilCore records or displays the event.
5. The user signs a message; Ethereum Net creates an intent and PhilCore requests approval.
6. The user reviews an Audit event for the signature.
7. The user checks trusted devices.
8. PhilCore locks after timeout or explicit lock.

In daily use, most read-only actions should feel lightweight. Sensitive actions should feel deliberate, bounded, and understandable.

## 14. Failure Cases

Network unavailable:

- Applications may show cached safe state.
- Execution intents cannot complete until network returns.
- Audit records failed execution attempts where appropriate.

Ethereum unavailable:

- Ethereum Net may enter read-only or degraded mode.
- Identity, vault, recovery, and audit should continue locally.

Bundler unavailable:

- Smart Account execution cannot submit.
- The intent may remain pending, fail, or be retried depending on policy.

Proof unavailable:

- Proof-required actions cannot proceed.
- Non-proof-required local previews may continue.

Recovery pending:

- Sensitive ordinary actions may be restricted.
- Recovery App remains available for recovery-specific intents.

Vault locked:

- Sensitive actions are blocked.
- Read-only public metadata may remain visible if policy permits.

Trust failure:

- The action is denied or escalated to stronger verification.

Policy rejection:

- The user should see that PhilCore denied the action under policy.
- The runtime should avoid leaking sensitive policy internals unnecessarily.

Adapter failure:

- The approved authorization may fail at execution.
- The user should see the adapter failure separately from trust/policy denial.

Capability denied:

- The application should not proceed.
- The denial should be auditable.

## 15. Notifications

PhilCore should notify the user about security-relevant events.

Examples:

- credential added
- credential rotated
- credential revoked
- new device trusted
- policy rejection
- large transfer requested
- recovery started
- recovery approved
- recovery completed
- proof failed
- Smart Account deployed
- encrypted backup exported
- audit bundle exported
- capability granted
- capability revoked
- suspicious or repeated unlock failures

Notifications should be useful, not noisy. High-risk events should be more prominent than ordinary read-only activity.

## 16. Future Expansion

Future applications should plug into PhilCore using the same philosophy:

```text
Application
  -> Intent
  -> Runtime API
  -> User Session
  -> Trust and policy evaluation
  -> bounded authorization
  -> adapter execution
  -> audit
```

Possible future applications:

- Bitcoin
- Solana
- SSH
- PGP
- Document Signing
- AI Permissions

Future adapters should not redefine identity. They should execute approved packages for their protocol or network.

AI permissions should follow the same intent model. Agents, automation, scheduled actions, delayed approvals, and delegated workflows create intents and receive scoped authority only after runtime approval.

## 17. Guiding Principles

- PhilCore is a Personal Security Operating System.
- Identity is device-first.
- `phil_secret -> identityRoot -> ownerCommitment` remains the identity root.
- Applications create intents.
- The Runtime API evaluates intents.
- Runtime evaluates trust.
- Runtime evaluates policy.
- Authorization is bounded.
- Authorization Engine creates authorization packages only after approval.
- Applications never receive root secrets.
- Applications never receive unrestricted wallet authority.
- Adapters execute approved packages.
- Execution adapters never define identity.
- Device Vault protects local state.
- Trust Manager governs trusted devices and credentials.
- Recovery is stronger than ordinary authorization.
- Audit is local and encrypted by default.
- Ethereum is the first execution environment.
- ERC-4337 Smart Accounts are the preferred Ethereum authority model.
- EOAs are compatibility paths.
- Proof-backed authorization strengthens execution where required.
- PhilCore does not overclaim full post-quantum security.
- Future applications should extend the model without changing the identity root.
