# User Session Lifecycle State Model

## Purpose

The User Session lifecycle model is a platform-neutral, non-secret state machine for PhilCore runtime session coordination.

It validates requested or observed lifecycle transitions only. It does not authenticate users, unlock Device Vault, execute WebAuthn or biometrics, verify World ID, grant capabilities, create authorization packages, execute proofs, call adapters, or persist session state.

## States

Current lifecycle states:

- `uninitialized`
- `locked`
- `unlocking`
- `partially_unlocked`
- `unlocked`
- `suspending`
- `suspended`
- `resuming`
- `expiring`
- `expired`
- `recovery_mode`
- `closing`
- `closed`

There is intentionally no `authenticated` lifecycle state. Authentication evidence may later permit a transition, but authentication is not the session itself.

## Events

Lifecycle events represent requested or observed changes:

- `initialize`
- `request_unlock`
- `unlock_succeeded`
- `unlock_failed`
- `request_suspend`
- `suspend_completed`
- `request_resume`
- `resume_succeeded`
- `resume_failed`
- `timeout_warning`
- `timeout_reached`
- `request_lock`
- `lock_completed`
- `request_recovery`
- `recovery_entered`
- `recovery_cancelled`
- `recovery_completed`
- `request_close`
- `close_completed`

Events do not execute the underlying platform action. For example, `unlock_succeeded` records that future unlock evidence was observed by a caller; it does not verify that evidence or open the vault.

## Transition Table

The runtime implementation exposes one deterministic transition table. Representative transitions include:

```text
uninitialized + initialize -> locked
locked + request_unlock -> unlocking
unlocking + unlock_succeeded -> unlocked
unlocking + unlock_failed -> locked
unlocked + request_suspend -> suspending
suspending + suspend_completed -> suspended
suspended + request_resume -> resuming
resuming + resume_succeeded -> unlocked
unlocked + timeout_warning -> expiring
expiring + timeout_reached -> expired
expired + request_lock -> locked
locked + request_recovery -> recovery_mode
recovery_mode + recovery_cancelled -> locked
recovery_mode + recovery_completed -> locked
locked + request_close -> closing
closing + close_completed -> closed
```

Illegal transitions are rejected explicitly. The state machine does not silently coerce states.

## Evidence References

Some transitions may carry evidence references, such as:

- authentication evidence reference
- unlock evidence reference
- recovery evidence reference
- timeout source reference
- user-presence evidence reference

These are references only. They must not include raw WebAuthn assertions, biometric payloads, World ID proofs, private keys, vault keys, passwords, recovery secrets, or other secret material.

Evidence references are not verified in this milestone.

## Lifecycle Store

The Ephemeral User Session Lifecycle Store is process-local and holds one lifecycle snapshot.

It can initialize, replace, inspect, clear, and request validated transitions for that snapshot. It does not persist, read Device Vault, authenticate, create timers, mutate active capabilities, create session keys, or become a durable session registry.

Snapshots are defensive/frozen where practical and include non-authority flags:

- `persisted: false`
- `ownsSecrets: false`
- `authenticatesUser: false`
- `unlocksVault: false`
- `grantsAuthority: false`

## User Session Context

Lifecycle snapshots may be used to derive a new non-secret `UserSessionContext` for correlation metadata.

Derivation is copy-based. It does not mutate the existing User Session store, does not add active capabilities, does not claim authentication, and does not unlock vault state.

## Audit Drafts

Lifecycle transition requests and results may create Audit Event Drafts.

Audit drafts record session ID, previous state, requested event, next state when available, transition outcome, reason, and audit correlation ID. They are not persisted and do not contain raw evidence payloads.

## Alpha 0 Diagnostic Mode

The Alpha 0 shell includes a lifecycle diagnostic mode:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence valid_unlock
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence invalid_transition
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence timeout
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence recovery
```

This mode is diagnostic only. It does not perform production authentication, unlock Device Vault, grant authority, execute proofs, call adapters, or persist artifacts.

## Fixture-Only Transition Bridge

The fixture-only authentication lifecycle bridge may permit controlled test transitions such as `unlocking + unlock_succeeded -> unlocked` and `resuming + resume_succeeded -> unlocked` when explicit developer fixture evidence has been verified.

This is not production authentication. An `unlocked` lifecycle state reached through the fixture bridge must still state that Device Vault remains locked, no active capability was created, no authorization was created, and no evidence or session state was persisted.

## Production-Verified Partial Unlock

Production WebAuthn verification may now support one bounded lifecycle slice:

```text
unlocking -> partially_unlocked
```

This path requires an already-supplied WebAuthn assertion, credential public information, expected challenge, expected RP ID, expected origin, session correlation, a successful `ProductionAuthenticationVerificationResult`, and valid `LifecycleTransitionEligibility`.

It does not invoke browser WebAuthn prompts, load credentials from Device Vault, unlock Device Vault, load protected identity state, create session keys, activate capabilities, create Authorization Packages, execute policy, execute proofs, call adapters, or persist session state.

`partially_unlocked` means a lifecycle authentication factor has been verified, but a stronger Device Vault unlock step is still required. It must not be treated as full `unlocked`.

## Controlled Device Vault Unlock

The controlled Device Vault unlock boundary may perform the next bounded lifecycle slice:

```text
partially_unlocked -> unlocked
```

This path requires an explicitly supplied in-memory encrypted Device Identity registry envelope, explicitly supplied in-memory unlock material, public Phil identity correlation, session correlation, and successful encrypted registry validation through the existing registry/key lifecycle helpers.

The resulting `unlocked` lifecycle state means protected local state is available through an opaque process-local vault handle. It does not expose `phil_secret`, raw vault keys, decrypted registry plaintext, or private credential material. It does not create active capabilities, session keys, Authorization Packages, policy decisions, proofs, adapter execution, or persisted session state.

The generic lifecycle transition table is not widened by this bridge. The controlled vault bridge owns this narrow transition so the broader lifecycle model remains behavior-neutral.

## Protected State Views

After the controlled Device Vault unlock reaches `unlocked`, the Runtime may request explicit protected-state views such as `identity_summary`, `credential_summary`, or `audit_summary`.

These views are least-privilege summaries only. They do not expose raw vault contents, decrypted registry plaintext, credential records, private keys, session keys, Authorization Packages, or application credentials. Vault unlocked means protected state is available to PhilCore through controlled boundaries; it does not mean all state is visible to applications.

## Future Work

Production authentication and consent integration should come later as explicit evidence interfaces/adapters. Those future adapters may produce evidence references for lifecycle transitions, but the lifecycle state machine should remain separate from authentication execution.
