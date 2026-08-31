# Production-Verified Partial Session Unlock

## Purpose

This boundary connects a successful production WebAuthn verification result to a controlled User Session lifecycle candidate.

It permits only:

```text
unlocking -> partially_unlocked
```

It does not permit a full `unlocked` session because Device Vault unlock has not occurred.

## Inputs

The flow consumes explicit in-memory inputs only:

- credential public information
- WebAuthn assertion payload supplied by the caller
- expected challenge
- expected RP ID
- expected origin
- session correlation
- current lifecycle snapshot
- lifecycle transition request

PhilCore does not call browser credential UI or `navigator.credentials.get` in this boundary.

## Flow

```text
Lifecycle unlock request
  -> explicit in-memory WebAuthn assertion inputs
  -> Production Authentication Verification Result
  -> Lifecycle Transition Eligibility
  -> Lifecycle Transition Candidate
  -> controlled transition to partially_unlocked
  -> audit event drafts
  -> stop
```

## Lifecycle Candidate

A `LifecycleTransitionCandidate` means a successful production WebAuthn verification result has been correlated to a lifecycle request and may be used for the partial-unlock transition.

Candidates reject failed verification, expired evidence, replayed evidence, session mismatch, owner commitment mismatch, credential mismatch, provider mismatch, challenge reference mismatch, transition request mismatch, insufficient assurance, unsupported lifecycle state, and unsupported target state.

## Partial Unlock

The bounded transition helper may create a new in-memory lifecycle snapshot with:

- `state: partially_unlocked`
- lifecycle authentication factor verified
- Device Vault still locked
- protected identity state unavailable
- active capabilities unavailable
- authorization unavailable
- stronger vault-unlock step required
- `persisted: false`

It never transitions to full `unlocked`.

## Replay Handling

The optional production verification consumption store is process-local and ephemeral.

It provides one-time use per verification result ID within the current process. It is not durable production replay prevention and does not write to storage.

## Security Boundaries

This milestone does not:

- invoke browser WebAuthn prompts
- invoke biometric APIs
- load credentials from Device Vault
- access Secure Enclave or Android Keystore
- unlock Device Vault
- load protected identity state
- grant capabilities
- create session keys
- create Authorization Packages
- evaluate policy
- verify World ID
- execute proofs
- call execution adapters
- persist session state or verification results

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_webauthn_partial_unlock
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_webauthn_partial_unlock --json
```

This diagnostic uses explicit in-memory WebAuthn test inputs and the existing production verifier. It is not a complete production login flow.

## Future Work

A future Device Vault unlock boundary may consume a valid `partially_unlocked` session and explicit in-memory vault-unlock material.

That future work must remain separate from capability activation, authorization packages, proof execution, adapter execution, and persistence until reviewed under Architecture Change Control.
