# Production Authentication Evidence Boundary

## Purpose

This boundary defines the request, evidence, and provider-adapter contracts needed for future production authentication.

It does not perform authentication. It does not invoke browser WebAuthn, platform biometrics, Secure Enclave, Android Keystore, Device Vault, encrypted storage, World ID, proof code, or execution adapters.

## Boundary Distinctions

Production authentication now has four separate concepts:

- Authentication request: a bounded request for future provider evidence.
- Evidence artifact: a provider-specific response represented as references and metadata for future verification.
- Evidence verification: future work that may validate signatures, counters, platform claims, challenge binding, or provider assertions.
- Session transition: the User Session lifecycle state machine remains responsible for lifecycle state changes.

An evidence artifact is not authentication. It is not trust approval, policy approval, user consent, authorization, vault unlock, or active capability.

## Provider Kinds

Current provider kinds are:

- `webauthn_passkey`
- `platform_biometric`
- `hardware_security_key`
- `device_signature`
- `local_pin`
- `recovery_credential`
- `developer_fixture`
- `unsupported`

World ID is intentionally not modeled as an ordinary session authentication provider. Canonical human uniqueness remains a separate enrollment and policy concern.

## Authentication Requests

A `ProductionAuthenticationRequest` may correlate to:

- session ID
- lifecycle transition request ID
- lifecycle event
- owner commitment
- application ID
- credential ID
- device ID
- provider ID
- requested assurance level
- challenge reference
- expiry
- audit correlation ID

Requests are shape-bound only. They set:

- `invokesProvider: false`
- `authenticatesUser: false`
- `unlocksVault: false`
- `grantsAuthority: false`
- `persisted: false`

## Evidence Artifacts

A `ProductionAuthenticationEvidence` artifact means only:

```text
A provider-specific authentication response has been represented and bounded for future verification.
```

Evidence outcomes include:

- `evidence_present`
- `evidence_missing`
- `evidence_malformed`
- `evidence_expired`
- `evidence_replayed`
- `provider_unsupported`
- `provider_unavailable`
- `challenge_mismatch`
- `correlation_mismatch`
- `assurance_insufficient`
- `verification_pending`

Evidence artifacts must not use outcomes such as authenticated, trusted, approved, or authorized.

## Provider Evidence References

Provider-specific evidence is represented by references only.

WebAuthn references may include credential ID, authenticator-data reference, client-data hash/reference, signature reference, sign counter, user-presence flag, user-verification flag, origin, RP ID, and challenge binding reference.

Platform biometric references may include platform evaluation reference, user-presence reference, secure hardware reference, evaluation timestamp, and platform/provider identifier.

Hardware-key references may include credential/key identifier, assertion/signature reference, challenge reference, user-presence reference, and device/provider identifier.

Recovery credential references may include recovery credential ID, recovery mode reference, recovery ceremony reference, required delay reference, and additional factor requirements.

No raw private keys, biometric templates, WebAuthn assertion payloads, clientDataJSON, authenticatorData, vault keys, seed phrases, recovery secrets, or raw signatures belong in this boundary.

## Adapter Contracts

Provider adapters are interface boundaries. Conceptual methods include:

- `describeProvider`
- `checkAvailability`
- `createAuthenticationRequest`
- `normalizeEvidence`
- `validateEvidenceShape`

Adapters must not mutate User Session lifecycle state, unlock vaults, create active capabilities, create authorization packages, persist evidence, or call execution adapters.

## Developer Fixture Adapter

The developer fixture adapter is local-test-only. It accepts explicit inputs and returns bounded evidence artifacts.

It is marked fixture-only and does not claim production authentication. It must not be reused as a production provider.

## Lifecycle Bridge

Authentication evidence may be converted into a lifecycle evidence reference for future lifecycle evaluation.

This bridge does not permit a lifecycle transition today. It carries:

- evidence ID
- request ID
- session ID
- lifecycle transition request ID
- lifecycle event
- `verificationPending: true`
- `verified: false`
- `rawEvidenceIncluded: false`

The lifecycle state machine remains authoritative for lifecycle transitions. Provider adapters cannot mutate lifecycle state directly.

## Future Work

A later fixture-only milestone may verify a bounded fixture evidence artifact and use that verified fixture reference to permit a controlled lifecycle transition in tests. That future work must still avoid production authentication claims until real platform providers are implemented and reviewed.
