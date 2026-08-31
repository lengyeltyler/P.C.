# Secure Enclave Validation Status

Status date: 2026-08-19

This document is the current source of truth for Secure Enclave claims. The
O.43 implementation and threat-analysis reports are historical phase records.

## Implemented in source

The iOS companion contains a native `SecureEnclaveCredentialManager` that, on
a physical device, requests a P-256 key using
`kSecAttrTokenIDSecureEnclave`,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and
`privateKeyUsage | userPresence`. Production-recovery queries bind the exact
application tag, EC key type, and Secure Enclave token. Public-key extraction
does not imply private-key export.

The simulator path intentionally creates a software-backed P-256 disposable
credential. It marks the record `simulatorOnly=true` and
`secureEnclaveBacked=false`; production descriptor construction rejects that
classification.

These are source-level properties. They do not by themselves prove that a
particular public key was created by genuine Apple hardware.

## Validation evidence

The repository contains one sanitized physical-device observation:

- baseline commit: `45c38dec9ba0e3f13db83bcbc943f1e72c64b894`;
- test:
  `PhilCoreCompanionTests/testDisposableKeyExportBoundary`;
- recorded result: one disposable physical-device test passed;
- observed scope: Secure Enclave classification, private-key
  non-exportability probe, and deletion; and
- explicitly not performed: production enrollment, recovery signing, or a
  user-presence signing prompt.

The record is operator-attested and digest-bound, not externally signed or
independently witnessed. Its raw build log and result bundle were removed
after the sanitized record was created.

Current iOS recovery source has changed materially since that baseline,
including production recovery signer, transport, approval, and lifecycle
work. The physical observation therefore does **not** validate the entire
current recovery implementation. No committed record establishes a completed
current-source simulator test matrix or production recovery ceremony.

## Claims that remain prohibited

Phil must not claim:

- current end-to-end physical-device recovery validation;
- completed simulator UI/accessibility validation;
- production credential creation or production recovery signing;
- externally audited Secure Enclave custody;
- cryptographic attestation of Apple hardware origin; or
- that an on-chain boolean or public key proves Secure Enclave provenance.

Production readiness still requires current-source simulator coverage,
current-source physical-device tests for creation, retention, user-presence
signing, cancellation, recovery, rotation, and deletion, reviewed attestation
and enrollment policy, and external security review.
