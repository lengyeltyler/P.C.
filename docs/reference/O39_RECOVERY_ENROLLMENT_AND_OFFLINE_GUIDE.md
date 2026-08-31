# O.39 Recovery Enrollment and Offline Guide

Status:
`FOUNDATION_COMPLETE_REAL_USER_AND_DEVICE_CEREMONY_NOT_PERFORMED`.

## Runtime foundation

`consumerRecoveryRegistrationPolicy` produces the fixed creation policy for
each reviewed role/class: resident credential, user verification required,
direct attestation requested, and platform or cross-platform attachment as
appropriate.

`finalizeConsumerRecoveryWebAuthnEnrollment` accepts only a production-
verified P-256 registration with UP, UV, approved attestation, a credential
ID of at least 128 bits, known RP/origin, positive generation, and BE/BS both
false. It derives the public descriptor and sends the raw credential ID to a
caller-provided secure-storage adapter. The returned enrollment result
contains only the credential-ID hash and an opaque storage reference.

The primary credential is recovery-only. It must not reuse the ordinary
execution validator. A secondary platform device and an external hardware
key use different canonical attachment/attestation tuples. Cross-device
registration may require a future QR or deep-link handoff UI; that transport
must bind the enrollment challenge and display the intended role/profile.

## Offline format

The initial export is:

```text
PHIL39-V1-<52 base32 entropy characters grouped by four>-<8 base32 checksum characters>
```

It carries 256 random bits. A domain-separated hash deterministically maps
the entropy into a nonzero secp256k1 recovery-only scalar. Five checksum
bytes detect transcription errors. The same payload can be printed or
encoded as QR. Restoration derives only the public signer and commitment for
comparison during a drill.

The recovery code is private authority. Runtime code never logs it and
committed O.39 evidence contains no code or private scalar. The only copy
must not remain inside the normal PhilCore Device Vault or ordinary device
backup. A password by itself is not an approved protection boundary. If an
encrypted machine-readable wrapper is later added, it requires a separate
reviewed high-entropy encryption key and version.

Operational rules:

- create it in a private setting;
- print or transcribe it once and verify the checksum;
- keep it offline and physically separate from both devices;
- do not photograph it or allow photo/cloud synchronization;
- protect it from theft, fire, and loss;
- perform the local restoration drill before initialization;
- replace it through the exact validator-plus-2-of-3 rotation flow if
  exposure is suspected.

## Plain-language setup UX

Standard setup:

1. Explain: “Any two of your three recovery methods can recover your
   account.”
2. Create the recovery key on this device.
3. Connect a separate trusted phone, tablet, or computer and create its key.
4. Create the offline recovery code.
5. Confirm that the offline copy is saved away from both devices.
6. Run a restoration check without exposing the code in logs.
7. Show any cloud-sync or independence warnings.
8. Review the three public commitments.
9. Lock the initialization package.

Enhanced setup replaces step 3 with “Insert and verify your hardware
security key.”

The UI must not claim separate cloud custody is cryptographically proven.
It must warn about same-device storage, same cloud-sync domain, missing or
untested offline copies, and the possibility that assets can be stranded if
recovery or deployment cannot be completed.

## Remaining ceremony

O.39 used deterministic synthetic test credentials only. To create
production values, the user must:

1. enroll the real primary recovery-only credential;
2. enroll either a real secondary platform device or hardware key;
3. attest separate custody and resolve all warnings;
4. generate the offline factor, export it, remove normal-vault copies, and
   pass the restoration drill;
5. approve the three public commitments and configuration hash;
6. generate an external user salt locally.

No such production ceremony, signature, account creation, or deployment
occurred in O.39.

O.40 preflight subsequently proved that the current desktop integration is
not yet able to perform that ceremony safely. In particular, the fixed
policy requires verified direct attestation while the current registration
verifier explicitly lacks trust-root validation. The desktop also lacks a
canonical secure RP/origin and the required credential, secondary-device,
and offline-factor interfaces. See the O.40 preflight/readiness document;
no credential was created and no policy was weakened.
