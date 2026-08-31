# O.41 Consumer Recovery Enrollment Environment and Secure Ceremony UI

Classification:
`LOCAL_ONLY_DESKTOP_RECOVERY_ENVIRONMENT_IMPLEMENTATION`.

O.41 implements the local desktop environment required by the next
interactive recovery ceremony. It does not create a production credential,
offline factor, recovery commitment, account, transaction, or public
deployment.

## Frozen recovery boundary

The recovery set remains exactly:

| Role | Authority | Ordinary account authority |
| --- | --- | --- |
| 0 | primary-device recovery-only WebAuthn P-256 credential | none |
| 1 | independent secondary platform credential or external security key | none |
| 2 | offline `PHIL39-V1` secp256k1 factor | none |

The threshold remains exact 2-of-3, with valid role bitmaps 3, 5, and 6.
Passwords, SMS, email, security questions, TOTP, centralized service
approval, and Runtime-supplied Booleans are not recovery authorities. TOTP
is `DEFERRED_OPTIONAL_DEFENSE_IN_DEPTH`; a later implementation may use it
only as a local warning barrier and must not make recovery depend on it.

## Canonical WebAuthn application origin

O.41 selects an application-controlled loopback HTTPS origin:

- RP ID: `recovery.philcore.localhost`;
- origin: `https://recovery.philcore.localhost:18443`;
- listener: fixed port 18443 on `127.0.0.1` only;
- application document: `/index.html`;
- development and packaged origin: identical.

The fixed port is part of the origin. Startup fails closed if another
process owns it. The service accepts only GET/HEAD, the exact Host header,
the exact origin when an Origin header is present, an allowlisted static
asset extension, and a random per-process authorization header injected by
the Electron session. The authorization value is not placed in a URL,
query string, renderer API, local storage, or log.

The application generates one per-install RSA TLS certificate locally with
the macOS system OpenSSL executable. Its private key is immediately
encrypted with Electron `safeStorage`; only an encrypted envelope and the
public certificate persist. Both directory and record modes are restricted
to 0700/0600. Electron accepts the otherwise untrusted certificate only
when the request origin and SHA-256 certificate fingerprint equal the
active local service binding. All other certificate errors are rejected.
No global trust root is installed and TLS errors are never generally
ignored.

The certificate persists across restart and rotates locally when fewer than
30 days of validity remain. Rotation changes the application pin but not
the RP ID/origin, so enrolled WebAuthn credentials remain RP-bound. A clean
install creates a new certificate. Removing the application data removes
the certificate envelope and credential records; uninstalling the app
without deleting application data intentionally leaves them for recovery
from reinstall. macOS may prompt for Keychain access through `safeStorage`;
unavailability blocks startup before enrollment.

`.localhost` is handled as a loopback name by Chromium. The service itself
also binds explicitly to `127.0.0.1`, so it never listens on Wi-Fi,
Ethernet, IPv6, or an external interface. The model remains functional
offline after installation and has no public availability dependency.

## Attestation policy V1

### Consumer Platform Policy V1

`PHILCORE_CONSUMER_PLATFORM_POLICY_V1` is used for Role 0 and for Standard
Role 1. It requires:

- exact RP ID, origin, enrollment challenge, and `webauthn.create` type;
- ES256/P-256 credential extraction from attested credential data;
- UP, UV, and AT flags;
- resident credential and required user verification;
- raw credential ID equality with the authenticator data;
- BE=false and BS=false;
- distinct credential/public material and custody-domain commitments;
- attestation conveyance `none`.

The fixed policy commitment is stored with each encrypted record and enters
later descriptor preparation through the O.39 independence/policy evidence
boundary. It makes no manufacturer, model, hardware provenance, or
attestation-chain claim.

### External Hardware Policy V1

`PHILCORE_EXTERNAL_HARDWARE_POLICY_V1` remains `BLOCKED`. No attestation
format or authenticator is allowlisted because there is no reviewed trust
root bundle, certificate-chain verifier, revocation policy, or metadata
integrity package. Direct attestation is rejected.

An external security key may be selected under Consumer Platform Policy V1
with cross-platform attachment. The UI labels the result
`CONSUMER_PLATFORM_NO_HARDWARE_ATTESTATION`; it must never be displayed as
Enhanced. This resolves the O.40 contradiction explicitly rather than
treating unverified direct attestation as verified.

## Credential storage and bridge

The protected root is:

`Electron userData/philcore-recovery-enrollment`

The path is outside the repository. `.philcore-recovery-enrollment/` is
also ignored for bounded developer fixtures. Certificate and credential
subdirectories use 0700 and records use 0600. Each credential record is an
atomic, versioned envelope containing `safeStorage` ciphertext and a
ciphertext hash. The encrypted plaintext is bound to its absolute storage
root, local user ID where available, schema version, reference, RP ID, and
origin. Symlinks, moved records, corrupt ciphertext, wrong permissions,
wrong ownership, duplicate credential identifiers, and unknown schemas
fail closed.

Only these safe fields cross from main to renderer: opaque reference,
public key/fingerprint, descriptor metadata, role, generation,
custody-domain commitment, policy commitment, BE/BS classification, and
timestamp. There is no read-secret or arbitrary-file method. Rotation
writes and validates the replacement before deleting the old record.
Deletion is exact-reference only.

The preload exposes named recovery commands only. Main validates every
payload and requires the sender frame to equal the canonical application
document. Caller-selected paths, origins, RP IDs, arbitrary methods,
commands, and generic filesystem access are absent. Assertion requests
return opaque credential references rather than raw IDs.

## Secondary-device handoff

Standard Role 1 uses a user-mediated protocol, so no public server or local
network discovery is required:

1. the primary creates a 256-bit session ID, registration challenge,
   five-minute expiry, and ephemeral P-256 ECDH key;
2. the public request binds the RP, origin, policy, challenge, expiry, and
   primary ephemeral public key;
3. PhilCore Desktop on the independent device verifies the request,
   requires user confirmation, and creates its WebAuthn credential;
4. the secondary derives an ECDH/HKDF key and AES-256-GCM encrypts the
   registration response and custody commitment to the exact request hash;
5. the user returns only the encrypted response;
6. the primary verifies the session, expiry, request hash, AEAD transcript,
   challenge, origin, RP, credential, policy, and custody commitment before
   atomic storage.

Requests are high entropy, short lived, cancellable, and single use.
Challenge substitution, response substitution, transcript tampering,
expiry, replay, and duplicate factors fail closed. Transfer text contains
no reusable recovery authority or authenticator private material. A future
QR renderer may encode the same public request/ciphertext without changing
the protocol; text transfer is the implemented minimal companion path.

## Offline-factor interface

The main process creates the O.39-compatible `PHIL39-V1` value. It returns
only the signer and public fingerprint. Reveal opens a dedicated sandboxed,
no-preload, no-DevTools window. The code is never an IPC response, terminal
value, URL, clipboard item, normal application record, or tracked artifact.

The protected view supports reveal, hide, the system print dialog, clear,
and close. It warns that screenshots, photos, shared printer queues, and
cloud-synced destinations can create copies PhilCore cannot erase. It does
not select a file destination. The restoration input disables autocomplete
and is wrapped and cleared in main memory. A checksum or fingerprint
mismatch invalidates the ceremony and clears the active secret. After a
successful drill the secret is cleared and only public signer, format,
fingerprint, confirmation status, and drill status persist.

## State machine and UI

The implemented states are `NOT_STARTED`, `PREFLIGHT_RUNNING`,
`PREFLIGHT_BLOCKED`, `PRIMARY_PENDING`, `PRIMARY_COMPLETE`,
`SECONDARY_PENDING`, `SECONDARY_COMPLETE`, `OFFLINE_PENDING`,
`OFFLINE_EXPORT_CONFIRMED`, `OFFLINE_DRILL_COMPLETE`,
`INDEPENDENCE_REVIEW`, `READY_FOR_COMMITMENT_APPROVAL`, `COMPLETE`,
`CANCELLED`, and `INVALIDATED`.

Every transition is allowlisted. Preflight, primary and secondary
verification, offline reveal/export, restoration drill, and independence
review cannot be skipped. Cancel clears ephemeral challenges, ECDH keys,
and offline material. Valid Role 0/1 public records can resume after restart;
partial pairing and unrecovered offline secrets never resume silently.

The Recovery setup screen contains an overview, environment check, primary
credential action, secondary companion and external-key choices, offline
reveal/restore controls, independence review, and safe public completion
summary. O.41 tests only synthetic credentials and secrets; no UI action was
used to create real material during this phase.

## Preflight V2

O.41 classifies profiles separately:

- Standard: `READY_WITH_USER_WARNINGS`;
- Enhanced: `BLOCKED`.

Standard warnings require a later interactive physical-device ceremony and
explicit custody-domain review. Enhanced blockers are the absent trust-root
bundle and attestation certificate-chain validation. Standard readiness
does not claim that a physical authenticator has already been tested.

## Packaging and remaining operational risk

The canonical origin is used in development and packaged builds. Local
build composition includes the origin, policy, enrollment host, protected
reveal assets, preload bridge, and O.39 WebAuthn verifier. Context isolation,
sandboxing, Node exclusion, CSP, navigation denial, production DevTools
exclusion, disabled Breakpad startup, and disabled crash-report upload remain
enforced. OS-managed native crash diagnostics are a disclosed residual risk.

The primary remaining work is operational: run the real Standard ceremony
on the intended primary and genuinely independent secondary devices, review
their custody domains, store the offline factor, and complete its
restoration drill. That later action requires fresh, explicit user
interaction. External security review remains required before real-value
use.
