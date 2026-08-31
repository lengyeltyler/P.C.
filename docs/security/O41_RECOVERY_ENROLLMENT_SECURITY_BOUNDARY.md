# O.41 Recovery Enrollment Security Boundary

O.41 is local-only infrastructure. Its public mutation count is zero.

## Secret ownership

| Material | Owner | Persistence | Renderer return |
| --- | --- | --- | --- |
| TLS private key | main process | `safeStorage` ciphertext | never |
| WebAuthn credential ID | main process | `safeStorage` ciphertext | never |
| authenticator private key | authenticator | authenticator only | impossible |
| pairing ECDH private key | main process | memory until complete/cancel | never |
| pairing payload | user-mediated | public request / AEAD ciphertext | safe transfer text |
| offline recovery code | main process + protected reveal | memory until drill | never |
| offline public fingerprint | main process | public local metadata | yes |

`SecretValue` serializes and stringifies as `[REDACTED_SECRET]` and requires
an explicit callback to consume. Recovery errors cross IPC only as bounded
uppercase error codes. Log redaction deny-lists secret-bearing keys and the
tests inject credential-ID, recovery-code, scalar, and pairing canaries.
Canaries are absent from JSON serialization, simulated crash context,
stdout, stderr, source evidence, and UI assets.

Electron starts with its Breakpad switch disabled and crash-report upload is
forced off and verified off. Uncaught exceptions and rejected promises
terminate without dumping error objects. The renderer startup diagnostic
prints only a fixed code. There is no analytics or telemetry path. macOS may
still create an operating-system diagnostic after a native process crash;
PhilCore cannot promise deletion of OS-managed diagnostics, so secret
lifetimes and serializable crash context are minimized.

## Threat controls

| Threat | Control |
| --- | --- |
| local origin impersonation | exclusive fixed port, loopback-only bind, exact Host, random process header, exact certificate pin |
| global CA pollution | no OS trust installation; app-local pin only |
| renderer compromise | sandbox, context isolation, no Node, strict CSP, narrow IPC, exact sender URL |
| credential substitution | main-owned challenge plus complete WebAuthn registration verification |
| backup-synced credential | BE and BS must both be false |
| manufacturer-provenance overclaim | Consumer policy says none; Enhanced remains blocked |
| record theft | `safeStorage` encryption and opaque references |
| record relocation | absolute-root and user binding inside ciphertext |
| filesystem race/symlink | lstat checks, exclusive temporary file, fsync, atomic rename, 0700/0600 |
| pairing replay/substitution | 256-bit ID, five-minute expiry, request hash, ephemeral ECDH, HKDF, AEAD, single-use state |
| duplicate factors | raw credential-ID fingerprint checked before write |
| offline secret leakage | dedicated no-preload window, no clipboard, no URL, no persistence, mandatory restore drill |
| state skipping | explicit transition allowlist |

## Frozen authority semantics

O.32 intent hashing, O.33 validator authorization, O.37.1 recovery
descriptors, O.37.4 authority transport, EntryPoint nonce ownership, and
exact 2-of-3 remain unchanged. O.41 changes no Solidity. The external-key
Consumer fallback does not become a new role and does not gain Enhanced
status. TOTP remains outside every on-chain commitment and recovery
combination.

## Bounded limitations

- The certificate depends on local Keychain-backed `safeStorage`.
- Application-level self-signed pinning is specific to the Electron
  session; the service is intentionally unusable from an ordinary browser.
- User-mediated text transfer does not automatically compare displays;
  the UI requires user confirmation and exposes a public request
  fingerprint.
- macOS cannot guarantee that a user does not photograph or screenshot a
  reveal; the UI makes no such claim.
- Physical-device behavior and custody independence require the later real
  ceremony.
- Enhanced attestation is unavailable until a reviewed local trust-root and
  metadata package exists.

These limitations produce Standard `READY_WITH_USER_WARNINGS`, not
unqualified production approval.
