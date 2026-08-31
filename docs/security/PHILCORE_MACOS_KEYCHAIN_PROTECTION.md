# PhilCore macOS Keychain Protection

Status: production-candidate boundary implemented; not production-approved.

Phase: O.3

## Decision

O.3 selects Electron `safeStorage` as the smallest defensible macOS Keychain protection boundary available in the current desktop stack.

This avoids adding a native dependency for O.3. It also avoids claiming stronger guarantees than the implementation provides.

## Options Evaluated

Model A - maintained native Node Keychain module:

- deferred because it would add native build, packaging, advisory, and maintenance risk;
- may be revisited if user-presence controls are required before Beta.

Model B - small Swift/Objective-C helper:

- strongest future path for explicit Keychain Services and LocalAuthentication controls;
- deferred because it adds signing, packaging, helper IPC, and binary provenance scope.

Model C - Electron safeStorage:

- selected for O.3;
- works in Electron main process;
- on macOS, Electron reports encryption availability based on Keychain availability;
- does not prove Touch ID, Secure Enclave, or biometric user presence.

Model D - WebAuthn/passkey only:

- deferred because Electron `file://` is not a valid production RP/origin model;
- future WebAuthn should authenticate session access separately from Keychain key custody.

## Protected Material

O.3 protects a random vault-wrapping key.

The wrapping key encrypts the local desktop identity, registry, execution-validator, and recovery-authority records after enrollment. The wrapping key is itself protected by the platform adapter and by an explicit passphrase fallback envelope.

The renderer never receives:

- wrapping key;
- vault key;
- `phil_secret`;
- raw private keys;
- recovery private keys;
- decrypted registry plaintext;
- generic Keychain service/account names;
- unrestricted signing authority.

## Sidecar Metadata

`platform-protection.json` records:

- format and version;
- identity binding;
- protection type;
- backend;
- protected wrapping-key blob;
- passphrase fallback wrapping envelope;
- policy;
- limitations.

It does not contain raw wrapping keys.

## Security Properties

Implemented:

- per-identity random wrapping key;
- versioned migration from O.2 passphrase-only records;
- Keychain/safeStorage-backed protected wrapping-key blob on macOS;
- explicit passphrase fallback;
- rollback on failed enrollment;
- platform unlock after restart;
- failed Keychain retrieval leaves vault locked;
- disablement restores passphrase-only records;
- identity reset removes the selected identity and best-effort deletes its platform reference;
- no renderer Keychain CRUD.

Not claimed:

- Secure Enclave custody;
- Touch ID;
- biometric verification;
- guaranteed user presence;
- production recovery sufficiency;
- public-network readiness.

## Device Replacement

Platform unlock is device-specific. Copying encrypted app data to another Mac may not preserve Keychain-protected access.

Users must retain passphrase fallback or a future encrypted backup/recovery path. Validator on-chain recovery is separate from local vault recovery. World ID is not a vault-unlocking secret.

## Audit Requirements

Audit events may include method, outcome, backend, identity reference, and limitation flags.

Audit events must not include Keychain values, wrapping keys, passphrases, private keys, assertion secrets, or decrypted registry material.
