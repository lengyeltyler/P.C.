# PhilCore Desktop Local Identity And Device Vault

Status: local Alpha durable identity and vault boundary implemented; O.3 platform protection available where enrolled.

Phase: O.2

## Scope

O.2 replaces the normal desktop fixture identity path with a real local PhilCore identity and encrypted local Device Vault/registry boundary.

The desktop app can:

- create a local Phil identity from protected generated root material;
- preserve the invariant `phil_secret -> identityRoot -> ownerCommitment`;
- persist encrypted identity, registry, execution-validator custody, and optional recovery-authority records;
- reopen the same local identity after app restart;
- authenticate with a local Alpha passphrase-derived key;
- unlock the Device Vault into process-local memory;
- expose only sanitized Runtime Home, credential, validator, recovery, vault, and audit summaries to the renderer;
- lock and clear process-local vault state;
- reset a locked local identity with explicit confirmation.

The O.2 passphrase path remains the local Alpha fallback. O.3 adds macOS Keychain/safeStorage wrapping-key protection where enrolled. This is still not Base Sepolia approval and does not claim Touch ID, Secure Enclave custody, or biometric authentication.

## Selected Storage Model

Selected for O.2: main-process encrypted file backend.

```text
Electron app data
  -> non-secret identity-index.json
  -> identity directory
     -> identity.encrypted.json
     -> registry.encrypted.json
     -> validator.encrypted.json
     -> recovery-authority.encrypted.json, optional
```

The renderer never receives filesystem paths. Path selection is owned by Electron main process app data.

Encrypted records use AES-256-GCM with a key derived from the local Alpha passphrase using scrypt. The implementation uses atomic file replacement, best-effort `0700` directory permissions, best-effort `0600` file permissions, bounded file-size reads, and symlink rejection before encrypted record reads.

After O.3 enrollment, the same records are re-encrypted with a random per-identity vault-wrapping key. The wrapping key is protected through platform protection and a passphrase fallback envelope.

The non-secret index contains display and public status metadata only. It is not trusted as authority; encrypted identity and registry binding are revalidated during authentication.

## Identity Creation

First launch can create:

- a new `phil_secret`;
- derived `identityRoot`;
- derived `ownerCommitment`;
- an encrypted private identity envelope;
- an encrypted registry;
- an encrypted execution-validator ECDSA custody record;
- an optional encrypted recovery-authority ECDSA custody record.

The execution validator and recovery authority are generated separately. Recovery authority is not derived from `phil_secret`, `identityRoot`, `ownerCommitment`, or the execution validator.

## Authentication And Unlock

The O.2 desktop unlock path is:

```text
selected local identity
  -> local Alpha passphrase authentication
  -> encrypted identity and registry binding validation
  -> partial session unlock
  -> Device Vault unlock
  -> sanitized Runtime Home
```

Wrong passphrases, ciphertext tampering, and identity-index owner tampering fail closed and leave the session locked.

The local Alpha passphrase is an interim desktop authentication mechanism. Production desktop unlock still requires a future accepted platform-authentication model.

## Protected State

Unlocked vault state is process-local and ephemeral. Locking clears the current unlocked vault object and best-effort zeroes process-local vault-key buffers.

The renderer may receive:

- owner commitment;
- public validator address;
- public recovery address;
- public credential metadata;
- lifecycle state;
- sanitized protected-view summaries;
- sanitized audit summaries.

The renderer must not receive:

- `phil_secret`;
- raw vault keys;
- raw private keys;
- recovery private keys;
- decrypted registry plaintext;
- raw signing sessions;
- unrestricted transaction authority.

## Restart And Tamper Behavior

O.2 tests verify:

- create, lock, app restart, reopen, authenticate, unlock;
- stable `ownerCommitment`;
- stable public validator and recovery addresses;
- wrong passphrase failure;
- ciphertext tamper failure;
- identity-index tamper failure;
- lock invalidates protected state;
- reset requires a locked identity and exact confirmation.

## Limitations

- Local Alpha passphrase unlock is not production biometric/passkey authentication.
- File permission controls are best effort across desktop platforms.
- In-memory secret clearing is best-effort JavaScript process hygiene, not a formal memory-zeroization guarantee.
- No public network transaction, UserOperation, paymaster, Base Sepolia deployment, or live chain mutation is enabled.
- Base Sepolia Beta remains blocked pending ACP acceptance, deployment verification, approved public-network controls, and external review.
- Electron safeStorage on macOS is Keychain-backed encryption availability, not a guarantee of biometric user presence.
