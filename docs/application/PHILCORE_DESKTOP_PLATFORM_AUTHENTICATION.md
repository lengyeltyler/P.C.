# PhilCore Desktop Platform Authentication

Status: production-candidate macOS Keychain protection boundary implemented; not production-approved.

Phase: O.3

## Scope

O.3 adds a platform unlock boundary to the O.2 encrypted local identity path.

The desktop app can now:

- check platform-protection availability;
- enroll an unlocked identity into platform unlock;
- generate a random per-identity vault-wrapping key;
- protect the wrapping key through the selected platform key adapter;
- migrate encrypted identity, registry, validator, and recovery records to the wrapping-key provider;
- preserve explicit local Alpha passphrase fallback;
- unlock the migrated vault through platform protection after restart;
- require fresh platform-auth evidence for sensitive local presentations;
- disable platform unlock without stranding the identity.

No public network operation follows platform unlock.

## Selected Model

Selected model for O.3:

```text
Electron main process
  -> Electron safeStorage on macOS
  -> macOS Keychain-backed encryption availability
  -> encrypted local platform-protection sidecar
  -> random per-identity wrapping key
```

Automated tests use an isolated fixture adapter. The fixture adapter proves Runtime behavior and failure handling; it is not real macOS integration evidence.

No native Node Keychain package was added. A small Swift/Objective-C helper and WebAuthn/passkey unlock were evaluated but deferred.

## What Is Actually Authenticated

O.3 keeps three concepts separate:

```text
Platform authentication / availability
  -> Keychain protected wrapping-key retrieval
  -> Device Vault decryption and registry integrity validation
```

Electron `safeStorage` on macOS reports whether Keychain-backed encryption is available. O.3 labels this as macOS Keychain protection. It does not claim Touch ID, biometric verification, Secure Enclave custody, or guaranteed user presence.

The UI should say:

- “Unlock with macOS Keychain” for safeStorage-backed unlock;
- “Unlock with Touch ID” only after a future implementation proves user-presence or biometric verification.

## Wrapping-Key Model

The wrapping key is:

- randomly generated;
- 32 bytes;
- bound to one identity;
- not derived from `phil_secret`;
- not derived from `identityRoot`;
- not derived from `ownerCommitment`;
- not derived from validator or recovery keys;
- never returned to the renderer;
- never written as plaintext application data.

The sidecar file `platform-protection.json` contains only versioned metadata, protected wrapping-key material, and a passphrase fallback wrapping envelope. It does not contain raw wrapping keys.

## Enrollment

Enrollment requires:

- selected identity;
- unlocked O.2/O.3 vault;
- current local Alpha passphrase;
- available platform key adapter.

The flow is:

```text
unlocked identity
  -> verify passphrase fallback
  -> generate wrapping key
  -> protect wrapping key
  -> rewrite encrypted records with wrapping-key provider
  -> write platform-protection sidecar
  -> verify protected-key round trip
  -> preserve passphrase fallback
```

If enrollment fails, O.3 restores the prior encrypted records and leaves passphrase unlock available.

## Unlock

Platform unlock:

```text
selected identity
  -> load platform-protection metadata
  -> retrieve protected wrapping key in main process
  -> decrypt identity and registry
  -> validate identity binding
  -> validate registry binding
  -> decrypt validator/recovery records
  -> transition session to unlocked
```

Possible failures include platform unavailable, cancellation, Keychain denial, missing item, invalid wrapping key, vault integrity failure, identity mismatch, migration required, unsupported platform, and malformed metadata.

The Runtime never silently falls back to passphrase. The user must choose passphrase fallback explicitly.

## Sensitive Actions

O.3 models fresh platform authentication evidence for sensitive local actions. The evidence does not expose Keychain values or wrapping keys.

Fresh authentication is required by policy for:

- execution-validator signing presentations;
- recovery-authority signing presentations;
- execution-owner rotation;
- recovery request and completion;
- recovery-authority rotation;
- changing unlock methods.

O.4 consumes fresh-authentication evidence in the desktop sensitive-action approval path. Local UserOperation signing, recovery request/completion, owner rotation, recovery-authority rotation, and platform-unlock disablement now require digest-bound approval and fresh evidence where applicable.

## Limits

- Real macOS Keychain behavior requires Electron main process.
- CLI diagnostics cannot trigger or prove actual macOS Keychain UI.
- Electron safeStorage does not guarantee Touch ID or biometric user presence.
- Keychain items may be device-specific and may not migrate with copied app data.
- Passphrase fallback remains required until recovery and device-replacement implications are reviewed.
- Production desktop authentication is not approved.
