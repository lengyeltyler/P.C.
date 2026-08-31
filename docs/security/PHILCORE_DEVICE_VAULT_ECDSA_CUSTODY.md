# PhilCore Device Vault ECDSA Validator Custody

Phase: N.3

Status: local Alpha custody boundary implemented; not production-approved.

## Scope

N.3 adds a bounded Device Vault custody path for the ERC-4337 Beta ECDSA validator key.

The boundary can:

- generate a dedicated secp256k1 validator key using secure randomness;
- store the private key only inside an AES-256-GCM encrypted local Device Vault validator record;
- return public owner-address metadata and opaque key references;
- create one-time, process-local signing sessions for exact EntryPoint v0.7 UserOperation hashes;
- satisfy the existing M.10 protected signer interface;
- revoke or mark local records pending rotation.

The boundary cannot:

- derive the validator key from `phil_secret`, `identityRoot`, or `ownerCommitment`;
- return, export, log, audit, or serialize the private key;
- sign arbitrary messages, transactions, typed data, or altered UserOperation hashes;
- persist signing sessions;
- deploy accounts, submit UserOperations, call bundlers, invoke paymasters, or mutate Base state;
- rotate the on-chain owner of `PhilCore4337Account`.

## Runtime Flow

```text
Authenticated unlocked session
  -> unlocked Device Vault handle
  -> ECDSA validator generation or resolution
  -> encrypted validator record
  -> opaque key reference
  -> public owner address
  -> one-time exact-hash signing session
  -> M.10 UserOperation hash signing
  -> signing session used/invalidated
  -> sanitized audit draft
  -> stop
```

## Security Model

The encrypted validator record is owner-bound, purpose-bound, and optionally account/chain-bound. Signing sessions require an `unlocked` User Session lifecycle state and a matching unlocked Device Vault handle.

`partially_unlocked`, `locked`, `suspended`, `expired`, and `recovery_mode` states are not eligible for ordinary validator signing in N.3.

## Remaining Blockers

N.4 adds local Alpha account-level owner rotation and delayed recovery. Local Device Vault revocation still must be coordinated with verified on-chain owner changes; local key-state changes alone are not sufficient evidence of account authority changes.

N.5 adds a recovery-authority custody wrapper around the same encrypted Device Vault ECDSA mechanics. Recovery keys use a separate purpose-bound record and may sign only recovery maintenance UserOperations. They are not derived from `phil_secret`, the execution validator, or `ownerCommitment`.

Local validator state coordination after recovery:

- old execution validator remains active locally until verified recovery completion;
- new execution validator remains pending until account owner state is verified;
- successful completion allows new validator activation and old validator revocation/archive;
- failed or cancelled recovery must not activate the new validator;
- local state must not claim account authority changed without receipt/state verification.

Base Sepolia Beta remains blocked until ACP-0002 is accepted for Beta scope, recovery authority custody and N.8 recovery-authority rotation are accepted for the selected Beta model, deployments are verified, remaining high tooling dependency advisories remain excluded from production runtime packaging, external review is complete, and public-network submission controls are approved. N.6 provides reproducible Slither/static-analysis evidence, but it is not a formal external audit.

## Phase O.2 Desktop Coordination

O.2 integrates local Alpha Device Vault custody into the desktop app's durable encrypted local identity boundary.

The desktop app creates an encrypted execution-validator custody record during local identity creation. It may also create a separate encrypted recovery-authority custody record. The renderer receives only public owner/recovery addresses and opaque references.

O.2 does not convert local custody into production approval:

- local Alpha passphrase unlock is not production authentication;
- encrypted file storage is not Secure Enclave/Keychain custody;
- public UserOperations remain disabled;
- Base Sepolia Beta remains blocked;
- no production recovery authority is activated.

## Phase O.3 Platform Protection Coordination

O.3 adds a random per-identity vault-wrapping key for enrolled desktop identities. The wrapping key protects local Device Vault records, including the execution-validator and recovery-authority custody records.

The wrapping key is not derived from `phil_secret`, `identityRoot`, `ownerCommitment`, validator keys, or recovery keys. It is protected through the desktop platform-auth boundary and remains unavailable to the renderer.

O.4 requires digest-bound approval and fresh-authentication evidence before the desktop local UserOperation signing presentation is consumed. The existing signer boundaries still remain responsible for exact-hash and exact-presentation checks.
