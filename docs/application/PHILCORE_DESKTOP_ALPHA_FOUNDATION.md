# PhilCore Desktop Alpha Foundation

Status: local Alpha foundation implemented; Base Sepolia Beta blocked; production not approved.

Phase: O.1

## Stack Decision

O.1 selects Electron 39.8.10 with a static HTML/CSS/JavaScript renderer.

Reasons:

- the repository already has a Node/TypeScript Runtime and local fixture tooling;
- no existing desktop or frontend application existed under `apps/`;
- Electron allows the smallest real desktop shell without adding a React/Vite/Tauri bridge;
- O.1 can harden the process boundary before adding product complexity.

Tauri remains a future option once the Runtime host boundary is stable.

## Application Mode

The desktop app runs in:

```text
mode = local_alpha
```

It also labels:

- `public_testnet_disabled`;
- `mainnet_disabled`;
- Base Sepolia Beta gate: blocked;
- ACP-0002: Proposed;
- production approval: false.

No public submitters, bundlers, paymasters, or public RPC mutation paths are registered in O.1.

## Navigation

The shell includes:

1. Welcome / First Launch
2. Unlock
3. Runtime Home
4. Identity
5. Trust
6. Ethereum Net
7. Recovery
8. Audit
9. Settings
10. Developer / Local Demo

The UI translates internal Runtime artifacts into user-facing local states rather than exposing raw collectors or unrestricted serialized objects.

## First Launch And Unlock

Supported O.1 actions:

- Create Local Phil Identity;
- Open Existing Local Identity, fixture-backed;
- Explore Local Demo;
- Authenticate Local Fixture;
- Lock session.

Restore/recover is shown as not fully supported for production recovery. Fixture authentication is labeled as fixture authentication, not production authentication.

O.2 supersedes the normal fixture identity path. The desktop normal path now creates or opens a durable encrypted local Phil identity, authenticates with a local Alpha passphrase, unlocks the encrypted local Device Vault, and exposes only sanitized summaries. See [PhilCore Desktop Local Identity And Device Vault](./PHILCORE_DESKTOP_LOCAL_IDENTITY_AND_VAULT.md).

## Runtime Home

Runtime Home displays:

- session state;
- Device Vault state;
- identity status;
- ownerCommitment short reference;
- active device;
- execution-validator public address;
- recovery-authority public reference;
- smart-account status;
- capability count;
- pending approvals;
- recent audit events;
- network mode;
- security-gate state.

No secret values are displayed.

## Local Authorization Demo

O.1 implements a guided local fixture workflow:

```text
Application Request
  -> Trust Check
  -> Policy Review
  -> User Approval
  -> Capability Activated
  -> Authorization Prepared
  -> Proof Generated
  -> Proof Verified
  -> Smart Account Operation Prepared
  -> Signed Locally
  -> Executed on Local Fixture
  -> Result Verified
```

The local demo requires Runtime-generated digest-bound approval before the execution stage and fresh-authentication evidence before the local signing step. It remains fixture-only and records sanitized audit events.

## Screens

Identity:

- local identity state;
- identity root public reference;
- ownerCommitment;
- current device;
- validator owner;
- recovery authority;
- canonical activation and World ID status as not integrated.

Trust:

- public fixture device and credential descriptors;
- provider type;
- lifecycle status;
- ordinary-use or recovery-only classification;
- last trust evaluation.

Ethereum Net:

- local fixture network;
- smart-account address;
- EntryPoint v0.7;
- approved ActionGate;
- execution owner and recovery authority;
- freeze/recovery state;
- latest local UserOperation;
- nullifier and consumer execution state.

Recovery:

- owner rotation;
- recovery request/cancel/complete;
- recovery-authority rotation request/cancel/complete;
- all local fixture only.

Audit:

- readable sanitized timeline;
- local/public classification;
- correlation references.

Settings:

- non-secret UI preferences only.

## Persistence

O.1 persists only non-secret desktop preferences. Runtime demo state is process-local fixture state. The app does not persist raw signing sessions, private keys, decrypted vault records, witnesses, proof bytes, or approval authority. O.4 approval artifacts and fresh-authentication evidence are process-local and one-time.

## Current Limitations

- no production WebAuthn prompt from the desktop app;
- no durable desktop identity/vault persistence beyond existing lower-level boundaries;
- no packaged/signed distribution;
- no public Base Sepolia mutation;
- no real public account deployment;
- no meaningful assets;
- not suitable for production.
