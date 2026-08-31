# O.31 V2 Three-Domain Recovery Architecture

## Superseded recovery-cancellation authority

Historical text in this document is preserved as design/audit history.
Current V2 actions 8–11 require the exact recovery-factor authority defined by
O.36.1/O.37.1. Actions 8, 9, and 11 use exact 2-of-3 current recovery factors.
Action 10 additionally requires the current validator plus exact 2-of-3 current
recovery factors. The validator never counts toward that recovery-factor
threshold, and validator-plus-one remains prohibited.

Canonical sources:

- [O.36.1 Recovery And Cancellation Semantics](./O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](./O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

Status: `RECOVERY_ARCHITECTURE_COMPLETE_LOCAL_ONLY`.

This document fixes the preferred V2 recovery model:

```text
Primary Device
  + Hardware Security Key
  + Recovery Factor
  -> exact 2-of-3 delayed validator recovery
```

The three roles are mandatory and represent independent failure domains. No
single role can request, complete, cancel, or reconfigure recovery by itself.
Recovery changes execution authority only. It cannot move assets, withdraw an
EntryPoint deposit, call a token, invoke typed execution, or create an
administrator.

## Security Objective And Limits

The control-plane objective is:

> Compromise of any one recovery domain is insufficient to take control of the
> account.

The exact V2.0 recovery threshold is two distinct role commitments out of
three. A signature cannot count twice, and two credentials on the same
primary device cannot satisfy two roles.

Initial local/test ordinary execution still uses one Device Vault secp256k1
validator under the O.30 responsibility split. Runtime requires proof,
approval, presence, exact intent, and hardware step-up for policy-classified
high-value actions. Those local checks are not all independently enforced
on-chain. Meaningful production assets remain blocked until a separately
reviewed production validator makes the required authorization composition
enforceable against a compromised execution-validator key.

## Role Definitions

### Role 0: Primary device

Purpose:

- daily local identity possession;
- protected Device Vault interaction;
- user-presence confirmation;
- one independent vote in recovery/configuration maintenance.

Required credential separation:

- the recovery credential is not the daily execution-validator key;
- it has a separate key reference, purpose, signing API, and lifecycle;
- it cannot sign ordinary UserOperations;
- it is not derived from `phil_secret`, identity root, owner commitment, or
  execution-validator material;
- production custody should be platform-hardware-backed.

Preferred implementation:

- a device-bound platform WebAuthn/P-256 credential with user verification; or
- a hardware-backed purpose key reachable only through Device Vault.

The current encrypted local ECDSA vault can model this role for local fixtures
but is not proof of hardware isolation or production custody.

Threat addressed: loss or compromise of the primary device does not provide
the hardware or recovery-factor vote. The hardware plus recovery factor can
recover to a new device and validator.

### Role 1: Hardware security key

Purpose:

- independent second-factor confirmation;
- high-value Runtime step-up;
- one independent vote in recovery/configuration maintenance.

Preferred implementation:

- external cross-platform FIDO2/WebAuthn security key;
- device-bound credential;
- non-exportable P-256 private key;
- user presence required and user verification required when supported;
- PhilCore RP ID, origin policy, owner commitment, role, account version, and
  registration challenge bound during enrollment.

Acceptable alternative:

- separately held hardware signer with non-exportable secp256k1 support and a
  PhilCore purpose-bound signing interface.

Not sufficient:

- a passkey synchronized through the same platform/cloud account as the
  primary device;
- another credential stored in the same Device Vault;
- a software key copied to the external key's host;
- a general hardware-wallet transaction-signing flow that cannot bind the
  PhilCore recovery digest.

Threat addressed: primary-device compromise alone cannot recover or
reconfigure the account.

### Role 2: Recovery factor

Purpose:

- emergency authority restoration;
- one independent vote held outside normal daily use.

Selected initial architecture:

- an independently generated recovery credential represented on-chain by a
  role-bound public commitment;
- stored either as an encrypted offline recovery package or on a separately
  trusted device;
- never stored on the primary device in decrypted or automatically usable
  form;
- never used for ordinary execution.

The package contains only the recovery credential and recovery instructions.
It must not contain `phil_secret`, the identity passphrase, the daily
validator, or a reusable account authorization.

Threat addressed: hardware-key loss is recoverable with primary device plus
recovery factor; primary-device loss is recoverable with hardware key plus
recovery factor.

## Recovery-Factor Alternatives

| Model | O.31 result | Reason |
| --- | --- | --- |
| Encrypted offline credential | selected local/test baseline | Direct cryptographic verification and strong separation when created and stored correctly; ceremony and backup risks remain |
| Secondary trusted PhilCore device | accepted preferred operational alternative | Better protected interaction and rotation UX; must not share synced key material with primary device |
| Threshold mechanism inside role 2 | future-compatible commitment type | Can reduce single-package custody risk, but adds protocol, availability, and audit scope |
| Human/social guardian alone | rejected for initial implementation | Social engineering and ambiguous identity verification |
| Managed operator recovery | rejected for production | Creates administrator/custodian risk |
| `phil_secret`-derived credential | prohibited | Couples identity-root compromise to recovery |
| Single recovery EOA | prohibited as complete recovery model | Violates three-domain threshold |

Changing the cryptographic realization of a role requires a new fixed verifier
kind or account version. It must not introduce an installable verifier module.

## Factor Commitments And Privacy

The account stores three ordered `bytes32` role commitments plus fixed
verifier-kind identifiers. It does not store raw private material.

Conceptually:

```text
factorCommitment = keccak256(
  abi.encode(
    FACTOR_COMMITMENT_TYPEHASH,
    accountVersionId,
    securityModelId,
    roleId,
    verifierKind,
    publicVerificationMaterialHash,
    rpIdHash,
    originPolicyHash,
    userVerificationPolicy,
    credentialGeneration
  )
)
```

Unused fields are not optional or silently zero-filled. Each verifier kind has
one exact descriptor schema and type hash.

On-chain state and events disclose:

- role index;
- verifier kind;
- factor commitment;
- configuration hash and epoch;
- factor bitmap used for a request/cancellation;
- transition timing and request IDs.

They do not disclose:

- local key-reference IDs;
- credential labels or device names;
- AAGUID or attestation certificate chain;
- encrypted package location;
- raw assertion/signature bytes in events;
- identity passphrase, `phil_secret`, proof witness, or private keys.

When a factor is used, the public witness required for verification appears in
transaction calldata. Commitment storage therefore protects pre-use passive
linkage, not permanent anonymity. Runtime must present this limitation during
registration.

## Hardware-Key Registration

Registration occurs before a counterfactual account is accepted for funding.
“Create Account” in the lifecycle means creating a local account
configuration/draft; deployment is not permitted with incomplete factors.

Ceremony:

1. Runtime creates a fresh registration challenge bound to owner commitment,
   account version, role, proposed chain-adapter configuration, and expiry.
2. Trusted PhilCore presentation identifies the hardware role and warns that a
   synced/platform credential does not satisfy it.
3. The external authenticator creates a new credential with user presence and
   required user verification.
4. Trust Manager verifies RP ID, origin, challenge, algorithm, credential
   public key, flags, and attestation policy.
5. Runtime records attestation evidence and credential metadata only in
   protected local storage.
6. Runtime derives the public role descriptor and commitment.
7. Runtime verifies that it differs from the primary-device and recovery
   commitments and from the execution validator.
8. The complete three-role configuration is bound into the factory/account
   creation inputs and deterministic address.

Attestation modes:

- production hardware role: explicit reviewed direct/enterprise attestation
  policy or a documented device-bound verification policy;
- local tests: fixture/permissive evidence is allowed only when marked
  non-production;
- `none` attestation cannot by itself prove cross-platform hardware
  independence.

Attestation roots, AAGUID policy, device inventory, and local trust decisions
remain off-chain. The account verifies only the accepted fixed credential
descriptor and recovery digest.

## WebAuthn/FIDO2 Assertion Design

The recovery digest is the WebAuthn challenge. The exact assertion must bind:

- `type = webauthn.get`;
- base64url challenge encoding of the recovery digest;
- accepted PhilCore origin and RP ID;
- authenticator-data RP ID hash;
- user-present flag;
- user-verified flag when required;
- fixed credential public key;
- canonical P-256 signature.

The later implementation may proceed only after selecting and testing an
accepted chain-side P-256 verification backend and bounded parser strategy.
Acceptable routes are:

1. a canonical chain-native P-256 primitive verified on the target chain; or
2. a fixed, audited, source-pinned in-account library with bounded input and
   gas behavior.

An external verifier chosen by calldata, delegatecall, mutable verifier
registry, or fallback to a same-device software key is prohibited.

Authenticator counters are monitored and persisted by Trust Manager. Recovery
replay security does not depend solely on the counter; it depends on exact
chain/account/UserOperation/request binding, EntryPoint nonce, request salt,
current configuration, epochs, timing, and state consumption. Zero or
unsupported counters must be surfaced as risk evidence.

## Recovery-Factor Creation And Storage

### Offline credential baseline

Creation:

1. use cryptographically secure random generation in a protected recovery
   ceremony;
2. create a purpose-only factor key;
3. bind the public descriptor to owner commitment, V2 version, role, and
   generation;
4. encrypt the private package with a recovery-specific secret that is not the
   identity passphrase;
5. verify a restore-and-sign test before enrollment;
6. destroy transient plaintext as far as the platform permits;
7. record only a package integrity hash and safe reference in Device Vault.

Storage:

- offline removable media or separately controlled encrypted storage;
- at least one verified backup is recommended, but copies remain the same
  role and cannot be counted twice;
- no application, renderer, repository, evidence artifact, telemetry, or
  cloud-sync default receives the package;
- no plaintext recovery secret is stored with the primary device.

Verification:

- decrypt only during a trusted recovery ceremony;
- sign one exact factor digest;
- verify public descriptor/commitment and canonical signature;
- immediately close and invalidate the local signing session.

### Secondary trusted device alternative

The secondary device generates its own non-exportable purpose credential. It
uses an out-of-band enrollment ceremony and proves the public commitment to
the primary Runtime. Shared backup, synced passkey, cloned vault, or copied
execution-validator material does not establish an independent role.

### Threshold role-2 alternative

A future role-2 threshold scheme may expose one fixed public verification
commitment while requiring multiple subparticipants off-chain. Its threshold,
coordinator, transcript, liveness, and compromise model require separate
specification and audit. It cannot change the account-wide 2-of-3 rule or
silently turn a service into an administrator.

## Recovery State Machine

```text
NORMAL
  |
  | exact 2-of-3 role authorization on nonce key 2
  v
RECOVERY_REQUESTED
  |
  | request recorded; keys 0 and 1 frozen
  v
CHALLENGE_DELAY
  |                            |
  | valid cancellation         | delay elapsed, not expired
  v                            v
CANCELLED                  COMPLETED
  |                            |
  | clear, no epoch change     | install fixed validator
  v                            | validatorEpoch + 1
NORMAL                         | recoveryEpoch + 1
                               v
                         NEW_VALIDATOR_EPOCH
                               |
                               v
                             NORMAL

CHALLENGE_DELAY -- after expiry --> EXPIRED -- exact cleanup --> NORMAL
```

State is represented by a closed discriminator, not independent booleans that
can form impossible combinations.

### Request

Required:

- state `NORMAL`;
- no pending recovery-config rotation;
- exact nonce key `2` sequence;
- exactly two distinct current role factors;
- current security-configuration hash and recovery epoch;
- proposed nonzero validator, new key-ID binding/commitment, and validator
  epoch equal to current plus one;
- fresh nonzero request salt;
- O.30 intent, Runtime authorization, chain/account/EntryPoint/UserOperation,
  maximum fee, validity, and no-asset lifecycle binding.

Effects:

- compute one deterministic request ID from the complete request and source
  state;
- set requested-at, executable-after at `+172800`, and expires-at at
  `+604800`;
- freeze lanes `0` and `1`;
- emit `RecoveryRequested`;
- make no external call and move no value.

### Challenge delay

Before `executableAfter`, completion fails. Cancellation remains available.
The request cannot be replaced, edited, accelerated, or redirected. Relayer,
bundler, validator, or caller identity does not change timing.

### Cancellation

Accepted combinations:

- any current 2-of-3 role factors;
- current validator plus hardware-security-key role;
- current validator plus independent recovery-factor role.

Rejected:

- current validator alone;
- one role alone;
- current validator plus primary-device recovery credential, because that is
  one failure domain;
- proposed validator;
- stale or proposed factor configuration;
- caller identity without the exact signed envelope.

Cancellation is allowed while the request is active, including after expiry
and before cleanup. It clears the exact request, unfreezes, changes no epoch,
makes no external call, and moves no value.

### Completion

Anyone may finalize only the exact stored request after the delay and before
expiry. The call accepts no proposed validator, recipient, amount, arbitrary
data, or factor replacement.

Completion:

- checks the request ID, state, timing, source epochs, and source
  configuration;
- clears pending state before installing new authority;
- installs only the threshold-authorized validator;
- increments validator and recovery epochs exactly once;
- unfreezes;
- emits old/new commitment and epoch evidence;
- makes no external call and moves no value.

After completion, old validator signatures and all old recovery/config
signatures fail by epoch. Device Vault activates the new validator and revokes
the old one only after receipt and state reconciliation.

### Expiry

After expiry, completion fails. Anyone may call exact expiry cleanup. Cleanup
does not install the proposed validator or change epochs. It clears the
request and unfreezes. The expired request cannot be replayed because state,
nonce, salt, timing, and epochs are bound.

## Recovery-Configuration Rotation

Factor registration after deployment occurs only through delayed replacement
of the complete three-role configuration.

Request authority:

- current execution validator; plus
- two distinct current role factors.

The current validator signature is separate and cannot also occupy role 0.
The proposed set must have exactly one commitment per role, unique public
verification material, fixed supported verifier kinds, and a new recovery
epoch equal to current plus one.

Rotation:

- is mutually exclusive with account recovery;
- blocks validator rotation;
- does not freeze ordinary execution;
- uses the same 48-hour delay and 7-day expiry;
- can be cancelled by two current factors or validator plus a non-primary
  factor;
- is completed permissionlessly to the exact stored configuration;
- increments only recovery epoch;
- makes no external call and moves no value.

Rotating one lost factor therefore proposes a complete configuration retaining
the two unchanged commitments and replacing one. If the required
cross-authorization is unavailable, there is no administrator bypass.

## Loss And Compromise Procedures

| Scenario | Safe path | Explicit limitation |
| --- | --- | --- |
| Primary device lost | hardware key + recovery factor request a new validator | account remains frozen during delay |
| Hardware key lost | primary-device factor + recovery factor, with current validator, rotate complete config | no hardware bypass; replace before another factor is lost |
| Recovery factor lost | primary-device factor + hardware key, with current validator, rotate complete config | verify new package before rotation |
| Execution validator compromised | any two roles request recovery and freeze | attacker may race typed actions before freeze inclusion |
| Primary device compromised | hardware + recovery recover; do not use compromised primary cancellation | local alerts/independent presentation required |
| Hardware key compromised | primary + recovery rotate config | compromised key can cause DoS only with another role |
| Recovery factor stolen | primary + hardware rotate config | theft plus social engineering of another role can reach threshold |
| Any two roles compromised | honest validator plus remaining non-primary role may cancel when applicable | colluding threshold can complete if not detected/cancelled |
| Two roles lost | no bypass | account may be unrecoverable; this is the cost of no hidden administrator |
| All roles unavailable | no recovery | funds may remain inaccessible |

## Rotation And Revocation

Local credential status is not chain authority.

Safe order:

```text
create and verify replacement credential
  -> mark replacement pending
  -> construct exact complete configuration
  -> obtain cross-authorization
  -> request delayed rotation
  -> monitor and allow cancellation
  -> finalize exact request
  -> verify receipt, configuration hash, role commitments, and epoch
  -> activate replacement locally
  -> revoke/archive old local credential
```

If request, completion, or verification fails, the current credential remains
active locally. Revocation never deletes the last locally recoverable copy
before verified on-chain replacement.

Hardware-key revocation includes removing its Trust Manager credential after
verified configuration change. Attestation or local credential revocation
alone cannot alter the account.

Offline-package revocation includes securely destroying known copies after
verified replacement. Destruction cannot be proven globally, so the recovery
epoch is the cryptographic invalidation boundary.

## Audit And Notification

Runtime records sanitized local events for:

- registration and independence checks;
- factor status changes;
- recovery/config request, cancellation, expiry, and completion;
- trusted presentation and participating role IDs;
- expected/observed chain state and epochs;
- hardware counter warnings;
- failed or suspicious attempts.

Notifications must show raw account/chain/commitment/request identifiers,
proposed validator, timing, and the statement “recovery moves no assets.”
Untrusted application labels cannot replace raw identifiers.

Notification infrastructure is advisory. It has no signing, cancellation,
completion, or asset authority.

## Security Invariants

1. Exactly three fixed roles exist and threshold is exactly two.
2. One physical/security domain cannot be counted twice.
3. The daily execution-validator key is not a recovery role.
4. Recovery factors are independent of `phil_secret` and owner commitment.
5. Recovery changes only validator authority and epochs.
6. Recovery/config transitions make no external calls and move no value.
7. Active recovery freezes ordinary and validator-maintenance lanes.
8. Completion installs only exact previously authorized pending state.
9. Cancellation, expiry, and completion consume the exact request.
10. Old configuration and epoch authority cannot replay.
11. Factor configuration changes are delayed and cross-authorized.
12. No hidden administrator, operator, guardian shortcut, or override exists.
13. Post-recovery asset movement requires a fresh ordinary intent, proof,
    approval, presence, validator signature, and public-mutation approval.
14. Funding is prohibited until the complete create-through-release lifecycle
    passes locally and on a fork.

## Stop Boundary

O.31 registers no real credential, creates no recovery package, requests no
WebAuthn assertion, touches no Device Vault secret, signs no digest, creates no
UserOperation, deploys no account, and mutates no public state.
