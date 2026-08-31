# O.38 Recovery Enrollment Readiness

Status: `NOT_READY_WAIT_FOR_REAL_THREE_DOMAIN_ENROLLMENT`.

The Runtime contains durable identity and Device Vault foundations,
platform-authentication and user-presence flows, V2 descriptor/hashing
libraries, deterministic fixture generators, and local recovery custody
diagnostics. These components prove schema and local test behavior. They do
not prove three independent production enrollments.

## Role status

| Role | Existing capability | Missing production work |
| --- | --- | --- |
| Primary Device | local identity, protected Device Vault session, platform presence, fixture descriptor support | create a distinct recovery-only credential, prove hardware custody, bind registration challenge/origin/RP/owner/version/role, persist protected metadata, and exercise rotation/loss ceremony |
| Hardware Security Key | WebAuthn/P-256 verification model and deterministic evidence fixtures | external cross-platform key enrollment UI/API, attestation/device-bound policy, independence check, credential counter policy, protected metadata lifecycle, and end-to-end real assertion test |
| Independent Recovery Factor | specification, offline-custody model, local synthetic custody diagnostics | production generation ceremony, separately trusted/offline storage, backup and restore drill, purpose-bound signing, compromise/loss handling, and independence verification |

Before a recoverable account is created, Runtime must:

1. enroll all three roles through fresh, purpose-bound challenges;
2. verify descriptor schema, public material, RP/origin policy, user
   verification policy, and required independence;
3. derive three nonzero, distinct public commitments;
4. persist only protected references and necessary public metadata;
5. reproduce the exact configuration hash;
6. exercise two valid 2-of-3 combinations and reject each single factor;
7. present loss, privacy, calldata-disclosure, delay, expiry, and rotation
   warnings to the user.

A temporary unrecoverable account is not permitted by the current policy.
The account and factory reject zero or duplicate commitments, O.31 makes all
three domains mandatory, and there is no separately approved disposable V2
account exception. Synthetic O.37.10 factors cannot be substituted.

Sepolia account deployment must wait. No credential enrollment or production
recovery signature occurred in O.38.
