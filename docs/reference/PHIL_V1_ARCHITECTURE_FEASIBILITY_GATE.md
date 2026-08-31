# Phil V1 Architecture Feasibility Gate

Status date: 2026-08-21

Status: evidence record; not production approval and not an accepted
architecture change

## Executive Verdict

```text
PHIL PRODUCT VISION: FEASIBLE
CURRENT STWO PRIVATE AUTHORIZATION PATH: PROHIBITED
STARKNET AS A NETWORK ADAPTER: FEASIBLE WITH COST AND COMPOSITION GATES
TARGET-PHONE WITNESS-HIDING PROVING: PROMISING; PHYSICAL DEVICE UNVERIFIED
SAME-IDENTITY AND DATA RECOVERY: FEASIBLE; PRODUCTION CEREMONY UNFINISHED
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC-NETWORK DEPLOYMENT AUTHORIZED: NO
```

The failed privacy property belongs to the current STWO artifact, not to
Phil's product model. Phil remains viable as a device-first personal security
operating system with a private, recoverable identity root, encrypted
user-controlled data, hardware-backed device approval, scoped public
identities, policy and capability enforcement, and network-specific execution
adapters.

The proposed architecture correction and ordered implementation gates are in
[ACP-0003](../architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md).

## Evidence Classification

This record separates four kinds of evidence:

1. **Verified repository evidence** is present in this source tree and its
   tests or security records.
2. **Isolated prototype evidence** was produced with synthetic secrets outside
   the product source tree. It establishes feasibility, not production safety.
3. **Upstream evidence** comes from primary project, platform, or standards
   documentation.
4. **Unverified claims** remain explicit gates and must not be promoted to
   implemented or production-ready status.

No prototype run used a real Phil secret, physical iPhone, external prover,
contract deployment, transaction submission, public-network mutation, or
production-source modification.

## Gate 1: Witness-Hiding Proof Feasibility

### Verified repository evidence

The pinned `stwo-unlock-keccak-v1` artifact is not witness hiding. Its queried
trace openings recover the witness bits. The current tree therefore confines
it to explicit process-local synthetic research and rejects Device Vault
witnesses, finalization, publication, adapter preparation, and execution.

Authoritative current records:

- [Witness-Hiding Proving-Stack Requirements](./WITNESS_HIDING_PROVING_STACK_REQUIREMENTS.md)
- [Pre-MVP Security Findings](../security/PRE_MVP_SECURITY_FINDINGS.md)
- [ACTION_UNLOCK Proof Specification](./ACTION_UNLOCK_PROOF_SPEC.md)

### Isolated circuit evidence

An exact-compatible synthetic Phil identity and nullifier relation was
implemented in Noir and Barretenberg. The private inputs were `phil_secret`
and `nullifierSeed`; the public relation bound the owner commitment, action,
policy, and nullifier.

Measured on the isolated desktop prototype:

- Noir `1.0.0-beta.26` and Barretenberg `5.2.0`;
- approximately `0.55 s` proving with an existing verification key;
- approximately `167 MiB` peak resident memory;
- `9,152`-byte proof;
- successful independent native and generated-Solidity verification;
- wrong secret, owner commitment, action, and nullifier cases rejected;
- repeated proofs randomized; and
- neither synthetic private literal appeared directly in serialized artifacts.

The last two checks are regression evidence, not an independent proof of zero
knowledge. The deliberately naive Solidity public encoding measured `938,650`
gas and is not a production cost target.

### Target-phone evidence

A native arm64 Barretenberg wrapper generated the packed synthetic proof in an
iPhone Simulator. A fresh run measured approximately `2.878 s` and reported
approximately `163 MiB` during proving.

This does **not** establish physical-iPhone performance. Simulator execution
uses Mac hardware and does not establish iOS memory pressure, battery cost,
thermal behavior, interruption handling, older-device support, or secure
composition with the Device Vault.

Gate result:

```text
TARGET-PHONE WITNESS-HIDING PROOF: CONDITIONALLY FEASIBLE
PHYSICAL IOS PROVING: UNVERIFIED
```

### Comparator evidence

An isolated RISC Zero `3.0.5/3.0.6` implementation verified the same synthetic
core relation and negative cases. It measured approximately `20-22 s`,
`2.31 GiB` peak resident memory, and a `256,986`-byte receipt. EVM compression
was not demonstrated. It remains a fallback comparator, not the preferred
mobile route.

## Gate 2: Starknet Verification And Account Composition

Starknet supports native account abstraction and custom account validation.
Garaga supports Noir Ultra Keccak ZK Honk verifier generation for Cairo and
Starknet:

- [Starknet accounts](https://docs.starknet.io/learn/protocol/accounts)
- [Garaga source and verifier support](https://github.com/keep-starknet-strange/garaga)
- [Garaga security status](https://garaga.gitbook.io/garaga/security)

The isolated Starknet-compatible prototype required the versions pinned by
Garaga rather than the newer desktop prototype. With that compatibility set:

- an exact packed proof was `9,408` bytes;
- public inputs were `256` bytes;
- the verification key was `1,888` bytes;
- proof generation measured approximately `0.95 s` and `232-240 MiB` locally;
- Garaga generated an approximately `8,362`-line Cairo verifier;
- the verifier compiled successfully;
- proof calldata contained `3,061` felts; and
- a positive verifier test passed against a read-only Sepolia state fork at
  approximately `270,576,970` L2 gas.

No verifier was declared or deployed, and no transaction was submitted. The
measured cost rules out proving every ordinary user action as the efficient
architecture. Garaga's documented audit covers core operations and Groth16;
it must not be overstated as a Phil-specific or Honk-specific production
audit.

The efficient composition is:

- root proof for identity/account enrollment, recovery, validator rotation,
  major policy changes, and high-risk capability issuance;
- separate hardware-backed device signature for user/device approval; and
- scoped, expiring capabilities plus account-enforced policy, nonce, expiry,
  limits, and revocation for routine actions.

The complete `proof + enrolled device signature + policy + nonce + expiry +
revocation` account transaction has not yet been demonstrated.

Gate result:

```text
STARKNET VERIFICATION: TECHNICALLY FEASIBLE
PROOF ON EVERY TRANSACTION: REJECTED
COMPOSED ACCOUNT AUTHORIZATION: UNVERIFIED
```

## Gate 3: Same-Identity And Data Recovery

An isolated synthetic prototype separated account recovery from recovery of
the Phil identity and encrypted user data:

1. Generate a random backup-encryption key and a separate data-encryption key.
2. Authenticated-encrypt the Phil identity package under the backup key.
3. Authenticated-encrypt user data under the data key.
4. Split only the backup-encryption key into a user-controlled `2-of-3` share
   set.
5. Restore the identity package, verify its canonical owner binding, and then
   restore the encrypted data.

Every valid two-share pair restored the exact original identity and data. The
prototype rejected one share, mixed recovery sets, corrupted identity
packages, corrupted user data, wrong recovery-set associated data, and owner
commitment mismatch. It printed neither the synthetic secret nor shares.

The model follows the structure of
[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md).
Its reference implementation is a correctness reference rather than a
production-hardened or side-channel-reviewed Phil ceremony.

Production still requires hardened implementation, physical-device ceremony,
share replacement, revocation, anti-rollback behavior, loss scenarios,
notifications, and independent review.

Gate result:

```text
SAME-IDENTITY AND DATA RECOVERY: FEASIBLE
PRODUCTION RECOVERY CEREMONY: UNVERIFIED
```

## Privacy And Data-Control Correction

Publishing one universal `ownerCommitment` across every network, app,
credential, and agent would create a cross-context correlation identifier.
The canonical root relationship may remain stable internally, but public
integration should use domain-separated, scoped commitments or pseudonymous
identifiers. Phil should prove common-root control across scopes only when the
user deliberately links them.

This aligns with the W3C DID privacy guidance to use pairwise identifiers to
reduce correlation:

- [W3C DID Core correlation risks](https://www.w3.org/TR/did/#did-correlation-risks)
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)

User data should be encrypted locally under user-controlled keys. Storage may
be local or user-selected remote/decentralized storage, but providers receive
ciphertext and minimal metadata. Public networks receive commitments,
revocation/status material, and minimal proofs rather than personal data.
Phil cannot revoke plaintext already copied by a recipient or erase data
deliberately published to an immutable public network.

## Device Trust And Post-Quantum Constraints

Apple's Secure Enclave creates non-exportable P-256 keys and cannot import an
existing Phil root. A production design should use an enclave-generated device
approval/wrapping key with explicit user presence while keeping the Phil root
inside an authenticated encrypted vault:

- [Apple Secure Enclave key protection](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)
- [Apple App Attest](https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity)

App Attest may provide server-side app-instance evidence. It is not Phil's
identity or recovery authority: it depends on Apple/server validation and its
key does not survive reinstall, device migration, or backup restoration.

Phil is not post-quantum secure today. NIST has standardized ML-KEM, ML-DSA,
and SLH-DSA, but current device, account, recovery, and proof paths still
contain classical cryptography:

- [NIST post-quantum standards announcement](https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved)
- [Post-Quantum Migration Readiness](./PQ_MIGRATION_READINESS.md)

The identity root must remain independent of validator and proof schemes.
Each network adapter should version its accepted signature and proof schemes,
support hybrid classical/PQ migration where the network permits it, and avoid
claiming network-level PQ protection on networks that cannot enforce it.

## Current Stop Conditions

Until the ordered gates in ACP-0003 are completed:

- STWO remains outside every real-secret and authorization path;
- no production proof backend is selected;
- no global public identity commitment is approved for cross-network use;
- no physical-device proving claim is allowed;
- no recovery ceremony is production approved;
- no Starknet or Ethereum/Base deployment is authorized; and
- no full post-quantum claim is allowed.
