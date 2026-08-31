# Phil V1 Step 5 Post-Quantum Migration Gate

Status: Complete; exact second corrective local candidate independently accepted

Date: 2026-08-22

## Decision

Step 5 freezes an algorithm-agile migration control plane. It does not make
Phil post-quantum secure and does not activate a PQ algorithm.

```text
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
HARDWARE PQ DEVICE AUTHORIZATION: NO
NETWORK-ENFORCED HYBRID/PQ PATH: NO
PRODUCTION PROOF BACKEND SELECTED: NO
STEP 5 ACCEPTED: YES - LOCAL ARCHITECTURE GATE ONLY
START STEP 6: NO
```

The canonical executable boundary is
`apps/phil-device-sdk/src/postQuantumMigrationV1.ts`. Its deterministic
fixture and hashes are in
`config/cryptography/PHIL_V1_STEP5_PQ_MIGRATION_FIXTURE.json` and
`PHIL_V1_STEP5_ARTIFACT_MANIFEST.json`.

## Frozen Registry

Every ID is `keccak256(utf8(exact label))`. An implementation, encoding,
parameter set, or verifier cannot change under an existing ID.

| Kind | Scheme | State | Quantum posture | Evidence |
| --- | --- | --- | --- | --- |
| Signature | P-256/SHA-256 | active reference | vulnerable | Step 2 independently reviewed |
| Signature | secp256k1/Keccak-256 | active reference | vulnerable | local implementation |
| Signature | ML-DSA-65 | candidate | resistant primitive | Apple Secure Enclave platform documented; not Phil verified |
| Signature | SLH-DSA-SHA2-128s | candidate | resistant primitive | specification only |
| Key establishment | P-256 ECIES cofactor/X9.63-SHA-256/AES-GCM local-key wrap | active reference | vulnerable | Step 2 independently reviewed |
| Key establishment | ML-KEM-768 | candidate | resistant primitive | Apple platform documented; not Phil verified |
| Key establishment | ML-KEM-1024 | candidate | resistant primitive | Apple platform documented; not Phil verified |
| Hash | SHA-256 | active reference | resistant primitive with quantum security reduction | local implementation |
| Hash | Keccak-256 | active reference | resistant primitive with quantum security reduction | independently reviewed boundary |
| Symmetric | AES-256-GCM | active reference | resistant primitive with quantum security reduction | independently reviewed boundary |
| KDF | HKDF-SHA-256 | active reference | resistant primitive with quantum security reduction | independently reviewed boundary |
| Recovery protection | pairwise HKDF/AES-256-GCM exact 2-of-3 | active reference | resistant composition with quantum security reduction | Step 2 implemented/reviewed; not externally audited cryptography |
| Proof | Step 3 Noir/UltraHonk/Keccak | active reference | vulnerable | independently reviewed local reference |
| Proof | transparent hash-STARK | reserved candidate | unassessed | exact instantiation absent |
| Proof | STWO experimental | forbidden | unassessed | witness-leaking path quarantined |
| Verifier | Step 3 Garaga 1.0.1 | active reference | vulnerable | independently reviewed local reference |
| Verifier | transparent STARK verifier | reserved candidate | unassessed | artifact absent |

NIST standardized ML-KEM, ML-DSA, and SLH-DSA in
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), and
[FIPS 205](https://csrc.nist.gov/pubs/fips/205/final). Standardization of a
primitive is not evidence that Phil's custody, recovery, proof, verifier, or
network path correctly implements it. NIST's transition plan remains a draft
in [IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd).

## Security Modes

- `CLASSICAL_ONLY`: only admitted classical signature, key-establishment,
  proof, and verifier components may be active.
- `HYBRID_AND`: device and validator authorization use admitted classical and
  PQ signature components with fail-closed AND semantics; key establishment
  is hybrid; recovery uses an admitted quantum-resistant protection suite; and
  proof and verifier are admitted PQ components.
- `POST_QUANTUM_ONLY`: all required components are admitted PQ schemes and the
  classical components have been retired through a later ceremony.

`signatureCombiner = all` applies inside each configured device/validator
hybrid signature set. It does not replace the separate recovery factor
threshold or turn the encrypted continuity package into a multisig.
Classical OR PQ acceptance is forbidden because it permits downgrade to the
weaker path.

A `SPECIFIED_CANDIDATE`, `RETIRED`, or `FORBIDDEN` record cannot be activated
in a policy bundle. The present registry therefore cannot construct a hybrid
or PQ policy. That failure is intentional: Phil has no admitted PQ device
signature, proof, or verifier today.

## Apple Device Boundary

Current Apple CryptoKit documentation exposes Secure Enclave ML-KEM-768/1024
key encapsulation, Secure Enclave ML-DSA-65 signing, and hybrid
ML-DSA-65/P-256 signing on supported iOS 26+ platforms in its
[quantum-secure workflow](https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows).
This improves the feasible route for hardware-backed PQ key wrapping on
supported Apple platforms and documents a feasible PQ device-signature route.
It is platform documentation, not Phil integration or device evidence.

Phil therefore records:

- Secure Enclave P-256 as the current admitted device signature;
- Secure Enclave ML-DSA-65 as a candidate signature capability;
- Secure Enclave ML-KEM-768/1024 as candidate key-establishment capabilities;
- no verified Phil ML-DSA or ML-KEM integration; and
- no hardware-backed PQ device-authorization claim.

Device authorization becomes hybrid only after Phil implements the exact
documented PQ signing path and its
key custody behavior, lifecycle, recovery, interoperability, and independent
review are admitted. ML-KEM alone cannot authorize an action.

## Registry, compatibility, and trusted state

Every network capability now binds the exact registry epoch and complete
registry hash. Every policy binds both again. The registry hash covers each
record's standard, exact implementation/artifact binding, lifecycle, evidence,
quantum posture, and compatible proof IDs. A scheme implementation or
classification change therefore changes the registry, capability, and policy
identities even if a short scheme ID remains unchanged.

Proof-verifier compatibility is explicit. A verifier record lists the exact
proof scheme IDs it accepts; both network and policy construction reject an
independently present but incompatible pair. Signature verification is not
misclassified as a proof verifier.

Self-consistency is insufficient. Validation requires a protected trusted
state containing:

- the admitted registry epoch and hash;
- the network ID and capability-authority hash;
- the greatest accepted capability epoch and exact expected capability hash;
- the exact accepted policy epoch and exact expected policy hash; and
- a deterministic trusted-state hash.

Older or unknown-future epochs, an unexpected capability or policy hash, an
untrusted authority/network, or a tampered trusted-state format/hash fail
closed. Production must persist this state in the protected runtime; the Step
5 fixture supplies only a disclosed synthetic example and grants no authority.

## Per-Network Records

Each record binds a network, epoch, account model, accepted scheme sets,
maximum security mode, implementation/evidence hashes, and whether the full
authorization path is actually available.

| Network | Current record | Maximum mode | Live authorization path |
| --- | --- | --- | --- |
| Starknet Sepolia | Step 4 local contract candidate using P-256 + Step 3 proof/verifier | classical only | no |
| Base mainnet | local ERC-4337 preparation; no Step 5 proof/verifier admitted | classical only | no |

Starknet supports programmable account validation, but that capability does
not establish Phil's PQ implementation or deployment. See
[Starknet accounts](https://docs.starknet.io/learn/protocol/accounts).
Likewise, [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) permits smart
account validation logic but supplies no automatic PQ guarantee.

A record may claim hybrid/PQ only when it is network-enforced and its active
signature, proof, and verifier sets satisfy that mode. An available path also
requires network-enforcement evidence. Local policy is never relabeled as a
network guarantee.

## Migration Ceremonies

Every transition binds the old and new policy bundles, old and new network
capability hashes, old and new trusted-state hashes, registry and policy
epochs, device/validator/recovery epochs, new key set, user approval, recovery
approval, independent review, activation window, and emergency freeze state.

Supported ceremony kinds are:

1. enroll classical-to-hybrid;
2. rotate all authorities within one mode;
3. retire classical only after hybrid-to-PQ transition evidence; and
4. emergency migrate and freeze.

The registry, capability, trusted-state floors, and security mode cannot move
backward. A changed capability record on the same network requires a higher
capability epoch; cross-network ceremonies and capability-authority rotation
are rejected. The policy epoch increments exactly once, and device, validator,
and recovery epochs each increment exactly once. Emergency migration must
freeze; ordinary migration cannot silently enable the emergency flag.

Recovery remains a separate 2-of-3 key-unwrapping authority. A migration must
rotate its policy and factor material independently; a device or validator
key cannot silently become recovery authority.

## Evidence Required To Advance A Claim

Before `HYBRID_AND` can be activated, all of the following are required for an
exact candidate:

1. admitted and independently reviewed PQ device-signature implementation;
2. admitted and independently reviewed PQ key-establishment implementation;
3. admitted and independently reviewed PQ proof and verifier;
4. network-enforced hybrid-AND account path;
5. independent recovery rotation and restoration evidence;
6. downgrade, rollback, retirement, loss, corruption, and replay tests; and
7. separate publication and production authorization.

Even then, the claim is scoped to the reviewed platform, account, network,
recovery configuration, proof system, and release. `wholeSystemPostQuantum`
remains false in this Step 5 model.

## Independent Review Result

The independent reviewer reproduced:

```text
npm run typecheck
npm run test:phil-v1-step5-pq-migration
npm run verify:phil-v1-step5-artifacts
git diff --check
```

The review verified every scheme identity and classification, Apple
ML-DSA/ML-KEM evidence, registry binding, exact proof/verifier compatibility,
trusted provenance/freshness, both current network records, same-network
capability migration, candidate non-activation, STWO prohibition, AND-only
semantics, downgrade guards, ceremony epoch rules, deterministic hashes, and
the absence of runtime/device/network authority.

Exact candidate `d1de6082f01756d68f7c732d0c3e8fe3d47d6c96` received
`ACCEPT_SECOND_CORRECTIVE_STEP_5_EXACT_CANDIDATE` with no unresolved finding.
See [the independent acceptance record](./PHIL_V1_STEP5_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D1DE608.md).
