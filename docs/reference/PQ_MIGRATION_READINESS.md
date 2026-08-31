# Post-Quantum Migration Readiness

Status: Step 5 complete; exact second corrective candidate independently accepted

Canonical gate: [Phil V1 Step 5 Post-Quantum Migration Gate](./PHIL_V1_STEP5_POST_QUANTUM_MIGRATION_GATE.md)

## Current Cryptography

PhilCore is not currently post-quantum secure. Current classical dependencies
include:

- WebAuthn ES256/P-256 for supported authentication evidence;
- secp256k1 ECDSA for the ERC-4337 execution validator;
- ECDSA recovery authority for the current local recovery model;
- current Apple device authorization using Secure Enclave P-256 signing;
- Keccak-256 and Blake2s commitments in identity, authorization, and STWO
  boundaries.

STARK authorization evidence is useful cryptographic agility, but the current
Noir/UltraHonk reference is not PQ and does not
make the complete identity, authentication, custody, recovery, or account stack
post-quantum.

Current Apple CryptoKit documentation includes Secure Enclave ML-KEM-768/1024
key encapsulation, Secure Enclave ML-DSA-65 signing, and hybrid
ML-DSA-65/P-256 signing on supported iOS 26+ platforms. Step 5 records these as
platform-documented candidates. Phil has not integrated or device-tested them,
so the admitted device-authorization path remains classical P-256.

## What Can Remain Stable

The protected Phil identity root is independent of every current network
validator key:

```text
phil_secret -> identityRoot -> rootOwnerCommitment
```

The validator key can rotate without changing the protected root. Public
relationships retain or rotate their scoped commitments according to their
own scope epochs; one universal public `ownerCommitment` is not the migration
anchor.

The current deployed-account design is less agile:

- `PhilCore4337Account` uses one ECDSA owner validation path;
- the account is intentionally non-upgradeable;
- it has no modular validator interface;
- recovery authority is also address/ECDSA shaped.

Therefore, a future PQ validator can preserve the private Phil identity, but it cannot
simply be installed into the current account contract. It requires a new
account version, a modular account accepted through Architecture Change
Control, or migration to a new account address while retaining the same
encrypted identity continuity and explicitly migrating the affected scoped
account binding.

## Implemented Step 5 Control Plane

The local candidate now provides:

1. exact, versioned IDs for signature, key establishment, hash, symmetric,
   KDF, proof, and verifier schemes;
2. active, candidate, deprecated, retired, and forbidden lifecycle states;
3. per-network capability and evidence records;
4. classical-only, hybrid-AND, and PQ-only modes;
5. candidate non-activation and fail-closed downgrade prevention;
6. rotation, hybrid enrollment, classical retirement, and emergency-freeze
   ceremony shapes; and
7. independent recovery, device, validator, policy, and registry epochs.

The bounded corrections also bind the complete registry into every capability
and policy, bind proof/verifier compatibility, require exact trusted
capability and policy identities, validate the trusted-state format, and permit
a ceremony to move to a higher capability epoch on the same network. Active
registry bindings identify the concrete implementing source and dependency;
the Apple P-256 local-key-wrap record names ECIES cofactor/X9.63-SHA-256/
AES-GCM rather than HKDF.

The current executable bundle remains classical-only. No hybrid/PQ bundle can
be constructed from the current registry because Phil has no admitted PQ
device signature, proof, or verifier. This is the intended result.

## Remaining Migration Route

1. Implement and evaluate the documented Secure Enclave ML-DSA-65 path and its
   hybrid P-256 composition, including device custody and lifecycle behavior;
   platform documentation alone does not satisfy this requirement.
2. Evaluate exact PQ key-establishment and recovery-wrapping behavior.
3. Select and review an exact PQ proof/verifier only when implementation and
   network constraints are known.
4. Add a network-enforced hybrid-AND account path and run migration, recovery,
   downgrade, loss, corruption, replay, calldata, and cost tests.
5. Retire classical authority only through a user-approved ceremony after a
   sustained hybrid period and separate review.

No experimental PQ algorithm should be presented as production protection
before its implementation, custody, interoperability, and audit evidence exist.
