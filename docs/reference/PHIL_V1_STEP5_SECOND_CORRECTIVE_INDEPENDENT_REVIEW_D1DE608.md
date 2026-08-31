# Phil V1 Step 5 Second Corrective Independent Review: `d1de608`

Status: Accepted exact local architecture candidate

Date: 2026-08-22

## Exact target

```text
candidate commit: d1de6082f01756d68f7c732d0c3e8fe3d47d6c96
candidate tree:   6987606552bf75b9116f618d87157857659bc387
candidate parent: d1c94c629ba8152799d6a994a45d28b7af3ad9a2
```

The reviewer verified these identities and reviewed the candidate rather than
the later packet commit. The review was read-only and left the repository
clean.

## Findings

No unresolved critical, high, medium, or low security, correctness,
semantic-binding, freshness, provenance, compatibility, downgrade, recovery,
artifact, or authority-boundary finding was identified.

## Corrective-finding adjudication

### Semantic implementation binding: closed

- The secp256k1 record binds exact blob `6da1f68e5a039c99245517fa647df0ac39a81c85`,
  whose source constructs the Keccak ceremony digest, enforces canonical
  low-S/range/v checks, and executes public-key recovery through locked Ethers
  6.17.0.
- The SHA-256 record binds exact blob
  `e59264255b0abdc51f488f5565e15dd6fd776088`, which contains concrete Ethers
  SHA-256 calls.
- The P-256 local-key-wrap record names and binds the exact accepted Apple
  `SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM` behavior in Step 2
  blob `78391d7e93bda3ab390134ec4eae6f380833b8cc`.
- Every referenced commit, blob, dependency-lock identity, path, function, and
  evidence level matched. The reviewer also checked every other active record
  and found no algorithm-to-artifact mismatch or overclaim.
- The obsolete Step 5 P-256 ECDH/HKDF scheme ID is absent from current Step 5
  source, fixture, generator, tests, manifest, and current architecture docs.

### Exact policy trust: closed

Trusted state binds the exact accepted policy epoch and exact expected policy
hash, with both fields included in its domain-separated hash. Policy creation
and validation require exact equality.

Independent reproductions confirmed:

- epoch `999` creation, validation, and claim assessment reject with
  `PHIL_PQ_POLICY_EPOCH_UNTRUSTED`;
- a different same-epoch policy rejects across all three paths with
  `PHIL_PQ_POLICY_UNTRUSTED`;
- substituted old/new policies reject during migration; and
- the exact old/new fixture policies under their respective trusted states
  reproduce the expected ceremony hash.

The explicitly untrusted policy-hash derivation helper returns only a candidate
hash. It cannot enter validation, claim assessment, or migration without an
independently supplied trusted-state record that pins the exact hash.

### Trusted-state format tampering: closed

Validation compares the caller-supplied format against the exact V1 domain
before reconstruction. Forged, missing, malformed, short, zero, unknown,
future-version, and alternate-case values all rejected with
`PHIL_PQ_TRUSTED_STATE_FORMAT_MISMATCH` through trusted-state, capability,
policy, claim, and migration paths.

## Earlier closures retained

- Apple Secure Enclave ML-DSA-65, ML-KEM-768/1024, and hybrid ML-DSA/P-256
  remain platform-documented candidates, not Phil-integrated authorization.
- Distinct higher-epoch same-network capability migration succeeds while
  authority substitution, cross-network migration, unchanged-epoch mutation,
  and rollback reject.
- The exact classical Step 3 Noir/Garaga pair remains mutually compatible and
  bound.
- All 17 scheme records remain unique and internally consistent.
- Candidate proof/verifier entries cannot activate, and STWO remains forbidden
  and unreachable.
- Recovery remains encrypted exact 2-of-3 key unwrapping.
- Current network records remain classical-only, and the epoch-2 capability
  remains explicitly synthetic.

## Reproduced evidence

```text
git diff --check
PASS

npm run typecheck
PASS

npm run verify:phil-v1-step5-artifacts
PASS

npm run test:phil-v1-step5-pq-migration
14 passing

npm run test:phil-v1-step3-root-proof-adapter
4 passing

npm run test:phil-v1-step4-composed-account
3 passing
```

Independent recomputation matched:

```text
scheme count:              17
registry hash:             0xc8c047f325c09f68c50795a4f261b87ed2b5ca0a3a99e669e632727389b87b79
source SHA-256:            d5354fbbb1fb869ba5decbfc79fa5c6ee7de6b8deda59d2590ef22cf08b25d28
fixture SHA-256:           49f01a397dffd54d999bee7cfa0da59e53eb0f71e2f51d5f2367d2e87249d72d
current policy hash:       0x164911292409b4daf8c2f2838516bab2630c1ac1d64d80240aedf80ee862039d
target policy hash:        0x2b1171b0a45024c9064ac1956955d1e45adf9c3c1258fa0f18ff91424e2b9e8c
rotation ceremony hash:    0x310276cbd83c00afbb3c32a19b3e21dec6d7ee1518b431f903e7767382ae8141
```

The fixture and manifest were exact and mutually consistent. No non-test or
runtime consumer reached the Step 5 module.

## Limits and authority boundary

The checks used the already-installed Node 26.5.1/npm 11.17.0 environment
rather than the repository's declared exact Node 26.0.0/npm 11.12.1 pair. No
dependencies were installed. This was accepted as a disclosed reproduction
limitation, not a candidate regression.

No physical device, secret, signer, external prover, RPC, deployment,
transaction, publication, production-backend selection, or Step 6 activity
occurred. Protected production trusted-state persistence, Phil PQ device
integration, and a formal cryptographic audit remain unverified future work.

## Verdict

```text
ACCEPT_SECOND_CORRECTIVE_STEP_5_EXACT_CANDIDATE
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```

Primary sources checked by the independent reviewer:

- [Apple quantum-secure workflows](https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows)
- [Apple ECIES cofactor X9.63 SHA-256 AES-GCM](https://developer.apple.com/documentation/security/seckeyalgorithm/eciesencryptioncofactorx963sha256aesgcm)
- [Ethers cryptographic functions](https://docs.ethers.org/v6/api/crypto/)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547 initial public draft](https://csrc.nist.gov/pubs/ir/8547/ipd)
