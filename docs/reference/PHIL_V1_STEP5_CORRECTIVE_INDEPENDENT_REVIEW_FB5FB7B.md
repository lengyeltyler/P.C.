# Phil V1 Step 5 Corrective Independent Review: `fb5fb7b`

Status: Rejected; second bounded corrective candidate required

Date: 2026-08-22

## Exact target

```text
candidate commit: fb5fb7bdf1ada9e142079086ee829a9e96af081d
candidate tree:   bec2fff0d3415dbebc0a8ee255be179c7c1b2875
candidate parent: 18b3cef30d9a27a3a3f80a3d849a17fac231b9df
```

The reviewer verified these identities and reviewed the candidate rather than
the later packet commit. The review was read-only and left the repository
clean.

## Blocking findings

1. **Active implementation bindings were semantically inaccurate.** The
   P-256 key-establishment record claimed ECDH/HKDF but bound Apple
   `eciesEncryptionCofactorX963SHA256AESGCM`; the SHA-256 record bound a
   Keccak-only source file; and the secp256k1 record bound a fixture/abstract
   validator that did not execute secp256k1 verification. The Git identities
   existed, but the bound artifacts did not implement the named schemes.
2. **Unknown future policy epochs passed trusted validation.** A trusted policy
   floor of 1 accepted and claim-assessed a self-consistent policy at epoch
   999 because validation rejected only lower epochs.
3. **Trusted-state format tampering passed.** Validation rebuilt the trusted
   state under the built-in format constant without first checking the
   caller-supplied `formatVersionHash`.

Original findings 1, 2, and 4 were closed. Original findings 3 and 5 remained
open for the reasons above.

## Passing evidence

- exact commit, tree, and parent matched;
- all 14 focused Step 5 tests passed;
- Step 3 and Step 4 regression tests passed;
- TypeScript validation, artifact verification, and diff checking passed;
- all 17 scheme IDs and every manifest hash independently recomputed;
- Apple ML-DSA classification, same-network capability migration, and exact
  proof/verifier compatibility were corrected;
- recovery remained encrypted exact 2-of-3 key unwrapping;
- current networks remained classical-only;
- STWO remained forbidden and unreachable; and
- no runtime, device, signer, prover, RPC, deployment, transaction,
  publication, backend-selection, or Step 6 authority was found.

Passing evidence did not cure the three reproduced defects.

## Verdict

```text
REJECT_CORRECTIVE_STEP_5_EXACT_CANDIDATE
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```

Primary sources used by the independent reviewer:

- [Apple quantum-secure workflows](https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows)
- [Apple Secure Enclave ML-DSA-65 signing](https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa65/privatekey/signature%28for%3A%29)
- [Apple ECIES cofactor X9.63 SHA-256 AES-GCM](https://developer.apple.com/documentation/security/seckeyalgorithm/eciesencryptioncofactorx963sha256aesgcm)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547 initial public draft](https://csrc.nist.gov/pubs/ir/8547/ipd)
