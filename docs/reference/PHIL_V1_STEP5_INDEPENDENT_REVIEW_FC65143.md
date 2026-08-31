# Phil V1 Step 5 Independent Review: `fc65143`

Status: Rejected; bounded corrective candidate required

Date: 2026-08-22

## Exact target

```text
candidate commit: fc6514394f5f1ff540c10ac87704a3c24e5f3a4b
candidate tree:   3a5c17ce0c81cf1063fd3c64ab47f1ca360c05c5
candidate parent: 15e175448fa7e19191e6c2895d184f1ebbf86e7b
```

The reviewer verified the exact identities and confirmed that current HEAD
differed only by the later review packet. The review was read-only and left the
working tree clean.

## Blocking findings

1. **Apple ML-DSA classification was stale.** Current Apple CryptoKit
   documentation demonstrates Secure Enclave ML-DSA-65 signing and hybrid
   ML-DSA-65/P-256 signing on supported iOS 26+ platforms. The candidate
   incorrectly labeled ML-DSA-65 specification-only and stated that Secure
   Enclave ML-DSA signing was undocumented. This is platform evidence only;
   Phil integration and physical behavior remain unverified.
2. **Capability migration was impossible.** A ceremony validated both bundles
   against one capability object and then required their capability hashes to
   match. A classical policy therefore could not migrate to a later capability
   epoch or hybrid-enforced record on the same network.
3. **Registry identity was not policy-bound.** Network and policy hashes bound
   scheme IDs and an epoch, but not the complete registry hash. Changing a
   scheme implementation/classification changed the registry hash while
   leaving existing bundle identity unchanged.
4. **Proof/verifier compatibility was unbound.** Independent proof and verifier
   set membership did not prove that the chosen verifier accepted the chosen
   proof system, circuit, codec, or parameter set.
5. **Freshness/provenance was caller-relative.** Self-consistent stale network
   records could pass without a trusted expected registry/capability hash or
   greatest-accepted epoch floor.

## Passing evidence

- exact commit, tree, and parent matched;
- TypeScript validation passed;
- all 11 focused tests passed;
- deterministic artifact verification and diff check passed;
- all documented registry, source, fixture, capability, bundle, and ceremony
  hashes were independently recomputed;
- Step 2 recovery remained exact encrypted 2-of-3 key unwrapping;
- Noir/UltraHonk and Garaga remained classical;
- STWO remained forbidden; and
- no runtime, device, signer, prover, RPC, deployment, transaction, or
  publication authority was found.

Passing evidence did not cure the five architecture findings.

## Verdict

```text
REJECT_STEP_5_EXACT_CANDIDATE
CURRENT PHIL CLAIM: ALGORITHM AGILE ONLY
WHOLE-SYSTEM POST-QUANTUM: NO
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
START STEP 6: NO
```

Primary sources used by the independent reviewer:

- [Apple quantum-secure workflows](https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows)
- [Apple Secure Enclave ML-DSA-65 signing](https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa65/privatekey/signature%28for%3A%29)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547 initial public draft](https://csrc.nist.gov/pubs/ir/8547/ipd)
