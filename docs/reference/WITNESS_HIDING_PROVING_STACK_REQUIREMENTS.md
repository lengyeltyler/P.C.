# Witness-Hiding Proving-Stack Requirements

Status: Active backend-admission support for the accepted exceptional
root-proof contract. No backend is selected.

## Current Decision

The current pinned STWO proof is not witness hiding. Every `phil_secret` bit is
copied into a trace column at every row, and the proof serializes authenticated
queried values from those columns. One proof therefore recovers the full
secret. Fiat-Shamir query placement, repeated proof generation, and deleting
fields from the outer serialization do not fix the construction.

The retained prover is synthetic research code only. It must not be used with a
real Phil secret, exported, transmitted, finalized, published, or accepted by
an adapter or execution path.

## Replacement Architecture Gate

A replacement may restore the product path only after all of the following are
specified, implemented, and independently reviewed:

- a supported zero-knowledge or witness-hiding trace-encoding construction,
  including the required random masking rows or polynomials and their AIR
  constraints;
- a cryptographically secure randomness source, explicit failure behavior, and
  proof-generation tests that reject deterministic or reused masking material;
- preservation of the canonical private-root derivation and implementation of
  the scoped exceptional-proof public inputs and complete authorization-envelope
  binding frozen in the accepted architecture;
- a new proof type, codec, verifier-key/domain label, artifact schema, and
  migration boundary so an old secret-bearing proof can never be relabeled;
- quantitative soundness and zero-knowledge parameters, trace/domain-size and
  performance impacts, and dependency/toolchain reproducibility;
- negative tests that attempt full and partial witness recovery from serialized
  proofs across multiple chosen secrets and repeated proofs;
- exact verifier compatibility tests and an external cryptographic review of
  the AIR, masking argument, transcript, commitment openings, and serialization;
- an explicit production enablement decision separate from source publication,
  public-network deployment, signing, custody, recovery, and release approval.

Circle STARK literature describes zero knowledge by randomizing trace
polynomial encodings, often with a larger evaluation domain for AIRs. The pinned
STWO API used here exposes no reviewed mode that performs that transformation.
Adding it locally would be a material proving-stack redesign, not a safe patch.

## Candidate Architectures

| Option | Privacy and canonical relation | Device/prover cost | Verifier and chain fit | Assumptions, maturity, and migration |
| --- | --- | --- | --- | --- |
| Upgrade STWO if a reviewed witness-hiding mode becomes supported | Best semantic continuity; retain the AIR only after proving that masking covers every witness-dependent column | Likely larger trace/domain and proof cost; benchmark on target mobile hardware | Strongest Starknet continuity; Ethereum/Base still needs a reviewed verifier or fact route | Preferred only if upstream owns and documents the mode; pinned proof type and verifier must be replaced |
| Apply an established zero-knowledge STARK trace transformation to Phil's AIR | Can preserve the exact relation, but the masking rows/polynomials and boundary constraints become security-critical | Expected material memory/time and domain-size increase | Preserves a transparent/hash-based direction but changes prover, verifier, transcript, and serialization | No supported implementation exists in the pinned stack; requires specialist design and external cryptographic review |
| Use a mature dedicated witness-hiding circuit proof for the narrow identity/nullifier relation | Clean privacy boundary and small statement; canonical encodings can be locked by cross-language vectors | Potentially more practical than a general zkVM, but must be benchmarked on mobile | Mature Ethereum verifier patterns are available; Starknet needs a separate verifier/fact adapter | May introduce elliptic-curve assumptions, a setup model, and weaker post-quantum posture depending on the selected system; migration is isolated behind a new proof type |
| Use a mature zero-knowledge zkVM | Reuse audited guest execution for the canonical derivation and avoid custom AIR masking | Usually the highest proving-memory/startup cost and least attractive for direct mobile proving | Receipt verification can be portable, but Ethereum/Starknet wrappers add dependencies and cost | Larger trusted computing base and dependency surface; useful only if benchmarks and auditability beat a narrow circuit |

`CURRENT ENGINEERING LEAD: NOIR/BARRETENBERG; FALLBACK COMPARATOR: RISC ZERO; PRODUCTION SELECTION: NONE; STWO: INELIGIBLE FOR PRIVATE AUTHORIZATION`

This isolates privacy from the current STWO research code and gives Phil a
small statement to benchmark and audit. The isolated prototype evidence does
not admit either candidate. Selection of the actual circuit stack
must explicitly compare setup requirements, zero-knowledge blinding,
elliptic-curve or hash assumptions, mobile prover memory/time, Ethereum verifier
cost, Starknet adapter availability, reproducible builds, and maintenance
maturity. If upstream STWO later ships a reviewed witness-hiding mode that wins
those measurements, it can supersede this preference through a new review; the
recommendation is not implemented by this repository.
