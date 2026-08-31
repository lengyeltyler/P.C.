# Phil V1 Step 3 Independent Review Packet: `11234ea`

Status: Awaiting review by a separate reviewer

Date: 2026-08-21

## Exact review target

```text
candidate commit: 11234ea623a6b8883eed0036f3d95174cef90627
candidate tree:   9ff5177d11525df640cf103fdf982d73fb47a4f1
candidate parent: 841a79cbd5f28b15bfdc06a831319a7dd7efcc46
review range:     841a79cbd5f28b15bfdc06a831319a7dd7efcc46..11234ea623a6b8883eed0036f3d95174cef90627
```

The reviewer must verify these identities before relying on any result. Review
the committed candidate, not the later packet commit or a mutable working tree.

## Review boundary

This is a read-only, local review. Do not edit, commit, install, download,
publish, connect a device, use a real secret, contact an RPC endpoint, create a
fork, deploy, declare, sign, submit, or start Step 4. Existing ignored build
outputs are not candidate evidence.

The candidate is a reference implementation only. Acceptance does not select a
production proof backend or authorize a network/account path.

## Required review

Independently establish all of the following from the exact candidate:

1. The authorization digest omits only the derived `rootProofNullifier`, avoids
   the Keccak fixed-point cycle, and still binds every action, scope, account,
   network, policy, validity, value, fee, device, recovery, validator, proof,
   and human-presentation field required by the architecture.
2. Routine, exceptional, and recovery envelope classes fail closed, and a root
   proof never replaces the separately required device signature.
3. The Noir circuit implements the exact ABI-compatible Keccak relation,
   enforces a non-zero canonical 251-bit Phil secret, and derives the scoped
   commitment and nullifier from the disclosed private witness and exact public
   inputs.
4. Treating `proofDescriptorHash` as an adapter/verifier admission binding
   rather than an in-circuit derivation is sound, explicit, and fail closed.
5. The descriptor binds the intended proof suite, versions, circuit, public-
   input schema, verification key, generated verifier source, and codec without
   a circular identity or caller-controlled downgrade.
6. TypeScript, Noir, native Barretenberg, Garaga calldata, and Cairo use the
   same seven logical public inputs and exact 13-value high/low `u128` plus
   `u64` encoding, with no truncation, field reduction, reordering, or omitted
   comparison.
7. The committed verification key, proof, public inputs, generated Cairo
   source, calldata, vector, and artifact manifest are mutually consistent and
   contain only the expressly disclosed synthetic witness fixture.
8. The positive and negative evidence supports the claims made in the report,
   including wrong-input rejection, proof randomization, private-literal
   absence, malformed-proof rejection, exact public-input return, and tampered-
   public-input rejection.
9. The generated verifier, dependency lock, compiler/test pins, class hashes,
   sizes, memory figures, and L2-gas figures are reported accurately enough for
   this local gate. Explicitly assess the beta/nightly toolchain risk and the
   lack of a network-fee measurement.
10. The candidate has no reachability from Phil runtime, renderer, preload,
    plugin, Device Vault, signer, account, submission, RPC, deployment, or STWO
    authority surfaces and grants no production authority.

Review at minimum the implementation report, threat model, artifact manifest,
envelope and root-proof modules, Noir circuit/test harness, canonical vector,
generated verifier project/test, dependency lock, and roadmap/gate changes.

## Permitted local checks

Read-only source and Git inspection is permitted. If the exact dependencies
are already present, the reviewer may run the documented tests without a
network, device, real secret, or mutation outside ignored disposable outputs.
Do not treat inability to reinstall a dependency under this review boundary as
evidence that the committed proof is valid or invalid; review the recorded
artifact identities and state the unrerun limitation.

## Required response

Report findings first, ordered by severity, with exact file and line evidence.
Separate verified source facts, reproduced local evidence, inference, and
unverified claims. Then return exactly one verdict:

```text
ACCEPT_STEP_3_EXACT_CANDIDATE
```

or

```text
REJECT_STEP_3_EXACT_CANDIDATE
```

Acceptance requires no unresolved security, correctness, binding, provenance,
artifact-consistency, or authority-boundary finding. Even if accepted:

```text
PRODUCTION PROOF BACKEND SELECTED: NO
START STEP 4: NO
```
