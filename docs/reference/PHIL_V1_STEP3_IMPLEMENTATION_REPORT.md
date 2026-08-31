# Phil V1 Step 3 Starknet Reference Adapter Implementation Report

Status: Exact candidate independently accepted as local reference evidence

Date: 2026-08-21

## Outcome

Step 3 now has a bounded Noir/Barretenberg/Garaga reference candidate for
Phil's exceptional root proof. The candidate is intentionally disconnected
from Phil authority and all networks. It does not select a production backend
and does not authorize Step 4.

The implementation preflight corrected one architecture defect before any
proof or envelope was deployed: the prior envelope definition included
`rootProofNullifier` in a digest from which that same nullifier was derived.
The corrected digest omits only that derived value; the proof enforces it. All
other envelope fields remain committed.

## Implemented boundary

- fail-closed `PhilAuthorizationEnvelopeV1` normalization and digest;
- exact `PhilProofDescriptorV1` and verifier-binding derivation;
- exact logical public-input validation and 13-value `u128`/`u64` codec;
- Noir circuit implementing Phil's canonical Keccak ABI preimages;
- disclosed synthetic cross-implementation vector;
- exact compiled circuit, verification key, randomized proof, and native public
  input artifacts;
- Garaga-generated Cairo verifier and local, no-fork positive/negative test;
- reproducible artifact manifest with SHA-256 and Keccak identities; and
- structural tests proving no runtime, UI, plugin, Device Vault, STWO, signer,
  submission, or deployment reachability.

## Exact toolchain

| Component | Identity | Role |
| --- | --- | --- |
| Nargo | `1.0.0-beta.16` | Noir compiler and witness solver |
| Barretenberg | `3.0.0-nightly.20251104` | UltraKeccakZK Honk prover/native verifier |
| Garaga | `1.0.1` at `aa91b6504c86995789edb4e78f9f9ba20571625c` | Cairo verifier and calldata generator |
| Generated Cairo target | `2.14.0` | Garaga project dependency |
| Local Scarb compiler | `2.14.0` | exact Garaga-generated project pin; local build only |
| Starknet Foundry | `0.53.0` | isolated local verifier test |
| Universal Sierra Compiler | `2.10.0` | local Starknet Foundry class compilation |

This exact lane follows Garaga `1.0.1` compatibility. It is not silently
interchangeable with the earlier Noir beta.26/Barretenberg 5.2 feasibility
prototype.

## Native proof results

| Measurement | Result |
| --- | ---: |
| ACIR opcodes | 3,894 |
| circuit size | 94,786 |
| logical public inputs | 7 |
| packed native public inputs | 13 |
| witness solve | 0.12 seconds; 71,172,096-byte maximum resident set |
| verification-key generation | 0.64 seconds; 209,108,992-byte maximum resident set |
| proof generation plus native verification | 0.80 seconds; 260,915,200-byte maximum resident set |
| proof size | 9,408 bytes |
| native public-input file | 416 bytes |
| Garaga calldata text fixture | 77,538 bytes |

Native proof verification succeeded independently of proof generation. Ten
wrong secret, seed, scope, epoch, envelope, nullifier, or zero-descriptor cases
failed. A byte-mutated proof failed native verification. Two proofs of the same
statement differed, and neither serialized proof/public-input combination
contained the disclosed Phil secret or nullifier-seed literal.

## Local Cairo results

The generated verifier compiled with the exact Scarb `2.14.0` lane in 2.97
seconds with a 1,591,541,760-byte maximum resident set. Incremental compilation
was disabled so the result did not depend on a disposable compiler cache.

| Measurement | Result |
| --- | ---: |
| Sierra contract-class JSON | 1,691,441 bytes; 36,843 program felts |
| Sierra class hash | `0x271bf805307ed1a7720fbd8364767eba0ccbd74c6799c975ae83f7f922ee5bd` |
| CASM contract-class JSON | 1,221,983 bytes; 66,178 bytecode felts; 531 hints |
| CASM compiled-class hash | `0x154b6afe8acf0e963177e9e80f46b7c760d2b554245f41aec3d2d78710d8911` |
| valid proof, whole test | approximately 272,378,527 L2 gas |
| valid proof, verifier call | 259,670,377 L2 gas |
| tampered public input, whole test until rejection | approximately 76,215,386 L2 gas |
| tampered input, verifier call until rejection | 42,923,366 L2 gas |
| verifier syscalls per case | 94 Keccak; 1 library call |
| two-test run maximum resident set | 2,160,181,248 bytes |

The valid proof returned all 13 exact packed public inputs. Altering only the
first public-input limb caused Garaga's generated verifier to abort during
proof decomposition, so the negative case failed closed. Both tests passed in
an isolated Starknet Foundry state with no fork or network endpoint. A network
fee was deliberately not measured because Step 3 authorizes no RPC or network
activity; the local L2-gas measurement is the bounded cost evidence.

## Independent acceptance

Exact candidate `11234ea623a6b8883eed0036f3d95174cef90627` received
`ACCEPT_STEP_3_EXACT_CANDIDATE` after separate cryptographic, Cairo, adapter,
artifact, and no-authority review. The accepted review and its explicit rerun
limits are preserved in the Step 3 independent-review record.

The acceptance is deliberately bounded:

```text
STEP 3 ACCEPTED: YES - LOCAL REFERENCE EVIDENCE ONLY
PRODUCTION BACKEND SELECTED: NO
START STEP 4: NO
```
