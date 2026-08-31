# O.37.6 V2 Solidity Code Size Architecture Review

Status: `COMPLETE_LOCAL_ARCHITECTURE_REDUCTION`.

O.37.6 selects a deployable architecture target after O.37.5 proved that the
frozen monolithic account and factory violate EIP-170. This phase creates no
Solidity, bytecode, deployment artifact, credential, signature, or
UserOperation. Public mutations are zero.

## Verified Baseline

The phase began at
`bb9efbc3ca5d8a391ecdc25aed1c4fad2a981e53` on
`codex/device-identity-v1` with a clean tracked worktree and no V2 Solidity.
O.20 through O.37.5 were reviewed. V1 source hashes remain:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

O.37.4 authority transport and fixtures and O.37.5 conflict evidence are
unchanged.

## Current Size

EIP-170 permits `24576` runtime bytes. The frozen direct OpenZeppelin build
measured:

| Artifact | Runtime bytes | Excess |
| --- | ---: | ---: |
| monolithic account | `35099` | `10523` |
| factory | `43013` | `18437` |

O.37.5's rejected native-P256 exploration provides source maps without
creating new bytecode in this phase:

| Account source family | Bytes |
| --- | ---: |
| account source | `24134` |
| authority cryptography source | `4534` |
| OpenZeppelin dependencies | `942` |
| Account Abstraction dependencies | `131` |
| compiler-generated/unattributed | `3055` |
| total | `32796` |

Native-only P-256 removed `2303` bytes but remained oversized and introduced
an unfrozen precompile requirement. The direct OpenZeppelin account therefore
totals `32796 + 2303 = 35099`.

The rejected native factory is attributable exactly as:

```text
34933 bytes embedded account creation code
 5777 bytes factory shell
-----
40710 bytes factory runtime
```

The same `2303`-byte increase appears in both direct account and factory
runtime, so direct OpenZeppelin account creation is inferred as `37236` bytes
and the factory shell remains `5777` bytes. This inference is planning
evidence, not accepted bytecode.

## Major Contributors

The dominant account contributors are:

1. typed action ABI dispatch, intent hashing, and repeated execution checks;
2. recovery envelope and descriptor decoding;
3. WebAuthn/P-256 and secp256k1 verification;
4. recovery lifecycle storage and transitions;
5. ERC20/ERC721/ERC1155 execution and receiver handling;
6. ERC-4337 caller, sender, nonce, fee, validity, and paymaster checks.

The dominant factory contributor is the embedded exact account creation code,
not CREATE2 hashing itself.

## Option Review

### A — minimal account kernel

Selected. Stateful security enforcement remains in the account while
stateless, computation-heavy evidence verification moves behind one fixed
onchain `STATICCALL` boundary. Runtime may prevalidate but cannot supply a
Boolean substitute.

### B — capability phasing

Selected. The initial minimal account supports confirmation, native ETH,
EntryPoint deposit withdrawal, validator rotation, validator recovery, and
recovery-configuration rotation. ERC20, ERC721, ERC1155, and receiver
interfaces move to future separately reviewed account versions.

The historical O.37.4 full-profile ABI remains evidence and is not rewritten.
The minimal profile uses a new account-version ID and does not claim ABI
compatibility with that full profile.

### C — library usage

Solidity internal libraries inline and do not solve the limit. Externally
linked libraries execute with `DELEGATECALL` and remain prohibited.

Selected instead: one stateless authority-verifier contract called only with
`STATICCALL`. Its address and runtime code hash are immutable factory
bindings. It has no storage, registry, admin, upgrade, callback, or execution
authority. The account checks code identity before every verification.

### D — factory reduction

Selected. The account kernel must shrink enough that its creation code plus a
minimal factory shell fits with explicit reserve. The factory remains the
CREATE2 deployer and never accepts caller-supplied creation code or chooses an
implementation.

## Hard Size Budgets

| Artifact | Hard maximum | EIP-170 reserve |
| --- | ---: | ---: |
| static authority verifier runtime | `20480` | `4096` |
| minimal account runtime | `15360` | `9216` |
| minimal account creation code | `18432` | n/a |
| minimal factory shell | `4096` | n/a |
| minimal factory runtime | `22528` | `2048` |

These are acceptance limits, not aspirations. Any compiler size warning or
budget excess fails the next phase even if an artifact remains barely below
EIP-170.

## Decision

Proceed only with the versioned minimal account, immutable static verifier,
and minimal version-specific factory described by O.37.6. This preserves all
authority and recovery security while reducing capability and moving
stateless computation across an explicit, code-hash-pinned onchain boundary.

No implementation is authorized by this document alone.
