# O.37.5 V2 Solidity Account And Factory Implementation Conflict Review

Status: `STOPPED_FAIL_CLOSED_BEFORE_SOLIDITY_RETENTION`.

O.37.5 was authorized to implement the frozen V2 account and factory locally.
The exact first compilation proved that the closed ABI, direct cryptographic
verification, and factory creation model cannot fit Ethereum's EIP-170
runtime-code limit. The phase stopped before retaining Solidity, compiler or
dependency changes, ABI, storage layout, bytecode, or CREATE2 vectors.

Public mutations are exactly zero.

## Verified Baseline

The phase began from:

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- source HEAD:
  `910b5f6f3be1637d1b05ad04ae209e5f232ca3aa`;
- tracked worktree: clean;
- upstream relationship without fetching: `origin/main`, ahead `105`,
  behind `0`.

O.20 through O.37.4, the O.36.1 freeze, O.37.1 descriptors and recovery
evidence, O.37.2 deterministic fixtures, and O.37.4 authority transport were
reviewed. Frozen V1 source remained:

- account SHA-256:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory SHA-256:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

No V2 Solidity existed at entry.

## Exact Frozen Compilation

The implementation attempt applied the required local-only toolchain:

- Solidity `0.8.27+commit.40a35a09.Emscripten.clang`;
- EVM `cancun`;
- optimizer enabled, `200` runs;
- viaIR enabled;
- literal-content metadata with IPFS bytecode hash and CBOR;
- OpenZeppelin Contracts `5.6.1`;
- Account Abstraction `0.7.0`;
- Hardhat `2.28.4`;
- Hardhat ethers plugin `3.0.8`;
- ethers `6.17.0`;
- Node.js `26.0.0`;
- npm `11.12.1`.

The draft followed the required order: account types and direct authority
verification, account, then version-specific CREATE2 factory. It preserved
the 20-field constructor, typed action surface, EntryPoint-owned nonces,
direct validator/recovery/combined envelopes, exact 2-of-3 recovery, and
forbidden-capability boundary.

## Blocking EIP-170 Result

Ethereum permits at most `24576` bytes of deployed runtime code.

The frozen direct OpenZeppelin WebAuthn/P-256 implementation compiled to:

| Contract | Runtime bytes | Excess |
| --- | ---: | ---: |
| V2 account | `35099` | `10523` |
| V2 factory | `43013` | `18437` |

The factory is larger because its runtime must carry the exact account
creation code for `CREATE2`, `createAccount`, `getAddress`, and
`accountCreationCodeHash`. Neither artifact is deployable under EIP-170.
This is a security and lifecycle failure, not a warning that may be waived.

An exploratory native-P256-only compile was also rejected. It would introduce
an unfrozen chain/precompile dependency and still produced:

| Contract | Creation bytes | Runtime bytes | Runtime Keccak-256 |
| --- | ---: | ---: | --- |
| V2 account | `34933` | `32796` | `0xaab6e7a386ba356b5c1d0ba5364577c15a3616677e2041cb1b987f1c13b326d7` |
| V2 factory | `41124` | `40710` | `0x87a3c3fdac9b758004ac78cca4528ed2e9f1cdd32002284fd734490a61dd38e3` |

Those hashes identify rejected temporary compiler outputs only. They are not
accepted bytecode, deployment artifacts, or CREATE2 authority.

## Unsafe Alternatives Rejected

Reducing the code below EIP-170 now requires at least one architecture change:

- move authority verification to an external contract;
- link a library that executes through `DELEGATECALL`;
- introduce a proxy or minimal proxy;
- reduce or change the frozen account ABI;
- add a verifier registry or mutable verifier selection;
- change the factory creation/deployer address model;
- require native P-256 precompile behavior not frozen by O.37.4.

O.36.1 and O.37.4 prohibit these choices or require separate architecture
review. Silently selecting one would change validator trust, constructor or
CREATE2 binding, bytecode review, storage assumptions, or forbidden
capabilities.

## Retained Repository State

No draft V2 Solidity, test harness, V2 compiler override, dependency pin,
ABI, storage layout, bytecode, or CREATE2 package is retained. The installed
local dependency state was returned to the repository lock. Rejected
temporary build artifacts were moved to the user's Trash under
`PhilCore-O37.5-oversize-artifacts-910b5f6` so they remain recoverable while
the repository contains no candidate bytecode.

The durable evidence is:

`config/solidity/O37_5_V2_IMPLEMENTATION_CONFLICT_EVIDENCE.json`

## Required Resolution

A separately approved architecture phase must choose and freeze a deployable
code-size strategy. It must re-evaluate:

1. the verifier trust and call boundary;
2. whether native P-256 is mandatory and on which chains;
3. factory/CREATE2 derivation and the identity of the actual deployer;
4. ABI and constructor compatibility;
5. delegatecall, proxy, library, and upgrade prohibitions;
6. source, bytecode, storage, gas, and failure-domain review;
7. new deterministic fixtures and threat analysis for the selected boundary.

Only after that review may a fresh Solidity implementation phase restart.

## Stop Boundary

No contract was deployed, no blockchain account was created, no RPC or
Sepolia endpoint was used, `.env.sepolia.local` was not read, no funds moved,
no credential or production signature was created, and no UserOperation was
created, estimated, or submitted. No push occurred.
