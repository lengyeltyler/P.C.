# O.37.10 V2 Minimal Account, Factory, and Local Lifecycle Implementation

Status: `COMPLETE_LOCAL_DEPLOYABLE_PACKAGE`.

Classification: `LOCAL_ONLY_SOLIDITY_IMPLEMENTATION_AND_INTEGRATION`.

O.37.10 implements the O.37.9 compressed account and its version-specific
CREATE2 factory. It also integrates the unchanged O.37.7 static authority
verifier and exercises the package through an ephemeral local ERC-4337 v0.7
EntryPoint. It makes no external RPC call, public deployment, funding action,
production signature, public UserOperation, or public mutation.

## Baseline

The phase started at
`b98acd6c3b81ea324c15a17e14d1dc7703a6bf5d` on
`codex/device-identity-v1` with a clean tracked worktree. The branch was 114
commits ahead of `origin/main`; no fetch was performed. O.20 through O.37.9
were reviewed. The frozen V1 sources still hash to:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

No security-relevant baseline discrepancy was found.

## Implemented Package

The account is `PhilCoreV2MinimalAccountV2`, version label
`philcore-v2-minimal-account-v2`, ID
`0xe3809f55cf56b419ecaebf3d2a2e0a43278b5d9a0b4714c063933a87ba2085d4`.
It implements exactly the 15 O.37.9 functions and the canonical 20-field
constructor tuple.

The factory is `PhilCoreV2MinimalAccountFactoryV2`, version label
`philcore-v2-minimal-factory-v2`, ID
`0x66e130d6512db6801362a672a59d58b9b6c16bb2ba76172808d6b5c21814d671`.
It is the actual CREATE2 deployer and the sole immutable source of the
verifier address and accepted verifier runtime hash.

The account supports only:

- ERC-4337 v0.7 validation and EntryPoint-owned keyed nonces;
- confirmation to one immutable target;
- native ETH transfer and EntryPoint deposit withdrawal;
- validator rotation;
- exact delayed validator recovery;
- exact delayed one-role recovery-configuration rotation.

Actions `1`, `2`, `6`, and `7` require validator authority; `8`, `9`, and
`11` require exact 2-of-3 recovery authority; action `10` requires validator
plus exact 2-of-3 recovery authority. The O.37.4 envelope is transported only
in `PackedUserOperation.signature`.

## Explicit Absences

There is no administrator, owner override, proxy, upgrade, delegatecall,
generic execute, batching, mutable verifier, registry, module, plugin,
session, paymaster, aggregator, token transfer, token approval, or token
receiver. ERC20, ERC721, and ERC1155 assets sent to the address may be
permanently stranded because this native-ETH-only version has no token
release surface.

## Evidence

Deterministic implementation evidence is rooted at
`config/solidity/O37_10_V2_MINIMAL_ACCOUNT_IMPLEMENTATION_EVIDENCE.json`.
The checked generator binds compiler settings, dependency versions, sources,
fixtures, ABI, storage, bytecode, size results, and local-only CREATE2
vectors.

See also:

- [Account ABI Report](./O37_10_ACCOUNT_ABI_REPORT.md);
- [Account Storage Layout Report](./O37_10_ACCOUNT_STORAGE_LAYOUT_REPORT.md);
- [Account and Factory Size Report](./O37_10_ACCOUNT_FACTORY_SIZE_REPORT.md);
- [Factory and CREATE2 Report](./O37_10_FACTORY_CREATE2_REPORT.md);
- [Local Lifecycle Report](./O37_10_LOCAL_LIFECYCLE_REPORT.md);
- [Security Boundary Report](./O37_10_SECURITY_BOUNDARY_REPORT.md);
- [Deployment Readiness Review](./O37_10_DEPLOYMENT_READINESS_REVIEW.md).

## Stop Boundary

The package is compiled and deployable only in an ephemeral local Hardhat
environment. O.37.10 does not access Sepolia or any external chain, designate
a production account address, create production authority, move public
funds, or push commits.
