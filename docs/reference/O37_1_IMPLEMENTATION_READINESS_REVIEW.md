# O.37.1 V2 Implementation Readiness Review

Status: `RECOVERY_INTERFACE_COMPLETE_SOLIDITY_STILL_SEPARATELY_GATED`.

O.37.1 corrects the recovery descriptor and evidence mismatch that stopped
O.37. It remains a local cryptographic-interface phase and does not resume
Solidity.

Public mutations are zero.

## Baseline

- repository: `<repository-root>`;
- branch: `codex/device-identity-v1`;
- source HEAD:
  `6dcc4099a78cd719d484c4e33c808586d2472780`;
- tracked worktree at phase start: clean;
- upstream without fetching: `origin/main`, ahead 97, behind 0;
- V1 account SHA-256:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- V1 factory SHA-256:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

No V2 Solidity account or factory existed at entry.

## O.37 Blocker Resolution

### Factor descriptor completeness: resolved

Descriptor version `2` binds the public material, credential-ID hash,
RP/origin policy, independence binding, WebAuthn policy, credential
generation, role, verifier, account version, security model, and explicit
recovery domain. Complete descriptors travel in public one-time evidence, so
the future account can reproduce stored commitments without expanding
permanent descriptor storage.

### Recovery evidence membership: resolved

Evidence version `2` includes all three current commitments, the two selected
commitments, exact bitmap/order, complete selected descriptors, action
context, account, chain, EntryPoint, request, epochs, validity, timing, and
proposal commitment. The account can now verify exact enrollment membership
before checking signatures.

### Rotation: resolved at the interface level

Configuration version `2` and recovery epoch invalidate replaced factors.
Changed factors increment generation once and must replace public material
and independence binding. WebAuthn replacement also changes credential ID.

### Runtime reproducibility: resolved

- Node.js: exactly `26.0.0`;
- npm: exactly `11.12.1`;
- lockfile: npm lockfile version `3`;
- install: `npm ci`;
- enforcement: `.node-version`, exact package engines, `packageManager`,
  `.npmrc` engine strictness, and `npm run check:o37-1-runtime`.

CI must use those exact versions, run `npm ci`, run the runtime check before
generation/build, verify all checked-in vectors with `--check`, then run
typecheck, compilation, and the complete conformance suite. CI must not
regenerate and accept changed vectors implicitly.

## Compatibility

### O.32

Intent types, Runtime authorization, validator authorization, recovery
authorization, config-rotation authorization, EIP-712 domains, nonces, epochs,
and checked-in O.32 vectors remain byte-for-byte unchanged.

The legacy O.32/O.36.1 factor and configuration commitments are superseded
for future Solidity by descriptor/configuration version `2`. This is safe
because O.32 recovery authority already binds `recoveryConfigHash`; the new
configuration hash flows through that unchanged digest.

### O.33

Validator selection, epoch checks, recovery freezes, authority-kind
separation, and fixture-only evidence references remain valid. The future
production recovery verifier consumes evidence version `2`; O.33 does not
decode signature bytes and needs no hash change.

### O.34

EntryPoint caller checks, typed action enforcement, nonce lanes, state
binding, recovery freezes, request ID as authorized-intent hash, and terminal
state transitions remain valid. Its local prototype configuration fixtures
remain historical. Future Solidity must require configuration version `2`.

### O.35

The ordered 20-field initialization remains valid because it stores the three
commitments and configuration hash, not complete descriptors. CREATE2
derivation, atomic deployment, activation verification, funding prohibition,
and migration rules do not change.

### O.36.1

The role model, exact threshold, direct P-256 and secp256k1 verifiers,
validator separation, cancellation authority, timing, validator envelope,
identity commitment, closed capability surface, and storage policy remain.

Only the incomplete factor commitment, configuration version, and factor
evidence envelopes are superseded by O.37.1.

## Deterministic Evidence

The checked-in O.37.1 package contains:

- exact type strings and type hashes;
- public P-256 points and secp256k1 signer identifiers;
- complete role descriptors and independence-binding inputs;
- descriptor and configuration commitments;
- one recovery-request context;
- one recovery-configuration rotation context;
- negative vectors for generation, policy, role, verifier, domain, epoch,
  duplicate-factor, bitmap, and same-factor rotation failures.

All fixture material is public and deterministic. No private key, real
credential, assertion, signature, or UserOperation exists.

O.37.2 preparation clarified that WebAuthn `rpIdHash` is SHA-256 of the
canonical RP-ID UTF-8 bytes. The O.37.1 public fixtures were regenerated with
that WebAuthn algorithm; no type string, descriptor field, threshold, or
authority rule changed.

## O.37.2 Test-Authority Resolution

O.37.2 separately authorizes and completes deterministic local-only signature,
recovery-evidence, and ERC-4337 v0.7 `PackedUserOperation` fixtures. The
accepted package is public, isolated to chain `31337`, and classified
`TEST_FIXTURE_ONLY`. It contains no private scalar, canonical PhilCore
identity, canonical validator, real credential, production authority, or live
network binding.

The public-test-input condition is therefore resolved. Solidity remains a
separate phase requiring explicit approval; O.37.2 does not resume it. See
[O.37.2 Solidity Test Readiness Review](./O37_2_SOLIDITY_TEST_READINESS_REVIEW.md).

That future phase must also apply the already frozen Solidity `0.8.27`,
OpenZeppelin `5.6.1`, Account Abstraction `0.7.0`, Hardhat `2.28.4`, plugin
`3.0.8`, ethers `6.17.0`, optimizer/viaIR/Cancun settings, and V1 compiler
override. O.37.1 deliberately does not change Solidity dependencies.

WebAuthn parser and P-256 gas/adversarial tests, exact ABI selectors/errors,
storage-layout artifacts, and bytecode review remain implementation-phase
work.

## Stop Boundary

No Solidity, bytecode, deployment, account, credential, signature,
UserOperation, transaction, RPC call, funding action, or public mutation was
created. Future Solidity implementation and any later deployment each require
separate approval.
