# O.37.8 V2 Minimal Account Core Implementation Conflict Review

Status: `STOPPED_FAIL_CLOSED_BEFORE_ACCOUNT_RETENTION`.

O.37.8 attempted only the locally compiled minimal ERC-4337 account selected
by O.37.6. It created no factory, deployment path, live account,
UserOperation, signature, credential, RPC call, funding action, or public
mutation.

## Verified Baseline

The phase started at
`21ca442c881198351b111c5f146e0d20cb1cef07` on
`codex/device-identity-v1` with a clean tracked worktree. O.20 through O.37.7,
including the O.37.4 transport, O.37.6 minimal architecture, and O.37.7
verifier evidence, were reviewed.

The preserved V1 source hashes matched:

- account:
  `39b512caf34bfec0d68436960087917519b4b1136bd18d55a7101f609c574a0a`;
- factory:
  `59d372df9087f0f5ffdfb80c9b4b17ff027f237680fec112a77f58252ae165f9`.

The O.37.2 deterministic fixtures and O.37.4 authority transport fixtures
were current. All 11 O.37.7 verifier tests passed unchanged.

## Size Gate Result

The frozen Solidity `0.8.27`, Cancun, optimizer-200, viaIR toolchain compiled
three transient account candidates without warnings. The first complete
candidate measured `20845` runtime bytes and `23146` creation bytes.

Removing duplicate public constant getters and duplicate execution-side hash
work, without removing verifier, nonce, typed-action, fee, validity, recovery,
or external-call checks, produced the smallest candidate:

| Measurement | Bytes | O.37.6 maximum | Excess |
| --- | ---: | ---: | ---: |
| Runtime | `19454` | `15360` | `4094` |
| Creation | `21755` | `18432` | `3323` |

Its runtime hash was:

```text
0xb7694928eac7de99d1d2557e51b0e91777356c314872c386726610b67b4b1147
```

A bounded canonical-word-decoder experiment increased runtime to `19591`
bytes, so it was rejected. The candidates remained below EIP-170, but O.37.6
explicitly makes its lower account budgets hard acceptance gates. Passing
EIP-170 alone is insufficient.

The principal retained-size families were all security-bearing:

- typed ABI dispatch and action-specific O.32 hashing;
- EntryPoint sender, nonce-lane, fee, validity, paymaster, and prefund rules;
- immutable/current-state derivation of the O.37.7 verifier request;
- code-hash verification and `STATICCALL` result handling;
- validator and exact-2-of-3 recovery lifecycle transitions;
- closed views and permissionless exact-request completion/expiry.

No security check was removed to force the artifact under budget.

## Architecture Discrepancy

The O.37.8 request listed verifier address and code hash as account
immutables. O.37.6 instead freezes an exact 20-field account constructor and
requires the account to read the verifier address and code hash from immutable
version-specific factory configuration by `STATICCALL`.

No prior architecture phase changes that rule. The transient candidate tested
the narrower direct immutable binding requested by O.37.8, but it was not
retained. This discrepancy independently requires architecture review before
a deployable account can be accepted.

## Retention Decision

The oversized Solidity contract, interface, ABI, storage layout, bytecode,
and dedicated build configuration were removed. Keeping them would turn a
failed gate into an attractive but noncanonical implementation.

O.37.8 retains only deterministic conflict evidence and this review. A future
phase must choose and freeze a size reduction and resolve the verifier-binding
source without weakening authority transport, recovery, nonce ownership,
typed execution, or verifier identity.

## Fund Safety And Stop Boundary

No funding workflow was added. Before any future funding phase, the project
still must define and verify funding entry, typed execution, residual release,
failed deployment behavior, and stranded-fund boundaries.

No account, factory, deployment, CREATE2 derivation, chain interaction,
Sepolia call, RPC call, fund movement, credential, signature, submitted
UserOperation, or push occurred.
