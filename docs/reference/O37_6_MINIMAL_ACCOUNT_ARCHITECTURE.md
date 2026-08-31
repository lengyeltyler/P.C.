# O.37.6 V2 Minimal Account Architecture

Status: `COMPLETE_LOCAL_ARCHITECTURE_REDUCTION`.

The selected profile is
`PHILCORE_V2_MINIMAL_STATIC_VERIFIER_V1`. Its account-version label is
`philcore-v2-minimal-account-v1`, with version ID:

```text
0xd9b8b73ed071d4a5da3b0a1d455d97ce219a8627d21b21cacde81f1c8c753369
```

It is a new account version, not an in-place reduction of an existing
deployed account. The identity commitment and security-model ID remain
unchanged. The changed account version, factory, and bytecode deliberately
produce a new CREATE2 address.

## Required Onchain Account Responsibilities

The minimal account retains:

- canonical EntryPoint v0.7 caller and sender checks;
- EntryPoint-owned nonce lane/sequence parity;
- chain, account, factory, identity, owner, version, and security bindings;
- exact typed calldata, intent, fee, validity, epoch, and freeze checks;
- paymaster rejection;
- immutable validator and recovery commitment initialization;
- validator and recovery epoch state;
- exact pending recovery and configuration-rotation state;
- fixed delay, expiry, cancellation, completion, and replay rules;
- execution reentrancy lock;
- native ETH transfer and residual release;
- EntryPoint deposit withdrawal;
- confirmation to the one immutable confirmation target;
- validator rotation;
- exact 2-of-3 validator recovery;
- validator-plus-exact-2-of-3 recovery-configuration rotation;
- permissionless completion and expiry;
- receive support for native ETH;
- reverting fallback.

No cryptographic check becomes a Runtime assertion. Heavy evidence validation
is performed by the fixed onchain verifier and consumed only after the
account verifies its address, code hash, caller binding, and return magic.

## Minimal Typed Action Surface

Supported O.32 action types:

| Action | Value | Authority |
| --- | ---: | --- |
| confirm | `1` | validator |
| native transfer | `2` | validator |
| EntryPoint deposit withdrawal | `6` | validator |
| validator rotation | `7` | validator |
| validator recovery request | `8` | exact 2-of-3 recovery |
| validator recovery cancellation | `9` | exact 2-of-3 recovery |
| recovery-configuration request | `10` | validator plus exact 2-of-3 |
| recovery-configuration cancellation | `11` | exact 2-of-3 recovery |

Action values, intent hashes, digests, authority classes, and envelope bytes
remain O.32/O.37.4 values. Unsupported action selectors and action values
fail; there is no generic execution fallback.

## Deferred Capabilities

The minimal version does not expose or accept:

- ERC20 transfer;
- ERC721 safe transfer;
- ERC1155 safe transfer;
- ERC721 receiver callbacks;
- ERC1155 receiver callbacks.

These capabilities are not moved to Runtime. They are absent. Runtime must
reject attempts to create those intents for this account version.

ERC20 contracts can transfer tokens to any address without receiver consent,
so unsolicited tokens may become stranded. This version must be presented as
native-ETH-only, and funding policy must prohibit intentional token deposits.
A future token-capable account is a separate reviewed version and factory,
never a module or upgrade. Native ETH can migrate through the existing typed
native-transfer path after fresh authorization.

## Static Authority Verifier

The selected verifier label is
`philcore-v2-static-authority-verifier-v1`, version ID:

```text
0x2e7f527e1c2212f8e2b14a62bc02e18dc7eb16cfcfe3a5f955c533eafb2cd402
```

It performs only stateless verification:

- typed action and authorized-intent hashing;
- O.37.4 authority-class dispatch;
- exact canonical envelope decode/re-encode;
- validator secp256k1 recovery;
- recovery context, bitmap, role, descriptor, and commitment checks;
- WebAuthn assertion and P-256 verification;
- purpose-bound recovery secp256k1 verification;
- account, chain, EntryPoint, UserOperation hash, nonce, fee, validity, epoch,
  proposal, and request bindings.

The account supplies a canonical verification request derived from its own
state and the exact UserOperation. The verifier requires the request account
to equal `msg.sender`. It returns one versioned success magic value or fails.
It never calls the account, EntryPoint, factory, token, or confirmation
target.

The account obtains the verifier address and accepted runtime code hash from
its immutable, version-specific factory, checks `EXTCODEHASH`, then uses
`STATICCALL`. The factory values cannot change. No registry, lookup by user
input, fallback verifier, retry loop, or alternate version is allowed.

## Runtime Responsibilities

Runtime continues to:

- protect identity, validator, recovery, credential, approval, and proof
  secrets;
- validate enrollment, attestation, origin, RP, attachment, backup, and
  custody-domain independence;
- construct exact typed intents and canonical envelopes;
- confirm fee, fund lifecycle, residual release, and account-version policy;
- prevalidate evidence for user feedback;
- reject deferred token actions and unsupported funding.

Runtime never replaces EntryPoint nonce enforcement, account state, onchain
signature verification, recovery threshold, delay, expiry, or execution
rules.

## Constructor And Storage

The exact 20-field commitment-only account initialization remains. No
descriptor or verifier address is added. The factory binding already in that
tuple identifies the immutable verifier configuration.

Mutable storage remains limited to validator fields, freeze/lock flags,
recovery commitments/configuration, epochs/state, and complete pending
recovery structures. There is no nonce mapping, storage gap, admin,
implementation slot, module map, allowance table, or generic replay map.
