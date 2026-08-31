# O.37.4 ERC-4337 Integration Specification

Status: `COMPLETE_LOCAL_SECURITY_INTERFACE_FREEZE`.

This document freezes how a future V2 account consumes authority from an
ERC-4337 v0.7 `PackedUserOperation`. It creates or submits no UserOperation.

## Signature Field

`PackedUserOperation.signature` contains exactly one canonical transport
selected from the O.37.4 action table:

- actions `0`--`7`: direct 320-byte validator envelope;
- actions `8`, `9`, and `11`: direct O.37.1 recovery envelope;
- action `10`: O.37.4 combined envelope containing the validator envelope
  followed by the recovery envelope.

There is no second authority argument, calldata-carried witness, registry,
aggregator, ERC-1271 fallback, or Runtime Boolean. Signature bytes are
authority evidence only; action parameters remain in the typed account
calldata and the O.32 authorized intent.

## Validation Order

A future `validateUserOp` implementation must fail closed in this order:

1. require the canonical EntryPoint caller, deployment chain, account, and
   exact account sender;
2. reject factory deployment fields inconsistent with the frozen account;
3. decode the typed account selector and exact action-specific parameters;
4. recompute the authorized intent, require account, chain, EntryPoint,
   nonce lane and sequence, epochs, validity, fee bound, and calldata parity;
5. derive the authority class from the action type;
6. decode and canonically re-encode the exact signature transport;
7. verify validator evidence when required;
8. verify exact 2-of-3 recovery membership and both factor signatures when
   required;
9. require the validator and factor digest bindings to the same
   `userOpHash`;
10. enforce recovery pending-state, delay, expiry, freeze, and proposal
    parity;
11. return only the ERC-4337 validation result permitted by the frozen
    interface.

`validateUserOp` cannot execute an action, enroll a factor, select a verifier,
or turn malformed evidence into a permissive validation result.

## Nonce Ownership

EntryPoint v0.7 exclusively owns keyed nonce sequence state. The nonce is:

```text
(uint192 nonceKey << 64) | uint64 nonceSequence
```

Frozen lanes are:

| Key | Lane |
| ---: | --- |
| `0` | ordinary typed execution |
| `1` | validator maintenance |
| `2` | recovery and recovery-configuration transitions |

The future account stores no nonce mapping and never increments or resets an
independent sequence. It verifies that the EntryPoint nonce key matches the
action lane and that both key and sequence equal the values in
`IntentCoreHeaderV1`. The intent includes these values for authorization and
replay binding; inclusion does not transfer sequence ownership to PhilCore.

Recovery request IDs, validator epochs, recovery epochs, pending-state IDs,
and timing windows are security state, not alternate ERC-4337 nonces. They
provide transition and replay constraints without duplicating EntryPoint
sequence management.

## Substitution Resistance

The O.32 domain and digests bind chain ID, account, canonical EntryPoint,
authorized intent, UserOperation hash, epochs, action, and nonce. The account
must recompute rather than accept these fields as assertions from the
envelope. Replacing the chain, EntryPoint, sender, calldata, nonce, action,
fees, epochs, or either nested envelope invalidates verification.

No paymaster path is exposed or supported. The account does not accept
aggregated signatures, alternate EntryPoints, generic JSON-RPC authority,
generic calls, or signature-format autodetection.

## Local-Only Boundary

O.37.4's fixture package includes synthetic digest bindings but deliberately
contains no newly built `PackedUserOperation`, calldata, init code,
paymaster data, live estimate, or submission authority. Solidity integration
and executable integration vectors remain separately gated.
