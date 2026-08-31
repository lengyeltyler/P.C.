# O.37.6 Code Size Security Impact Review

Status: `COMPLETE_LOCAL_ARCHITECTURE_REDUCTION`.

O.37.6 reduces bytecode by capability phasing and an explicit stateless
onchain verification boundary. It does not remove authority or recovery
checks.

## Reduction Review

| Reduction | Change | Required replacement or invariant |
| --- | --- | --- |
| externalize evidence cryptography | verifier code leaves account runtime | fixed address and runtime code hash, account-bound request, `STATICCALL`, exact return magic |
| defer ERC20 | selector/action absent | Runtime rejects use and intentional token funding; future support requires a new account version |
| defer ERC721/ERC1155 | execution and receiver selectors absent | safe transfers revert; future support requires a new account version |
| consolidate hashing and decoding | one verifier path | exact O.32 hashes and O.37.4 bytes remain fixture-checked |
| reduce factory shell | remove duplication only | factory remains CREATE2 deployer and validates exact tuple/code/state |
| move enrollment checks to Runtime | unchanged existing boundary | commitments and signatures remain verified onchain; Runtime Boolean is never accepted |

## Static Verifier Trust Boundary

The verifier is code, not authority. It has:

- no storage;
- no admin or owner;
- no upgrade or proxy;
- no registry or selectable implementation;
- no token, native-value, account-execution, or recovery capability;
- no callback into the account;
- no `DELEGATECALL` or `SELFDESTRUCT`;
- no acceptance of a Runtime Boolean.

The factory fixes verifier address and runtime code hash immutably. The
account checks both before every call and uses `STATICCALL`. The verifier
requires the calling account to match the request's account field. Any code
absence, hash mismatch, revert, malformed return, or wrong magic fails
authorization.

Because verification runs in the verifier's own storage context, it cannot
write account state. Because the account performs execution and recovery
state transitions itself, a verifier success cannot choose a target, amount,
proposal, nonce, or epoch outside the exact request.

## Preserved Authority

O.37.4 transport remains byte-for-byte unchanged:

- direct 320-byte validator envelope for supported validator actions;
- direct O.37.1 exact-2-of-3 recovery envelope for actions `8`, `9`, `11`;
- combined validator-plus-exact-2-of-3 envelope for action `10`.

No alternate decoder, fallback signature scheme, factor duplication,
validator-as-factor, or single-factor path is added. O.37.2 and O.37.4
fixtures remain mandatory conformance inputs.

## Preserved Recovery

The account retains commitments, configuration hash, validator/recovery
epochs, pending state, delay, expiry, freezes, and completion/cancellation
transitions. The verifier validates evidence; the account independently
requires state and proposal parity before mutation.

Recovery cannot transfer assets, call a target, change timing, bypass
EntryPoint, or authorize a deferred token capability. Exact threshold `2` and
bitmaps `3`, `5`, `6` remain.

## Preserved ERC-4337 Boundary

EntryPoint v0.7 remains the sole nonce-sequence owner. Neither account,
factory, nor verifier stores a duplicate nonce. The exact lane and sequence
remain intent and verifier inputs.

Paymasters, aggregators, alternate EntryPoints, generic execution, and
signature-format autodetection remain prohibited.

## Capability Phasing Risks

The minimal account is intentionally native-ETH-only. ERC20 transfers cannot
be refused by the receiving address, so unsolicited tokens can be stranded.
This is disclosed and classified as unsupported custody; Runtime must not
offer token deposit or transfer flows for this version.

A future token-capable account requires a new account version, factory,
address, bytecode review, fund lifecycle, and fresh authority. It cannot be
installed into this account.

## Rejected Alternatives

- Solidity linked external libraries: rejected because execution uses
  `DELEGATECALL`.
- Proxy or minimal proxy: rejected because implementation replacement or
  dependency changes the account security boundary.
- Mutable verifier registry: rejected as hidden upgrade authority.
- Native-P256-only verifier: not selected; the next implementation retains
  the reviewed OpenZeppelin fallback unless separately changed.
- Caller-supplied creation code or alternate deployer: rejected because it
  breaks reviewed CREATE2 identity.
- Removing canonical re-encoding, role, epoch, fee, nonce, or proposal checks:
  rejected as security weakening.

## Residual Risks And Gates

The architecture is not yet proven to meet its budgets. The next phase must
compile in order and stop immediately on any warning, opcode violation,
fixture mismatch, or hard-budget excess. External-call failure behavior and
verifier gas must receive adversarial tests before any deployment review.

No deployment is authorized by O.37.6.
