# Phil V1 Step 6B Local Smart-Account Threat Model

Status: Exact second corrective candidate independently accepted

Date: 2026-08-22

## Boundary

The protected object is one routine Step 6A authorization carried by a packed
ERC-4337 operation. The local account must not execute unless the operation,
envelope, enrolled device approval, immutable capability policy, nonce, and
time window all agree.

The candidate trusts its constructor configuration, the accepted Step 6A hash
contracts, OpenZeppelin's P-256 implementation, Solidity/EVM behavior, and the
EntryPoint address as caller. The local harness is not trusted as evidence of
official EntryPoint behavior.

## Threats And Controls

| Threat | Candidate control | Residual risk |
| --- | --- | --- |
| Direct account call | Validation and execution require the pinned EntryPoint address | Address/code authenticity is not proven by the local harness |
| Raw UserOperation substitution | Recomputes `userOpHash`; compares every supported packed field; requires canonical calldata | Official EntryPoint and bundler behavior remain untested |
| Account, chain, EntryPoint, target, or calldata substitution | Recomputes Step 6A account, action, nonce, and intent hashes; pins chain, EntryPoint, and target | Only one target surface is modeled |
| Manifest self-authorization | Constructor pins the independently accepted Step 6A manifest hash | Production persistence/deployment of the trust anchor is unimplemented |
| Device or key substitution | Constructor pins device ID, key ID, epoch, and valid P-256 coordinates | Synthetic-key testing is not Secure Enclave evidence |
| Signature malleability or forgery | Actual P-256 verification; OpenZeppelin rejects high-S signatures | No external contract audit or Base gas evidence |
| Capability or policy substitution | Pins scoped capability binding, policy hash, target, and value/fee ceilings | Issuance, revocation, rotation, and policy-update administration are absent |
| Expired approval | Validation returns the intersection of action and approval windows; execution rechecks both | Bundler clock/validation behavior is not tested |
| Replay | Keyed sequence and authorization hash checked at validation and consumed before execution | Production EntryPoint nonce interaction is untested |
| Reentrancy or target failure | Consumption precedes the single external call; reentry lacks EntryPoint authority; revert rolls all state back | Malicious-target review is bounded to this single-call model |
| Dynamic deployment or sponsorship | Rejects non-empty `initCode` and paymaster data; requires zero missing prefund | No factory, deposit, or prefund lifecycle exists |
| Scope expansion | Routine operations only; no proof, recovery, batch, delegatecall, upgrade, or arbitrary target | Later capability classes need new gates |
| Legacy/STWO reachability | New source is isolated and static tests reject runtime/network/STWO markers | Repository history still contains quarantined compatibility code |

## Security Interpretation

Passing Step 6B shows that the accepted local Phil binding can control one
local smart-account call without a reproduced bypass. It would not show that
the account is production safe, deployed, externally audited, recovery-ready,
post-quantum, officially ERC-4337 integrated, or usable on Base.

The first independent review found no source bypass but rejected incomplete
committed negative coverage. The bounded correction directly exercises the
omitted branches without changing the production account source.

The first corrective review confirmed all but one branch. Its before-action
test was timestamp-shadowed by the later approval-start condition. The second
bounded correction schedules and observes the actual transaction at
`validAfter - 1`; production account and harness source remain unchanged.
Independent review accepted exact candidate `d65aa5d` after reproducing that
transaction timing and the intended action-start rejection. The residual risks
in this threat model remain unchanged.
