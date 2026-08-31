# PhilCore Controlled Sepolia Beta P3 Evidence

Date: 2026-08-27 America/Denver (2026-08-27 UTC)

Verdict:

```text
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```

P3 is complete through one corrective physical ceremony, one digest-bound
nonce-`1` ERC-4337 v0.7 UserOperation submission, successful Sepolia
inclusion, and independent read-only reconciliation. This record does not
authorize P4, P5, mainnet, meaningful assets, signed Beta distribution,
production use, a ready-for-review transition, or merge.

## Frozen source, package, and review

- source commit:
  `a5e38dba06dbc4c915ad1b640f617d758926009d`
- source tree:
  `96608f943e551ef860f210e872fe3f910959cd7b`
- protected untracked `pqREADME.md` SHA-256:
  `7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`
- iPhone package: `PhilCoreCompanion-0.1.0-build56.app`
- bundle/version/build:
  `com.philcore.ios.companion.localalpha` / `0.1.0` / `56`
- package-tree SHA-256:
  `56d1dbef62cbe7151cb0d13011c4f13c2bd1c6a7a6898b0bccca561ccd4d2e8b`
- executable SHA-256:
  `415f300f0d4ead2c55877368170f41aafe37dc559794841eabb3468e60e27e19`
- independent Phase 2 review SHA-256:
  `6718194c0e82407f91a1be386d205713ecdbd28f3bb5ab675b5842ba835ca9ae`
- review disposition: zero CRITICAL, HIGH, or MEDIUM findings; two LOW and
  four INFORMATIONAL findings carried forward below
- review boundary: independent AI review plus owner risk acceptance, not a
  professional audit

The package embedded the full source commit and tree and was independently
inspected before physical use. Package identity was also confirmed visibly by
the operator on the installed phone. This is operator verification, not remote
application or hardware attestation.

## Historical sequence and corrective boundary

P2 had already confirmed one distinct nonce-`0` operation, pass token `1`,
EntryPoint nonce `1`, and consumed P2 replay fields. P2 and P3 are separate
operations with separate proofs, device approvals, plans, owner approvals,
locks, and receipts.

The initial P3 ceremony produced UserOperation
`0x3cb1fffacce39bfdabce03f4636375f04f623f95c82aa0d445ea74f89e9ca843`.
Its one permitted submission was rejected by the bundler before acceptance
because its verification-gas efficiency was below the bundler's threshold.
There was no retry. Bundler lookup and independent provider reconciliation
proved no inclusion, no nonce change, no pass mint, and no public P3 state
mutation. The rejected hash remains preserved as historical incident evidence.

The corrective runner selected a P3-only verification-gas limit of `80000`.
P2F remains `150000`; P2F behavior was not changed. A later physical enrollment
attempt stopped before accepted enrollment persistence, and its older evidence
could not distinguish the last protocol stage. Repeated physical retries were
stopped.

Phase 1 then added phone-free lifecycle diagnostics, explicit expiry and
cancellation, restart invalidation, stale-attempt isolation, safe resume only
from protected durable states, distinct enrollment and second-scan states, and
visible source/package identity. Simulator and source evidence validated those
changes but was not represented as physical-device evidence. Phase 2 froze and
independently reviewed the exact source and package identified above before a
new physical attempt was authorized.

## Successful corrective physical ceremony

Exactly one physical attempt was used under the final Phase 3 authorization.
The operator:

1. freshly installed the exact frozen package and confirmed the visible full
   commit/tree identity;
2. created one fresh enrollment request;
3. observed one matching enrollment preflight and one accepted completion;
4. confirmed protected enrollment persistence;
5. observed the physically distinct second-scan action;
6. created a distinct exact-authorization request;
7. obtained fresh iPhone user presence and P-256 proof of possession;
8. generated and verified a fresh real local Noir proof;
9. locally verified the exact proof, phone approval, policy, epochs, expiry,
   fees, replay tuple, envelope, and action; and
10. released Device Vault signing authority only after those checks passed.

The ceremony created exactly one signed-but-unsubmitted artifact. It caused no
public-network mutation. Raw QR payloads, signatures, keys, witnesses, device
secrets, and credential-bearing endpoints remain private and are not embedded
in this record.

## Signed artifact and no-send plan

- signed-artifact SHA-256:
  `0c595f8d01b46c1b14f5a733e5dffc65b056fcb4658d63f960f8e52cc65f3a70`
- authorization-envelope digest:
  `0x2db392b8c2842732e4f419d66643830530b34377ed807215d9020f67b998fc83`
- plan SHA-256:
  `32709df23fb22e32f4bd8e92ffef7443705d62377efceb25342502c40d62f095`
- full-plan digest:
  `0x28b7ce5e86e39c24a692c7dd96420b0ad7f5ab44fd3e3eced46bf945d4d5c16a`
- UserOperation hash:
  `0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d`

The planner was no-send. It recomputed the signed UserOperation and hash,
bound the exact source/package/review and live state, proved the rejected P3
hash absent, and revalidated the bundler and both provider roles. Execution
required the owner's exact approval phrase bound to the full-plan digest.
Neither the earlier rejected-attempt approval nor phone authorization alone
authorized public execution.

## Public execution and reconciliation

- submission attempts planned: `1`
- actual bundler submission attempts: `1`
- automatic retries: `0`
- manual resubmissions: `0`
- additional funding: `0` wei
- durable execution-lock SHA-256:
  `009a3d7dbeffe0f9548581ddbfcdc663d53401996a106bd078654ec8d6a264e6`
- durable receipt SHA-256:
  `424d7e2ea6a0860e93642b549f2275b0d4e4c546e5c86c38e4793d29594e8091`
- confirmed UserOperation:
  `0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d`
- bundle transaction:
  [`0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0`](https://sepolia.etherscan.io/tx/0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0)
- confirmation block: `11579252`
- transaction receipt status: `1`

Alchemy served the authenticated primary-RPC and ERC-4337 bundler roles.
Credential-free PublicNode served the independently operated reconciliation
role. Credential-bearing URLs are omitted. Bundler acceptance was not treated
as finality: the Alchemy bundler, Alchemy ordinary Ethereum RPC, and PublicNode
all correlated the same UserOperation, transaction, block, receipt, events,
and final state.

## State transition and events

| Check | Before P3 | After P3 |
| --- | ---: | ---: |
| EntryPoint nonce | `1` | `2` |
| Pass balance | `1` | `2` |
| Existing/minted pass | token `1` | token `2` minted; token `1` unchanged |
| Next token ID | `2` | `3` |
| P2 replay fields | consumed | still consumed |
| P3 replay fields | unconsumed | envelope, nullifier, and device nonce consumed |

Token `2` is owned by
[`0xCCFdf0a8172A8B10529a48F77F75941A1FB7aA81`](https://sepolia.etherscan.io/address/0xCCFdf0a8172A8B10529a48F77F75941A1FB7aA81).
The receipt contained exactly one `UserOperationEvent`, one
`PhilSepoliaLocalComposedAuthorizationConsumed` event, and one
`PhilSepoliaMintPassIssued` event, all bound to the approved operation,
account, recipient, and fresh replay fields.

## ERC-4337 gas, prefund, and transaction accounting

The UserOperation and bundler transaction are separate accounting surfaces.

UserOperation accounting:

- actual gas used: `313475`
- applicable gas price: `1135541612` wei/gas
- actual UserOperation gas cost: `355963906821700` wei
- equation:
  `313475 * 1135541612 = 355963906821700`

Bundler transaction accounting:

- Ethereum transaction gas used: `247316`
- transaction effective gas price: `1135541612` wei/gas
- bundler transaction gas cost: `280837609313392` wei

The transaction cost is the bundler transaction sender's Ethereum gas cost; it
is not the Phil account's ERC-4337 UserOperation charge.

Phil account funding reconciliation:

- EntryPoint deposit:
  `779861479486230 -> 700036093178300` wei
- contribution from the pre-existing deposit:
  `79825386307930` wei
- smart-account native balance:
  `3630000000000000 -> 3353861479486230` wei
- missing prefund supplied during `validateUserOp`:
  `276138520513770` wei
- total UserOperation charge:
  `79825386307930 + 276138520513770 = 355963906821700` wei
- frozen maximum prefund: `1056000000000000` wei
- refund/remaining deposit equation:
  `1056000000000000 - 355963906821700 = 700036093178300` wei

No paymaster was used. No external or new funding action occurred. During
validation, the smart account supplied the exact missing prefund from its
already-existing native balance; EntryPoint then charged the UserOperation and
returned the unused prefund to the account's deposit.

## Trust boundary

Noir proves the Phil identity/envelope relationship locally. The enrolled
iPhone P-256 authorization and user-presence requirement are also verified
locally. PhilCore local composition checks the proof, device approval, policy,
epochs, expiry, fees, replay state, and exact action before Device Vault release.

Ethereum independently verifies the ERC-4337 account signature, nonce, and
restricted ActionGate execution path. Ethereum does not independently verify
the Noir proof or the iPhone P-256 authorization. This is not on-chain Noir
verification and does not establish remote iPhone application or hardware
attestation.

## Carried residual risks and limitations

LOW:

- `P2-L1`: the observational lifecycle journal does not independently require
  a matching positive preflight before labeling accepted persistence. The
  concrete enrollment host and protected enrollment store enforce the
  authority-producing boundary.
- `INHERITED-L1`: the executor does not independently re-read the four accepted
  review-environment bindings at execution time; it validates the plan/source
  bindings and still requires the exact owner phrase for the full-plan digest.

INFORMATIONAL:

- `P2-I1`: after durable exact phone approval and local Device Vault signing,
  an interruption before exclusive artifact creation can cause an exact repeat
  local signature of the same hash after restart. It cannot create changed
  authority, two active artifacts, or a submission without the later owner
  digest gate.
- `P2-I2`: package identity is operator-verified in the inspected build and
  visible UI, not remotely attested by the phone protocol.
- `INHERITED-I1`: stale-nonce rejection classification accepts a broad set of
  bundler text containing nonce terminology.
- `INHERITED-I2`: the guard suite combines behavioral tests with structural and
  source-pattern assertions.

Independent AI review is not a professional audit. Physical testing is limited
to the controlled evidence described here. This is Sepolia/testnet evidence,
not mainnet or production readiness, and it establishes no meaningful-assets
or post-quantum-security claim. STWO remains quarantined because its queried
trace openings are witness-recoverable. Local Noir/iPhone verification is not
independent Ethereum verification.

## Remaining gates

P3 is complete and reconciled. P4/P5, signed Beta packages, the full physical
matrix and trusted cohort, later acceptance/release gates, and any production
or mainnet work remain incomplete and separately authorized.

```text
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```
