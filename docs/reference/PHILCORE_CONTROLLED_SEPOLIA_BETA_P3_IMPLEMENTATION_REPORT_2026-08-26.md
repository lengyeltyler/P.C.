# Controlled Sepolia Beta P3 Runner Implementation

Status updated: 2026-08-27; initial implementation and rejection evidence dated
2026-08-26 remains historical below.

```text
P3 RUNNER IMPLEMENTED: YES
P3 INITIAL EXACT-SOURCE INDEPENDENT REVIEW COMPLETE: YES
P3 INITIAL PHONE CEREMONY COMPLETE: YES
P3 INITIAL PUBLIC SUBMISSION ATTEMPT AUTHORIZED: YES
P3 INITIAL USER OPERATION ACCEPTED OR CONFIRMED: NO
P3 CORRECTIVE EXACT-SOURCE INDEPENDENT REVIEW COMPLETE: YES
P3 PHONE-FREE CEREMONY RELIABILITY IMPLEMENTED: YES
P3 PHONE-FREE CEREMONY RELIABILITY INDEPENDENTLY ACCEPTED: YES
P3 CORRECTIVE PHONE CEREMONY COMPLETE: YES
P3 CORRECTIVE PUBLIC MUTATION CONFIRMED: YES
P3 CANONICAL STATUS: COMPLETE AND RECONCILED
```

## Scope

P3 is the second harmless composed action on the already-deployed controlled
Beta smart account. It is not a deployment, funding, recovery, mainnet, or
meaningful-asset operation.

The implementation extends the reviewed P2 runner core with an explicit P3
mode and three dedicated entry points:

- `prepare:philcore-controlled-sepolia-beta-p3-composition`
- `prepare:philcore-controlled-sepolia-beta-p3`
- `execute:philcore-controlled-sepolia-beta-p3`

P3 has separate signed-artifact, plan, receipt, and durable execution-lock
paths under the ignored controlled-Beta evidence root. Existing P2 evidence is
read-only input and is never deleted, overwritten, or reused as P3 authority.

## Initial P3 submission stop and reconciliation

The first reviewed P3 ceremony produced plan digest
`0x211ce78797e0c9a85d7b2071bfc280e4fa98c3de316ca565bacdc09bcceb7b45`
and UserOperation hash
`0x3cb1fffacce39bfdabce03f4636375f04f623f95c82aa0d445ea74f89e9ca843`.
The owner approved that exact plan. The one-shot executor acquired its durable
attempt lock and called `eth_sendUserOperation` once. The bundler rejected the
request with RPC code `-32602` because the signed verification-gas efficiency
was `0.2502533333333333`, below its required `0.4` threshold. The executor did
not retry.

Required read-only reconciliation then established all of the following:

- the bundler returns `null` for both the rejected hash's operation and receipt;
- both independent providers still report EntryPoint nonce `1`;
- the account balance remains `3630000000000000` wei;
- the EntryPoint deposit remains `779861479486230` wei;
- next token ID remains `2`; and
- P2 pass `1` and all three P2 replay fields remain confirmed.

The receipt conservatively records that a public submission request occurred,
but no P3 UserOperation was accepted and no P3 on-chain mutation was confirmed.
The failed attempt and its lock remain preserved as evidence.

## Corrective P3 gas policy

The corrective runner uses a P3-only verification-gas limit of `80000` instead
of reusing P2F's `150000` limit. The rejected submission measured `37538` gas;
`37538 / 80000 = 0.469225`, which exceeds the observed `0.4` admission
threshold while retaining `42462` gas of headroom above measured validation.
The P2F gas policy is unchanged.

The corrective planner and executor also freeze the rejected plan and
UserOperation identities and require both bundler lookup methods to keep
returning `null`. Discovery of the old operation fails closed. A corrective
attempt requires a new proof, new phone approval, new signed hash, new plan
digest, new exact-source review, and a new digest-specific owner approval; the
initial approval cannot authorize it.

## Frozen P2 origin

The P3 runner binds the exact confirmed P2 result:

- P2F plan digest:
  `0xde6052b2b94b28118afa05d4cbc73b343b893171991818d020610ef7d0da836e`
- P2F receipt SHA-256:
  `821dfa42c6c554725a6a31d7038ca7487dde1a2a8d51a2de60a5a7481efecec7`
- P2 UserOperation:
  `0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670`
- P2 transaction:
  `0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934`
- confirmed starting state for P3: EntryPoint nonce `1`, pass balance `1`,
  EntryPoint deposit `779861479486230` wei, next token ID `2`, and all three
  P2 replay values consumed.

The local P2 plan is independently digest-checked before its runtime-code
bindings are accepted. The P2 receipt bytes, plan bytes, on-chain transaction,
bundler receipt, account runtime, replay mappings, token mappings, pass owner,
nonce, exact remaining EntryPoint deposit, balance, and next token ID are
rechecked before P3 composition and again before P3 execution.

## P3 composition

Composition remains local-only and cannot submit a public mutation. It requires
an accepted exact-source P3 review before RPC, Keychain, private-interface, or
phone access. It then requires:

- the deployed account at live keyed EntryPoint nonce `1`;
- empty `initCode` and no factory/factory-data RPC fields;
- a fresh real Noir proof;
- a fresh physical iPhone P-256 approval requiring user presence;
- fresh authorization-envelope, root-nullifier, and device-approval values;
- Device Vault release only after the composed authorization succeeds; and
- a signed but unsubmitted nonce-`1` v0.7 UserOperation.

The existing controlled-Beta assurance boundary is unchanged: Ethereum does
not verify the Noir proof or P-256 approval, and remote hardware/application
attestation is not claimed.

## Phone-free ceremony reliability

The corrective source at `fe5ae94` received an independent accepted review
with zero unresolved critical/high findings. A subsequent physical enrollment
attempt stopped before the Mac persisted accepted enrollment, but the prior
evidence could not distinguish no contact, preflight, completion rejection, or
persistence failure. No physical retry is authorized.

Phase 1 adds an explicit owner-only, allowlisted ceremony lifecycle record at
the P3 Desktop enrollment/exact-authorization boundary. It records only safe
phase, request identity, time, reviewed source/package identity, counters,
allowlisted diagnostic codes, and boolean outcome flags. It never serializes
QR payloads, authorization envelopes, signatures, secrets, credentials,
endpoints, or arbitrary exceptions. Unsafe process-local enrollment and
waiting/reviewing authorization state is marked restart-detected, invalidated,
and preserved in a distinct incident archive before a fresh request. A
protected accepted enrollment and a durably persisted approved authorization
are the only safe resume points and are revalidated from their protected
stores. Enrollment acceptance transitions only to readiness for the distinct
second authorization scan; it grants no execution authority.

This is phone-free source and simulator evidence. It does not prove physical
iPhone presentation, Secure Enclave behavior, Face ID, app installation, or
package identity on a device. It does not authorize P3 planning, signing,
approval, submission, or public mutation.

## Read-only stale-P2 replay proof

The P3 planner loads the exact prior signed P2 UserOperation and calls only
`eth_estimateUserOperationGas`. It accepts the stale-operation demonstration
only when the bundler reports EntryPoint nonce rejection (`AA25`, invalid
account nonce, or an equivalent nonce error). This call cannot mutate Sepolia.
The planner separately requires both providers to agree that all three P2
replay fields remain consumed.

The stale P2 operation is never sent again.

## P3 plan and executor

The planner contains no public submission method. It freezes exactly one
zero-value, factory-free, nonce-`1` UserOperation, exact source and review
identity, endpoint hashes, gas and fee caps, expiry, proof/device digests,
the P2 origin evidence, and the read-only stale-rejection result. Its serialized
starting-state evidence binds the exact nonzero P2 EntryPoint deposit
`779861479486230` wei; the executor requires that same frozen value instead of
accepting the P2F-only zero-deposit assumption.

Execution requires the exact phrase:

```text
I_APPROVE_PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_<64 uppercase plan-digest hex>
```

before reading the plan or endpoints. After revalidation it acquires a durable
P3-only exclusive attempt lock, persists `submission_requested`, and contains
exactly one `eth_sendUserOperation` call. It has no funding path and no retry.
Any timeout or ambiguity stops for read-only reconciliation.

Success requires the bundler and both independent providers to agree on:

- exactly one successful P3 UserOperation event at nonce `1`;
- final keyed EntryPoint nonce `2`;
- the three fresh P3 replay values consumed;
- pass token `2` owned by the current execution validator;
- execution-validator balance `2` and next token ID `3`;
- the three P2 replay values still consumed and P2 pass `1` unchanged; and
- exactly one matching gate-consumption and pass-issued event.

## Final corrective completion

Phase 2 froze exact source commit
`a5e38dba06dbc4c915ad1b640f617d758926009d`, tree
`96608f943e551ef860f210e872fe3f910959cd7b`, and the fresh build-56 iPhone
package. Independent source/package review found zero CRITICAL/HIGH/MEDIUM,
two LOW, and four INFORMATIONAL findings. Those findings remain carried
residual risks; independent AI review is not a professional audit.

Exactly one later authorized physical attempt used that package. Fresh
enrollment and accepted persistence led to a physically distinct second scan,
fresh user-presence P-256 approval, a fresh locally verified Noir proof, exact
local composition, Device Vault release, and exactly one signed-but-unsubmitted
artifact. No public mutation occurred during that ceremony.

The no-send planner froze full-plan digest
`0x28b7ce5e86e39c24a692c7dd96420b0ad7f5ab44fd3e3eced46bf945d4d5c16a`
and UserOperation
`0x7cecc29755c1420f5844047b5c9f22d0f02adcb030db2157fb95bb74979def0d`.
After the separate exact owner approval, the executor submitted once and did
not retry. Transaction
`0x2e51d90bc1453cd7f56f906a5d5db375b06fc085913ad3678929142d01b314e0`
confirmed in block `11579252`. The Alchemy bundler, Alchemy primary RPC, and
PublicNode agreed on receipt status, final nonce `2`, pass balance `2`, token
`2`, next token ID `3`, replay consumption, and exactly one event of each
expected kind.

The exact source/package/review identities, artifact and plan hashes, receipt
and lock hashes, gas/prefund arithmetic, trust boundary, and residual risks are
recorded in the
[canonical P3 evidence](./PHILCORE_CONTROLLED_SEPOLIA_BETA_P3_EVIDENCE_2026-08-27.md).

## Local verification

The focused P2 regression suite and corrective P3 guard suite pass. The P3 suite
covers review ordering, nonce/factory bindings, exact P2 origin constants,
the serialized nonzero starting-deposit binding, read-only stale rejection,
exact approval ordering, one submission call, zero funding, no retry, durable
P3 paths, the rejected-attempt absence proof, the P3-only gas cap, and
final-state requirements.

The earlier corrective implementation was independently accepted at
`fe5ae94`. The later Phase 1 reliability changes were independently reviewed
and frozen at `a5e38dba`, then exercised through the separately authorized
physical, planning, digest-approval, execution, and reconciliation gates
described above. P3 is complete and reconciled. P4/P5 and all later
acceptance/release gates remain incomplete and separately authorized.
