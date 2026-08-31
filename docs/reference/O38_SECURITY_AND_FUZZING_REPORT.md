# O.38 Security And Fuzzing Report

Status: `LOCAL_GATE_PASS_EXTERNAL_AUDIT_REQUIRED`.

## Static analysis

Slither `0.10.4` ran in a disposable repository copy against the retained
O.37.10 package. It reported 23 detector occurrences touching the V2
contracts: one High, six Medium, seven Low, eight Informational, and one
Optimization. Detector impact is not the final security classification.

| Detector family | Slither impact | O.38 classification | Disposition |
| --- | --- | --- | --- |
| native-transfer reentrancy | High | false positive | `_executionLock` is set before the external call, all action and settlement entry points reject the lock, and the malicious-recipient test proves settlement reentry fails |
| confirmation/withdraw reentrancy | Medium/Low | false positive | same execution lock; only the lock reset and post-call event follow the bounded call |
| zero timestamp equality | Medium | informational | zero is the exact canonical no-pending sentinel |
| ignored third `ECDSA.tryRecover` return | Medium | false positive | the returned error enum is checked; the unused error argument cannot authorize a signature |
| recovery timestamps | Low | informational | exact delay and expiry are required security rules |
| bounded assembly | Informational | informational | fixed-word reads and canonical length/range checks are regression tested |
| low-level calls | Informational | informational | only bounded prefund, native transfer, factory binding `STATICCALL`, and verifier `STATICCALL` paths exist |
| complexity / numeric syntax / immutable suggestion | Informational/Optimization | informational | no authority or deployment bypass |

Unmitigated High: `0`. Unmitigated Critical: `0`. No code-level Medium
finding remains open. The package still requires an independent external
audit before a separately authorized public deployment and is not approved
for meaningful real-value use.

## Property and invariant coverage

O.38 adds deterministic seed reproduction for 128 arbitrary authority
envelopes with lengths from 0 through 1,024 bytes. It also checks 32
truncations, 32 extensions, seven unknown or retired action types, chain and
artifact guard changes, production initialization drift, and both absent and
present approval flags against a deliberately missing broadcast path.

The unchanged O.37.7 verifier suite covers valid validator, recovery, and
combined envelopes; low-s enforcement; wrong signer; digest, chain, account,
and epoch binding; bitmaps `3`, `5`, and `6`; duplicate factors; role order;
descriptor membership; caller binding; empty storage; and state-changing
opcode absence.

The unchanged O.37.10 suite deploys the actual
`@account-abstraction/contracts@0.7.0` EntryPoint and covers:

- keyed lanes 0, 1, and 2, with replay rejected by EntryPoint;
- paymaster rejection, fee ordering, prefund, validation data, `handleOps`,
  beneficiary accounting, and revert behavior;
- exact authorized native value and failed/malicious recipient behavior;
- validator rotation and stale authority rejection;
- exact 2-of-3 recovery request, cancellation, delay, completion, expiry,
  deterministic settlement, and single epoch advancement;
- recovery-configuration rotation and one-role-only change;
- exact EntryPoint deposit withdrawal and residual reconciliation;
- CREATE2 prediction, domain-bound salts, constructor sensitivity, duplicate
  deployment rejection, and direct-EOA construction rejection;
- fixed verifier code-hash binding and malformed verifier response failure.

The complete isolated O.32–O.38 regression contains 216 passing tests and
zero failures. O.38 contributes five focused guard/property cases.

The account has no nonce storage or replay mapping; EntryPoint owns nonce
advancement. Recovery actions contain no native-transfer or arbitrary-call
surface. Native execution is typed and cannot select arbitrary calldata.

## Fork limitation

No credential-free, pre-approved Sepolia endpoint abstraction was available.
O.38 did not read `.env.sepolia.local` and did not perform a fork. The
strongest equivalent test deploys the exact package-pinned EntryPoint 0.7.0
bytecode locally and compares repository-retained Sepolia infrastructure
identifiers. A later read-only phase must freshly verify live code hashes.

Deterministic seed rule: seed integers `1..128`, xorshift
`state ^= state << 13; state ^= state >> 7; state ^= state << 17`, with
length `(seed * 73) % 1025`.
