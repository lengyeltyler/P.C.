# O.29 Recovery-Capable Account V2 Threat Model

Status: architecture-stage threat analysis; not an external audit or
deployment approval.

## Protected Assets And Authority

- Phil identity and immutable owner commitment;
- execution validator and validator configuration epoch;
- recovery factors and recovery configuration epoch;
- smart-account native currency, tokens, NFTs, and EntryPoint deposits;
- exact Runtime authorization, approval, presence, and proof evidence;
- chain-adapter configuration and capability-adapter policy;
- nonces, action IDs, expiry, receipts, and audit events.

## Trust Boundaries

Trusted for the initial local architecture:

- protected local authentication;
- Runtime policy and exact-intent construction;
- Device Vault custody and one-time signing sessions;
- reviewed account/factory source and local fixtures.

Untrusted:

- applications and renderers;
- RPC providers, bundlers, paymasters, and relayers;
- token and NFT contracts;
- capability adapters and target contracts until reviewed;
- recovery request submitters;
- public chain ordering and mempool observers.

The local-proof model still trusts Runtime to enforce the proof. Production
meaningful assets require a separately accepted proof-backed or equivalent
on-chain validator composition.

## Threat Analysis

| Threat | Attack | Required defense | Residual risk |
| --- | --- | --- | --- |
| Stolen device | Attacker obtains an unlocked or unlockable primary device | Fresh authentication, short sessions, exact approval, fresh presence, one-time Device Vault signing, value policy | Fully compromised device and user-auth channel may authorize actions until recovery freezes it |
| Compromised validator | Key signs without legitimate Runtime proof | Typed narrow ABI, value and adapter policy, validator rotation, threshold recovery, future on-chain proof validator | Initial ECDSA-compatible V2 still cannot prove local STARK verification on-chain |
| Malicious application | App widens recipient, amount, target, calldata, or batch | Applications submit intent only; Runtime independently resolves and presents every exact field | Social engineering remains possible if presentation is misleading |
| Malicious bundler | Censors, delays, reorders, substitutes, or repeats a UserOperation | Full UserOperation hash signature, EntryPoint nonce, expiry, returned-hash verification, receipt reconciliation, no automatic authority reuse | Censorship and delayed inclusion remain possible |
| Malicious RPC | Lies about balances, code, nonce, fees, or receipt | Restricted methods, infrastructure binding, block-pinned reads, independent derivation, read reconciliation | Availability failure can stop progress |
| Malicious paymaster | Adds token charges or validity constraints | Paymasters disabled by default; later bind exact paymaster data, charge, validity, and maximum liability | Sponsored flow can still be censored |
| Malicious recovery attempt | Attacker proposes its validator | Threshold independent factors, delay, freeze, cancellation, exact new-validator binding, expiry, recovery epoch | Colluding threshold factors can recover authority |
| Compromised recovery factor | One factor attempts takeover | Threshold greater than one, independent failure domains, no single-factor completion | Correlated compromise or weak guardian ceremony |
| Social engineering | User or guardian approves attacker-controlled recipient or validator | Human-readable exact presentation, recipient identity cues, delay, out-of-band recovery notification, cancellation | Users or threshold guardians can still be deceived |
| Replay | Reuses an old action or recovery request | EntryPoint keyed nonce, unique action/request ID, expiry, validator/recovery epoch, consumed evidence | Cross-system audit correlation remains operationally important |
| Chain replay | Reuses authority on another chain or EntryPoint | Chain ID, EntryPoint, account, adapter profile, and security-model domain binding | Incorrect adapter configuration must fail closed |
| Wrong account | Valid intent is redirected to another PhilCore account | Account address and owner commitment binding in Runtime and signature domain | Counterfeit UI can still misrepresent addresses without trusted presentation |
| Wrong recipient or amount | Calldata is changed after approval | Typed decoder plus recipient/amount and full UserOperation-hash binding | Nonstandard token semantics may change actual received value |
| Token callback/reentrancy | NFT/token recipient calls back during transfer | Checks-effects-interactions, action lock where needed, no ambient reusable authority, adversarial token fixtures | Hostile token contracts can revert or report misleading behavior |
| Capability-adapter compromise | Reviewed adapter later changes or is substituted | Exact code/configuration hash, adapter policy version/root, target and selector binding, no delegatecall | Mutable external targets require renewed review |
| Batch confusion | One item is hidden or reordered | Batching initially disabled; future ordered root, count/value limits, complete item presentation | Large batches increase review and UI risk |
| Recovery as withdrawal | Recovery authority transfers assets directly | Recovery selectors rotate authority only and perform no value movement | Newly recovered validator can later transfer only with a fresh ordinary authorization |
| Hidden administrator | Factory, proxy, owner, or disposable wallet bypasses policy | Non-upgradeable implementation, no admin selectors, no direct EOA execute, Account 1/2 prohibited | Version migration requires operational coordination |
| Stranded funds | Account/deposit/token has no tested release route | Mandatory full lifecycle simulation and exact maximum-stranded calculation before funding | Some hostile or nonstandard assets may remain irrecoverable and must not be funded |

## Recovery-Specific Invariants

1. Recovery changes validator authority, not identity.
2. Recovery never changes `ownerCommitment`.
3. Recovery request and completion transfer no value.
4. No recovery factor can invoke ordinary execution.
5. A request identifies exactly one proposed validator configuration and epoch.
6. Ordinary execution is frozen during an active recovery challenge.
7. Current legitimate authority has a cancellation window.
8. Requests expire and cannot be completed after expiry.
9. Completion is replay-protected and consumes the pending request.
10. Asset release after recovery requires an entirely fresh ordinary intent.
11. Recovery-factor rotation has its own delay and cross-authorization.
12. Account 1 and Account 2 have no recovery or release privilege.

## Execution-Specific Invariants

1. Only EntryPoint calls execution and maintenance selectors.
2. The account exposes no raw generic execute or delegatecall.
3. Every action has one typed selector and exact field layout.
4. Unknown selectors, appended bytes, missing fields, and noncanonical
   encodings fail.
5. Signature validation binds the complete Packed UserOperation hash.
6. The validator configuration epoch prevents old-key authority reuse.
7. Recovery freeze blocks the ordinary nonce lane.
8. Native and token transfers emit auditable action events.
9. EntryPoint deposit withdrawal uses the same exact approval standard.
10. Batch, paymaster, session-key, and adapter features default to disabled.

## Required Adversarial Fixtures Before Implementation Acceptance

- wrong signer, validator key ID, validator epoch, recovery epoch, and threshold;
- wrong chain, EntryPoint, account, nonce key, nonce sequence, and expiry;
- wrong action type, purpose, target, selector, recipient, amount, token, token
  ID, calldata hash, fee limit, and batch root;
- direct EOA calls and account-self nesting;
- malformed, appended, and noncanonical calldata;
- replay before and after validator/recovery rotation;
- recovery before delay, after expiry, after cancellation, and during another
  request;
- recovery authority attempting native, token, deposit, adapter, or batch
  execution;
- Account 1 and Account 2 attempting execution, recovery, cancellation, or
  release;
- malicious token callbacks, false return values, fee-on-transfer behavior,
  NFT receiver callbacks, and reentrancy;
- malicious bundler/RPC mutation and ambiguous submission handling;
- full create/fund/execute/release/final-balance lifecycle.

## Architecture Verdict

The selected direction can support recovery without adding a hidden
administrator because recovery is delayed threshold validator rotation, while
fund release remains an ordinary typed action. This is an architecture result,
not proof of implementation security. Contract design, formal invariants,
local/fork fixtures, static analysis, external review, and separate deployment
approval remain required.
