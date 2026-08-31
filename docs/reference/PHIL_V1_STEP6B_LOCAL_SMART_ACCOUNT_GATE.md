# Phil V1 Step 6B Local Smart-Account Enforcement Gate

Status: Exact second corrective candidate independently accepted

Date: 2026-08-22

## Decision

Step 6B implements one isolated, local-only ERC-4337 account surface that
consumes the independently accepted Step 6A Base binding and fails closed
before a target call.

```text
STEP 6B LOCAL ACCOUNT CANDIDATE: IMPLEMENTED
STEP 6B INDEPENDENTLY ACCEPTED: YES
ACCEPTED EXACT CANDIDATE: d65aa5d734de8dd93a524d5a45eb31de7a012ceb
STEP 6B CORRECTIVE TEST EVIDENCE: IMPLEMENTED
STEP 6B SECOND CORRECTIVE TIMESTAMP EVIDENCE: IMPLEMENTED
STEP 6 COMPLETE: NO
REAL P-256 DEVICE-APPROVAL VERIFICATION: YES - SYNTHETIC LOCAL KEY ONLY
OFFICIAL ENTRYPOINT INTEGRATION VERIFIED: NO
BASE DEPLOYMENT OR SIMULATION: NO
PRODUCTION AUTHORITY: NO
NETWORK ACTIVITY: NO
```

“No deployment, simulation, or network activity” refers to Base or any other
external network. The tests necessarily deploy and call disposable contracts
inside the in-process Hardhat chain and install harness bytecode at the
documented EntryPoint address. That local mutation is synthetic test evidence,
not public-network activity.

The candidate account is
`contracts/base/erc4337/PhilV1Step6BLocalAccount.sol`. It implements the
ERC-4337 `IAccount.validateUserOp` boundary, pins the Step 6A manifest, Base
chain and EntryPoint, enrolled P-256 public key and device identity, scoped
owner, exact capability binding, policy hash, target, and value/fee ceilings.

The account independently recomputes the Step 6A action hash, account binding,
nonce domain, intent, authorization-envelope digest, device-approval digest,
and adapter-authorization hash. It then verifies a low-S P-256 signature,
requires canonical account calldata, consumes the exact authorization and
keyed nonce before the target call, and relies on transaction rollback when
the target reverts.

## Local ERC-4337 Boundary

The tests use a stateless harness installed locally at Base's documented
EntryPoint v0.7 address on a Hardhat chain shaped with chain ID `8453`. The
harness computes the ERC-4337 `userOpHash`, calls `validateUserOp`, enforces the
returned validity range, and then calls the account's exact calldata.

This establishes account-side validation/execution coupling. It does not
establish compatibility with the official EntryPoint implementation, bundler
simulation rules, validation gas limits, deposits, prefunding, factories,
counterfactual deployment, or Base execution.

The P-256 test uses a disclosed synthetic private key. It does not use the
Step 2 iPhone, Secure Enclave, a real credential, or any undisclosed secret.
OpenZeppelin's P-256 verifier uses the RIP-7212 precompile when supported and a
Solidity fallback otherwise. Step 6B does not claim that a native P-256
precompile is available or production-ready on Base.

## Enforced Properties

- only the pinned EntryPoint address can validate or execute;
- `userOpHash` is recomputed from the raw packed operation, EntryPoint, and
  chain ID;
- sender, keyed nonce, empty `initCode`, empty paymaster data, canonical
  calldata, gas limits, fee fields, target, target calldata, and value must
  match the signed Step 6A envelope;
- the immutable device, scoped owner, capability, policy, target, value
  ceiling, and maximum-fee ceiling must match;
- routine operations only: no root proof, recovery, deployment, paymaster,
  batch, self-call, EntryPoint call, delegatecall, upgrade, or unrestricted
  execution;
- the narrower intersection of action and device-approval time windows is
  enforced;
- authorization hashes and keyed nonce sequences are exact-once; and
- target failure rolls consumption back atomically.

## Deliberate Non-Claims

Step 6B does not implement capability issuance/revocation administration,
device rotation, recovery, account factory/deployment, upgrades, deposits,
prefunding, official EntryPoint or bundler integration, Base RPC, simulation,
transactions, publication, additional networks, credentials, apps, agents, or
post-quantum validation. Its immutable configuration is a bounded test policy,
not a production lifecycle design.

Existing PhilCore V1/V2/EVM contracts remain compatibility or separate
product-history surfaces. They were not relabeled, wired into, or modified by
this candidate.

## Candidate Verification

```text
npm run compile:phil-v1-step6b-account
npm run test:phil-v1-step6b-account
npm run typecheck
npm run test:phil-v1-step6a-base-adapter
npm run verify:phil-v1-step6a-artifacts
npm run test:phil-v1-step3-root-proof-adapter
npm run test:phil-v1-step4-composed-account
npm run test:phil-v1-step5-pq-migration
git diff --check
```

The corrective focused suite contains fourteen tests covering the valid P-256
path; exact signature, raw operation, binding, constructor, fee-overflow,
time-window, capability/policy, nonce, replay, and terminal-counter negatives;
atomic rollback; and source isolation.

## Independent Review Result

Exact first candidate `8b72646fb4bc2c09fe3f494ad42995d9735c53be`
was independently rejected because its production source documented more
fail-closed branches than its committed seven-test suite executed. The review
found no source authorization bypass or unsigned mutable operation field. See
[the review record](./PHIL_V1_STEP6B_INDEPENDENT_REVIEW_8B72646.md).

The bounded correction adds the missing direct regression coverage and two
test-only harness methods without changing the production account source. It
is not accepted until another independent review accepts its exact commit and
tree. See [the corrective report](../security/PHIL_V1_STEP6B_CORRECTIVE_IMPLEMENTATION_REPORT.md).

Independent re-review of exact corrective candidate
`58731cf65a30ab4646d5fd698044b99c289931a5` confirmed every other correction
but rejected one false-positive timestamp case: the transaction intended for
`validAfter - 1` was mined at `validAfter` and reached the later approval-start
predicate. See [the corrective review record](./PHIL_V1_STEP6B_CORRECTIVE_INDEPENDENT_REVIEW_58731CF.md).

The second bounded correction schedules the actual transaction for
`validAfter - 1` and asserts the observed mined-block timestamp. It changes no
production account or harness source. Independent read-only review accepted
exact commit `d65aa5d734de8dd93a524d5a45eb31de7a012ceb`, tree
`0e451a219cff96d91fd40453866e3de784b2d11c`, after independently observing the
actual `executeOnly` transaction at `validAfter - 1`. See
[the second corrective report](../security/PHIL_V1_STEP6B_SECOND_CORRECTIVE_IMPLEMENTATION_REPORT.md).
The complete verdict and residual-risk accounting are in
[the acceptance record](./PHIL_V1_STEP6B_SECOND_CORRECTIVE_INDEPENDENT_REVIEW_D65AA5D.md).

## Next Gate

Step 6B is complete as an independently accepted local synthetic gate. Step 6
as a whole remains incomplete. Independent review rejected the first Step 6C
definition and its first corrective; the second corrective candidate still treats Step 6B as synthetic P-256
account evidence, not proof that Apple's DER/SHA-256 profile already matches
the raw `(r,s)` account wire format. It also removes Step 6B's second account
sequence from the future official-EntryPoint design to avoid failed-execution
nonce deadlock. It also binds target runtime code, exact crash-reconciliation
operation evidence, literal Solidity tuples/selector, and transport bytes.
Exact second corrective definition `227bd48`, tree `cd5a734`, was independently
accepted, but separately authorized implementation later stopped before a
source candidate on its nonce-bound catalog/policy contradiction. Bounded
third-corrective status-correction candidate `fcc0103`, tree `209df24`, is now
independently accepted, and Step 6C-1 synthetic local implementation is
candidates `a158688`, `aea7359`, `591f6b6`, and `5ab4650` were independently rejected and are
superseded. Corrective source candidate `6f048eb`, tree `a9032b2`, is frozen;
exact candidate `22b5cf3`, tree `2b0ff7f`, is independently accepted for
Step 6C-1. Physical-device signing, Base simulation/deployment,
RPC, submission, and production wiring remain separate later authorities.
