# Verified Fact Publication And Execution Readiness Boundary

> **Current security gate:** this boundary is dormant for real proof input.
> The current STWO artifact is secret-bearing and cannot produce a valid
> finalized Authorization Package. Shared package validation rejects it before
> publication or execution readiness. Tests of later lifecycle shapes use
> explicitly hypothetical non-secret proof references only.

## Purpose

Phase M.5 originally introduced a bounded readiness boundary after local
`ACTION_UNLOCK` proof verification and finalization. It is retained for a
future witness-hiding proof type.

It may consume one valid finalized Authorization Package, create a verified-fact publication request draft, validate Ethereum/Base execution configuration, perform read-only fact/nullifier state checks through supplied readers, and produce a readiness snapshot for future publication/execution preparation.

It does not publish facts or execute authorization.

## Flow

```text
Finalized non-executing Authorization Package
  -> verified-fact publication request draft
  -> chain/verifier/registry/consumer configuration validation
  -> read-only fact-state check
  -> read-only nullifier-state check
  -> execution-readiness snapshot
  -> sanitized Audit Event Draft
  -> stop
```

## Publication Request Versus Publication

A verified-fact publication request draft means only:

```text
The finalized package and public proof/fact/nullifier/configuration references are structurally ready for future publication review.
```

It is not fact publication, contract calldata, a verifier call, a fact-registry call, a nullifier claim, adapter execution, a UserOperation, a transaction, or executable authority.

The payload draft may contain public data only:

- proof type `stwo-unlock-keccak-v1`
- proof artifact reference
- proof digest
- `proofInputHash`
- `[fact_high, fact_low]`
- owner commitment
- public nullifier
- finalized package ID
- verifier/registry references
- expiry
- audit correlation

It must not contain `phil_secret`, `nullifierSeed`, witness material, vault handles, credential material, signing keys, transaction signatures, executable UserOperations, or private proof inputs.

## Exact Binding

M.5 requires exact equality across:

- one finalized Authorization Package
- one proof artifact reference
- one local proof-verification result reference
- one `[fact_high, fact_low]` pair
- one `proofInputHash`
- one public nullifier
- one Ethereum/Base target profile
- one verifier reference
- one fact-registry reference
- one consumer/smart-account reference
- one application
- one session
- one owner commitment
- one action
- one issue/expiry window
- one audit correlation

Silently translated or partially matching inputs are rejected.

## Ethereum/Base Configuration

M.5 supports only the current Ethereum/Base execution direction.

Base remains an Ethereum Adapter profile/config. No multi-chain behavior is introduced.

Configuration binds:

- chain ID `8453`
- network `base`
- profile ID `ethereum-base`
- adapter ID `ethereum`
- verifier reference/address
- fact-registry reference/address
- consumer/smart-account reference/address
- expected proof type `stwo-unlock-keccak-v1`
- expected fact shape `[fact_high, fact_low]`
- future nullifier-consumption behavior

Bundler and paymaster references may be modeled for future execution preparation, but M.5 does not contact bundlers, paymasters, RPC endpoints, contracts, adapters, or smart accounts for execution.

## Read-Only Fact State

`VerifiedFactStateReader` is a read-only boundary.

Allowed states:

- `fact_not_published`
- `fact_already_published`
- `fact_state_unknown`
- `reader_unavailable`
- `configuration_mismatch`

The M.5 implementation uses fixture/local readers for tests and diagnostics. Future RPC-backed readers must be explicitly reviewed, perform `eth_call` only, use configured addresses, apply bounded timeouts, perform no signing, send no transactions, and document the exact method called.

## Read-Only Nullifier State

`AuthorizationNullifierStateReader` is a read-only boundary.

Allowed states:

- `nullifier_available`
- `nullifier_already_consumed`
- `nullifier_state_unknown`
- `reader_unavailable`
- `configuration_mismatch`

M.5 does not reserve or consume nullifiers. It accepts only the public nullifier. It never accepts or exposes `nullifierSeed`.

## Readiness Versus Execution Authority

An execution-readiness result means only:

```text
The package, configuration, and read-only state snapshots are ready for future publication/execution preparation review.
```

Every successful readiness result must state:

- `factPublished = false`
- `nullifierConsumed = false`
- `contractCalled = false`
- `userOperationCreated = false`
- `transactionSigned = false`
- `transactionSubmitted = false`
- `adapterExecuted = false`
- `chainStateMutated = false`
- `persisted = false`

Applications, adapters, contracts, publishers, and transaction preparers must not consume readiness as authority.

## Race And Freshness

Read-only fact/nullifier checks are snapshots, not reservations.

Readiness results preserve:

- check timestamp
- state-reader source
- block reference when available
- freshness window
- race-condition warning
- revalidation requirement before actual transaction submission

Future publication or execution preparation must independently revalidate package validity, fact state, nullifier state, target network, and configuration immediately before preparing or submitting any transaction.

## Future Interfaces

M.5 defines future-facing interfaces only:

- `VerifiedFactPublisher`
- `AuthorizationNullifierConsumer`
- `EthereumAuthorizationExecutionPreparer`
- `SmartAccountUserOperationPreparationInput`
- `EthereumAdapterFinalizedAuthorizationInput`

None are implemented in M.5. They exist to mark future boundaries and to prevent readiness results from being mistaken for transaction authority.

## Alpha 0 Diagnostic

The Alpha 0 shell includes:

```bash
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_execution_readiness
```

Supported scenarios:

- `exact`
- `fact_already_published`
- `nullifier_already_consumed`
- `fact_state_unknown`
- `nullifier_state_unknown`
- `configuration_mismatch`
- `expired_package`

The exact scenario reaches a readiness snapshot with fixture read-only fact/nullifier state. Blocking scenarios produce diagnostics only. No scenario publishes a fact, consumes a nullifier, calls a contract, creates a UserOperation, signs/submits a transaction, calls an adapter, mutates chain state, exposes witness material, or persists execution authority.

## Negative Guarantees

M.5 does not:

- change `ACTION_UNLOCK`
- change the public tuple
- change `proofInputHash`
- change `proofType = "stwo-unlock-keccak-v1"`
- change `[fact_high, fact_low]`
- change proof schemas
- change contract schemas
- change existing contracts
- introduce multi-chain behavior
- publish verified facts
- consume nullifiers
- call contracts
- call adapters
- build executable UserOperations
- sign or submit transactions
- mutate chain state
- persist execution authority
- expose `phil_secret`, `nullifierSeed`, witness material, vault keys, credential private material, or registry plaintext

## Next Work

The next boundary may prepare a verified-fact publication transaction payload, but it must remain controlled, require fresh state revalidation, and still not sign, submit, consume nullifiers, call adapters for execution, or mutate chain state.
