# PhilCore Desktop Real Local Authorization

Status: historical O.5 local Alpha evidence; current ordinary execution is
structurally blocked at the secret-bearing STWO proof boundary; Base Sepolia
Beta blocked; production not approved.

Phase O.5 historically wired one desktop action through the real local
PhilCore Runtime path:

```text
durable local identity unlock
-> Runtime intent
-> authoritative Trust and Policy boundaries
-> digest-bound desktop approval
-> scoped Capability Grant
-> Authorization Package Draft
-> protected witness resolution
-> real Rust/STWO ACTION_UNLOCK proof generation
-> real local proof verification
-> finalized Authorization Package
-> local mirrored-fact fixture
-> Base ActionGate execution preparation
-> ERC-4337 v0.7 UserOperation preparation
-> digest-bound signing presentation
-> fresh authentication
-> Device Vault ECDSA signing
-> local EntryPoint fixture execution
-> nullifier and consumer verification
```

The selected action is a fixed zero-value local `contract_call` through `PhilBaseActionGate.verifyAndConsume(...)` and `PhilUnlockConsumer`. The renderer cannot choose arbitrary targets, calldata, proof inputs, signers, EntryPoint calls, RPC providers, or UserOperations.

## Evidence Labels

- durable identity, Device Vault, Trust/Policy, approval, STWO proof generation, proof verification, ERC-4337 preparation, Device Vault signing, and EntryPoint execution: `real_local`
- mirrored fact availability: `local_fixture`
- Starknet publication, L1 anchoring, L1-to-Base relay, public Base publication, public bundler submission: `not_executed`

O.5 uses local fixture fact availability only. It does not claim Starknet, Ethereum L1, or public Base state changed.

Current source retains this sequence only as historical and explicitly labeled
regression evidence. An ordinary Desktop action stops after approval when proof
preparation reaches the quarantined secret-bearing STWO artifact. It does not
reach a signing approval, fresh user presence, Device Vault signing, nullifier
consumption, consumer execution, or public mutation.

## Guardrails

- `phil_secret`, nullifier seed, witness material, validator private key, recovery key, vault key, wrapping key, decrypted registry plaintext, raw proof bytes, and raw unrestricted UserOperations are not sent to the renderer.
- Every stage shares one workflow correlation spine.
- Signing approval binds the exact ERC-4337 signing presentation digest.
- Fresh authentication is required before Device Vault validator signing.
- Lock, restart, or cancellation invalidates pending signing state.
- Identity reset now requires fresh authentication or passphrase reauthentication in addition to typed confirmation.

## Protected Action Lifecycle

The renderer owns one explicit action lifecycle: `idle`, `preparing`, `awaiting_approval`, `approved`, `generating_proof`, `verifying_proof`, `confirming_user_presence`, `signing_locally`, then one of `completed`, `rejected`, `cancelled`, `failed`, or `timed_out`. Progress overlays are derived from this lifecycle and always expose Cancel. Missing protected Mac unlock is detected during preflight and never enters user-presence progress.

Operation deadlines are intentionally separate: preflight 5 seconds, approval bridge work 10 seconds, proof/workflow preparation 150 seconds with a 120-second prover/verifier deadline, native macOS user presence 65 seconds with a 70-second renderer deadline, and local signing/execution 60 seconds. Approval presentations retain their existing five-minute presentation expiry and one-time approval semantics.

Every operation is bound to a stable action ID. Cancellation, timeout, lock, replacement, or restart invalidates that ID; late results cannot update the renderer or complete another action. A non-secret process-local action marker records an in-progress workflow so the next launch can report it as interrupted and clear stale authority.

## Limits

This is suitable for local Alpha testing. It is not suitable for Base Sepolia Beta until the Beta gate passes, public deployments and relayer/bundler prerequisites are approved, and ACP-0002 is accepted for Beta scope. It is not production-approved.
