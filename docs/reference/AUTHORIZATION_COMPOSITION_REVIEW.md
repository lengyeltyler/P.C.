# Authorization Composition Review

Status: O.17 internal review; public signing and submission disabled.

## Composition Invariant

Every stage carries the same:

- `actionId`;
- canonical typed action digest;
- identity reference and owner commitment;
- chain and smart account;
- audit correlation.

Stages that possess them also carry exact proof, approval, fresh-presence, and
UserOperation digests. The final envelope is the only input accepted by the
future Sepolia signing guard.

```text
request
 -> policy
 -> approval presentation/result
 -> fresh user presence
 -> STWO public inputs/proof
 -> Runtime authorization
 -> PackedUserOperation
 -> Device Vault signing request
```

The implementation uses ABI typed encoding with an explicit domain separator.
It does not concatenate variable-length strings or rely on renderer text.

## Existing Digest Layers

- `PHIL_ACTION_UNLOCK_V1`: protected action tuple commitment.
- `PHIL_POLICY_V1`: chain, consumer, target, expiry, and policy-data commitment.
- `PHIL_NULLIFIER_V1`: identity/action/policy and private seed commitment.
- `PHIL_UNLOCK_PROOF_INPUTS_V1`: exact proof public-input tuple.
- EntryPoint v0.7 hash: packed UserOperation, EntryPoint, and chain.
- M.10 signing presentation digest: account, owner, chain, EntryPoint, proof,
  nullifier, nonce, UserOp hash, value, gas, and fees.
- `PHILCORE_SEPOLIA_USEROP_AUTHORIZATION_V1`: O.17 final composition envelope.

## Substitution Review

Proof A cannot be combined with approval B because action ID and canonical
digest differ. Approval B cannot be combined with presence C for the same
reason and because the evidence digests are final-envelope fields. A
UserOperation D cannot be substituted because its sender, chain, EntryPoint,
nonce, initCode, full calldata, gas, fees, paymaster data, and hash are checked.

The O.17 adversarial tests mutate proof, approval, presence, and UserOperation
artifact references independently. They also mutate chain, EntryPoint,
account, target, calldata, value, gas/fees, nonce, expiry, and paymaster data.
All fail closed.

## Remaining Integration Work

The envelope is a readiness boundary. The existing desktop workflow must be
updated in the separately approved live phase to construct it from actual
artifacts rather than fixtures and to make Device Vault require it. Until that
integration and the fact-route decision are accepted, no public signing is
allowed.

