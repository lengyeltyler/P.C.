# O.37.10 Local Lifecycle Report

Status: `COMPLETE_EPHEMERAL_HARDHAT_LIFECYCLE`.

The O.37.10 suite deploys an ephemeral Account Abstraction `0.7.0`
EntryPoint, verifier, confirmation target, factory, and CREATE2 account on
Hardhat chain `31337`. These deployments disappear with the local test
process and are not public mutations.

The suite covers:

- exact initialization, address prediction, deployment, and duplicate
  rejection;
- real O.37.7 validator-envelope verification;
- sender, chain, account, UserOperation hash, action, keyed nonce, epochs,
  fees, validity, paymaster, calldata length, and signer failures;
- real EntryPoint nonce replay rejection;
- exact native transfer and balance change;
- immutable-target confirmation and direct-call rejection;
- validator rotation and stale-validator rejection;
- validator-recovery freeze, cancellation, delay, completion, expiry, and
  epoch transitions;
- one-role recovery-configuration request, cancellation, completion, and
  exact resulting configuration hash;
- exact EntryPoint deposit withdrawal and residual reconciliation;
- malicious-recipient settlement reentrancy rejection during an external
  native transfer;
- malformed factory/verifier binding failures;
- ABI, storage, fixture, and forbidden-surface invariants.

The unchanged O.37.7 suite separately verifies valid recovery envelopes for
bitmaps `3`, `5`, and `6`, combined validator/recovery authority, malformed
evidence, factor order, descriptor membership, and epoch/digest bindings.
The focused O.37.10 suite contains 14 passing cases. O.37.10 does not
generate any production signature or public UserOperation.
