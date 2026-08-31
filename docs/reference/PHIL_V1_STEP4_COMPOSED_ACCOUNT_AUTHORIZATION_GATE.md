# Phil V1 Step 4 Composed Account Authorization Gate

Status: Passed by exact candidate 3377606

Date: 2026-08-21

## Objective

Demonstrate one exceptional Phil account action whose authorization succeeds
only when the accepted Step 3 root proof, a separate enrolled-device P-256
approval, exact policy and action binding, replay state, time and value limits,
current epochs, and revocation state all pass in one atomic Cairo contract
call.

This is a local account-composition gate, not a deployment or production proof-
backend decision. It authorizes no RPC, account funding, declaration,
deployment, signing service, transaction, physical device, real secret, public
release, Step 5 work, or protected-product wiring.

## Reference action

The only Step 4 action is a synthetic exceptional account confirmation. The
contract records an immutable local receipt after successful authorization. It
has no arbitrary call, token, transfer, delegate-call, upgrade, signer,
submission, or external execution surface.

The configured account state binds exactly:

- the scoped owner commitment, scope ID, scope instance, and scope epoch;
- network, account, adapter, principal, nonce-domain, action-type, parameters,
  intent, policy, proof-descriptor, human-presentation, and device-signature-
  suite hashes;
- current capability, device, recovery, and validator epochs;
- one enrolled active device ID, key ID, and P-256 public key;
- the expected action value and fee plus policy ceilings;
- the next account nonce;
- the accepted Step 3 verifier class; and
- active scope, proof descriptor, policy, device, and emergency-stop state.

No caller-controlled field may be substituted after device approval or proof
generation.

## Exact composition

`execute_exceptional_reference_action` must perform the following as one
contract invocation:

```text
recompute authorizationEnvelopeDigest from the exact envelope
+ validate exact operation/action/account/network/policy bindings
+ validate current scope/capability/device/recovery/validator epochs
+ validate time window, action value, action fee, and policy ceilings
+ reject emergency stop and every revoked component
+ reject consumed envelope digest, root nullifier, approval nonce, or wrong account nonce
+ recompute the deviceApprovalDigest
+ verify canonical low-S P-256 signature against the enrolled key
+ library-call the exact accepted Step 3 Garaga verifier
+ require all 13 returned values to equal the exact seven logical public inputs
+ atomically consume every replay key and write one action receipt
```

The authorization digest continues to omit only `rootProofNullifier`. The same
invocation must compare that public nullifier to the proof result and consume
it. Proof validity alone, a device signature alone, or a policy decision alone
never authorizes the action.

## Cryptographic formats

- Root proof: exact Step 3 candidate
  `11234ea623a6b8883eed0036f3d95174cef90627`.
- Proof codec: six `bytes32` public values split big-endian into high/low
  `u128`, with the `u64` scope epoch between them, for exactly 13 values.
- Device signature: ECDSA P-256 over the 32-byte
  `PhilDeviceApprovalV1` digest, represented as canonical non-zero `r` and
  low-S `s` values.
- Device public key: exact affine P-256 `qx` and `qy` coordinates admitted in
  account configuration.
- Hashing: Keccak-256 over the architecture-frozen ABI word order.

The synthetic signing key used by tests must be disclosed and must never be
classified as a Secure Enclave, production, or user key.

## Fail-closed precedence

The implementation must reject in this order before state mutation:

1. unsupported format, operation, or incomplete configuration;
2. emergency stop, inactive scope, revoked policy, revoked descriptor, or
   inactive/revoked device;
3. wrong scope, network, account, adapter, principal, action, parameters,
   intent, policy, descriptor, presentation, signature-suite, or capability
   binding;
4. stale scope, capability, device, recovery, or validator epoch;
5. not-yet-valid, expired, approval-time, value-limit, fee-limit, or policy-
   ceiling failure;
6. wrong account nonce or consumed envelope, nullifier, or approval nonce;
7. malformed device coordinates or invalid/high-S P-256 signature;
8. malformed or invalid root proof; or
9. any mismatch among the 13 returned proof public values.

Only after every check passes may the account consume the envelope digest,
root nullifier, approval nonce, increment its nonce, and write its receipt.
A revert or panic at any stage must leave all replay and receipt state
unchanged.

## Required adversarial matrix

The local tests must reject at minimum:

- missing, malformed, or corrupted proof;
- wrong secret-derived commitment, scope ID, scope instance, scope epoch,
  envelope digest, nullifier, or proof descriptor;
- missing, malformed, wrong-key, high-S, or corrupted device signature;
- wrong device ID, key ID, device epoch, suite, approval nonce, presentation,
  approval time, or approval expiry;
- wrong network, account, adapter, principal, action, parameters, intent, or
  policy;
- stale capability, device, recovery, validator, or scope epoch;
- not-yet-valid or expired envelope;
- action value or fee above either the envelope limit or policy ceiling;
- inactive scope, revoked device, policy, or proof descriptor, and emergency
  stop;
- wrong/duplicated account nonce, reused envelope digest, reused root
  nullifier, and reused approval nonce; and
- any attempted state change after a rejected composition.

One valid action must consume every replay key and advance exactly one account
nonce and one receipt counter. Repeating it must fail.

## Required evidence

- exact Cairo/Scarb/Starknet Foundry/USC identities and lockfile;
- exact Step 3 verifier dependency and class identity;
- deterministic TypeScript/Cairo envelope, approval-digest, P-256, public-
  input, and receipt parity;
- local valid and adversarial test results;
- contract class sizes, class hashes, execution resources, and L2 gas;
- reproducible synthetic fixture and artifact manifest;
- structural proof of no runtime, UI, signer, RPC, deployment, transaction,
  device, real-secret, or STWO reachability; and
- independent review of the frozen exact candidate.

## Exit contract

Step 4 passes only when all required composition and atomicity tests pass, the
exact artifacts and measurements are recorded, and a separate reviewer accepts
the frozen candidate with no unresolved finding.

Accepted result:

```text
STEP 4 ACCEPTED: YES
ACCEPTED EXACT CANDIDATE: 3377606d404312ef7f7dcfec37a11c046f2c907e
PRODUCTION PROOF BACKEND SELECTED: NO
PUBLIC DEPLOYMENT AUTHORIZED: NO
STEP 5 STARTED: NO
```
