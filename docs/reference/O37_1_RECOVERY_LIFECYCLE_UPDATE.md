# O.37.1 V2 Recovery Lifecycle Update

Status: `COMPLETE_LOCAL_LIFECYCLE_CORRECTION`.

This update integrates descriptor version `2` into O.35 and O.36.1 without
changing threshold authority, typed execution, or constructor-only account
initialization.

## Initial Enrollment And Activation

The requested conceptual sequence:

```text
Create Account -> Register Factors -> Activate Recovery
```

is entirely local until the last atomic deployment step:

```text
construct counterfactual account configuration locally
  -> register and verify all three factors locally
  -> compute three descriptor commitments and configuration hash
  -> independently review complete initialization
  -> atomically deploy the account with all commitments active
```

There is no onchain partially initialized account, post-deployment enrollment
window, or separate activation call. This preserves O.35's complete
constructor-only initialization and counterfactual-funding prohibition.

Runtime rejects:

- missing or duplicate roles;
- duplicate public material, WebAuthn credential ID, or custody domain;
- an unknown or synced authenticator for the hardware role;
- an unattested/self-asserted hardware classification;
- a recovery factor correlated with the execution validator;
- zero generation, unsupported descriptor version, or wrong domain;
- any proposal whose commitments do not reproduce independently.

## Validator Recovery

Request:

1. exact current 2-of-3 factors authorize action type `8`;
2. descriptor evidence reproduces two selected stored commitments;
3. the request binds the current configuration and epochs, proposed validator
   commitment, exact timing policy, account, chain, EntryPoint, intent, and
   UserOperation hash;
4. request ID equals the authorized-intent hash;
5. the account records complete pending state and freezes ordinary and
   maintenance lanes;
6. no external call or value movement occurs.

Cancellation uses action type `9`, the exact pending request and proposal,
and fresh exact 2-of-3 current-factor evidence. It changes no epoch.

Completion remains permissionless after the delay and before expiry. It
installs only the stored validator proposal, increments validator and recovery
epochs exactly once, clears pending state, and makes no external call.

Expiry remains permissionless at or after expiry and installs nothing.

## Factor Rotation

Factor replacement uses the existing delayed recovery-configuration lifecycle:

```text
current validator plus exact 2-of-3 current recovery factors
  -> complete proposed descriptor set
  -> fresh typed authorization
  -> delayed pending configuration
  -> permissionless exact completion
  -> recovery epoch increments once
  -> old factor commitment becomes invalid
```

Every proposed configuration contains all three ordered descriptors. At least
one role must change. For every changed role:

- credential generation is exactly current generation plus one;
- public verification material changes;
- the independence binding changes;
- a WebAuthn credential-ID hash also changes.

An unchanged role keeps the exact old descriptor commitment. Generation may
not skip, decrease, or change without factor replacement. A policy-only
mutation under the same credential is rejected; policy changes require a new
credential and generation.

The request uses action type `10`, proposed recovery epoch `current + 1`, and
the exact new version-2 configuration hash. It requires the current validator
plus exact 2-of-3 current factors, with no double counting.

Cancellation uses action type `11` and exact 2-of-3 current factors.
Completion installs only the stored configuration and increments recovery
epoch exactly once. Once the epoch and configuration change, old factor
evidence cannot authorize a new action.

## Replacement And Revocation Records

Runtime stores the protected replacement record, including old/new local
credential references, ceremony evidence, reason, approval, and revocation
status. Public evidence contains only hashes and descriptors.

Onchain revocation is represented by the new configuration hash and recovery
epoch. No general revocation registry, administrator, module, or mutable
verifier exists.

## Recovery Security Invariants

1. One factor cannot request, cancel, or rotate recovery.
2. The validator is never a recovery factor.
3. Validator authority plus one factor is insufficient.
4. Recovery and factor rotation cannot spend, approve, or transfer assets.
5. Recovery cannot call an arbitrary target.
6. Completion can install only an exact stored proposal.
7. Old factors fail after configuration/epoch rotation.
8. Same-factor relabeling or generation replay fails.
9. Initial activation is atomic and complete.
10. No deployment, credential enrollment, signature, or UserOperation occurs
    in O.37.1.
