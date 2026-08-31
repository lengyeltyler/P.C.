# PhilCore Recovery Authority Decision Record

Status: current V2 authority decision record.

Decision date: July 31, 2026.

## Scope

This record applies to `PhilCoreV2MinimalAccountV2` recovery and
recovery-configuration actions. It does not redefine the separate N-series
`PhilCore4337Account` owner/recoveryAuthority model.

## Decision

Actions `8` and `9` require exact 2-of-3 current recovery factors. Action `10`
requires the current validator plus exact 2-of-3 current recovery factors, with
no double counting. Action `11` requires exact 2-of-3 current recovery factors.
Valid pair bitmaps remain `3`, `5`, and `6`. The ordinary execution validator
never counts toward the 2-of-3 recovery-factor threshold. Validator-only and
validator-plus-one-factor authority remain prohibited.

The residual risk that two compromised recovery domains can control request and
cancellation is explicitly accepted. This model was re-accepted unchanged on
July 31, 2026. Changing it requires a separate security architecture phase.

## Actions Covered

| Action | Authority |
| --- | --- |
| `8` request validator recovery | exact 2-of-3 current recovery roles |
| `9` cancel validator recovery | exact 2-of-3 current recovery roles |
| `10` request recovery-configuration rotation | current validator plus exact 2-of-3 |
| `11` cancel recovery-configuration rotation | exact 2-of-3 current recovery roles |

## Canonical Sources

- [O.36.1 Recovery And Cancellation Semantics](../reference/O36_1_RECOVERY_SEMANTICS_SPECIFICATION.md)
- [O.37.1 V2 Recovery Lifecycle Update](../reference/O37_1_RECOVERY_LIFECYCLE_UPDATE.md)

## Limits

This record does not authorize public deployment, public-network recovery
activity, or a physical recovery ceremony. Any future authority-composition
change requires separate architecture and security review.
