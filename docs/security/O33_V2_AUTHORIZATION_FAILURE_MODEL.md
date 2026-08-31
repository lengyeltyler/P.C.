# O.33 V2 Authorization Failure Model

Status: `EXPLICIT_LOCAL_REJECTION_MODEL`.

The O.33 authorization engine fails closed with stable internal failure codes.
It does not throw raw cryptographic/provider messages into audit or UI
surfaces and does not echo protected authority evidence.

## Result Contract

Every rejection returns:

- `accepted: false`;
- `status: rejected`;
- one exact code;
- one validation stage;
- execution, signature, and UserOperation flags set to false;
- public mutation count zero.

An external presentation may group failures to avoid giving an attacker a
verification oracle. Sanitized internal diagnostics retain the exact code so
security tests and operators can distinguish cause and impact.

## Failure Codes

| Code | Stage | Meaning and security implication |
| --- | --- | --- |
| `STATE_INVALID` | state | Trusted state is malformed; no validation can proceed safely. |
| `INTENT_INVALID` | intent | O.32 rejected the intent shape, action/purpose/lane relation, range, or canonical encoding. |
| `CHAIN_MISMATCH` | intent | Prevents cross-chain replay. |
| `ENTRYPOINT_MISMATCH` | intent | Prevents verification under a substituted ERC-4337 environment. |
| `ACCOUNT_MISMATCH` | intent | Prevents cross-account replay. |
| `OWNER_COMMITMENT_MISMATCH` | intent | Prevents substituting another Phil identity commitment. |
| `AUTHORIZATION_NOT_YET_VALID` | intent | Authorization was presented before its allowed window. |
| `AUTHORIZATION_EXPIRED` | intent | Authorization was presented after its exact expiry. |
| `VALIDATOR_REVOKED` | authority | Local Runtime state has revoked validator use; recovery may remain available. |
| `VALIDATOR_MISMATCH` | authority | Claimed validator is not the configured authority. |
| `VALIDATOR_KEY_ID_MISMATCH` | authority | Device Vault/key-reference substitution was attempted. |
| `VALIDATOR_EPOCH_STALE` | intent/authority | Old authority was presented after rotation/recovery. |
| `VALIDATOR_EPOCH_FUTURE` | intent/authority | Caller attempted to authorize against state not yet installed. |
| `RECOVERY_EPOCH_STALE` | intent/authority | Authority belongs to an old recovery configuration/state. |
| `RECOVERY_EPOCH_FUTURE` | intent/authority | Caller attempted to pre-authorize a future recovery state. |
| `RECOVERY_CONFIG_MISMATCH` | authority | Factor authority does not belong to the active configuration. |
| `ORDINARY_EXECUTION_FROZEN` | recovery | Lane `0` is blocked during active validator recovery. |
| `MAINTENANCE_FROZEN` | recovery | Validator maintenance is blocked during recovery or config rotation. |
| `RECOVERY_ACTION_INVALID_FOR_STATE` | recovery | Recovery action is not the single action permitted by current recovery state. |
| `INTENT_HASH_MISMATCH` | intent | Amount, recipient, purpose, expiry, nonce, or another intent-bound field changed. |
| `RUNTIME_INTENT_HASH_MISMATCH` | runtime | Runtime evidence refers to a different intent. |
| `RUNTIME_AUTHORIZATION_DIGEST_MISMATCH` | runtime | Proof, policy, approval, presence, or declared Runtime digest changed. |
| `AUTHORIZED_INTENT_HASH_MISMATCH` | runtime | Declared authorization does not match the exact intent and Runtime digest. |
| `AUTHORITY_MISSING` | authority | Unsigned/unauthorized input is never accepted. |
| `AUTHORITY_KIND_MISMATCH` | authority | Validator, threshold recovery, combined cancellation, or config authority was used for the wrong action. |
| `RECOVERY_THRESHOLD_NOT_MET` | authority | Only one recovery role was supplied. |
| `RECOVERY_FACTOR_BITMAP_INVALID` | authority | Factor selection is malformed, overbroad, duplicated, or outside O.32's exact bitmaps. |
| `AUTHORITY_DIGEST_INVALID` | authority | Final O.32 authority digest could not be constructed. |
| `AUTHORITY_DIGEST_MISMATCH` | authority | Claimed final digest differs from the canonical digest. |
| `AUTHORITY_EVIDENCE_MALFORMED` | authority | Evidence-reference format or verifier boundary is invalid. |
| `AUTHORITY_VERIFIER_UNSAFE` | authority | Verifier can sign, accepts generic messages, lacks exact-digest binding, or misreports its identity/result boundary. |
| `SIGNATURE_INVALID` | authority | Purpose-bound verifier rejected, failed, or could not resolve exact authority. |
| `AUTHORIZATION_REPLAY` | replay | The exact final authority digest was already consumed. |
| `NONCE_REPLAY` | replay | The exact ERC-4337 keyed nonce was already consumed. |

## Failure Ordering

The engine checks immutable identity/environment bindings before hashes and
checks hashes before authority verification. This produces deterministic
classes:

- wrong chain/account/EntryPoint/identity fails at the intent boundary;
- validly shaped amount/recipient/purpose/expiry/nonce mutation fails as an
  intent-hash mismatch;
- Runtime evidence mutation fails before the authority verifier;
- stale state and recovery freeze fail before cryptographic work;
- wrong or malformed authority fails only after the exact digest exists;
- replay is rejected before a fixture or future production verifier is asked
  to validate the authority.

The order is part of compatibility testing. It must not be rearranged in
future implementations without reviewing both side-channel exposure and
expected failure semantics.

## Recovery Failures

A single recovery factor is a threshold failure, not an invalid signature.
A malformed or unsupported bitmap is a factor-selection failure. A correctly
shaped factor bundle under an old epoch is a stale-state failure. These
classes matter operationally:

- threshold failure suggests incomplete authority;
- bitmap failure suggests malformed or adversarial role selection;
- stale epoch indicates replay or outdated local state;
- freeze failure indicates the account is intentionally unavailable for that
  lane.

Recovery failures never fall back to validator-only authority, administrator
authority, a generic signature, or ordinary execution.

## Signature And Verifier Failures

O.33 has no production signature verifier and no signature bytes. Its
fixture-only verifier accepts one allowlisted digest/evidence-reference/public
binding tuple. Any deviation returns `SIGNATURE_INVALID` or
`AUTHORITY_EVIDENCE_MALFORMED`.

A future production verifier must retain these properties while adding
canonical low-`s` secp256k1 verification. Transport errors, unavailable key
providers, unsupported formats, recovered-signer mismatches, and malformed
signatures must remain failures; they must never trigger retry with a weaker
format or generic message API.

## No Fallback Authority

No failure permits:

- skipping Runtime proof/policy/approval/presence binding;
- validator substitution;
- old/future epoch coercion;
- recovery-factor downgrade;
- generic message signing;
- administrator override;
- public execution or state mutation.
