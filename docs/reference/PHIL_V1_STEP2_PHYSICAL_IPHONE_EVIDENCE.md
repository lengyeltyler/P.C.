# Phil V1 Step 2 Physical-iPhone Evidence

Status: Bounded ceremony passed; exact observed envelope restricted by
fail-closed admission policy; Step 2 exact source candidate independently
accepted

Date: 2026-08-21

## Outcome

One authorized, disposable ceremony passed on an iPhone 17 running iOS 26.6.
It established that the Step 2 candidate can create and use a user-presence-
protected Secure Enclave P-256 key, wrap and unwrap a random local-vault key,
survive app termination, lock/unlock, and reboot, and delete the exact
candidate afterward.

The cancellation exercise found and corrected a real error-classification
gap. The final run returned no signature and reported cancellation correctly.
The disposable private key and its public metadata were deleted and proven
absent at the end.

This is one-device boundary evidence, not production approval, a population
benchmark, proof-backend evidence, or independent review.

## Bound Candidate

- initial physical-ceremony harness: `c308a72a0b50fd1bc3a495bc25dee6df8b6be999`;
- fail-closed cancellation observation correction:
  `459f8b8448e4cd03449f9bbc0b04f50403b5f16e`; and
- tested cancellation-classification source:
  `0f7e54d840bb2ad8f60d0eace265346fe59f2faf`.

The key-generation, wrapping, unwrapping, persistence, and deletion behavior
did not change between those commits. The final commit added explicit mapping
for Local Authentication cancellation and denial errors.

## Sanitized Environment

| Field | Observation |
| --- | --- |
| Device model | iPhone 17 |
| Device class reported by the app | iPhone |
| OS | iOS 26.6, build 23G71 |
| Security prerequisites | Face ID and passcode enabled |
| Xcode | 26.6, build 17F113 |
| iPhoneOS SDK | 26.5 |
| Physical memory reported by the OS | 7,671 MiB total device memory; not app peak usage |
| Battery during recorded passes | 100% |
| Low Power Mode during recorded passes | Off |
| Thermal state during recorded passes | Nominal |

No device name, serial number, device identifier, Apple Account, phone number,
or biometric data is retained here.

## Final Passing Observations

| Check | Duration | Result |
| --- | ---: | --- |
| Create disposable candidate and confirm presence | 25 ms | Secure Enclave-backed and user-presence-required record present |
| Cancel user-presence prompt | 5,983 ms | No signature; cancellation classified correctly |
| Sign, independently verify, wrap, unwrap, and test non-exportability | 3,795 ms | Signature valid; random 32-byte local key round-tripped; private key not exportable |
| App termination plus at least 60-second lock/unlock | 467 ms | Same candidate present and synthetic signature valid after authentication |
| Full reboot plus first passcode unlock | 609 ms | Same candidate present and synthetic signature valid after authentication |
| Delete exact candidate and confirm absence | 13 ms | Private key and public metadata absent |

Durations are individual operation/test durations, not installation or build
time. They are single observations and do not define performance limits.

## Corrective Cancellation Evidence

The cancellation gate was deliberately fail-closed:

1. In the first attempt, authentication completed before cancellation and a
   signature over only the fixed synthetic test digest was returned. The test
   failed. No Phil, wallet, recovery, account, transaction, proof, or network
   authority was involved.
2. The harness was corrected so a returned signature exits immediately and
   can never emit a passing observation.
3. In the next attempt, no signature was returned, but the application mapped
   the cancellation to a generic failure. The test failed again.
4. The manager was corrected to recognize Local Authentication user, app, and
   system cancellation separately from denial.
5. The final attempt returned no signature, emitted only the sanitized passing
   observation, and passed the test.

This sequence is retained because the failed attempts materially influenced
the tested implementation. Only the final attempt satisfies the cancellation
acceptance rule.

## Material And Authority Boundaries

The ceremony used only:

- one dedicated disposable Secure Enclave key;
- fixed synthetic 32-byte digests;
- one random 32-byte in-memory local-vault key; and
- local, sanitized observations.

It used no `phil_secret`, `K_data_root`, recovery factor, account validator
key, wallet secret, real authorization, transaction, RPC, proof, deployment,
external signer, or public-network action. The random local-vault plaintext
and all cryptographic artifacts were excluded from evidence.

## What Remains Unverified

- induced Secure Enclave metadata-persistence failure cleanup (the successor
  adds exact-key rollback, but this failure branch was not exercised in the
  original physical ceremony);
- app peak-memory and energy profiling rather than total device memory;
- low-battery, Low Power Mode, serious/critical thermal, biometric lockout,
  passcode change, biometric enrollment change, OS update, and migration
  behavior;
- support across additional admitted iPhone models and OS versions; and
- production notification, custody, reconciliation, and recovery operations.

These unverified conditions are not silently admitted. The later executable
policy rejects every profile or resource state outside this exact observation
and grants no production authority.

## Verdict

`BOUNDED PHYSICAL IPHONE CEREMONY: PASSED WITH CORRECTIVE IMPLEMENTATION`

`DISPOSABLE DEVICE MATERIAL DELETED AND ABSENCE VERIFIED: YES`

`STEP 2 COMPLETE: YES`

`STEP 3 STATUS: READY FOR SEPARATE USER DIRECTION; NOT STARTED`
