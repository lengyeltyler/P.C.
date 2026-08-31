# Phil V1 Step 6C-2 Independent Review — 09E5A9E

Date: 2026-08-23

Review mode: independent, read-only exact-source review

Candidate: `09e5a9eb743501c12aa164a9f250f71e162f4dec`

Tree: `1da89d07c51c6a1e33b3e29f8f92b67143a6d12f`

## Verdict

`REJECT_FOURTH_CORRECTIVE_STEP_6C_2_IPHONE_DESKTOP_PRODUCT_WIRING_EXACT_SOURCE_CANDIDATE`

## Findings

1. Swift passed the already-derived 32-byte Desktop acceptance digest to
   CryptoKit's data-verification overload, which SHA-256 hashed it again.
   Desktop Noble signed the digest directly with `prehash:false`, so a real
   Desktop acceptance could never verify on iPhone. The Simulator test hid the
   mismatch by using CryptoKit's matching data-signing overload instead of the
   exact TypeScript-generated fixture signature.
2. Desktop retained the ephemeral acceptance private key after successful
   persistence even though replay used only the cached acceptance body.
   Completed-session replay also bypassed the enrollment expiry and remained
   live indefinitely.
3. After authenticated generation-2 enrollment, `CompanionModel` did not
   refresh its cached routine approval record. The idle/failure UI could
   continue displaying the generation-1 public-key fingerprint.

## Confirmed prior-finding closure

- The QR-bound acceptance transcript, same-record replay, ambiguous published
  activation retention, and pre-publication-only rollback design were present.
- Only exact missing enrollment selected enrollment; runtime failures
  propagated.
- Retryable pre-commit and poisoned committed deletion failures were
  distinguished.

## Reproduced evidence

- 32 of 40 permitted no-network focused Step 6C-2 cases passed, including all
  12 Swift Simulator cases; listener/network and RPC-bearing cases were not run
  by the reviewer.
- All 37 focused Step 6C-1 cases and all 43 inherited Step 3 through Step 6B
  cases passed.
- Type checking and all six artifact verifiers passed.
- Classification validation reproduced only the known 17 inherited omissions;
  no candidate omission was introduced.
- No physical iPhone, external network, RPC, deployment, publication, real
  secret, or production signing was used.

Passing synthetic evidence did not override the cross-language cryptographic
incompatibility. This review granted no implementation acceptance or
downstream authority.
