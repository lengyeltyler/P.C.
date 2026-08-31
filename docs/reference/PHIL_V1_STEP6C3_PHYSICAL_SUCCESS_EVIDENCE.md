# Phil V1 Step 6C-3 Physical Success Evidence

Status: Fresh physical ceremony passed; exact evidence candidate awaiting independent review

Date: 2026-08-23

## Boundary

The ceremony used the existing isolated disposable Desktop identity and its
separate Secure Enclave routine-approval key on an iPhone 17 running iOS 26.6.
The iPhone remained on the same private Wi-Fi network as the Mac. The ceremony
used no Phil identity root, recovery key, meaningful asset, public RPC,
deployment, public transaction, external prover, or production authority.

The installed iPhone application was `PhilCore Companion` version `0.1.0`,
bundle version `48`, bundle identifier
`com.philcore.ios.companion.localalpha`. Device inspection confirmed those
installed values after the ceremony. Its corrective source was commit
`945c7c9238c0e16ec2d28b652eb44a9b66e37129`, tree
`71dbf275031366d468627195717045868a7f59ef`.

## Desktop Packaging Correction

The first authorization attempt after successful enrollment exposed a separate
Desktop packaging defect. The product-owned runtime depended on
`PhilV1Step6CHarmlessTarget`, but that contract lived below a `test` directory
which the package policy correctly pruned. Hardhat therefore failed with
`HH700: Artifact for contract "PhilV1Step6CHarmlessTarget" not found`, and
Desktop startup silently substituted the visibly unavailable fail-closed host.

Corrective source commit
`41d9ab89b88e6792bfabeeaa4b79f1cdbe31dea6`, tree
`320fbc4dabc4079038f67ba2c65c90c4ebdbf521`, promotes the harmless target to
the runtime contract directory, updates its implementation identity and
deterministic evidence, and makes both its source and artifact mandatory in the
package verifier. Evidence commit
`cc35294aa799d13898e94e12c2b23fe94857bb99`, tree
`65a9d0d4524c3ed52b6893f0ad413eb5fd415608`, binds the regenerated Step 6C
fixture and manifest.

The rebuilt unsigned local-Alpha package was generated from `cc35294`:

- package: `PhilCore Desktop Local Alpha-0.1.0-local-alpha-macos-darwin-arm64.zip`;
- bytes: `160056116`;
- SHA-256: `3e65ee7eec04e8dc1c7e9d1fb450f4540ac6b1e98b341268c8e62bf37d659860`;
- bundle identifier: `com.philcore.desktop.localalpha`;
- package verification: passed, with the expected unsigned-local-Alpha warning;
- public-network mutation: false; and
- production approval: false.

## Reproduced Local Evidence

- All 37 focused Step 6C-1 cases passed.
- Both product-owned local-runtime cases and the complete product-flow case
  passed.
- The package-pruning and routine-authorization IPC checks passed.
- Step 6C deterministic artifact verification passed after forced recompilation.
- The package verifier confirmed the harmless-target source and artifact are
  present and no debug artifact or development-only file is packaged. Empty
  directory shells are not counted as files and remain outside that claim.
- The broad legacy packaged harness still failed its inherited headless fresh-
  authentication demo path. That path is outside this routine-authorization
  result and is not waived or represented as passing.

## Physical Result

At approximately 15:02 MDT:

1. The corrected packaged Desktop initialized the product-owned authorization
   runtime from the already durable generation-1 iPhone enrollment.
2. The unlocked disposable Desktop identity created one expiring harmless-
   action authorization request and displayed a routine-authorization QR.
3. The user selected **Approve** in PhilCore Companion, scanned that QR,
   compared the displayed request, and authorized it with Face ID.
4. Desktop polling reached the terminal success state and displayed:
   `The harmless local action completed and its receipt was verified.`
5. The request button returned to its enabled state and the terminal QR was no
   longer displayed.

No QR payload, comparison fingerprint, device public key, signature, encrypted
profile, request body, receipt body, journal record, passphrase, or private
material is retained in this report.

## Disposable Cleanup Result

After the accepted authorization result:

1. The user selected **Delete disposable routine key** in PhilCore Companion
   and reported that deletion completed. This is user-observed physical-device
   evidence; no iPhone key material was exported or inspected.
2. Desktop invoked its separately scoped **Delete disposable profile** action
   only after the authorization was terminal.
3. Desktop reported that the disposable routine profile and journal were
   deleted without changing Phil identity or recovery state.
4. The dedicated Desktop routine-profile root contained 11 files immediately
   before deletion and zero files afterward.
5. The four encrypted identity files and two recovery-origin files retained
   byte-identical SHA-256 sets across the deletion. The hashes themselves are
   intentionally not retained in this report.

The cleanup therefore evidences both required halves of the disposable
ceremony without treating the routine key as identity or recovery authority.

## Interpretation

The bounded physical path now demonstrates that the installed iPhone app can
use its disposable user-presence-protected routine key to approve the exact
displayed local action and that the corrected packaged Desktop can receive,
validate, execute, and verify the resulting local receipt. It does not validate
a public network, production signing, a meaningful asset, recovery, a proof
backend, or post-quantum authorization.

## Candidate Verdict

```text
FRESH STEP 6C-3 PHYSICAL CEREMONY: PASSED
PACKAGED ROUTINE AUTHORIZATION PATH: PASSED FOR THE BOUNDED LOCAL CEREMONY
PUBLIC NETWORK MUTATION: FALSE
PRODUCTION AUTHORITY: FALSE
INDEPENDENT EVIDENCE REVIEW: PENDING
STEP 6C COMPLETE: FALSE PENDING INDEPENDENT EVIDENCE ACCEPTANCE
```
