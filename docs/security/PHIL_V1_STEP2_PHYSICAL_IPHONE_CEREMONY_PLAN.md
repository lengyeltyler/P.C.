# Phil V1 Step 2 Disposable Physical-iPhone Ceremony Plan

Status: Completed; bounded ceremony passed with corrective implementation

Date: 2026-08-21

## Purpose

Collect bounded physical-device evidence for the Step 2 device-approval and
local-vault-wrapping boundary. This ceremony does not enroll production Phil
authority and does not test or select a proof backend.

## Authorized Device And Toolchain

- device class: iPhone 17;
- operating system: iOS 26.6;
- security prerequisites: passcode and Face ID enabled;
- application target: iPhone, minimum iOS 17;
- Xcode: 26.6 build 17F113; and
- installed iPhoneOS SDK: 26.5, with Xcode on-device debugging support for iOS
  15 and later.

No device name, serial number, UDID/CoreDevice identifier, Apple Account,
phone number, or biometric data may be written to committed evidence.

## Allowed Material

The harness may create only:

- one disposable Secure Enclave P-256 key under the dedicated
  `com.philcore.ios.companion.device-approval.v1` namespace;
- fixed synthetic 32-byte approval digests;
- one random 32-byte in-memory local-vault key;
- AES-GCM/ECIES wrapper ciphertext for that random local key; and
- sanitized pass/fail, duration, battery, thermal, OS, and device-class
  observations.

It must not receive or create a Phil root, `phil_secret`, `K_data_root`,
recovery factor, account validator key, wallet secret, real authorization,
transaction, RPC request, proof, or external signing request.

## Harness

Run each method individually and in order from
`PhilDeviceApprovalPhysicalCeremonyTests`:

1. `test01CreateDisposableCandidateAndVerifyPresence`
2. `test02CancelUserPresenceWithoutSigning`
3. `test03SignWrapUnwrapAndNonExportability`
4. `test04VerifyPersistenceAfterInterruption`
5. `test05DeleteCandidateAndVerifyAbsence`

Step 4 is run twice: first after background/termination plus lock/unlock, then
again after a full reboot/unlock.

## User Actions

1. Connect the unlocked iPhone to the Mac by USB only when Codex explicitly
   states that the harness build is ready.
2. Keep the iPhone unlocked and visible during installation.
3. For step 2, prevent Face ID from authenticating and tap **Cancel**. A
   signature must not be returned.
4. For step 3, read each system prompt and authenticate only when its text
   states that the operation is a synthetic Step 2 test with no Phil, account,
   recovery, or network authority.
5. Before the first step-4 run, send the app to the background, lock the phone
   for at least 60 seconds, then unlock it.
6. Before the second step-4 run, reboot the phone and unlock it with the
   passcode before allowing the test to continue.
7. Step 5 must delete the exact disposable candidate and prove both key and
   public-metadata absence.

## Stop Conditions

Stop immediately without approving a prompt if:

- a prompt mentions a wallet, Phil identity, recovery, account, transaction,
  network, payment, or any action other than the named synthetic test;
- Xcode requests an unplanned Apple Account login, certificate change,
  distribution action, or Developer Mode policy change;
- the device reports serious/critical thermal state, low battery, passcode or
  biometric security changes, or an unexpected restart;
- any test output contains a private key, local-vault plaintext, device
  identifier, or user data; or
- the cancellation step produces a signature or the deletion step cannot
  prove absence.

## Acceptance Rules

Physical evidence passes only if:

- key creation is Secure Enclave-backed and ThisDeviceOnly;
- private-key use requires user presence;
- cancellation returns no signature;
- the synthetic signature independently verifies;
- a random local key wraps and unwraps exactly;
- private-key export remains impossible after authentication;
- the key remains usable after background/lock and reboot/unlock;
- deletion proves key and metadata absence; and
- every recorded observation remains synthetic, sanitized, and local.

Passing this ceremony does not complete Step 2. Independent cryptographic,
iOS, recovery-lifecycle, and protected-runtime review remains mandatory.

The sanitized result, corrective cancellation history, residual limits, and
deletion evidence are recorded in the
[physical-iPhone evidence report](../reference/PHIL_V1_STEP2_PHYSICAL_IPHONE_EVIDENCE.md).
