# Phil Local Alpha Demo

## Purpose

This demo presents Phil as a device-first personal web identity: a user creates and unlocks a local identity, enters a world of separately permissioned networks and applications, and uses an iPhone-bound key plus Face ID or passcode to authorize one harmless local action without exposing a root secret.

The demo is intentionally local. It does not send a transaction, use meaningful assets, enable a public network, or claim production proof or recovery readiness.

## What the recording should demonstrate

1. Phil gives the identity a recognizable face while protected identity material remains on the user's devices.
2. The Desktop app explains trust before asking the user to act.
3. Unlocking opens the door to a catalog of independently permissioned network destinations.
4. The Mac and iPhone establish an expiring private local session and compare a short fingerprint.
5. The iPhone shows the exact bounded request before Face ID or passcode authorizes it.
6. PhilCore verifies the local receipt, records the result in Activity, and makes no public network change.
7. Recovery remains a separate exact 2-of-3 design and does not share the routine-approval key.

## Pre-record checklist

- Use the current frozen iPhone companion and the matching Desktop candidate from the same source commit.
- Keep the Mac and iPhone on the same private Wi-Fi network. Confirm Wi-Fi is enabled on the iPhone.
- Confirm Local Network, Camera, and Face ID permissions are enabled for PhilCore Companion.
- Use a disposable Alpha identity and no production secret, meaningful asset, or funded account.
- Put both devices in Do Not Disturb and hide unrelated notifications.
- Open PhilCore Companion once before recording and leave it on **Status**.
- Keep the iPhone unlocked when the Desktop creates a QR request.
- Use **Approve** for routine enrollment and routine authorization. **Pair** is for the separate Desktop pairing flow.
- If a QR expires, cancel it on the Desktop and create one new request. Do not reuse an old screenshot.

## Recommended recording sequence

### 1. Meet Phil

1. Launch PhilCore Desktop on the **Hello** screen.
2. Randomize Phil once to show that the artwork is a local preview, not a minted token.
3. Choose **Create Phil**.
4. Record the four introduction scenes:
   - device-first identity;
   - review before trust;
   - Mac and iPhone working together;
   - one identity with separately permissioned future networks.

### 2. Create and unlock the local identity

1. Enter a disposable identity name and a strong disposable passphrase off-camera.
2. Create the identity.
3. Unlock it.
4. Hold on the door-opening transition, then reveal the Phil network world.

### 3. Show the world without overstating it

1. Show the bundled network catalog and search.
2. Open **Ethereum**.
3. Point out that Ethereum has a local protected-action demonstration while other network destinations are previews.
4. State that future network and post-quantum integrations must pass their own security gates before activation.

### 4. Enroll the disposable iPhone routine key

Skip this section when the matching disposable routine key is already enrolled.

1. On iPhone, open **Approve** and create a disposable routine key.
2. On Desktop, choose **Set up or replace iPhone routine key**.
3. On iPhone, remain in **Approve** and choose **Scan routine QR code**.
4. Scan the fresh Desktop QR.
5. Compare the fingerprint on both devices and confirm only when it matches exactly.
6. Complete Face ID or passcode approval.
7. Wait for both devices to show that the routine key was enrolled.

### 5. Run the harmless cross-device approval

1. On Desktop Home, choose **Request harmless local action**.
2. On iPhone, open **Approve** and choose **Scan routine QR code**.
3. Scan the fresh request.
4. Compare the fingerprint if prompted.
5. Show the iPhone review screen: application, action, network, account, target, parameters, value, maximum fee, and expiry.
6. Approve with Face ID or passcode.
7. Show the verified local result on Desktop.
8. Open **Activity** and show the recorded authorization outcome.

### 6. Explain the remaining product boundary

1. Open **Recovery setup** on Desktop and **Recovery** on iPhone.
2. Explain that routine approval and recovery use separate device-bound keys.
3. Explain that production recovery requires exactly two of three independent factors.
4. Open **Ask Phil** on iPhone to close with the product explanation.
5. End on Desktop Home with **No public blockchain changes** visible.

## Successful demo acceptance

The recording is successful only when:

- every character image renders without a broken asset;
- the introduction reaches identity creation;
- unlock shows the door transition and then Home;
- the fresh routine QR is accepted from the iPhone **Approve** screen;
- the fingerprint matches on both devices;
- Face ID or passcode is requested for the bounded approval;
- Desktop reports the harmless local action as verified;
- Activity records the outcome;
- neither device claims a public transaction, production recovery, production proof privacy, or production readiness.

## Stop conditions

Stop the recording and create a fresh request if the iPhone is off Wi-Fi, the devices show different fingerprints, the QR is expired, the app labels a routine QR as a pairing request, Face ID or passcode is unexpectedly bypassed for a new key or approval, or either app reports a failed or cancelled terminal state.
