# Phil V1 Step 6C-3 Physical Failure and Corrective Report

Status: Physical ceremony stopped; bounded corrective candidate under review

Date: 2026-08-23

## Boundary

The ceremony used one isolated disposable Desktop identity and one separate
Secure Enclave routine-approval key on an iPhone 17 running iOS 26.6. It used
no Phil identity root, recovery key, meaningful asset, public RPC, deployment,
transaction, external prover, or production authority.

The exercised source was accepted Step 6C-2 commit
`4a81b089b84984ba7d3eadd4ee40f8a270796876`, later documented at pre-correction
HEAD `38430e195b6b45a41c944c3138afccf467e4f6f5`, tree
`a20569198949764058f3cfa39d7c41f0ceddb930`.

## Failure Evidence

- Installed iPhone binary SHA-256:
  `fa6d4ccf1330d7df7b3f37975a99297fb7c2bfc8951bdef9f3723902a3fbaafc`.
- First visible fail-closed screenshot SHA-256:
  `2baf1c6fd269497451e2892e1b62c33783e9a16bb76701ecb0cf8d52420d57bd`.
- iOS application-settings screenshot SHA-256:
  `d7201efa2871fb6942d27af345cdbab20be67a13b2f6ecb14df466fd4bfeedc0`.
- Visible cancellation screenshot SHA-256:
  `450f930ba23984a686504ddf5ee5b5ff96dbf8e34e4f024cb0366a50167e5286`.
- The Desktop remained in its waiting transport state after the repeated scan.
- The isolated Desktop protected routine-profile root contained zero files, so
  no durable enrollment record, journal key, request, or receipt existed.
- Independent Core Image decoding proved that the QR labeled as a harmless
  authorization request was a canonical generation-1
  `phil-step6c-routine-enrollment-v2:` payload. No payload bytes or key
  fingerprints are retained in this report.

## Root Cause

The physical failure exposed a composed product-state defect rather than a
cryptographic verification failure.

1. `ScannerController` stopped its capture session and permanently set a
   one-delivery flag after the first QR. It reset neither state when a retained
   SwiftUI sheet controller was presented again. The observed first-scan result
   followed by a silent repeated scan and an untouched Desktop listener matches
   this lifecycle defect.
2. When the Desktop lacked a durable enrollment, the product host correctly
   returned an enrollment bootstrap, but the renderer presented it with generic
   authorization copy. The user therefore could not distinguish enrollment,
   replacement enrollment, and routine authorization.
3. Terminal and expired requests retained a visible stale QR until a manual
   refresh.
4. The iOS scene handler treated every transient inactive phase as a security
   cancellation. A system Local Network or authentication sheet can make the
   scene inactive without backgrounding it, so the first permission flow could
   cancel its own request.
5. The routine URL session disabled connectivity waiting even though initial
   local-network permission resolution can temporarily leave the route
   unavailable.

Opening iOS Settings explains the later visible `cancelled` state because a
real background transition intentionally invalidates the pending request. It
does not explain the preceding silent scan.

## Bounded Correction

The corrective candidate:

- resets the scanner delivery gate and restarts/stops capture for every sheet
  presentation, including retained-controller reuse;
- keeps actual background transitions fail closed while allowing transient
  system permission/authentication overlays to resolve;
- enables URLSession connectivity waiting while retaining ephemeral storage,
  no cookies/cache/proxy, no cellular/expensive/constrained access, one host
  connection, strict expiry, response bounds, and redirect rejection;
- classifies enrollment, replacement enrollment, and authorization explicitly
  in Desktop copy and QR accessibility labels;
- serves the new renderer state helper through the pinned local HTTPS origin
  with an executable JavaScript media type and a focused packaged-origin
  regression check;
- automatically polls bounded local status and removes terminal or expired QR
  material; and
- adds repeat-presentation, malformed-first-scan, scene-policy, local-network
  configuration, renderer-state, stale-poll, and stale-QR regression tests, and
  reruns the existing composed enrollment-to-authorization product-flow case.

The deterministic Step 6C-2 fixture and manifest remain classified
`physicalDeviceVerified=false` until a new physical ceremony succeeds and a
separate independent review accepts its exact evidence.

## Current Verdict

```text
STEP 6C-2 ORIGINAL SOURCE ACCEPTANCE: SUPERSEDED FOR PRODUCT USE
STEP 6C-3 FIRST PHYSICAL CEREMONY: FAILED AND STOPPED
CORRECTIVE SOURCE CANDIDATE: ACCEPTED (c32d8f8 / 12eb24e)
PHYSICAL DEVICE VERIFIED: FALSE
PACKAGED PRODUCT VERIFIED: FALSE
STEP 6C COMPLETE: FALSE
```
