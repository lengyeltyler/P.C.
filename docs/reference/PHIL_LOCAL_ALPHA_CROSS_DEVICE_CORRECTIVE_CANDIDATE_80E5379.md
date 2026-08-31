# Phil Local Alpha Cross-Device Corrective Candidate 80E5379

Status: Frozen for independent read-only re-review

Date: 2026-08-23

## Exact Corrective Source

- source commit: `80e5379c75302942220e884d05a8b9f434545755`;
- source tree: `e2d556fcc204e77919aeb76dfba2d78c53eac1c7`;
- branch: `codex/phil-v1-efficient-route`;
- source tree at both builds: clean;
- visual reference: PhilUI commit
  `2451778eb948468ec66f4ba06107261209977517`.

This document is a later evidence-only wrapper around the immutable corrective
source. Candidate `2a2d1ab` and its package are rejected historical evidence.

## Closed Independent-Review Findings

1. Desktop now embeds `THIRD_PARTY_NOTICES.md` and the complete Pixelify Sans
   OFL text. The iPhone resource phase embeds the complete OFL text alongside
   the font.
2. Desktop packaging now fails before compilation unless the exact repository
   runtime check passes. The corrective package was built with Node `26.0.0`
   and npm `11.12.1`; package verification independently enforces both values.
3. The iPhone build process requires a clean tree, embeds the full source
   commit/tree/clean state in `Info.plist`, freezes the signed `.app`, and emits
   deterministic app-tree, executable, resource, and signature evidence.
4. `ASSET_RIGHTS.md` records each font's creator, exact upstream package or
   revision, license, modification status, SHA-256, and publication treatment.
5. `STATUS.md` now distinguishes the implemented bounded native iPhone/Secure
   Enclave evidence from unproven broad-device and production-release scope.

## Corrective Desktop Artifact

- zip:
  `apps/philcore-desktop/release/local-alpha/PhilCore Desktop Local Alpha-0.1.0-local-alpha-macos-darwin-arm64.zip`;
- zip SHA-256:
  `ac3bbabb0a8656e06c7b3f7a52e31892ff1c77cd0999ea8dd9a4c809d7386306`;
- zip bytes: `160081625`;
- embedded manifest SHA-256:
  `f19e2639e4ac73cf4c296528fb3d14c39bbd57f8205965a7a5ea05786c89a93d`;
- embedded source commit:
  `80e5379c75302942220e884d05a8b9f434545755`;
- embedded source tree: checked, clean, zero changed paths;
- embedded app bytes: `390063123`;
- embedded runtime: Node `v26.0.0`, npm `11.12.1`;
- code signed: no;
- notarized: no;
- production approved: no;
- public-network mutation: disabled.

Package verification passed. The app and zip contamination audits passed with
zero findings. Packaged E2E, first-run/returning-user walkthrough, action
lifecycle, and routine-authorization UI tests passed. The quarantined proof
path stopped before signing and execution, left the nullifier unconsumed,
executed no consumer, exposed no private material, and performed no public
mutation.

## Corrective iPhone Artifact

- frozen app:
  `apps/philcore-ios-companion/release/local-alpha/PhilCoreCompanion-0.1.0-build49.app`;
- local evidence record:
  `apps/philcore-ios-companion/release/local-alpha/philcore-ios-local-alpha-evidence.json`;
- evidence-record SHA-256:
  `848d9175654695af814a7e9131882171ff08f608a71f48110fe3804ff5f919bd`;
- embedded source commit:
  `80e5379c75302942220e884d05a8b9f434545755`;
- embedded source tree:
  `e2d556fcc204e77919aeb76dfba2d78c53eac1c7`;
- embedded clean state: `true`;
- bundle: `com.philcore.ios.companion.localalpha`;
- version/build: `0.1.0 (49)`;
- signed-app tree SHA-256:
  `97eaf649e0e49482a914a296fb4ae4e81ada09cd29946ce5deda3f103a8472b4`;
- executable SHA-256:
  `265d6264ccdd613d307fee8810ec6fe6388f08fccda7959b4e1537f24521fb47`;
- `Info.plist` SHA-256:
  `425669243b23638aebbc84e7188578a35cf2a7f110ab1201b65ccba4da3266fe`;
- font SHA-256:
  `9ba86cd010a4de309d263ceff8e8044092c9db7efda869620cb9ff1c4389e8a5`;
- embedded OFL SHA-256:
  `06971e20750c950ccf4b3ec8fadc968f398670df8f9504d79b817a954741d9c2`;
- code-signature verification: passed;
- Team ID: `B342738S82`;
- authority kind: Apple Development.

The focused iOS routine-authorization Simulator suite and safety-critical UI
reachability test passed. The exact frozen signed app was installed over the
existing local Alpha on the paired iPhone 17 and launched. This did not delete,
create, or re-enroll a device key and did not repeat a physical authorization
ceremony.

## Boundary And Re-Review Contract

The functional baseline remains the previously accepted Step 6C physical
success and two-sided cleanup. The corrective source changes release binding,
license delivery, provenance, tests, and documentation; it does not change the
Desktop or iPhone cryptographic call surfaces or any identity, device,
recovery, proof, signature, policy, capability, account, adapter, or network
authority.

Independent re-review must inspect the corrective source and both local
artifacts, reproduce their bindings, and return one exact verdict. Any source
change requires another freeze. Publication, external distribution,
notarization, public networks, meaningful assets, production secrets, RPC,
deployment, transactions, and a new physical ceremony remain unauthorized.
