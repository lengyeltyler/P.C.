# Phil Local Alpha Cross-Device Corrective Independent Review — `6b6e512`

Status: Accepted for the bounded local-alpha cross-device milestone

Date: 2026-08-23

## Exact Target

```text
evidence wrapper commit: 6b6e5121cc4ce352761aab5dd6b679c2cc0fe45a
evidence wrapper tree:   4a4ed419253b957e60612a3ec71a17924fa8d568
source commit:           80e5379c75302942220e884d05a8b9f434545755
source tree:             e2d556fcc204e77919aeb76dfba2d78c53eac1c7
```

The independent review was read-only. It did not edit source, use a physical
device, publish or distribute an artifact, contact a public network, deploy a
contract, submit a transaction, use a production secret, or grant production
authority.

## Findings

No candidate-blocking finding remains. The reviewer verified closure of all
five findings from the rejected initial candidate:

1. Both distributables include the required Pixelify Sans OFL text, and the
   Desktop distributable also includes the complete third-party notice.
2. Desktop packaging and verification enforce Node `26.0.0` and npm
   `11.12.1` before compilation.
3. The frozen signed iPhone app is mechanically bound to its clean source
   commit and tree through embedded metadata and deterministic evidence.
4. `ASSET_RIGHTS.md` records exact font provenance, hashes, license status,
   modification status, and distribution treatment.
5. `STATUS.md` distinguishes bounded native iPhone and Secure Enclave evidence
   from unproven broad-device and production-release scope.

The corrective changes do not alter Desktop renderer or main-process authority
logic, iPhone authorization logic, SDK proof-finalization logic, contracts,
adapters, identity, signing, recovery, or network authority. STWO remains
fail-closed and outside the authorization path.

## Independently Reproduced Artifacts

### Desktop

- zip bytes: `160081625`;
- zip SHA-256:
  `ac3bbabb0a8656e06c7b3f7a52e31892ff1c77cd0999ea8dd9a4c809d7386306`;
- embedded manifest SHA-256:
  `f19e2639e4ac73cf4c296528fb3d14c39bbd57f8205965a7a5ea05786c89a93d`;
- embedded source: `80e5379c75302942220e884d05a8b9f434545755`,
  clean, zero changed paths;
- embedded runtime: Node `v26.0.0`, npm `11.12.1`;
- embedded Pixelify Sans WOFF2 SHA-256:
  `4a5633a0c9c1b73abd133a56d3716c2d8df2ed03cb987346f72194aeb224f382`.

The reviewer reproduced the Desktop product, packaged lifecycle, packaged E2E,
and packaged routine-authorization tests. The lifecycle stopped before signing
and execution, left the nullifier unconsumed, executed no consumer, exposed no
private material, and performed no public-network mutation.

### iPhone

- frozen app-tree SHA-256:
  `97eaf649e0e49482a914a296fb4ae4e81ada09cd29946ce5deda3f103a8472b4`;
- app entries: `7`;
- app bytes: `2354197`;
- executable SHA-256:
  `265d6264ccdd613d307fee8810ec6fe6388f08fccda7959b4e1537f24521fb47`;
- `Info.plist` SHA-256:
  `425669243b23638aebbc84e7188578a35cf2a7f110ab1201b65ccba4da3266fe`;
- Pixelify Sans TTF SHA-256:
  `9ba86cd010a4de309d263ceff8e8044092c9db7efda869620cb9ff1c4389e8a5`;
- OFL SHA-256:
  `06971e20750c950ccf4b3ec8fadc968f398670df8f9504d79b817a954741d9c2`;
- evidence-record SHA-256:
  `848d9175654695af814a7e9131882171ff08f608a71f48110fe3804ff5f919bd`;
- embedded source: `80e5379c75302942220e884d05a8b9f434545755` /
  `e2d556fcc204e77919aeb76dfba2d78c53eac1c7` / clean `true`;
- strict code-signature verification: passed;
- signing authority: Apple Development, Team ID `B342738S82`.

The review did not rerun a Simulator or physical-device lane. It verified the
source wiring and exact frozen signed app directly; the preceding candidate
gate had already run the focused Simulator suite, safety-critical UI test, and
installation and launch of this frozen app on the paired iPhone 17.

## Residual Boundary

A separately regenerated static-analysis report identified inherited Step 6C
contract findings, including a reentrancy heuristic. They are not regressions
in this corrective UI/release-binding candidate. The adversarial EntryPoint
test demonstrates failed target reentry, and the frozen Desktop lifecycle
cannot reach signing or execution. The findings remain production-review debt
and prohibit using this acceptance as a production asset-execution approval.

The static-analysis command changed two generated tracked reports after the
review began. The owner restored those command-generated changes to the exact
candidate, leaving the worktree clean. They did not alter the immutable source,
the frozen Desktop zip, the frozen iPhone app, or any recorded artifact hash.

## Verdict

```text
ACCEPT_CROSS_DEVICE_CORRECTIVE_CANDIDATE
```

This verdict accepts the bounded local-alpha cross-device milestone. It does
not authorize publication, external distribution, notarization, public-network
activity, meaningful assets, production secrets, deployment, transactions, or
production use.
