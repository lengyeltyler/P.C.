# Phil Local Alpha Cross-Device Release Candidate 2A2D1AB

Status: Rejected by independent read-only review; superseded by a corrective candidate

Date: 2026-08-23

## Exact Source And Reference

- release source commit:
  `2a2d1ab165a80e3465dbdc649b5856d8fbf9af96`;
- release source tree:
  `66a6f33cdc95d973c1882acb029c44c3b5000234`;
- branch: `codex/phil-v1-efficient-route`;
- PhilUI reference commit:
  `2451778eb948468ec66f4ba06107261209977517`.

The source tree was clean when the package was built. This evidence document
is a later documentation-only wrapper around that immutable release source.

## Desktop Artifact

- package:
  `apps/philcore-desktop/release/local-alpha/PhilCore Desktop Local Alpha-0.1.0-local-alpha-macos-darwin-arm64.zip`;
- package SHA-256:
  `b2e840e43554bdf6c9a0c9c8d4fe1decfe9dbbddf93478a320178979ea064444`;
- package bytes: `160077287`;
- embedded release-manifest SHA-256:
  `9e356137f99a55d0aca00358c800d56d3a2a47fdd551ed5ee52aed9034dc4d50`;
- embedded source commit:
  `2a2d1ab165a80e3465dbdc649b5856d8fbf9af96`;
- embedded app bytes: `390055123`;
- package build number: `0.6.0-local-alpha`;
- code signed: no;
- notarized: no;
- production approved: no;
- public-network mutation: disabled.

Package verification, app and archive contamination audits, packaged E2E,
first-run and returning-user walkthroughs, packaged action lifecycle, and the
packaged routine-authorization UI test passed. The protected-action package
tests stopped before signing and execution at the secret-bearing proof
quarantine, left the nullifier unconsumed, and exposed no private material.

Actual packaged Welcome, Home, Settings, Ethereum, and preview-network
screens were visually inspected. They contain the local Pixelify font,
crimson/black backdrop, green/pink visual language, and clipped obsidian
surfaces described by the cross-device contract.

## iPhone Artifact

- product: `PhilCoreCompanion`;
- bundle identifier: `com.philcore.ios.companion.localalpha`;
- marketing version: `0.1.0`;
- build: `49`;
- source commit:
  `2a2d1ab165a80e3465dbdc649b5856d8fbf9af96`;
- bundled Pixelify font SHA-256:
  `9ba86cd010a4de309d263ceff8e8044092c9db7efda869620cb9ff1c4389e8a5`.

The focused routine-authorization Simulator suite and the UI reachability
test across Status, Pair, Recovery, and Settings passed. The built UI was
visually inspected on an iPhone 17 Pro Max Simulator. Build 49 was then signed
with the configured development identity, installed over the existing local
Alpha on the paired iPhone 17, and launched. Installation did not delete or
re-enroll device key material and was not a new cryptographic ceremony.

## Functional Evidence Boundary

The prior bounded Step 6C physical-success evidence remains the functional
baseline: the enrolled iPhone approved one harmless local action and Desktop
verified its receipt, followed by two-sided disposable-key cleanup. This
presentation-only source candidate does not rewrite that historical evidence
or claim that the physical ceremony was repeated.

No identity, vault, recovery, device-admission, proof, signature, policy,
capability, account, adapter, or network-authority implementation changed in
this candidate. The STWO proof remains secret-bearing and structurally
quarantined. No public network, meaningful asset, production secret, external
prover, RPC mutation, deployment, transaction, publication, or distribution
occurred.

## Independent Review Contract

The reviewer must verify both this documentation wrapper and the immutable
release-source/package binding above. The review must independently confirm:

1. the PhilUI mismatch is corrected on Desktop and iPhone;
2. the bundled font has complete OFL attribution;
3. the visual changes do not add or bypass authority;
4. the package and iPhone build bind to the exact release source;
5. the tested proof-quarantine and public-network stops remain fail closed;
6. current status documents no longer contradict the completed six-step local
   route; and
7. the candidate is acceptable or rejected for a concrete finding.

Publication, signing for external distribution, notarization, release to a
tester, public-network access, device re-enrollment, or a new physical
authorization ceremony requires separate authorization.

## Independent Review Result

Verdict: `REJECT_CROSS_DEVICE_CANDIDATE`.

The reviewer found that the Desktop and iPhone distributables did not embed
the OFL notice, the Desktop package used Node 26.5.1 instead of pinned Node
26.0.0, the installed iPhone build lacked a frozen app/hash/source-binding
record, font provenance was absent from `ASSET_RIGHTS.md`, and `STATUS.md`
retained stale mobile-scaffold language. This candidate and its package hashes
are historical rejected evidence and must not be released.
