# Phil V1 Cross-Device Visual Integration Candidate

Status: First candidate `2a2d1ab` rejected; corrective source/package candidate `80e5379` frozen for re-review

Date: 2026-08-23

> Historical visual record. The crimson/green/pink presentation and its flat
> character assets were superseded on 2026-08-24 by the
> [Black-and-white interface with full-color Philenator world](./PHIL_3D_MONOCHROME_PHILENATOR_CANDIDATE.md).
> The security and authority boundaries below remain unchanged.

## Why The Earlier Apps Did Not Match PhilUI

The earlier Desktop candidate used selected ideas from PhilUI, but it did not
reproduce the reference typography, palette, clipped geometry, or spatial
backdrop. The iPhone companion was outside that visual task and retained its
standard SwiftUI presentation. The mismatch was therefore a scope and
implementation gap, not a device cache or failed installation.

This corrective candidate treats cross-device presentation as one release
requirement. Desktop and iPhone now share the same visual system while keeping
their different jobs: Desktop is the identity portal and local runtime; iPhone
is the device-first approval and recovery companion.

## Reference And Rights Boundary

The user-controlled PhilUI repository was inspected at exact commit
`2451778eb948468ec66f4ba06107261209977517`. Its presentation direction is the
reference, not a second source of authority.

The implementation uses Phil-owned HTML, CSS, SwiftUI, and existing local Phil
preview behavior. Pixelify Sans is bundled locally under the SIL Open Font
License 1.1; its files and license notice are included in the candidate. No
unresolved character sprite, secret, credential, build output, or private
application authority was copied from PhilUI.

## Shared Visual Contract

Both applications now use:

- Pixelify Sans for the Phil display language, with technical values remaining
  readable and distinguishable;
- dark crimson/black spatial backdrops;
- `#55f58a` readiness and approval accents;
- `#ff3eb5` navigation-energy and destructive/attention accents;
- clipped obsidian surfaces rather than generic light utility cards; and
- the user-facing description `Your trustworthy digital identity`.

Desktop retains the intended door-opening transition after a real successful
vault unlock. The transition cannot start from failed or cancelled unlock
results, has no authority, cannot receive pointer input, and provides a
reduced-motion path.

The iPhone companion applies the same system to Device status, Pair, Approve,
Recovery, and Settings. It preserves the established accessibility labels,
tab names, security copy, scanner boundaries, and Face ID/Secure Enclave flow.
The displayed app version is read from the installed bundle rather than a
stale hard-coded value.

## Security And Product Boundary

The visual correction changes presentation resources only. It does not change
identity, vault, recovery, device admission, cryptographic suites, capability,
policy, proof, signing, adapter, account, or network authority.

The functional baseline remains the successful bounded Step 6C physical test:
an enrolled iPhone approved one harmless local action and Desktop verified its
receipt. Disposable routine-key material was then removed on both sides. That
evidence predates this presentation-only correction and is not represented as
a new cryptographic ceremony.

The current STWO artifact remains secret-bearing and structurally quarantined.
Ordinary protected actions must stop before signing and execution when that
proof path is reached. No public network, meaningful asset, root secret,
deployment, transaction, RPC mutation, or external prover is enabled here.

## Validation And Freeze Contract

Before acceptance, the exact candidate must have:

- JavaScript, plist, Xcode-project, whitespace, and local font-resource checks;
- full Desktop regression tests;
- the focused iOS routine-authorization Simulator suite;
- an iOS UI reachability run across Status, Pair, Recovery, and Settings;
- a clean unsigned local Desktop package with manifest, composition, and
  contamination verification;
- visual inspection of the actual packaged Desktop and built iPhone UI;
- an exact source commit/tree, package SHA-256, package manifest, and iPhone
  version/build identity;
- independent read-only review of the exact frozen candidate; and
- the existing deterministic public-source gate, without publication.

Any finding that changes source requires a new freeze and a new independent
review. Publication, signing, notarization, distribution, device re-enrollment,
secrets, RPC, deployment, and network mutation remain separately authorized.

The exact source, package, and iPhone build identities are recorded in the
[2a2d1ab release-candidate evidence](./PHIL_LOCAL_ALPHA_CROSS_DEVICE_RELEASE_CANDIDATE_2A2D1AB.md).
That first candidate is rejected. Its five findings and the exact corrective
artifacts are recorded in the
[80e5379 corrective evidence](./PHIL_LOCAL_ALPHA_CROSS_DEVICE_CORRECTIVE_CANDIDATE_80E5379.md).
