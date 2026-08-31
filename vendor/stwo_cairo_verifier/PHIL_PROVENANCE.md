# Phil Provenance Record: STWO Cairo Verifier

Publication status: **CLEARED FOR REDISTRIBUTION UNDER APACHE-2.0**

## Recovered source

- Upstream project: Stwo Cairo
- Upstream owner: StarkWare (`starkware-libs` on GitHub)
- Upstream repository: <https://github.com/starkware-libs/stwo-cairo>
- Recovered base revision:
  [`0a5e70b73f397d84c683310382c4e61dc2729f13`](https://github.com/starkware-libs/stwo-cairo/commit/0a5e70b73f397d84c683310382c4e61dc2729f13)
- Upstream revision date: 2026-04-16
- Import into Phil history:
  `ed57751821deab7336bf9b375ac0a1c72a7a2a37` on 2026-04-24

The imported directory has the same 280 paths as
`stwo_cairo_verifier/` at the recovered base revision. Of those files, 275 are
byte-for-byte identical. The following five files differ and contain
Phil-specific compatibility and proof-parity changes:

- `crates/verifier_core/src/channel/blake2s.cairo`
- `crates/verifier_core/src/pcs/quotients.cairo`
- `crates/verifier_core/src/pcs/quotients/test.cairo`
- `crates/verifier_core/src/pcs/verifier.cairo`
- `crates/verifier_core/src/vcs/blake2s_hasher.cairo`

No later Phil commit changed the original 280 imported files before this
provenance record was added.

## License finding

The recovered revision itself contained no repository-level `LICENSE`,
`COPYING`, or `NOTICE` file. Later upstream history supplies an explicit grant
for this code lineage:

- On 2026-01-27, upstream commit
  [`a71e9bcc1c56730842434197190f0c2408ca43e9`](https://github.com/starkware-libs/stwo-cairo/commit/a71e9bcc1c56730842434197190f0c2408ca43e9)
  added `license = "Apache-2.0"` to the Rust prover workspace metadata. That
  metadata covered the Rust workspace crates, but did not by itself establish
  the license of the separately manifested Cairo verifier.
- On 2026-05-13, upstream commit
  [`77718b381a05e889e2cd5222aab20625859bd5c0`](https://github.com/starkware-libs/stwo-cairo/commit/77718b381a05e889e2cd5222aab20625859bd5c0)
  added a repository-level statement that Stwo Cairo is licensed under the
  Apache License, Version 2.0. The same README expressly identifies
  `stwo_cairo_verifier/` as the project's recursive Cairo verifier. The change
  was made through upstream pull request
  [#1767](https://github.com/starkware-libs/stwo-cairo/pull/1767), authored by
  an upstream collaborator, approved by a StarkWare maintainer, and merged into
  the upstream default-branch lineage.
- The recovered revision is an ancestor of that repository-level grant. Of its
  280 verifier paths, 260 remained at the same paths in the grant commit, 18
  continued as detected renames, and two generated files were replaced. All
  five files modified by Phil remained at the same paths and were byte-for-byte
  identical to the recovered revision when the repository-level Apache-2.0
  statement was added.

This maintained, project-wide grant covers the upstream verifier lineage Phil
imported and permits redistribution of the five Phil-modified files as
Apache-2.0 derivative works. It does not make the upstream implementation
Phil-owned or MIT-licensed.

## Distribution obligations

A distribution containing this directory must:

- include the Apache License 2.0 text at
  [`LICENSES/Apache-2.0.txt`](../../LICENSES/Apache-2.0.txt);
- retain applicable upstream source notices and attribution;
- retain [`NOTICE`](./NOTICE), including the list of files changed from the
  recovered upstream revision;
- keep the prominent modification notice in each of the five changed files;
- state changes made by Phil contributors without implying upstream endorsement;
  and
- avoid using StarkWare names or marks as though Apache-2.0 granted trademark
  rights.

No upstream `NOTICE` file existed at the recovered revision, the grant commit,
or the upstream revision reviewed for this record, so there is no upstream
NOTICE text to reproduce verbatim. The Phil notice records attribution and
modifications without inventing an upstream copyright statement.
