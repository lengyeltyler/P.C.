# PhilCore Repository Map

Status: **current organization record as of 2026-08-25**

## Canonical product repository

[`lengyeltyler/PhilCore`](https://github.com/lengyeltyler/PhilCore) is the only
active PhilCore engineering trunk. Its default branch is `main`. New product,
security, Desktop, iPhone, proof-composition, recovery, and network-adapter work
must converge here through reviewed branches.

The canonical local checkout is:

```text
~/Developer/PhilCore
```

Its remotes have distinct purposes:

- `origin` points to the public canonical `lengyeltyler/PhilCore` repository.
- `phil-private` points to the preserved private `lengyeltyler/Phil` delivery
  repository. It is not a second active product trunk.

The untracked root file `pqREADME.md` is user-owned, intentionally excluded
from PhilCore, and must not be added, modified, moved, deleted, or cleaned.

## Preserved local repositories and worktrees

These locations are retained for evidence, review, or history. They are not
independent product trunks and were left unchanged during this organization
pass:

| Location | Purpose |
| --- | --- |
| `~/Developer/Phil-public-candidate` | Historical public-source candidate snapshot. |
| `~/Developer/Phil-public-hardening` | Isolated public-hardening and visual-integration worktree. |
| `~/Developer/Phil-proof-feasibility-v1` | Isolated proof-backend feasibility prototypes and reports. |
| `~/Developer/PhilCore-pre-mvp-synthesis-preserved` | Preserved pre-MVP synthesis history. |
| `~/Developer/PhilCore-worktrees/*` | Bounded review and implementation worktrees belonging to the canonical PhilCore repository. |
| `~/Desktop/Desktop/samplePhil` | Non-Git reference material; not a repository or source-of-truth location. |

The bounded worktrees were inspected as clean checkouts. Their number reflects
preserved security-review history, not multiple current products. Removing or
pruning them is a separate destructive archival task and is not authorized by
this document.

## Related GitHub repositories

- `lengyeltyler/Phil` is a preserved private delivery/history repository and
  remains separate from the public canonical trunk.
- `lengyeltyler/Philenator` retains its standalone artwork-generator history.
  The required Philenator history and assets are also preserved in PhilCore's
  ancestry and packaged Alpha surface.
- `lengyeltyler/PhilUI` is a separate UI repository. Current PhilCore product UI
  work is integrated and released from PhilCore; this organization pass makes
  no publication or archival decision for PhilUI.
- Other historical `Phil`, `zkPhil`, trait-generation, and NFT repositories are
  not sources of current PhilCore authority unless a future architecture change
  explicitly imports and reviews them.

## Organization rules

1. Product truth lives in PhilCore source plus `docs/CANONICAL_DOCS.md`.
2. Historical repositories may provide evidence but cannot silently override
   current PhilCore architecture, tests, or security gates.
3. A copied checkout is not a new trunk. Preserve provenance with Git history,
   archive refs, or an explicit import commit.
4. Do not copy secrets, local identity state, device material, RPC credentials,
   signing keys, or ignored execution artifacts into any repository.
5. Public-source readiness, testnet-demo readiness, Beta readiness, and
   production readiness are separate verdicts.
6. Mainnet work requires a future, separately approved production gate; it is
   not part of Beta.
