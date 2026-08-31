# Controlled Sepolia Beta final release status

Status date: 2026-08-31

Controlled Sepolia Beta technical and UI development are complete within the
accepted owner-operated testnet scope. P2 and P3 completed and reconciled the
first two composed actions. P4 public recovery execution remains deferred by
accepted scope. P5 attempt 2 succeeded and reconciled: one send, zero retries,
zero additional funding, final account nonce `3`, zero native account balance,
and the two existing harmless passes retained. Its transaction is
[`0xceb0…f5c2d`](https://sepolia.etherscan.io/tx/0xceb00a759a8347aa7d70299afb46f7fd18e2f0ba4b3e41ea379b15bca21f5c2d).
The rejected P5 attempt 1 remains permanently consumed; this success does not
reclassify it or authorize another submission.

The owner-present physical acceptance session used product source `effb38a` and
iOS version `0.1.0`, build `58`. That session passed under
the owner's revised three-request scope: Q1 approved and executed, Q2 was
accidentally approved and executed, and separately authorized Q3 supplied the
authenticated rejection without execution. It was not a pass of the original
exactly-two-request protocol. User presence passed; the evidence does not
separately attest Face ID rather than another permitted local presence method.
The later final UI and public-source work changed no product runtime or security
semantics, so the accepted physical session did not need to be repeated.

The final accepted engineering source is commit
`7fd7ade7b992e9b5b4b6029b3938e1294f372e73`, tree
`7489b116f05d5c44635ea58b45f55824c69941ba`. This clean public-source candidate
starts a new history from that tree with the documented private exclusions and
release-only metadata corrections. It excludes the uncleared historical SVG
blobs; their rights have not been retroactively cleared. The Desktop notice
and final UI corrections are signed, notarized and frozen, with no product
runtime or security-semantics change.
Publication remains subject to final clean-source audit and explicit owner
repository-transition authority. Previous physical acceptance remains bound to
its original artifacts; its continued applicability follows from the verified
zero product-runtime source delta rather than acceptance of a changed package.
There is no mainnet or production-custody approval, no current post-quantum
security claim, and no professional-audit claim. Noir and iPhone P-256 were
locally verified, not Ethereum-verified. V2 recovery is not deployed. STWO is
quarantined research and is not the production authorization prover.

The accepted source/freeze/physical bindings are:

- Product commit: `effb38a262e0e9829563af61374eb4b9e35df968`.
- Product tree: `4f62ad81e71ef8d76d285ca9ac28dea2add95773`.
- Landed baseline checker: `426b871461e6d78d31d45e235c0cc435bbb03792`.
- Prior combined release freeze SHA-256: `436e9354829d7d03949ed4e5097b2e18351f16a00b3879bc27fbbf7a8239a853`.
- Owner-only physical reports are preserved outside this public-source export.
  They are not redistributed and are not required inputs to public deterministic CI.

No trusted-cohort completion, public release tag, new physical acceptance, or
acceptance of the remediation candidate is implied. Those claims require their
own evidence. Historical operations below retain their original stop conditions;
none is an instruction to repeat a consumed action.

The immutable final Desktop archive SHA-256 is
`831f59cf1a0d67e49e69a179cb32e2e579f25f6ea4f778d27e498f6f4ab1883d`;
stapled app tree SHA-256 is
`4f0ea628c257891cb14a10de0662683d850ecf029e59b36a58ca312067b2c634`.
Its embedded source identity remains the engineering commit above; it is not
relabeled as built from this new public root commit. Public-source export does
not rebuild or modify that artifact. iOS remains version 0.1.0, build 58.
