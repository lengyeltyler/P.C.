# Public Phil Source Boundary

This is the authoritative classification rule for preparing a clean public
Phil release. It defines the contents of a curated snapshot; it does not by
itself authorize publication or a visibility change.

> If a component is necessary for an independent researcher to determine
> whether Phil actually implements a claimed security property, strongly
> prefer PUBLIC unless there is a concrete legal, privacy, credential, or
> operational-security reason not to publish it.

Competitive advantage is not a reason to hide security-critical
implementation.

## PUBLIC - required for verifiability

Subject to established redistribution rights, include:

- the Phil SDK/runtime and public interfaces under `apps/phil-device-sdk/`;
- application code needed to understand security boundaries, including the
  desktop main/preload/renderer boundary and the iOS recovery implementation;
- smart contracts, validators, ERC-4337 integration, authorization, recovery,
  replay/nonce/epoch controls, WebAuthn/P-256/secp256k1 handling, and exact
  action restrictions;
- the Rust, Cairo, STARK, and proof implementation needed to reproduce claimed
  proof behavior;
- deterministic fixtures, cryptographic vectors, relevant tests, build files,
  pinned toolchains, lockfiles, and non-deploying validation scripts;
- current threat models, security limitations, PQ migration architecture,
  build instructions, and reproducible CI; and
- sanitized configuration schemas and public test profiles required to run the
  validation paths.

If a required component cannot legally be redistributed, it must be licensed
or replaced. Omitting it while retaining the related security claim is not an
acceptable publication shortcut. The `vendor/stwo_cairo_verifier/` component
has been cleared for redistribution under Apache-2.0; its provenance and
notice obligations are recorded in that directory.

## PUBLIC - optional or curated

Include only when current, useful, sanitized, and rights-cleared:

- selected architecture and design history;
- public roadmaps and examples;
- contribution and governance documentation;
- non-sensitive screenshots and synthetic UI illustrations; and
- historical evidence that materially helps reviewers interpret current
  guarantees.

Historical material must be labeled as historical and must not override the
current source-of-truth documents.

## PRIVATE - excluded from public distribution

Exclude:

- all real or suspected credentials, local `.env` files, RPC/bundler secrets,
  signing material, Apple credentials, wallet exports, keystores, and generated
  recovery secrets;
- private infrastructure, internal deployment configuration, operator-only
  procedures, unreleased commercial infrastructure, and private incident data;
- AI prompts, coordination transcripts, temporary audit scratch files,
  disposable diagnostics, and obsolete internal reports that are not needed to
  evaluate current behavior;
- machine-specific paths/evidence, unnecessary personal metadata, and private
  development-history metadata;
- third-party material without established redistribution rights; and
- experimental or abandoned work that is neither part of a public claim nor
  needed to understand the shipped security boundary.

## Snapshot gate

Before a public release is created, the curator must build an explicit
allowlisted snapshot from a reviewed source commit, resolve every
required component's license, remove excluded material, scan both the snapshot
and its new history for secrets/personal metadata, reproduce validation, and
confirm that public documentation describes only the code actually included.
Any separately retained development archive is outside the public source and
does not define the released tree.
