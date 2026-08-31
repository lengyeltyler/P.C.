# Architecture Change Control

PhilCore V1 architecture is frozen at ACP-0003 Step 1. Implementation remains
subject to the ordered gates in ACP-0003.

This does not mean the architecture can never change. It means architecture changes must be driven by implementation evidence, security findings, or developer-experience failures discovered while building PhilCore.

## Rules

1. Architecture changes must be driven by implementation evidence, not speculation.
2. Do not redesign proactively because a different pattern looks interesting.
3. Do not change accepted architecture, functional behavior, technical specifications, cryptographic semantics, contracts, proof code, schemas, or runtime behavior without explicit review.
4. If implementation reveals a flaw, mismatch, missing boundary, security concern, or unusable developer experience, document the evidence and propose a targeted architecture change.
5. Historical research may inform a proposal, but it does not override the accepted architecture documents.

## Accepted Architecture Documents

These documents define the current architecture, functional behavior, and technical direction:

- [PhilCore Core Boundary](./PHILCORE_CORE_BOUNDARY.md)
- [PhilCore Runtime Lifecycle](./PHILCORE_RUNTIME_LIFECYCLE.md)
- [PhilCore Functional Specification v1](./PHILCORE_FUNCTIONAL_SPEC_V1.md)
- [PhilCore Technical Specification v1](./PHILCORE_TECHNICAL_SPEC_V1.md)
- [Phil V1 Secure Identity Architecture](./PHIL_V1_SECURE_IDENTITY_ARCHITECTURE.md)
- [ACP-0003](./architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md)

The secure-identity architecture is controlling for root privacy, scoped
identity, encrypted identity/data recovery, device approval, capability and
exceptional-proof authorization, adapter isolation, and algorithm migration.
Existing implementation specifications remain controlling for their current
byte-stable compatibility surfaces where they do not conflict with it.

## Change Proposal Requirements

Every architecture change proposal must include:

- Problem observed
- Implementation evidence
- Affected documents
- Affected modules
- Affected invariants
- Security impact
- Migration impact
- Rejected alternatives
- Recommended change
- Review status

## Protected Invariants

Architecture changes must preserve these unless explicitly reviewed:

- `phil_secret -> identityRoot -> rootOwnerCommitment`, with existing
  `ownerCommitment` bytes preserved as a compatibility alias;
- `identityRoot` and `rootOwnerCommitment` protected by default, never reused
  as a universal public identifier;
- pairwise scoped public commitments and explicit, purpose-bound linking;
- separate root, data, backup, device, account, and recovery key classes;
- user-controlled `2-of-3` identity/data key unwrapping, distinct from account
  recovery;
- replaceable device approval plus policy for every authorization;
- narrow capabilities for routine actions and an admitted witness-hiding root
  proof only for exceptional actions;
- the chain-agnostic authorization envelope and adapter isolation;
- immutable, versioned algorithm/proof/verifier suite identifiers;
- no proof-backend, network-identity, production, or post-quantum overclaim;
  and
- byte-stable `ACTION_UNLOCK`, `proofInputHash`, legacy proof tuple,
  `stwo-unlock-keccak-v1`, and `[fact_high, fact_low]` artifacts only as
  quarantined compatibility/research surfaces without new product authority.

## Review Status Values

Use one of these statuses for architecture change proposals:

- `draft`: evidence is being gathered.
- `proposed`: change is ready for review.
- `accepted`: change is approved and source-of-truth docs must be updated.
- `rejected`: change is not approved; rejected alternatives should explain why.
- `superseded`: proposal was replaced by a later proposal.

## Implementation Evidence Standard

Good evidence includes:

- A concrete implementation blocker.
- A failing or impossible integration path.
- A security boundary that cannot be enforced as specified.
- A missing boundary that causes secret exposure, privilege leakage, or adapter bypass risk.
- A developer workflow that is unusable without changing the architecture.

Weak evidence includes:

- Preference for a different pattern.
- Speculation about future multi-chain support.
- Aesthetic renaming without product or security impact.
- Reopening decisions already resolved by accepted architecture documents.

## Change Discipline

Architecture change proposals should be narrow. Prefer the smallest change that fixes the observed issue while preserving the accepted PhilCore model:

- PhilCore is a Personal Security Operating System.
- Applications create intents.
- PhilCore Runtime API evaluates intents.
- Trust Manager evaluates trusted credentials/devices.
- Policy and Authorization Engines gate sensitive actions.
- Ethereum Net is the first user-facing execution application.
- Ethereum Adapter is the first execution adapter.
- Ethereum/Base execution does not become the identity layer.
