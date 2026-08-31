# PhilCore Desktop Alpha Product Journey

This document describes the user-facing Local Alpha product journey. It does not replace the Core Boundary, Runtime Lifecycle, Functional Specification, or Technical Specification.

## Product Goal

PhilCore Desktop should feel like a Personal Security Operating System, not an engineering console. A non-developer should be able to create or open a local identity, understand its protection state, approve one safe local action, and review what happened without interpreting proof-system, ERC-4337, runtime, or release-engineering terminology.

## Primary Journey

1. Start PhilCore.
2. Create or open a local PhilCore identity.
3. Understand that the identity is stored securely on this Mac and is not merely an Ethereum wallet.
4. Unlock the identity with a passphrase or enrolled platform protection.
5. Arrive at Home and see protection, identity, trust, recovery, Ethereum, and recent activity status.
6. Review local trusted credentials and recovery posture.
7. Use Home or Ethereum to start **Test a protected action** in local testing mode only.
8. Review a first-class in-app approval panel that explains the request, affected identity/account, authority, digest binding, expiry, one-time use, local-only behavior, and rejection outcome.
9. Approve, reject, or cancel the action inside PhilCore.
10. If approved, satisfy fresh user presence where policy requires it.
11. Let PhilCore attempt the local security proof boundary.
12. In current source, observe the safe stop before signing because the STWO
    artifact is secret-bearing and quarantined. Local ERC-4337 fixture execution
    remains historical regression evidence, not an available product success path.
13. Review Activity for a grouped plain-language workflow and expandable technical details.
14. Lock or exit safely, then reopen the same local identity later without retaining reusable pending approval authority.

## User-Facing Language

The renderer uses a presentation layer to translate internal state into stable user-facing language. Examples:

- `local_alpha` -> Local testing mode
- `public_testnet_disabled` -> Public blockchain connections are off
- `pending_signature` -> Waiting for approval
- `stwo-unlock-keccak-v1` -> Local security proof
- `deployed_local_fixture` -> Local test account ready

Raw values remain available in technical details, diagnostics, logs, and developer mode.

## Information Architecture

Normal navigation is:

- Home
- Recovery setup
- Activity
- Settings

Identity, Trust, Recovery, and Security are Settings sections. Ethereum and
other ecosystems are destinations from Home.

Developer mode is visually separated and can be hidden from Settings. Developer mode may show raw runtime stages, proof references, local fixture labels, nullifier references, and correlation data. It must not bypass approval, trust evaluation, policy, proof verification, user presence, or network restrictions.

Home and Ethereum use the same canonical Runtime operation, while Developer
mode remains a diagnostic view over the same workflow. Current ordinary
execution fails closed at the quarantined proof boundary before signing.

## Normal Protected Action

The normal action is labeled **Test a protected action**.

Eligibility comes from the Runtime snapshot:

- unavailable with no identity;
- unavailable while locked;
- unavailable when the Device Vault signing key is not available;
- unavailable while another protected action is active;
- available only when the local identity and protected state are unlocked.

The primary copy says PhilCore will confirm unlock state, evaluate trust and
policy, and ask for explicit approval. The current ordinary path then fails
closed when the secret-bearing STWO artifact reaches the proof boundary. It
does not request signing approval, use the Device Vault signer, consume the
nullifier, or execute against the local Ethereum fixture. Internal terms such
as nullifier, STWO proof type, UserOperation hash, and fixture addresses are
available only in technical details.

## Approval State

The approval surface projects authoritative Runtime state. It supports preparing, awaiting approval, approved, rejected, cancelled, expired, awaiting user presence, executing, completed, and failed outcomes. The renderer does not create approval grants. It only displays the current Runtime-generated presentation and sends a decision for the exact displayed digest.

Approvals are one-time, expire, and cannot be reused after consumption. The approval panel shows expiration state, disables approval after expiry, prevents duplicate decision submission, and requires a fresh review when the displayed digest no longer matches Runtime state. Locking the identity, closing the app, or reopening after a pending approval fails closed unless Runtime can prove the request remains current, unexpired, and unconsumed.

## Local-Only Ethereum Behavior

Ethereum is presented as local testing mode:

- no real funds;
- no public transactions;
- no public account deployment;
- no public bundler;
- no paymaster;
- no arbitrary target selection;
- no public-network mutation.

The local workflow remains useful because it exercises the production-shaped
Runtime, unlock, trust, policy, and approval preparation, then proves that the
current quarantined STWO boundary stops before signing or local EntryPoint
execution.

## Recovery Posture

The Alpha can create a same-Mac recovery authority for testing. The UI must not present same-device recovery as robust external recovery. Production-grade recovery still requires independent custody, operational review, and external audit.

## Activity And Audit

Activity uses plain-language event titles, timestamps, short explanations, and result summaries. Technical details preserve raw categories, event names, evidence classes, and correlation references. Underlying audit fidelity is not reduced.

Protected-action events are grouped by workflow stage where practical: request, trust, policy, approval, proof generation, proof verification, signing, local execution, and result verification. Normal Activity shows a summary of whether approval, proof verification, Device Vault signing, and local execution occurred; Developer mode can show raw stage identifiers and evidence labels.

For the maintained local QA matrix, see [PhilCore Desktop Alpha QA Checklist](./PHILCORE_DESKTOP_ALPHA_QA_CHECKLIST.md).

## Current Implementation Map

Complete locally:

- durable encrypted local identity;
- local passphrase unlock;
- platform unlock where enrolled;
- digest-bound approvals;
- normal Home/Ethereum protected-action entry using the local Runtime authorization workflow;
- structural rejection of the secret-bearing STWO proof before signing or execution;
- historical synthetic STWO and local execution fixtures retained only for bounded regression evidence;
- sanitized Activity summaries;
- secure renderer/preload boundary.

Fixture-only or local-only:

- Ethereum execution state;
- fact availability;
- smart-account deployment;
- consumer execution;
- recovery drills;
- native user-presence automated evidence outside manual prompt flows.

Developer-only:

- raw proof references beyond safe summaries;
- diagnostic workflow stage internals;
- fixture addresses beyond normal technical details;
- nullifier references beyond short safe summaries;
- release and packaging diagnostics.

Missing or blocked for Beta:

- public Starknet/L1/Base fact route execution;
- public Base Sepolia account deployment and UserOperation submission;
- production recovery custody;
- an admitted witness-hiding production proof backend;
- external audit;
- Base Sepolia Beta gate approval;
- production approval.

## Security Boundaries

The Alpha product UI must preserve:

- `contextIsolation: true`;
- `nodeIntegration: false`;
- `sandbox: true`;
- `webSecurity: true`;
- bundled preload;
- narrow allowlisted IPC;
- no renderer filesystem, shell, or child-process access;
- no public-network mutation;
- digest-bound approval;
- fresh authentication where required;
- encrypted local storage;
- per-user storage isolation;
- recovery restrictions;
- sanitized audit output.

Usability changes must not weaken those boundaries.
