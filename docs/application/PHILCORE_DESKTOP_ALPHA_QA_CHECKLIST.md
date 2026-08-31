# PhilCore Desktop Alpha QA Checklist

This checklist is for local Alpha and release-candidate rehearsal only. It does not authorize public-network execution, signing, notarization, deployment, distribution, or real-fund use.

PhilCore identity remains chain-independent. Ethereum/Base is the first local execution direction and adapter path, not the identity root. Current WebAuthn, ECDSA, ES256, P-256, and ERC-4337 pieces are production-shaped classical-cryptography boundaries, not a complete post-quantum security claim.

## Required Manual Matrix

Record each case with scenario, expected result, actual result, pass/fail, evidence, and defect reference when applicable.

Identity and session:

- no identity;
- identity exists but locked;
- identity unlocked;
- identity relocked;
- app reopened;
- corrupted or unreadable local state where safely testable.

Protected-action eligibility:

- unavailable without identity;
- unavailable while locked;
- available after unlock;
- unavailable while another workflow is active;
- restored after terminal result;
- restored after lock/unlock;
- restored after navigation.

Approval behavior:

- Home opens Ethereum, and the approval modal opens from Ethereum's supported local action;
- digest displayed in the modal matches Runtime state;
- technical details expand and collapse;
- Reject prevents signing and execution;
- Cancel and Escape prevent signing and execution;
- Approve requires explicit focus or pointer activation;
- repeated activation does not duplicate a decision;
- expired or stale requests fail closed.

User presence and signing:

- the ordinary current path does not reach signing approval or Device Vault signing;
- hypothetical witness-hiding regression fixtures keep user-presence and signing failure coverage explicitly separate from the product walkthrough;
- cancellation, denial, helper failure, malformed evidence, and unavailable helper prevent signing and execution;
- lock during user presence fails closed.

Proof and local execution:

- the current secret-bearing STWO proof is rejected before signing;
- separately labeled hypothetical regression fixtures prove that proof generation,
  proof verification, Device Vault signing, and local fixture execution failures
  remain fail closed without describing those stages as current product success.

Restart and interruption:

- close while approval is open;
- close while waiting for current proof quarantine;
- source-level hypothetical fixtures retain interruption checks for later stages;
- reopen after rejection, cancellation, quarantine failure, and interruption;
- no reusable approval authority survives restart.

Navigation and projection:

- the normal sidebar contains only Home, Recovery setup, Activity, and Settings;
- Identity, Trust, Recovery, and Security remain available as Settings sections;
- Home, Ethereum, Activity, Settings, and Technical developer diagnostics remain consistent during and after a workflow;
- Bitcoin, Solana, Base, Polygon, Cardano, Arbitrum, and Optimism remain clearly labeled Preview and expose no action;
- User and Technical modes show the same authoritative Runtime state;
- Activity shows a normal-user summary and technical details;
- no stale pending approval, pending signature, or executing state remains after a terminal result.

Accessibility:

- keyboard-only navigation;
- focus trap and focus restoration in approval modal;
- visible focus;
- safe Escape behavior;
- accessible labels and status announcements;
- no reliance on color alone;
- readable long values;
- reduced-motion behavior.

Release readiness:

- unsigned local package builds;
- signed and notarization paths remain externally guarded;
- preload, native helper, proof binaries, and release manifest are packaged;
- contamination audit passes for app and archive;
- clean-environment packaged execution succeeds.

## Manual Result Semantics

For the current product path, success means approval was handled correctly and
the quarantined proof stopped the action before signing, execution, nullifier
consumption, or public mutation. A full local proof/signing/execution success is
valid only in an explicitly labeled hypothetical witness-hiding regression
fixture; it is not current product authority.

Rejected, cancelled, expired, stale, interrupted, or failed cases must state that no reusable approval remains. They must also state whether signing and execution occurred. For rejection, cancellation, stale request, expiry, user-presence failure, proof failure, or signing failure, signing and execution must be false.

Protected-action lifecycle regression command:

```bash
npm run desktop:test-packaged-action-lifecycle
npm run desktop:test-packaged-user-shell
```

The lifecycle and user-shell harnesses both require the ordinary product path
to stop at the current proof quarantine before signing. The lifecycle harness
also covers missing enrollment, rejection, cancellation, and timeout release
of the approval UI. Hypothetical witness-hiding success belongs only in
separate source-level research fixtures; it is never enabled in the packaged
product harness. Neither harness substitutes for a physical human walkthrough.

The user-shell harness additionally covers first-run and returning-user
navigation, the local chain catalog and search, User/Technical switching,
Settings relocation, Activity history loading, identity-name persistence, and
the Ethereum entry path.

## Prohibited During QA

- no public RPC mutation;
- no public bundler;
- no paymaster;
- no Starknet/L1/Base public transaction;
- no real funds;
- no app signing, notarization, stapling, distribution, or tester upload;
- no private key, vault key, wrapping key, `phil_secret`, proof witness, biometric data, or raw proof-byte exposure.
