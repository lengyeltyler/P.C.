# PhilCore Alpha 0 Non-Authoritative Demo

## Purpose

Alpha 0 is a local development demo that connects the current non-authoritative Runtime, Trust Manager, Security Policy Engine, approval draft, user decision fixture, and capability activation candidate boundaries.

It proves that the artifact chain can be orchestrated end to end without creating authority.

## Pipeline

```text
Create validation-only Runtime API
  -> create ephemeral User Session context/store
  -> create Capability Request
  -> create Capability Grant Draft
  -> create Trust Evaluation Draft
  -> evaluate explicit public Trust metadata
  -> create Possession Verification Draft
  -> verify explicit WebAuthn test fixture
  -> create non-authoritative Possession Evaluation Result
  -> create Bounded Trust Evaluation Result
  -> evaluate explicit Policy Set
  -> create User Approval Request Draft
  -> record local approve fixture
  -> create Capability Activation Candidate
  -> inspect Audit Draft trail
  -> print final non-authoritative summary
  -> stop
```

## Run

```bash
npm run demo:runtime-alpha0
npm run demo:runtime-alpha0 -- policy_denial
npm run demo:runtime-alpha0 -- canonical_activation_world_id_required
npm run demo:runtime-alpha0-shell
npm run demo:runtime-alpha0-shell -- --scenario ordinary_success
npm --silent run demo:runtime-alpha0-shell -- ordinary_success --json
npm run demo:runtime-alpha0-shell -- --lifecycle
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence valid_unlock
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence fixture_unlock
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_webauthn_partial_unlock
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_webauthn_vault_unlock
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_protected_state_view
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_public_credential_directory
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_selected_credential_public_material
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_trust_manager_verification_input
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_trust_manager_assertion_verification
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_trust_decision_candidate
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_credential_counter_persistence
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authoritative_trust_decision
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authoritative_policy_decision
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_platform_user_approval_decision --approval-outcome approve
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_decision_candidate
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_decision_candidate --authorization-candidate-scenario capability_mismatch
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_package_draft
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_package_draft --authorization-package-draft-scenario invalid_nullifier
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_action_unlock_proof_generation
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_action_unlock_proof_generation --action-unlock-proof-generation-scenario witness_binding_mismatch
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_finalized_authorization_package
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_finalized_authorization_package --finalized-authorization-package-scenario invalid_proof
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_execution_readiness
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence production_authorization_execution_readiness --authorization-execution-readiness-scenario fact_already_published
```

Failure scenarios return a failed demo result but exit zero by default so they can be inspected locally. Use `--strict-failures` when a failed scenario should exit non-zero.

## Interactive Shell

`demo:runtime-alpha0-shell` is a terminal diagnostic tool for exploring Alpha 0 scenarios. It lets a developer list scenarios, select one, inspect stage-by-stage results, inspect the final non-authoritative summary, inspect sanitized audit draft summaries, and return to the scenario menu.

The shell also supports non-interactive mode:

```bash
npm run demo:runtime-alpha0-shell -- --scenario policy_denial
npm run demo:runtime-alpha0-shell -- canonical_activation_world_id_required
npm --silent run demo:runtime-alpha0-shell -- ordinary_success --json
npm run demo:runtime-alpha0-shell -- --lifecycle --lifecycle-sequence timeout
```

The shell displays:

- stage name
- stage status
- artifact ID when available
- outcome
- failure reason when applicable
- whether processing stopped
- whether the stage produced an audit draft
- final non-authority flags

JSON mode emits sanitized result data only. It does not include raw WebAuthn fixture payloads, private material, vault data, proof payloads, adapter payloads, or secret-bearing metadata.

The shell also includes a separate User Session lifecycle diagnostic mode. Lifecycle diagnostics can list states, run a valid unlock-shaped sequence, attempt an invalid transition, run a timeout sequence, or run a recovery sequence. This mode validates lifecycle transition rules only; it does not perform authentication, unlock Device Vault, mutate capabilities, create authorization, execute proofs, call adapters, or persist state.

The lifecycle shell also includes `fixture_unlock`, a controlled developer-fixture sequence that verifies explicit fixture evidence and reaches `unlocked` lifecycle state for testing. It is not a real login: production authentication is not performed, Device Vault is not unlocked, no active capability is created, no authorization is created, and nothing is persisted.

The lifecycle shell also includes `production_webauthn_partial_unlock`, a diagnostic that verifies an explicit in-memory WebAuthn assertion with the existing production verifier and reaches `partially_unlocked`. It does not invoke a browser WebAuthn prompt, load credentials from Device Vault, unlock Device Vault, fully unlock the session, create active capabilities, create authorization, or persist state. It is not a complete production login flow.

The lifecycle shell also includes `production_webauthn_vault_unlock`, a diagnostic that continues from explicit production WebAuthn verification into an explicit in-memory Device Vault test-envelope unlock. It reaches `unlocked` only through the controlled vault boundary. It does not expose `phil_secret`, raw vault keys, decrypted registry plaintext, or private credential material; it does not load application credentials, create active capabilities, create session keys, create authorization, execute proofs, call adapters, or persist state.

The lifecycle shell also includes `production_protected_state_view`, a diagnostic that requests an explicit `identity_summary` after the controlled vault unlock. It demonstrates the difference between "vault unlocked" and "state visible": only a non-secret summary is returned, credentials are not loaded into applications, raw vault contents remain hidden, applications still have no authority, and nothing is persisted.

The lifecycle shell also includes `production_public_credential_directory`, a diagnostic that lists allowlisted public credential descriptors after the controlled vault unlock. It prints credential count, provider kinds, lifecycle statuses, recovery-only count, ordinary-use eligible count, and sanitized descriptor references. It does not load private credential material, execute assertions, make Trust Decisions, create capabilities, create authorization, or persist state.

The lifecycle shell also includes `production_selected_credential_public_material`, a diagnostic that composes the controlled vault unlock, public credential directory, and one selected credential materialization request. It prints a sanitized verification-profile summary, public key fingerprint/reference, supported verification method, and process-local handle metadata. It does not print raw public key bytes, load private credential material, perform authentication, execute assertions, make Trust Decisions, create capabilities, create authorization, verify World ID, or persist state.

The lifecycle shell also includes `production_trust_manager_verification_input`, a diagnostic that composes selected credential public material with one explicit production authentication request to create a bounded Trust Manager verification input. It prints sanitized correlation, challenge, assurance, and expiry data. It does not perform authentication, invoke WebAuthn, verify signatures, make Trust Decisions, expose Device Vault access to Trust Manager, create capabilities, create authorization, verify World ID, or persist state.

The lifecycle shell also includes `production_trust_manager_assertion_verification`, a diagnostic that consumes one bounded Trust Manager verification input plus one explicit WebAuthn assertion and reuses the existing production verifier. It prints sanitized challenge/origin/RP/signature/counter results. It does not create a Trust Decision, grant capabilities, create authorization, expose Device Vault access to Trust Manager, persist counters, verify World ID, execute proofs, call adapters, or persist state.

The lifecycle shell also includes `production_trust_decision_candidate`, a diagnostic that consumes successful production assertion evidence plus explicit public lifecycle/session/application/purpose context to create a bounded Trust Decision candidate. It prints credential lifecycle, assurance, counter-persistence, and no-authority status. It does not create an authoritative Trust Decision, grant capabilities, create authorization, persist counters, verify World ID, execute proofs, call adapters, or persist state.

The lifecycle shell also includes `production_credential_counter_persistence`, a diagnostic that persists one verified WebAuthn counter update against an explicit local/test encrypted registry fixture. It prints credential safe reference, previous counter, verified returned counter, persisted counter, registry verification status, and candidate counter-resolution status. It does not create an authoritative Trust Decision, grant capabilities, create authorization, verify World ID, execute proofs, call adapters, expose registry plaintext, expose vault material, or touch real user data.

The lifecycle shell also includes `production_authoritative_trust_decision`, a diagnostic that consumes successful production assertion verification, a bounded Trust Decision candidate, and a verified counter persistence receipt to create a bounded Trust Manager decision. It prints the session, purpose, assurance, expiry, and no-downstream-authority status. It does not grant capabilities, approve policy, collect user approval, create Authorization Packages, issue session keys, verify World ID, execute proofs, call adapters, submit transactions, expose vault material, or persist authority.

The lifecycle shell also includes `production_authoritative_policy_decision`, a diagnostic that consumes a bounded authoritative Trust Decision plus an explicit demo policy set. It prints policy outcome, effective restrictions, approval requirement, and no-downstream-authority status. It does not grant capabilities, collect user approval, create Authorization Packages, issue session keys, execute proofs, call adapters, submit transactions, expose vault material, or persist authority.

The lifecycle shell also includes `production_platform_user_approval_decision`, a diagnostic that consumes an authoritative Trust Decision, an authoritative Policy Decision requiring approval, an exact platform approval request, and an explicit in-memory local platform artifact. It supports `--approval-outcome approve|deny|cancel|expired|digest_mismatch`. It prints trust/policy acceptance, presentation digest status, approval surface, user outcome, validity, and no-downstream-authority status. It does not grant capabilities, create Authorization Packages, issue session keys, execute proofs, call adapters, submit transactions, invoke native UI, store biometric/platform secrets, expose vault material, or persist authority.

The lifecycle shell also includes `production_authoritative_capability_activation`, a diagnostic that consumes an authoritative Trust Decision, authoritative Policy Decision, approved Platform User Approval Decision, exact activation request, lifecycle snapshot, and User Session context to create one scoped process-local active capability grant. It supports the same `--approval-outcome` values. Only `approve` creates a grant; denied, cancelled, expired, or digest-mismatched approval creates no grant. The grant is not action authorization: it does not create an Authorization Package, issue session keys, execute proofs, call adapters, submit transactions, verify World ID, expose vault material, or persist authority.

The lifecycle shell also includes `production_authorization_decision_candidate`, a diagnostic that consumes one process-local active capability grant plus one exact action intent and current runtime context to create a bounded Authorization Decision Candidate. It supports `--authorization-candidate-scenario exact|capability_mismatch|scope_widening|target_mismatch|value_limit_exceeded|additional_approval_required`. Only `exact` creates a candidate. Rejected scenarios produce diagnostics only. The candidate is not action authorization: it does not assemble `ACTION_UNLOCK`, create `proofInputHash`, create an Authorization Package, sign, issue session keys, execute proofs, call adapters, submit transactions, expose vault material, or persist authority.

The lifecycle shell also includes `production_authorization_package_draft`, a diagnostic that consumes one bounded Authorization Decision Candidate plus explicit canonical `ACTION_UNLOCK` inputs to assemble the locked public tuple and canonical `proofInputHash`. It supports `--authorization-package-draft-scenario exact|mutated_action|invalid_nullifier|expiry_beyond_capability_grant|evidence_chain_mismatch|consumer_data_mismatch`. Only `exact` creates a draft. Rejected scenarios produce diagnostics only. The draft is not executable authorization: it does not generate proofs, verify facts, consume nullifiers, sign, issue session keys, call adapters, submit transactions, expose witness material, or persist authority.

The lifecycle shell still exposes the historical `production_action_unlock_proof_generation` diagnostic name, but ordinary execution now fails closed with `ACTION_UNLOCK_PROOF_REQUEST_MALFORMED`. The current STWO artifact is secret-bearing, so the shell supplies neither the exact synthetic-research acknowledgement nor an authorized research-only route. No proof artifact is returned and no Device Vault witness reaches the prover. Synthetic research generation is tested directly at the lower-level boundary only.

The `production_finalized_authorization_package` and `production_authorization_execution_readiness` diagnostic names are retained for compatibility, but both stop at the same proof-generation quarantine. They do not verify the current artifact, create a finalized package or fact preview, create a publication request, or reach execution-readiness checks.

The lifecycle shell also includes `production_authorization_execution_readiness`, a diagnostic that consumes one finalized non-executing Authorization Package, creates a verified-fact publication request draft, checks fixture read-only fact/nullifier state, and prints an execution-readiness snapshot. It supports `--authorization-execution-readiness-scenario exact|fact_already_published|nullifier_already_consumed|fact_state_unknown|nullifier_state_unknown|configuration_mismatch|expired_package`. Only `exact` reaches readiness. The diagnostic does not publish verified facts, call verifier/fact-registry contracts, consume nullifiers, create UserOperations, sign or submit transactions, call adapters, mutate chain state, expose witness material, or persist execution authority.

## Supported Scenarios

- `ordinary_success`
- `malformed_capability_request`
- `insufficient_public_trust_metadata`
- `failed_webauthn_fixture`
- `revoked_credential_lifecycle`
- `policy_denial`
- `canonical_activation_world_id_required`
- `denied_user_decision_fixture`
- `expired_artifact_chain`
- `correlation_mismatch`

## Non-Production Limits

Alpha 0 application scenarios do not perform production authentication, collect production consent, create active capability grants, mutate User Session active capabilities, issue session keys, create authorization packages, execute proofs, call adapters, submit Ethereum transactions, verify World ID, access Device Vault, load encrypted credentials, or persist artifacts.

The listed lifecycle diagnostics perform production-oriented WebAuthn cryptographic verification from explicit in-memory test inputs only. Later authorization diagnostics may reach a process-local capability grant, authorization candidate, and proofless package draft. Proof generation, finalization, publication-draft creation, and execution readiness are now deliberately blocked by the secret-bearing-proof quarantine. The suite still does not create executable authorization, session keys, verified fact publication, adapter execution, World ID verification, nullifier consumption, transaction signing/submission, chain-state mutation, or durable authority persistence.

All demo fixtures are local/test-only and non-authoritative.

The interactive shell is not a production application, wallet, approval interface, durable active capability manager, Authorization Engine, or production audit viewer.

## World ID Behavior

Ordinary runtime capability requests do not automatically require World ID. Canonical Phil activation stops on unresolved World ID enrollment and does not fake or implement World ID verification.

## Next Work

The next production-bound work should define controlled verified-fact transaction preparation without exposing witness material, consuming nullifiers, permitting adapter execution, signing, or submitting transactions.
