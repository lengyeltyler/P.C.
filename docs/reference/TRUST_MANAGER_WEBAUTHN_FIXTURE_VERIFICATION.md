# Trust Manager WebAuthn Fixture Verification

WebAuthn Fixture Verification is a test-fixture-only bridge from Possession Verification Request Drafts into the existing WebAuthn assertion verifier.

It accepts explicit fixture data only: assertion payloads, public credential metadata, expected challenge, origin, RP ID, and previous sign count. It does not invoke browser WebAuthn, does not call `navigator.credentials.get`, does not load credentials, and does not access Device Vault or encrypted storage.

`fixture_verified` means only that the explicit fixture passed the local verifier. It is not production authentication, not a Trust Decision, and not proof that PhilCore should grant authority.

Counters are evaluated using the existing verifier result and reported in the fixture artifact, but updated counters are not persisted.

Challenge binding is fixture-only in this milestone. The fixture must reference the Possession Verification Request Draft challenge reference. No production challenge generation is introduced.

The fixture artifact creates no trust authority, grants no capabilities, creates no authorization packages, calls no adapters, and persists nothing.
