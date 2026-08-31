# Trust Manager Possession Verification Drafts

Possession Verification Request Drafts represent future possession checks only.

They may be created after a public Trust metadata evaluation indicates that possession verification is still required. They do not verify possession, authenticate a user, verify signatures, invoke WebAuthn, load credentials, access Device Vault, or create a trust decision.

Challenge descriptors are non-executing metadata. They may carry public/request references such as purpose, expected application/session/credential/device IDs, expiry, verification method, and placeholder binding references. They must not contain raw challenge secrets, WebAuthn assertion responses, private keys, signing keys, or recovery secrets.

Drafts create no trust, grant no authority, grant no capabilities, create no authorization packages, call no adapters, and persist nothing.
