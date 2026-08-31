# Phil final Beta UI boundaries

Phil is the product; P.C. is the intended clean public home of PhilCore. The
Controlled Sepolia Beta remains test-assets-only, with no production custody,
Mainnet readiness, autonomous AI, or current post-quantum security claim.

## Local naming

Choose a Phil name before creation. The trimmed, printable name is limited to
64 UTF-16 code units and passes through the existing profile display-label
metadata API. Settings can rename it. The name is not the identity root, owner
commitment, signing authority, account address, proof input, or ENS name.
Renaming leaves encrypted identity files and account identity unchanged.

The name is local to this Mac. The iPhone pairing and routine protocols do not
carry this display label; this change adds no synchronization protocol and
requires no iOS source or build change.

## Future ENS, unavailable in this Beta

ENS belongs in a future Mainnet Ethereum adapter. Phil identity does not depend
on ENS. This Beta performs no ENS lookup, availability check, registration,
reservation, minting, or gas pricing. There are no live-looking suggestions.
Ethereum is the first supported public execution network, not the identity layer.

## Presentation and privacy

Ordinary cards and buttons use closed borders. The dedicated locked screen
shows the existing generated character/background, local name, passphrase and
unlock controls. Navigation, balances, addresses, activity and Advanced details
are hidden while either the session or vault remains locked. Existing Mac
unlock appears only when already configured by the unchanged protected flow.

The short light transition requires successful authentication and vault unlock.
Failure stays locked. Reduce Motion uses a short fade without door motion.
No authorization, user-presence, vault or cryptographic policy changed.

## Passive contextual Phil

The floating character opens bounded static guidance for the current page. It
has no bridge access, network client, AI, signing, or action authority. Drag it
or focus it and use arrow keys. Position is stored locally and clamped to the
viewport. Settings includes Reset Phil position and the same help topics for
keyboard access. Escape or Close help collapses the panel.

Security dialogs hide the helper. Password fields, critical warnings and action
controls take precedence over its position; if no safe location exists it
collapses or hides. Active routine and preparation requests suppress the helper.

## Release impact

Desktop package bytes change and require a fresh build, Developer ID signature,
notarization, stapling, Gatekeeper, notices, SBOM and exact artifact freeze after
source validation. iOS build 58 and the prior owner-present authorization
acceptance remain applicable to the unchanged authorization product source.
Desktop unlock interaction is checked independently with disposable local
profiles. No owner QR or Face ID retest is implied by this UI change.

The earlier clean export is rehearsal evidence only. A new one-root P.C. export
and its complete audit/CI must come from the final accepted engineering tree.
GitHub repository renaming, visibility changes, creation and publication remain
subject to the owner's separate explicit transition authority.
