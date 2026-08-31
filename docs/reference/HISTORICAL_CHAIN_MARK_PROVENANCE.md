# Historical chain-mark creation provenance

Audit baseline: commit `b80a890f4d0626ccf462bb872ff723508a5b6a40`, tree
`c5de06f4ad03e6bf6273d218be6295a527cbe3f0`. All paths below have the prefix
`apps/philcore-desktop/src/renderer/assets/chains/`.

| File | Exact Git blob | Current HEAD | Current Desktop package |
| --- | --- | --- | --- |
| `bitcoin.svg` | `bbc9605e47893b5199709389a380ebfbe21eda27` | Absent | Absent |
| `ethereum.svg` | `0e2f3ca22ba1c43a3251390a36cf09fa47160fe2` | Absent | Absent |
| `solana.svg` | `242dceb16e9bdfa0da5fb856eb0856d3a9455cf0` | Absent | Absent |

All three were introduced by commit
`a9c7f758a235dfbd39075af90d5cbe9261793f0c` and remain reachable in the retained engineering repository's
ancestry, which is not copied into this clean public repository. Their SHA-256 file hashes, respectively, are:

- `a66e6680dc80b6138d2df669f269f82e8ff9f618ad362a8b1b25ea6d093e8bde`
- `46d7b54f19884cfefc28a3f9d83e61b371f699c0861717ccb847ad863d2137ce`
- `ba965b0473450df84f95fb83282482e6481037326f489dc27fbe21f589b81ec8`

The successful local authoring event at `2026-07-25T17:02:55.474Z`, in
authoring turn `019f9a36-cada-74c3-a31a-e634ac2316a5`, records generated
inline SVG additions whose contents match all three blobs byte for byte.
The surrounding user request called for recognizable local chain icons.
No downloaded asset source was identified in that authoring turn. Git history,
prior branches, source comments, asset metadata and local asset directories
were also examined. Independent review confirmed the three content matches.
The private source session and sanitized evidence hashes are retained in the
release audit; neither private conversation contents nor the removed artwork
is reproduced here.

Classification: **locally AI-generated Phil renditions of third-party marks**.
This is not a claim that the depicted marks are Phil-created, that the files
came from an official logo package, or that local generation grants exclusive
copyright or trademark rights.

## Rights adjudication

No applicable affirmative redistribution permission for these exact renditions
has been established. This is an unresolved release-clearance question, not a
finding of infringement. Nominative/reference use has not been adjudicated and
is not asserted as the release basis.

| Rendition | Copyright / permission basis | Attribution required | Trademark notice required | Modification allowed |
| --- | --- | --- | --- | --- |
| Bitcoin | Local generation proven; no exact third-party asset grant identified. BitPay's CC0 grant covers its own assets, not automatically this rendition. | Undetermined without applicable basis | Undetermined | Not established |
| Ethereum | Local generation proven; Ethereum website content licensing does not itself establish permission for this exact rendition or grant trademark rights. | Undetermined without applicable basis | Undetermined | Not established |
| Solana | Local generation proven; no identified permission for this exact modified rendition under Solana's branding guidance. | Undetermined without applicable basis | Undetermined | Not established |

Primary references checked on 2026-08-31:

- [BitPay bitcoin-brand license](https://github.com/bitpay/bitcoin-brand/blob/master/LICENSE)
- [Ethereum terms](https://ethereum.org/terms-of-use/)
- [Solana Foundation terms](https://solana.org/tos)
- [Solana branding guidance](https://solana.com/branding)

These sources have different scopes. None is treated as a blanket prohibition
on every reference to a project, or as an automatic grant for these three
files. The root Phil MIT software license supplies no third-party mark rights.

The owner authorized Option C local preparation: this clean repository begins
from the accepted engineering tree and excludes the three historical objects.
Their absence resolves this clean-history inclusion blocker without claiming
rights clearance. Existing engineering history is preserved without rewriting.
No GitHub visibility/name change, repository creation, push, tag or publication
is authorized by preparation. Those actions require a separate owner transition
gate. Current product branding and runtime behavior remain unchanged.
