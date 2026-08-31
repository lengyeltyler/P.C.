# Asset Rights and Publication Classification

This record covers tracked visual assets that could enter a future public Phil
source snapshot. It records repository evidence, not trademark permission or a
legal conclusion.

## Phil-controlled or generated assets

| Asset | Classification | Public-snapshot treatment |
| --- | --- | --- |
| `docs/reference/images/o43/iphone-small-status-synthetic.{svg,png}` | Phil-generated synthetic documentation image | Optional/curated; may be included as documentation if its synthetic status remains clear. |
| `docs/reference/images/o43/iphone-large-pairing-synthetic.{svg,png}` | Phil-generated synthetic documentation image | Optional/curated; may be included as documentation if its synthetic status remains clear. |
| `apps/philcore-desktop/src/renderer/assets/characters/phil/*.png` and `apps/philcore-ios-companion/PhilCoreCompanion/Characters/phil_*.png` | Tyler Lengyel-owned 3D Phil artwork; 12 exact 192x208 cell extractions from the authorized `pets copy/phil/spritesheet.webp` atlas supplied by the owner. SHA-256 of the 12 Desktop file contents concatenated in lexical path order: `94c7fbda8a5615c7e2f19ae23c4cc8e217bb4fa642742c364a32c79727aa2aa3`. | Authorized for use and adaptation in Phil and PhilCore. Separately controlled brand artwork; not granted under the repository MIT software license. |
| `apps/philcore-desktop/src/renderer/assets/characters/avastar/*.png` and `apps/philcore-ios-companion/PhilCoreCompanion/Characters/avastar_*.png` | Tyler Lengyel-owned 3D Avastar artwork; 12 exact 192x208 cell extractions from the authorized `pets copy/avastar/spritesheet.webp` atlas supplied by the owner. SHA-256 of the 12 Desktop file contents concatenated in lexical path order: `8da6fbd3ea6e4623546e94b352c47e115a7e7dee631ec877ba4ee5c252c163c7`. | Authorized for use and adaptation in Phil and PhilCore. Separately controlled brand artwork; not granted under the repository MIT software license. |
| `apps/philcore-desktop/src/renderer/assets/philenator/` and `apps/philcore-desktop/src/renderer/philenator-engine.js` | Tyler Lengyel-owned Philenator artwork imported from the owner-controlled private repository `lengyeltyler/Philenator` at exact commit `f174dedda16a354c592e3252d9b0b5805bab59c4` and tree `85ba6dcf4c3712e2ec46c60cdf639ba6cc045635`. The imported manifest SHA-256 is `2831da85bfccd9b1d674b118d638c6a867580f40b9863bb50a5ba87fc5e90dbc`; the 503 SVG contents concatenated in lexical path order have SHA-256 `192ce3fc0ee8055d1966c847e44e4b5a1d8172fe1e6e7fef1c77a23dd81196c4`. | Authorized by the owner for use and adaptation in Phil and PhilCore. Separately controlled brand artwork; not granted under the repository MIT software license. |
| `apps/philcore-ios-companion/PhilCoreCompanion/Characters/philenator_bg.png` | Full-color iPhone presentation background rasterized from the owner-controlled Philenator `BgNebula/3/Nebula3Bubblegum.svg` trait; SHA-256 `9bfcb71620345530e60c0d278b0bbe6ad54900c3003fe08452ef7ea3a6b425d5`. | Authorized Phil presentation asset. It grants no application authority and is not an identity credential. |

## Rights-cleared third-party presentation assets

| Asset | Creator and exact source | License and modification status | Public-snapshot treatment |
| --- | --- | --- | --- |
| `apps/philcore-desktop/src/renderer/assets/pixelify-sans-latin-wght-normal.woff2` | Pixelify Sans Project Authors; `@fontsource-variable/pixelify-sans` npm package `5.3.0`, resolved by the PhilUI lockfile from `https://registry.npmjs.org/@fontsource-variable/pixelify-sans/-/pixelify-sans-5.3.0.tgz` | SIL OFL 1.1; copied unmodified; SHA-256 `4a5633a0c9c1b73abd133a56d3716c2d8df2ed03cb987346f72194aeb224f382` | Include with `THIRD_PARTY_NOTICES.md` and `LICENSES/OFL-1.1-Pixelify-Sans.txt`; the Desktop distributable must carry both notices. |
| `apps/philcore-ios-companion/PhilCoreCompanion/Fonts/PixelifySans-wght.ttf` | Pixelify Sans Project Authors; Google Fonts `ofl/pixelifysans/PixelifySans[wght].ttf` at commit `9ce5017522020232f525003b39971ddb67e33243` | SIL OFL 1.1; copied unmodified; SHA-256 `9ba86cd010a4de309d263ceff8e8044092c9db7efda869620cb9ff1c4389e8a5` | Include with `LICENSES/OFL-1.1-Pixelify-Sans.txt`; the iPhone application resource phase must carry the license text. |

## Historical chain-mark renditions

The retained engineering history contains three small SVG renditions introduced by
Phil commit `a9c7f758a235dfbd39075af90d5cbe9261793f0c`: Bitcoin, Ethereum, and
Solana. The original successful local authoring record has now been recovered:
all three generated file contents match their introduction Git blobs byte for
byte. They were locally AI-generated Phil UI renditions of third-party marks;
this establishes their creation origin, not independent ownership of the marks.
See [the exact historical provenance record](./HISTORICAL_CHAIN_MARK_PROVENANCE.md).
**Creation provenance is resolved; rights clearance has not been established.**
The owner-authorized Option C export excludes all three historical blobs from
this clean public history. This resolves their inclusion in this source scope
without claiming a license or erasing the retained engineering history.
The engineering repository transition is a separate owner gate. The Phil MIT
license grants no third-party trademark rights. Current branding is unchanged.

## Excluded artwork

The public candidate continues to exclude uncleared chain-logo renditions and
third-party-project preview artwork. The newly tracked 3D Phil and Avastar
character poses are a narrow exception backed by the owner's direct
authorization above. The previously used flat-character and riding-pair assets
are not runtime inputs. The Desktop catalog continues to use generic text/CSS
tiles, without replacement logos or implied third-party endorsement.

Future assets must record creator, source, governing license or permission,
required attribution, modification status, and whether the asset is software
documentation or separately controlled Phil branding.
