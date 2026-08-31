# Phil Black-and-White Interface and Full-Color Philenator World

Status: implemented candidate pending independent acceptance

Date: 2026-08-24

## Outcome

Desktop and iPhone use a black-and-white product interface. Phil, Avastar, and
the generated Philenator world retain their intended colors. Every runtime
character pose is an exact cell extraction from the owner-supplied 3D `pets
copy` sprite sheets. The earlier flat Phil, flat Avastar, and composite
riding-pair images are not used.

Desktop now runs the owner-supplied Philenator asset system locally at pinned
revision `f174dedda16a354c592e3252d9b0b5805bab59c4`. Creating or randomizing a
Phil composes thirteen local trait groups: `bgColor`, `bgNebula`, `bgStars`,
`bgSpiral`, `bgDust`, `bgOverlay`, `bodyBase`, `body`, `spikes`, `teeth`,
`jawNose`, `eyes`, and `top`. The six background groups are also rendered
behind the identity interface in full color, with contrast and brightness
treatment preserving interface legibility.

iPhone uses a full-color Philenator nebula trait as its
presentation background and the extracted 3D poses for companion guidance.
The iPhone remains an approval and recovery companion; it does not independently
create or mutate the Desktop identity.

## Asset and implementation boundary

- Both 1536x2288 source atlases have an 8-column by 11-row layout. Each runtime
  pose is a lossless 192x208 extraction with transparency preserved.
- Desktop and iPhone each carry 12 Phil poses and 12 Avastar poses.
- No `avastar`, `phil`, or `riding_pair` download-directory asset is referenced
  directly at runtime; only the reviewed 3D extractions are packaged.
- Philenator executes in the local Desktop renderer and reads only its bundled
  manifest and 503 reviewed SVG traits. It makes no external network request.
- Decorative generated SVG is cached in renderer-local storage for stable
  restart presentation. Protected identity metadata retains the eight trait
  fingerprints and exact generator revision rather than treating artwork bytes
  as a credential.
- The generated artwork and background grant no authorization, signing,
  recovery, proof, account, or network capability.

## Product contract preserved

This candidate changes presentation and identity artwork generation only. It
does not change the existing vault, device admission, Face ID, Secure Enclave,
routine authorization, recovery, proof quarantine, adapter, smart-account, or
network authority boundaries. A failed or cancelled protected action continues
to fail closed.

The STWO proof artifact remains experimental and secret-bearing. It is not
enabled for production identity authorization, and this visual candidate does
not resume any public-network work.

## Acceptance checks

The candidate is ready for review only after all of the following succeed on
the same committed source:

- the full Desktop regression suite;
- the focused iOS routine-authorization Simulator suite;
- local Desktop and iPhone builds;
- packaged Desktop manifest, composition, and user-shell checks;
- a scan proving no riding-pair runtime files or references remain;
- a visual inspection proving the interface chrome is black and white while
  the Philenator background and 3D characters retain their colors; and
- a Philenator interaction proving initial generation, randomization, generated
  background presentation, and restart persistence.

Owner-controlled asset rights and bundled geometry-library licenses are
recorded in [Asset Rights](./ASSET_RIGHTS.md),
[Third-Party Notices](../../THIRD_PARTY_NOTICES.md), and the `LICENSES/`
directory.
