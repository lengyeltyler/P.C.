# Phil V1 Step 4 Reference Manifest Maintenance

Status: Reconciled without Step 4 implementation change

Date: 2026-08-22

## Reason

The independent Step 6B review found that the Step 4 artifact verifier reported
drift in four source references. The same drift existed at Step 6B parent
`58731cf65a30ab4646d5fd698044b99c289931a5`, so it was not introduced by the
accepted Step 6B correction.

The reference manifest hashes shared documents and `package.json`. Those files
legitimately evolved as Steps 4, 5, 6A, and 6B were reviewed and documented,
while the manifest still retained its pre-acceptance Step 4 status.

## Bounded Reconciliation

- Set the generator and generated manifest status to accepted exact Step 4
  candidate `3377606d404312ef7f7dcfec37a11c046f2c907e`.
- Refresh the current hashes and byte counts for `docs/CANONICAL_DOCS.md`,
  `docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md`,
  `docs/reference/PHIL_V1_STEP4_COMPOSED_ACCOUNT_AUTHORIZATION_GATE.md`,
  the generator itself, and `package.json`.
- Reproduce the manifest from the deterministic generator.

No Step 4 Cairo source, TypeScript implementation source, test, fixture,
proof calldata, compiled-class identity, gas measurement, toolchain identity,
accepted Step 3 verifier artifact, production authority, or network-activity
claim changed.

## Step 6C Definition Reconciliation

The separately authorized Step 6C definition candidate legitimately updates
the same two mutable current-status documents. The deterministic generator was
run again without changing its source or any Step 4 implementation/evidence
input. It refreshed only these manifest entries:

```text
docs/CANONICAL_DOCS.md
  sha256 f9a0e317090d2c2727de87e0ae54ebe5c50f3d993c19ab518f14a4a489d040d5

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 bb307f5054bdba642f433a1dc044f9cda58363608356c74a9768f1175edf779a

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 cb120c3277ba472535ecc78151a6f9ad5f1e9b6356b1dbefef276e1618758f58
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, and all
other manifest entries remained byte-identical.

## Corrective Step 6C Definition Reconciliation

The first exact Step 6C definition candidate was independently rejected, and
the bounded corrective definition again changed only the two mutable current-
status documents tracked by the historical Step 4 manifest. Deterministic
regeneration refreshed exactly these entries:

```text
docs/CANONICAL_DOCS.md
  sha256 9ad7f9958dfd367c13295422f3062dc5c01d5e609bd2d75eaa414749191ebfef

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 96b5b6f6a62a7d5baf08f9b1c5be5a3023066b59bed2069a5c576cbde689b463

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 533f20722dbabeb65ea4251ba9822ff2d9e4d11e4a81e0c6ecb3373f902446a5
```

The generator rewrote the fixture outputs deterministically, but their bytes
remained unchanged. Every other manifest entry also remained byte-identical.
This reconciliation records documentation evolution only; it does not change
or re-accept Step 4 implementation evidence.

## Second Corrective Step 6C Definition Reconciliation

Independent review rejected the first corrective Step 6C definition, and the
bounded second correction again changed only the two shared current-status
documents in the historical Step 4 manifest. Deterministic regeneration
refreshed exactly:

```text
docs/CANONICAL_DOCS.md
  sha256 8f4c688c8975c110e09be236e7adc29d47addb5d3c925031d14d081025107012

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 4ddfcab7a6c9bdba426d628769acd38ee4a5667fa2269acc95255e5a4737f489

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 2bb84391710152745e9a0abe85413361a3578c276d5916ff88215a93ebbcebfa
```

The fixture, generated Cairo fixture, proof calldata, and every other manifest
entry remained byte-identical. This remains documentation-reference
maintenance only.

## Step 6C Definition Acceptance Reconciliation

Recording independent acceptance of exact second corrective definition
`227bd48` changed the two shared current-status documents one final time.
Deterministic regeneration refreshed exactly:

```text
docs/CANONICAL_DOCS.md
  sha256 2604e0ec20d40a258cd7f02e4dd3e9c0f7c010c08d55550938c426f5fbe345db

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 bd3fa34c59ed74041fe05386605294faf9e0ddad97764787f20663a166a12b84

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 8b9585164877a55970429b87b092f876ffbdaad64fac8f525a82dd1739d56afb
```

All historical Step 4 implementation, fixture, proof-calldata, and remaining
manifest entries stayed byte-identical.

## Step 6C Third Corrective Definition Reconciliation

Separately authorized Step 6C-1 implementation stopped before a source
candidate after exposing the nonce-bound frozen-catalog/policy contradiction
in historical accepted definition `227bd48`. Recording the bounded third
corrective definition changed the two shared current-status documents.
Deterministic regeneration refreshed exactly:

```text
docs/CANONICAL_DOCS.md
  sha256 412999aaf7cf3757c82253c278e0fe1b0ddc9c9506017408aad7814189657559

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 e25a3cfb9e878b05ddab8b26573dd40d1726cd977a0dc5862e63eec71405c374

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 58cf2a3215f9c203ba84e08cf2dee417bcc10a48a2764dbbbd4c15aa4fd4274b
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, and all other manifest entries remained
byte-identical. This is documentation-reference maintenance only; it changes
no Step 4 semantics, acceptance, proof, or authority.

## Step 6C Third-Corrective Acceptance Reconciliation

Recording independent acceptance of exact status-correction candidate
`fcc0103`, tree `209df24`, changed the two shared current-status documents.
Deterministic regeneration refreshed exactly:

```text
docs/CANONICAL_DOCS.md
  sha256 6dd7ed0d0dfc9e139419ea4b8f0d7fc2095c57d68f71adbda0002816d7ba45da

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 c146a0dc26294509402b3ce5b4d461ff1beceae7a44fc1ce63460d60e439aee9

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 f131463a3e1821e95f85f7151c038761b921389c0aca72d1610d4e54e6e53040
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, and all other manifest entries remained
byte-identical. This is documentation-reference maintenance only; it changes
no Step 4 semantics, acceptance, proof, or authority.

## Step 6C-1 Source-Candidate Reconciliation

Freezing the bounded Step 6C-1 source candidate updated the two shared current-
status documents and added Step 6C package scripts. Deterministic regeneration
refreshed exactly these tracked entries:

```text
docs/CANONICAL_DOCS.md
  sha256 089d8cacd4d8172f70aa26459881e1edf7c5c6ab1bcaea3833b93cb5fe3c2e3e

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 1dcb4eb424152b5e73d98e45abda6d26450e8016cb260171a7db77d855bd06bc

package.json
  sha256 e31a55f540522ee1ba4848d00bf4be782cb7a32e9d76a34596991efb8641172b

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 4f8287cb85f924c058fa4a933ee159ea09c43dba995fb7989823710e242006ed
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, generator, and all other manifest entries
remained byte-identical. This is reference maintenance only and does not
change Step 4 implementation evidence or acceptance.

## Step 6C-1 Corrective-Candidate Reconciliation

Recording rejection of candidate `a158688` and freezing corrective source
`9ed8274`, tree `979432f`, changed the two shared current-status documents.
Deterministic regeneration refreshed exactly these tracked entries:

```text
docs/CANONICAL_DOCS.md
  sha256 58028ce1833939cfb364129b4c67baaef738cb479d066516f30e5b1ccff1e92a

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 82b5d3e4dd480ce88f411734f15c9b7ba37bbab5b069fb3bb4842639c94e550c

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 62cdc6a62aa927b2b781dd1d678508e46e312e741f7b8d08dbd8596cabca9a8b
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, generator, and all other manifest entries
remain byte-identical. This is reference maintenance only and does not change
Step 4 implementation evidence or acceptance.

## Step 6C-1 Durable-Evidence Corrective Reconciliation

Recording rejection of candidate `aea7359` and freezing durable-evidence source
`c5fda8a`, tree `782b71b`, changed the two shared current-status documents.
Deterministic regeneration refreshed exactly these tracked entries:

```text
docs/CANONICAL_DOCS.md
  sha256 463e87c8a624be03226a4fafaba8b2bd44356cf5d6d44b3f27283f3b7816b518

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 1482eb585e6530d732261710c68b35fe13f3b2eaf4a631dce1e23f3be2041dfb

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 e2999caddc0edc1cf289f2f3ab131d22ad47b87b390b616ad15f42a200ab4693
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, generator, and all other manifest entries
remain byte-identical. This is reference maintenance only and does not change
Step 4 implementation evidence or acceptance.

## Step 6C-1 Restart-Chain Corrective Reconciliation

Recording rejection of candidate `591f6b6` and freezing restart-chain source
`13a7859`, tree `a1374c9`, changed the two shared current-status documents.
Deterministic regeneration refreshed exactly these tracked entries:

```text
docs/CANONICAL_DOCS.md
  sha256 035931363002056bb2e208b03a2867d152129547c4eae36b64f5680ac7d41d79

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 0f01342aff75ddfab351a963d6a3e041aafa5a606cf631c014caea878fe05e5d

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 32664175dc04e5b5fad830cc0728232dd1a1ecd1b8317e720a236be0325dd9b3
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, generator, and all other manifest entries
remain byte-identical. This is reference maintenance only and does not change
Step 4 implementation evidence or acceptance.

## Step 6C-1 Authenticated-Restart Corrective Reconciliation

Recording rejection of candidate `5ab4650` and freezing authenticated-restart
source `6f048eb`, tree `a9032b2`, changed the two shared current-status
documents. Deterministic regeneration refreshed exactly these tracked entries:

```text
docs/CANONICAL_DOCS.md
  sha256 ddf22bb96e3fc97d3784686166672cfbcabd98d8a94143e28422fca5ed7fcb7b

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 38e1555de850a8ea49b82f946e0467e3284ada78ab71d2f3f12aeb439c8d02fc

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 51f26c3a4f2cc6f752e1479761f9c1f96d5e904716ad92f1d70ec5e6ba6be957
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, generator, and all other manifest entries
remain byte-identical. This is reference maintenance only and does not change
Step 4 implementation evidence or acceptance.

## Step 6C-1 Independent-Acceptance Reconciliation

Recording independent acceptance of exact candidate `22b5cf3`, tree `2b0ff7f`,
changed the two shared current-status documents. Deterministic regeneration
refreshed exactly these tracked entries:

```text
docs/CANONICAL_DOCS.md
  sha256 1f5fe153583c55d87f368a5d9d74f833001aab48bc96bd1a4e9f4b048cc51e55

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 088bdfb993989a601ca3266ed0d6b7335cc3063b255e07af4d33657653a5f1c9

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 7b8d94f72a2d3cb153e8961e88d01ec84020f02606c2cdad940ae0ca9f100169
```

The canonical Step 4 fixture, generated Cairo fixture, proof calldata, Cairo
source, TypeScript source, tests, generator, and all other manifest entries
remain byte-identical. This is reference maintenance only and does not change
Step 4 implementation evidence or acceptance.

## Step 6C-2 Source-Candidate Reconciliation

Adding the separately authorized Step 6C-2 product-wiring commands and current
status changed the package command surface and the two shared current-status
documents. Deterministic regeneration refreshed exactly these tracked entries:

```text
package.json
  sha256 8a23f67248a444fa4f05e2572dff96e22458cc1d5277b164cba8467fba8df620

docs/CANONICAL_DOCS.md
  sha256 25bb4034c6711436f5fd29362459b81254a81e8460ae827074ac738a056d6b2f

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 f31a54d1b02ed5bc3805f76e749e6df9b05e2721917ca4e501e29704bf55aa4c

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 99029db9650d65acd9db8f2e8d3e0f1d9932a33030ca3a6fb261fd9c9cecbbfa
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests, and
cryptographic values remain byte-identical. This does not make Step 6C-2
accepted, physical-device verified, network-admitted, or production-ready.

## Corrective Step 6C-2 Source-Candidate Reconciliation

Recording the rejected initial candidate and adding the corrective enrollment,
product-runtime, and evidence commands changed the package command surface and
the two shared current-status documents. Deterministic regeneration refreshed
exactly these tracked entries:

```text
package.json
  sha256 b28237c6dd0f670662b3bc1a9640228928e2e4a67a05f5c05ef1e5e8bd2f0ac0

docs/CANONICAL_DOCS.md
  sha256 ae3f81f758e39265a741b1baef3bbd3b7d32983fe8d2fc4cf34cb5ca6fd3291c

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 b1aa7867055833b299e8f254948d34972523b18bc83b4dbfa4cad50d3b11d441

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 2ea58fbf8125ac9b4e51695c4959ad1c237dd6206834c3ca593e5fb882746866
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests,
generator, and cryptographic values remain byte-identical. This is reference
maintenance only. It does not accept the corrective Step 6C-2 candidate or
establish physical-device, packaged-product, network, or production evidence.

## Authority

This maintenance restores current deterministic verification. It does not
re-review or replace the independent acceptance of exact Step 4 candidate
`3377606`, select a production proof backend, grant production authority, or
authorize deployment or network activity.

## Fourth-Corrective Step 6C-2 Source-Candidate Reconciliation

Recording the rejected third-corrective candidate and the fourth-corrective
authenticated enrollment-acceptance, deletion-boundary, and runtime-failure
status changed the two shared current-status documents. Deterministic
regeneration refreshed these tracked entries:

```text
package.json
  sha256 3cbec9d69b0da345614c46a7015b785cc0e55c9de7bea52da54993bc01642bbe

docs/CANONICAL_DOCS.md
  sha256 dc0f7959c3773697021ec7f08a504290ad9113f9717a0b548076c4a89071ca25

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 61bd7e593ddb6e8aa5df1805c44fce3b9ca656a0e851256cf7781fdd107a4595

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 79ce4c8fc54985ccd191e5cf09722d4bb0317aae2b098b442f5598c2de193f79
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests, and
cryptographic values remain byte-identical. This is reference maintenance
only. It does not accept the fourth-corrective Step 6C-2 candidate or establish
physical-device, packaged-product, network, or production evidence.

## Fifth-Corrective Step 6C-2 Source-Candidate Reconciliation

Recording the rejected fourth-corrective candidate and the fifth-corrective
prehashed-verification, key-lifetime, replay-expiry, and fingerprint-refresh
status changed the two shared current-status documents. Deterministic
regeneration refreshed these tracked entries:

```text
package.json
  sha256 3cbec9d69b0da345614c46a7015b785cc0e55c9de7bea52da54993bc01642bbe

docs/CANONICAL_DOCS.md
  sha256 e874b8cd18834ba0c8a31d15d53c83809cb40043bafce959b78650fe380340ea

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 13a910b1823d96f215f89c90fc20f2ee5440ad80d6ef921c9b0c265f091bb407

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 d2b4fbc8f92d84633f63eaeb6272dc650af6c67fd1a0d378328fa4f51c9ddfdc
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests, and
cryptographic values remain byte-identical. This is reference maintenance
only. It does not accept the fifth-corrective Step 6C-2 candidate or establish
physical-device, packaged-product, network, or production evidence.

## Sixth-Corrective Step 6C-2 Source-Candidate Reconciliation

Recording the rejected fifth-corrective candidate and the sixth-corrective
documentation-only status changed the two shared current-status documents.
Deterministic regeneration refreshed these tracked entries:

```text
package.json
  sha256 3cbec9d69b0da345614c46a7015b785cc0e55c9de7bea52da54993bc01642bbe

docs/CANONICAL_DOCS.md
  sha256 b3262c5f9bbef9789f33c080f94fa271cccfc39b01116bb44fafd322d10bb3d5

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 21ea5229812003abc9780816670fcccebaf80bb7f8b24324d9f8ad744a31bb8f

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 8725cfbf2b0a0c31c563a3fdf99b5eaaa7987f918da4b3c51adc73bcc69bbf41
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests, and
cryptographic values remain byte-identical. This is reference maintenance
only. It does not accept the sixth-corrective Step 6C-2 candidate or establish
physical-device, packaged-product, network, or production evidence.

## Accepted Sixth-Corrective Step 6C-2 Reconciliation

Recording independent acceptance of exact Step 6C-2 candidate `4a81b08`, tree
`188d7d0`, changed the two shared current-status documents. Deterministic
regeneration refreshed these tracked entries:

```text
package.json
  sha256 3cbec9d69b0da345614c46a7015b785cc0e55c9de7bea52da54993bc01642bbe

docs/CANONICAL_DOCS.md
  sha256 9f399417974a83439f42568ea2f377ed92f9763da975a42c309440656df24acb

docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 e98a086779d3c0a95721974746a14cba6e76eb2998a56ab5a2c17312c7c71abf

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 87a62ed94c9c59915ca95e930c730a7f019d6861b8dd310703c1bcf2c2eae27f
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests, and
cryptographic values remain byte-identical. This is reference maintenance
only. It does not establish Step 6C-3 physical-device evidence, packaged-
product verification, network admission, or production authority.

## Desktop Visual Candidate Roadmap Reconciliation

Recording the local PhilUI-inspired Desktop visual candidate as the efficient
next milestone changed the shared ACP-0003 current-status document.
Deterministic regeneration refreshed these tracked entries:

```text
docs/architecture-changes/ACP-0003-PHIL-V1-SECURE-IDENTITY-ROADMAP.md
  sha256 af735b4a8e0808f9c796a9a2d9306d35c588603916a5865a98f498ddc62b0a2c

starknet/phil-v1-step4-account-gate/artifacts/reference-manifest.json
  sha256 a326432f23a740719b255deedc8fbbcd77d1f3dc924265016d0a2aa85028202d
```

The Step 4 implementation source, fixtures, Cairo proof calldata, tests, and
cryptographic values remain byte-identical. This is reference maintenance
only. It does not accept the Desktop visual candidate or establish device,
network, distribution, or production authority.
