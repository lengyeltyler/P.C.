# Phil Sepolia Mint Alpha Evidence

Status: **END-TO-END SEPOLIA MINT DEMO READY: YES**

Completed: `2026-08-25T03:42:04.231Z`

This record preserves the completed bounded Alpha demonstration. It is not a
Beta deployment manifest, production approval, external audit, or permission
to use meaningful assets.

## Frozen source and packages

- Source commit: `010bbb791c3df080a0c7da5bbbc03158349410ad`
- Source tree: `2d7b5b3d7e98640dd0ef399ae20677e725b61ea1`
- Branch at execution: `codex/local-alpha-demo-ready`
- Desktop: `com.philcore.desktop.localalpha`, version `0.1.0`, build
  `0.8.0-sepolia-mint-demo`
- iPhone: `com.philcore.ios.companion.localalpha`, version `0.1.0`, build `56`,
  Apple Development team `B342738S82`
- Protected untracked `pqREADME.md` SHA-256:
  `7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`

## Composed authorization

- Authorization-envelope digest:
  `0x788190cd53ca7c90fb051d5c9f0cd0e3b0a65a0e4258eb83a7a77af185db5fd0`
- Root-proof nullifier:
  `0x7e0919f5b237af42b772e77bfe0d4e1ca24415726c7c57df4e54a68a77de7fcf`
- Device approval nonce:
  `0xbded9a1b335126629cc6c48cd374e088b8b70ad69952e56cd3d49d44c3871938`
- UserOperation hash:
  `0xa898da76eef5932cd76bd74686bc1ba325e65323a3f9df6e570f57162896bb3b`

The Desktop generated and independently verified the real Noir/Barretenberg
proof. The enrolled iPhone displayed the same request, required Face ID, and
used its Secure Enclave P-256 routine key to sign the same digest-bound
approval. Policy, device state, epochs, expiry, value, fee, nonce, cancellation,
revocation, and durable replay state passed before the Device Vault signed the
exact ERC-4337 UserOperation.

## Deployed Alpha infrastructure

| Role | Address | Deployment transaction |
| --- | --- | --- |
| EntryPoint v0.7 | [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.etherscan.io/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032) | Canonical pre-existing EntryPoint |
| Factory | [`0xee49bdFeA3535D8d68edBE3b91c8AA8734A2B48A`](https://sepolia.etherscan.io/address/0xee49bdFeA3535D8d68edBE3b91c8AA8734A2B48A) | [`0xe020...398d`](https://sepolia.etherscan.io/tx/0xe020808a3ecf48bd9303a8666a8ad11e1bc43ec8ff77fe88aeee999e0168398d) |
| ActionGate | [`0xCbd3b73C257Fbe4ac4a1084163Aa4cA63ddE8AFA`](https://sepolia.etherscan.io/address/0xCbd3b73C257Fbe4ac4a1084163Aa4cA63ddE8AFA) | [`0x3436...5d2e`](https://sepolia.etherscan.io/tx/0x3436c8d7b1a0b5a553ca905acd3871e3cd50ae220f9b4e0d12e16aa11a965d2e) |
| Mint-pass consumer | [`0xb453815C2804BBB85fd6B10579b80b2E7Dc4fB32`](https://sepolia.etherscan.io/address/0xb453815C2804BBB85fd6B10579b80b2E7Dc4fB32) | [`0xc880...4b88`](https://sepolia.etherscan.io/tx/0xc8802c963fe04d368cdc28d0e297d03778d4b86f8f4d5d783aa5764597114b88) |
| Phil smart account | [`0x1c2408e4Ce718263a5956d4e5212e69198D5E61a`](https://sepolia.etherscan.io/address/0x1c2408e4Ce718263a5956d4e5212e69198D5E61a) | Counterfactually deployed by the UserOperation |
| Proof verifier / attestation | **none** | Not applicable |

The exact prefund transaction was
[`0x344d...57a2`](https://sepolia.etherscan.io/tx/0x344da21ce9528f2c4639c12d401a4ebb4fd9e4817768a8785cdca998a08c57a2).

## Independently reconciled result

- UserOperation transaction:
  [`0x5b26b57ca7593acaf26f7d4c0e464d64f4cc6fabe576b94687495e7b4bdfbedc`](https://sepolia.etherscan.io/tx/0x5b26b57ca7593acaf26f7d4c0e464d64f4cc6fabe576b94687495e7b4bdfbedc)
- Receipt status: `1` / success
- Block: `11561486`
- EntryPoint `UserOperationEvent.success`: `true`
- Account nonce after execution: `1`
- Issued pass/token ID: `1`
- Pass owner: `0x1c2408e4Ce718263a5956d4e5212e69198D5E61a`
- Factory registration: `true`
- Envelope consumed: `true`
- Root nullifier consumed: `true`
- Device approval nonce consumed: `true`
- Read-only replay result: rejected with `EnvelopeAlreadyConsumed`
- Automatic retry: `false`

The deployment transaction inputs matched the frozen plan byte-for-byte; their
receipt addresses, constructor bindings, chain ID, EntryPoint, factory, gate,
consumer, and account relationships were reconciled through a public Sepolia
RPC separate from the bundler receipt. Runtime code was present at every
address. Solidity constructor immutables mean an unpatched generic runtime hash
is not a valid equality check; the exact creation inputs and live immutable
getter values were used instead.

## Cost and residual state

- Deployment and funding-transaction fees:
  `1471325154353917` wei
- UserOperation actual gas cost: `927206200850575` wei
- Total network fees: `2398531355204492` wei
- Remaining EntryPoint deposit: `3434027420249425` wei

The immutable Alpha account intentionally has no general withdrawal or owner
rotation surface. The remaining disposable Sepolia deposit may be stranded and
must not be treated as a recoverable asset.

## Enforcement boundary

Ethereum does not verify the Noir proof or iPhone P-256 signature. The local
composition service verifies both against the identical envelope and releases
the protected execution signature. Ethereum enforces the v0.7 account
signature and nonce, restricted zero-value ActionGate call, factory
registration, Sepolia chain and expiry, three replay dimensions, and gate-only
pass issuance.

This trusted local-composition boundary is acceptable only for this Alpha
testnet demonstration. The deployed contracts and disclosed disposable test
operator key are not Beta custody and must never receive meaningful assets.
