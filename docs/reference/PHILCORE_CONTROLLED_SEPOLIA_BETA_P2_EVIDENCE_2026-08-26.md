# PhilCore Controlled Sepolia Beta P2 Evidence

Date: 2026-08-26 America/Denver (2026-08-26 UTC)

Verdict:

```text
P2 FIRST COMPOSED ACTION CONFIRMED: YES
P3 SECOND ACTION AUTHORIZED: NO
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```

P2 is complete through one confirmed account deployment, one confirmed
nonce-`0` ERC-4337 v0.7 UserOperation, and independent read-only
reconciliation. This record does not authorize P3, P4, P5, mainnet,
meaningful assets, signed Beta distribution, or a production claim.

## Final frozen source and review

- final P2F source commit:
  `b6341e294045050c0bb5bb7e265a338968849692`
- final P2F source tree:
  `150df1d6e0e62b541a96337a9a3bfc707bbd1b8a`
- protected untracked `pqREADME.md` SHA-256:
  `7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`
- final P2F gas-correction review disposition:
  `ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH`
- final P2F review report SHA-256:
  `cc690ffe2a642a58120dfde81116658390aabd2663ccd046f17cf207e58a13d0`
- exact-source hosted CI run: `33012867535`, six of six jobs passed at the
  final P2F commit
- review boundary: independent AI review plus owner risk acceptance; no
  professional-audit claim

Earlier accepted corrective reviews remain part of the P2 evidence chain:

| Scope | Report SHA-256 | Result |
| --- | --- | --- |
| P2R recovery runner | `47a3d11b9870549808f7bad96ba27780aed7a647dd43eae24d593cd674c0a210` | accepted, zero unresolved critical/high |
| P2 factory-stake recovery and P2A/P2F route | `1f60bb9af8e466f7668c0e5081deb46ec1ddb541d04883e24fbf9dff2593fb45` | accepted, zero unresolved critical/high |
| P2A reconciler and P2F final runner | `fd6f3e2afe273dcf9d8c640c0a1426109c97224e65095a31a2dbc39e7cde6c1b` | accepted, zero unresolved critical/high |
| P2F runtime-manifest binding correction | `80569d3dd40c4e30cc8574a0e220ff536386c2004f013f62cd64ed217941cb5b` | accepted, zero unresolved critical/high |

## Authority, account, and provider boundary

- smart account:
  [`0xb72053013089F089502B075009c0BD807349eCC6`](https://sepolia.etherscan.io/address/0xb72053013089F089502B075009c0BD807349eCC6)
- initial execution validator and pass owner:
  [`0xCCFdf0a8172A8B10529a48F77F75941A1FB7aA81`](https://sepolia.etherscan.io/address/0xCCFdf0a8172A8B10529a48F77F75941A1FB7aA81)
- official EntryPoint v0.7:
  [`0x0000000071727De22E5E9d8BAf0edAc6f37da032`](https://sepolia.etherscan.io/address/0x0000000071727De22E5E9d8BAf0edAc6f37da032)
- final primary RPC and bundler: Alchemy Sepolia, credential omitted
- final independent reconciliation RPC: PublicNode Sepolia
- endpoint credentials were neither committed nor written to public evidence

The phone ceremony used a fresh install built from the final P2F source as
PhilCore iOS version `0.1.0`, build `56`. The app artifact tree SHA-256 was
`4638389232c43cb0bdfae90b02da9984c3a11c8e9573ba11803c43f79f0e2ca7`
and the executable SHA-256 was
`cd6d8155bd24795610f2e22121263378c155a384c0c1f966302e3c4ae9c2e711`.
The ceremony proved possession of the enrolled P-256 key and required local
user presence. It did not establish remote hardware or app attestation.

## Exact public-mutation sequence

Every mutation below had its own digest-specific approval and durable attempt
lock. No executor retried automatically.

### Original P2 funding and rejected first operation

- plan digest:
  `0x23467979ac3c95b6f7aa2c288292aa4718b4ae5c94e2998636ed7f9868ae0997`
- confirmed account-funding transaction:
  [`0x60029b4b50246fa4c318caaf61ea184b838d6c28e2c41be6782409ff15136c9a`](https://sepolia.etherscan.io/tx/0x60029b4b50246fa4c318caaf61ea184b838d6c28e2c41be6782409ff15136c9a)
- funding block: `11568484`
- funding value: `4840000000000000` wei
- rejected UserOperation:
  `0xff258b993d44b5d8729b1bee326887b9e65166b71bbf0337525f03be5e9e2cf6`

The funding transaction confirmed on both then-configured providers. The
bundler rejected the UserOperation during precheck because its priority fee
was below the bundler's required floor. Read-only reconciliation found no
bundler receipt or operation, no account deployment, nonce zero, deposit zero,
all replay fields unused, and no pass. The funding transaction was not
repeated.

### P2R factory-stake rejection

- P2R plan digest:
  `0x560db6caffb96f9c36df4c1ac7903f2187298df9a4ef60b7fa8fdc18d015dee9`
- rejected UserOperation:
  `0x74e3ec0f673028e14c4c143562e4f5539957a6b518dae83b779707ad37f121ef`
- preserved receipt SHA-256:
  `4f0636ceedd68673bf582efa1c8e39200532fda19ef6340de7fc25e35057c3c7`

The corrected-fee P2R operation was rejected synchronously with
`entity stake/unstake delay too low`. Read-only reconciliation found no
bundler receipt or operation and no on-chain state change. The prefunded
account address remained counterfactual and all replay fields remained
unused. The attempt was not retried.

### P2A account deployment

- P2A plan digest:
  `0xdf9fcb7a6aaacb5946d70845404d1235aa424d9784ccda1d2b690bae19e75519`
- confirmed deployment transaction:
  [`0x78770827598af3378b6ddea04c1131df2b3b7b42baf530163078c2a5fb6cf2ce`](https://sepolia.etherscan.io/tx/0x78770827598af3378b6ddea04c1131df2b3b7b42baf530163078c2a5fb6cf2ce)
- confirmation block: `11572932`
- gas used: `1557868`
- read-only reconciliation SHA-256:
  `1abf551065b120620a9a9b949e7f9197298a163f1978ecf208e3ad1bd3834521`

The zero-value factory call deployed the already-prefunded account and
registered it with the reviewed factory. Both providers agreed on the receipt,
runtime, constructor bindings, factory registration, native balance
`4840000000000000` wei, EntryPoint nonce zero, and deposit zero.

The P2A executor stopped after the transaction because its first post-check
treated the immutable-bearing runtime hash as a fixed hash. The transaction
was not retried. A dedicated read-only reconciler masked only the compiler-
declared immutable ranges, verified every getter and remaining runtime byte,
and recorded the confirmed deployment.

### P2F pre-mutation and bundler incidents

P2F plan
`0x709d0b178a1adc83430704162e4ac9842a930e4a402812582c4353e4c6e99d64`
was superseded before submission after the executor's runtime-manifest binding
check failed closed. It acquired no execution lock and caused no public
mutation.

The next approved P2F plan,
`0x8e5b6fd494c56a44558627df2579deb331d7399c9c6538cebd38e9b2f5cc3688`,
requested submission of UserOperation
`0xd61a81ba6f41408d0bc7364dd32fbf606901c91875a561b28f329451ed0603a0`.
The bundler rejected it because verification-gas reservation efficiency was
below `0.4`. The executor conservatively recorded that a public mutation may
have occurred because `eth_sendUserOperation` was invoked, then stopped
without retry. Two-provider and bundler reconciliation proved no operation,
receipt, nonce change, balance change, replay consumption, or pass. The
reconciliation artifact SHA-256 is
`a4d4f2d6dc5fdd86e86041822fad4569a9895136f134c35802594ca47b8ad97e`.

The reviewed correction selected a P2F-only `150000` verification-gas limit,
preserved every other gas and fee field, required a newly signed operation,
and required a fresh physical ceremony.

## Confirmed P2F result

- final plan digest:
  `0xde6052b2b94b28118afa05d4cbc73b343b893171991818d020610ef7d0da836e`
- UserOperation hash:
  `0x0d96fa9ff4fd9a0fe3717b217b3151fbfeda51d682bf9d071b350086e251b670`
- bundle transaction:
  [`0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934`](https://sepolia.etherscan.io/tx/0x24a3a28989e8707bc52ff66e1f0ed1b9a8d31a8b151cf6177320a8285eb0b934)
- block: `11573471`
- receipt status: `1`
- actual UserOperation gas cost: `430138520513770` wei
- additional funding: `0` wei
- durable final receipt SHA-256:
  `821dfa42c6c554725a6a31d7038ca7487dde1a2a8d51a2de60a5a7481efecec7`

Alchemy and PublicNode independently agreed on the transaction receipt and
the following final state at block `11573477` or later:

| Check | Confirmed value |
| --- | --- |
| Account runtime code hash | `0x5ee74f9e45b3d944b6bf220d60cb83000d04ca878c26ab455eaeda1dcea8b8ad` |
| EntryPoint nonce | `1` |
| EntryPoint deposit | `779861479486230` wei |
| Account native balance | `3630000000000000` wei |
| Authorization-envelope replay marker | consumed |
| Root-proof-nullifier replay marker | consumed |
| Device-approval-nonce replay marker | consumed |
| Pass token | `1` |
| Pass balance of execution validator | `1` |
| Next token ID | `2` |

The receipt contained exactly one `UserOperationEvent`, one
`PhilSepoliaLocalComposedAuthorizationConsumed` event, and one
`PhilSepoliaMintPassIssued` event, all bound to the approved operation,
account, recipient, and replay fields.

## Trust boundary and remaining gate

Ethereum enforced the official EntryPoint flow, the account execution
signature, the restricted target/value surface, current-owner recipient, and
on-chain replay consumption. Noir proof verification and iPhone P-256 approval
occurred locally before Device Vault released the execution signature;
Ethereum did not independently verify either item.

P2 proves the first composed action only. P3 must use the same deployed account
at live nonce `1`, empty `initCode`, a new proof, a new physical phone approval,
fresh replay fields, one separately approved UserOperation submission, and a
non-mutating demonstration that the stale P2 authorization cannot be replayed.
