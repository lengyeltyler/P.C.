# PhilCore Controlled Sepolia Beta P1 Evidence

Date: 2026-08-25 America/Denver (2026-08-26 UTC)

Verdict:

```text
P1 INFRASTRUCTURE DEPLOYMENT CONFIRMED: YES
PHILCORE CONTROLLED SEPOLIA BETA READY: NO
```

P1 is complete through independent read-only reconciliation. This evidence
does not authorize P2, a UserOperation, a mint, P3-P5, mainnet, meaningful
assets, or a production claim.

## Frozen source and review

- deployed source commit: `64eb809859f8612dc09ee2302729747efdc700b9`
- deployed source tree: `edd6005ab8f28868a7efa5d4b7b49ad95afaa468`
- protected untracked `pqREADME.md` SHA-256:
  `7702166308feec4d81733842f0d7da4034c64fab2381bb353bd2a769b99b24c8`
- P1R independent landed-source review disposition:
  `ACCEPTED_ZERO_UNRESOLVED_CRITICAL_HIGH`
- P1R review report SHA-256:
  `d4ceb4e9dacbb711a758a7c8292524914295bd0cd58829631a84b0b95a0f8a7b`
- review boundary: independent AI review plus owner risk acceptance; no
  professional-audit claim

## Approved plans

- original P1 plan digest:
  `0x3d351428a723bbae0dbf084d49fa3900b420c6cfc4fb2d348d5307f23f3f58b5`
- P1R plan digest:
  `0x2934e38a2e6ca80f6c7011a4c45b38b0943182ee8c2473541e2a0ec66467d673`
- P1R public mutations: exactly three zero-value contract creations
- automatic retry: false; no retry occurred

The original P1 funding transaction confirmed, but its first deployment was
rejected before network acceptance. P1R independently proved that state and
contained only the remaining deployments.

## Funding evidence

- funding source:
  [`0x549A5C770085b00B60F6D729DB99f8Bffb72eE12`](https://sepolia.etherscan.io/address/0x549A5C770085b00B60F6D729DB99f8Bffb72eE12)
- fresh Beta deployer:
  [`0xF4F3d0E5df54908BC2bf0864B4EdC18653f09ad1`](https://sepolia.etherscan.io/address/0xF4F3d0E5df54908BC2bf0864B4EdC18653f09ad1)
- confirmed funding transaction:
  [`0x96918482e96263c01ac881ab67e975530fdf8647bba12edf3f5d2a1add6fd239`](https://sepolia.etherscan.io/tx/0x96918482e96263c01ac881ab67e975530fdf8647bba12edf3f5d2a1add6fd239)
- funding block: `11567203`
- funding block hash:
  `0xca5886b8df089378cf2bbf22343dd9db7973186f4169f6e0644232109158d68a`
- rejected and absent original deployment hash:
  `0xfa8fcb3935c0ba912db96c17908931188228ab0b76ad347c31d413bc44684086`

## Confirmed infrastructure

| Order | Contract | Address | Transaction | Block | Runtime code hash |
| --- | --- | --- | --- | ---: | --- |
| 1 | `PhilSepoliaMintPassConsumerV1` | [`0x683EeE209640D9fb5bFB12876B916B35A19E18e5`](https://sepolia.etherscan.io/address/0x683EeE209640D9fb5bFB12876B916B35A19E18e5) | [`0x7a55386d18987270bcb9083c6cb525d8ad4de75e6dd11e7791442909127f8d7f`](https://sepolia.etherscan.io/tx/0x7a55386d18987270bcb9083c6cb525d8ad4de75e6dd11e7791442909127f8d7f) | 11567420 | `0x0a51746d6e9eab9ac2e7000cc70d3b374d10f86ef2b8dd0ac90c134988e11891` |
| 2 | `PhilSepoliaLocalComposedActionGateV1` | [`0xD48e07a5c3A4E472E4923Db39219140F417A42D4`](https://sepolia.etherscan.io/address/0xD48e07a5c3A4E472E4923Db39219140F417A42D4) | [`0x3aee6c0e5d3c43e8385dc540fe83a5ccaeafb161e2bd166fa923e72720f42a29`](https://sepolia.etherscan.io/tx/0x3aee6c0e5d3c43e8385dc540fe83a5ccaeafb161e2bd166fa923e72720f42a29) | 11567421 | `0x137555ca098aebbcdbc8c4bee8d20e1e92643c67fd81cdeea7fc800380502a3a` |
| 3 | `PhilCore4337AccountFactory` | [`0xCcbdB547b70741D78d327B4584607C651ddF327A`](https://sepolia.etherscan.io/address/0xCcbdB547b70741D78d327B4584607C651ddF327A) | [`0x1a37d8f2bd5c3eb7eb3c18dc93a300860686f24e37c46bdc942e97df809a156d`](https://sepolia.etherscan.io/tx/0x1a37d8f2bd5c3eb7eb3c18dc93a300860686f24e37c46bdc942e97df809a156d) | 11567422 | `0x1e622114595755e7091fec38985ce4bccd6f2f3b8dd48bda755c754f1d9a312e` |

Alchemy and Infura independently returned the same receipt status, block
number, block hash, contract address, gas used, and deployed bytecode for each
transaction. All receipt statuses are `1`. The deployer nonce is `3` and its
reconciled remaining balance is `5880227765598289` wei.

## Constructor-binding reconciliation

Both providers independently returned the following exact bindings:

- consumer ActionGate:
  `0xD48e07a5c3A4E472E4923Db39219140F417A42D4`
- gate chain ID: `11155111`
- gate factory:
  `0xCcbdB547b70741D78d327B4584607C651ddF327A`
- gate consumer:
  `0x683EeE209640D9fb5bFB12876B916B35A19E18e5`
- gate authorized account:
  `0xb72053013089F089502B075009c0BD807349eCC6`
- factory EntryPoint:
  `0x0000000071727De22E5E9d8BAf0edAc6f37da032`
- factory approved ActionGate:
  `0xD48e07a5c3A4E472E4923Db39219140F417A42D4`
- factory recovery authority:
  `0x8d9eaf12897d52612fC24189a8aA899C51aE7A83`
- recovery delay: `172800` seconds
- recovery expiry: `604800` seconds
- factory-predicted account:
  `0xb72053013089F089502B075009c0BD807349eCC6`

The account remains counterfactual (`eth_getCode == 0x`), as required before
P2. P1 deployed infrastructure only; P2 is the separately approved first-use
account deployment and composed action.

## Verifier incident and resolution

After all three deployments confirmed, the P1R executor preserved a
`STOPPED_REQUIRES_READ_ONLY_RECONCILIATION` receipt with failure code
`PHILCORE_CONTROLLED_BETA_P1_RECOVERY_CONSTRUCTOR_BINDING_INVALID`.

The stop was caused by an off-chain method-name collision. In ethers,
`factory.getAddress()` is a base-contract helper that returns the factory's own
address. The verifier intended to call the Solidity overload
`getAddress(address,bytes32,uint256)`. Selecting that full signature returned
the exact planned counterfactual account through both providers. The original
incident receipt remains unchanged; the verifier is corrected in both the P1
and P1R executors, with a regression test that forbids the ambiguous call.

No public mutation was required to resolve the incident, and no transaction
was rebroadcast.

## Remaining gate

P1 infrastructure is confirmed. The controlled Sepolia Beta is not ready.
The next possible public stage is P2, which must independently freeze and
approve one capped account-funding transaction and one first ERC-4337
UserOperation after its proof/device ceremony and all exact fields are fixed.
