# UserOperation Authorization Bindings

Status: canonical O.17 readiness envelope; no signing or submission.

## Canonical Envelope

`EthereumSepoliaUserOperationAuthorizationEnvelope` is encoded with ABI typed
encoding under:

```text
PHILCORE_SEPOLIA_USEROP_AUTHORIZATION_V1
```

It binds:

- authorization and Runtime versions;
- identity reference and `ownerCommitment`;
- action ID and canonical action digest;
- policy ID and commitment;
- chain `11155111`;
- account, factory when deployment is included, and canonical EntryPoint;
- nonce;
- terminal target, zero value, terminal calldata hash, call type;
- complete account-execute UserOperation calldata hash;
- verification, call, and pre-verification gas;
- maximum and priority fees plus total fee ceiling;
- validity start and expiry;
- nullifier;
- proof input hash and `stwo-unlock-keccak-v1`;
- whether account deployment is included;
- final v0.7 UserOperation hash;
- approval-presentation and fresh-presence evidence digests;
- audit correlation.

The Device Vault signing boundary must receive an immutable instance and
recompute the v0.7 UserOperation hash. UI text is not authority.

## Binding Matrix

| Field | STWO | Runtime approval | fresh presence | signing authorization | UserOp hash | contract |
| --- | --- | --- | --- | --- | --- | --- |
| identity / owner commitment | owner commitment | yes | correlation | yes | indirectly by account/factory | account stores commitment |
| action ID / canonical digest | through action/policy/consumer commitments | yes | yes | yes | call data | gate/consumer events |
| policy | `policyHash` | yes | correlation | yes | call data | gate public inputs |
| chain | `actionHash`/`policyHash` | yes | yes | yes | yes | `block.chainid` in action recomputation |
| account | `actionHash` | yes | yes | yes | sender | UnlockConsumer action hash |
| factory/deployment flag | not directly | yes | yes | yes | initCode hash | factory CREATE2 |
| EntryPoint | not directly | yes | yes | yes | yes | immutable account binding |
| nonce | not directly | yes before signing | yes | yes | yes | EntryPoint |
| target/value/calldata | `actionHash` and `consumerDataHash` | yes | yes | yes | full callData hash | account/gate/consumer |
| gas and fees | not directly | yes | yes | yes | yes | EntryPoint |
| fee ceiling | not directly | policy | presentation | signing guard | component fees | Runtime guard |
| validity/expiry | proof expiry | yes | evidence expiry | yes | not native | gate plus Runtime |
| nullifier | yes | yes | correlation | yes | call data | ActionGate once |
| proof type/input hash | yes | yes | correlation | yes | call data | verifier/gate |
| approval and presence digests | no | yes | yes | yes | not native | Runtime/Device Vault |

No security-critical execution field exists only as display text. Fields not
inside the STWO tuple are bound by the final typed envelope and exact UserOp
hash before Device Vault signing.

## Validation

O.17 rejects:

- cross-chain, cross-EntryPoint, cross-account, cross-nonce replay;
- target, terminal calldata, account calldata, value, gas, or fee mutation;
- a nonempty v0.7 paymaster field;
- an expired or invalid validity window;
- an operation exceeding the approved total fee ceiling;
- missing or mismatched request, policy, approval, presence, proof, Runtime,
  UserOperation, or signing artifacts.

