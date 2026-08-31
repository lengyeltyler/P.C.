# O.24 Factory Deployment

## Scope

O.24 authorizes exactly one Ethereum Sepolia mutation: deployment of
the reviewed `PhilCore4337LocalProofAccountFactoryV1` from the disposable
deployment wallet at nonce `2`.

The factory is bound to the canonical ERC-4337 v0.7 EntryPoint, the
verified O.23R confirmation target, and Ethereum Sepolia chain ID
`11155111`. It embeds the account creation bytecode and deploys accounts
directly with CREATE2; no standalone implementation deployment exists.

## Guarded Evidence

The immutable pre-deployment proposal is:

* `config/ethereum-sepolia/O24_FACTORY_DEPLOYMENT_PROPOSAL.json`

The confirmed deployment receipt is:

* `config/ethereum-sepolia/O24_FACTORY_DEPLOYMENT_RECEIPT.json`

Both contain public addresses, hashes, gas evidence, and sanitized state
only. Private keys and RPC credentials remain in the ignored mode-`0600`
local environment.

## Explicit Stop

O.24 does not use the future funding wallet, call the factory, deploy or
fund the counterfactual account, generate a proof, request Device Vault
signing, configure or contact a bundler, create an EntryPoint deposit, or
submit a UserOperation. ACP-0002 remains Proposed, and Beta and
production approvals remain false.

## Confirmed Deployment

The factory-only transaction succeeded on Ethereum Sepolia:

* factory: `0x6a9905Bc18620d9689e6a3214C43eC10B99b824e`;
* transaction:
  `0xb909b23c4bd2e6b59347b460b4bb994f120cd0d06ad6efbf5707757c8bab6ccf`;
* block: `11366062`;
* gas used: `1040663`;
* exact cost: `1158517844356847` wei.

The deployed immutable-patched runtime hash is
`0x8a356af155426d2de17da0762d29c4c0a7956e3bc4e4b6811d1b819da789722f`.
Read-only getters confirm the canonical EntryPoint, the unchanged O.23R
confirmation target, and Sepolia chain ID. The explicit Solidity
`getAddress(address,bytes32,bytes32,uint256)` method returns
`0xF7212776373B51c1514Dd9C4490048270056C150`.

An initial post-deployment check used ethers' built-in
`Contract.getAddress()` method instead of the same-named Solidity
function. It stopped after the already-successful receipt and made no
additional mutation. The corrected verifier uses the full ABI signature,
and a separate read-only reconciliation recorded the final evidence.
