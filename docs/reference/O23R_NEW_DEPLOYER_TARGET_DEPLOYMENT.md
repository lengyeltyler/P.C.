# O.23R New-Deployer Target Deployment

## Scope

O.23R refreshes the Sepolia proposal for two explicitly separated,
disposable accounts and permits exactly one public mutation:
deployment of the current `PhilCoreLocalProofConfirmationTargetV1`.

The deployment wallet pays only for that target deployment in O.23R.
The future prefunding wallet is observed read-only and is not used. The
canonical PhilCore Device Vault validator remains unchanged.

## Evidence

The current proposal and funding evidence are:

* `config/ethereum-sepolia/O23R_NEW_DEPLOYER_DEPLOYMENT_PROPOSAL.json`
* `config/ethereum-sepolia/O23R_NEW_DEPLOYER_FUNDING_READINESS.json`

After a successful one-transaction deployment, the receipt is recorded
in:

* `config/ethereum-sepolia/O23R_CONFIRMATION_TARGET_DEPLOYMENT_RECEIPT.json`

These files contain public addresses, hashes, gas evidence, and sanitized
state observations only. Private keys and RPC credentials remain solely
in the ignored mode-`0600` `.env.sepolia.local`.

## Guards

The proposal generator verifies both key/address pairs locally, preserves
the canonical validator and identity bindings, recompiles against the
reviewed O.22 bytecode, reads Sepolia state without mutation, recalculates
the target/factory/account addresses from the new pending nonce, rejects
collisions, and creates a one-time target-only approval digest.

The deployment command repeats chain, key, nonce, balance, address,
bytecode, constructor, gas, fee, block, collision, and approval checks.
It recovers the signer before broadcasting. The command contains no
factory, funding, Device Vault, bundler, or UserOperation execution path.

## Explicit Non-Approvals

O.23R does not approve or perform:

* account-factory deployment;
* use of the future prefunding wallet;
* smart-account deployment or funding;
* Device Vault signing;
* bundler contact;
* UserOperation submission;
* Base Sepolia or production approval.

ACP-0002 remains Proposed.

## Confirmed Deployment

The O.23R target-only transaction succeeded on Ethereum Sepolia:

* target: `0x334577B0feB9e1f49d4ca4ff6dAcc6f8732594D7`;
* transaction:
  `0xb832191373d189cd7da208a3012b018dfba2cf44ac539f18dd88f561f5d43453`;
* block: `11365970`;
* gas used: `304234`;
* exact cost: `332448030178684` wei.

The deployed runtime bytecode and `SECURITY_MODEL_ID` matched the
approved current-source artifact. The proposed factory remains
undeployed, the proposed smart account remains empty and unfunded, the
future prefunding wallet was unchanged, no bundler was contacted, and
no UserOperation was submitted.
