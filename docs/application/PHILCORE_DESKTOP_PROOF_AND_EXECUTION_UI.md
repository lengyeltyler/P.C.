# PhilCore Desktop Proof And Execution UI

Status: local Alpha implemented; public publication and production execution disabled.

The O.5 desktop UI shows a local authorization timeline with safe summaries only.

Visible stage names:

- Request received
- Trust checked
- Policy approved
- Your approval
- Capability active
- Authorization prepared
- Proof generating
- Proof generated
- Proof verified
- Local fact fixture
- Smart account call prepared
- Ready to sign
- Signed
- Executed locally
- Result verified

## Proof Panel

The proof panel may show:

- proof type;
- proof digest;
- shortened `proofInputHash`;
- shortened `[fact_high, fact_low]`;
- generation and verification status;
- approximate proof and verification durations.

It must not show raw witness data, `phil_secret`, nullifier seed, raw proof bytes by default, private keys, vault keys, wrapping keys, or decrypted registry plaintext.

## Execution Panel

The execution panel may show:

- local smart-account address;
- local EntryPoint;
- ActionGate;
- consumer;
- UserOperation hash;
- local transaction hash;
- nonce;
- public nullifier reference;
- nullifier-consumed status;
- consumer-executed status.

It must label the path as local and must not imply public bundler submission, paymaster use, Starknet publication, Ethereum L1 anchoring, L1-to-Base relay, or public Base state mutation.

## Interruption

Pending approval, fresh-authentication evidence, protected witness material, signing sessions, and in-flight proof authority do not survive lock or restart. If the app closes mid-proof, the workflow is interrupted and a new authorization attempt is required.
