# Ethereum Sepolia Bundler Requirements

Status: provider-neutral requirements; no endpoint selected or contacted.

## Required Support

The bundler must support Ethereum Sepolia, canonical EntryPoint v0.7, packed
UserOperations, and:

- `eth_supportedEntryPoints`
- `eth_chainId`
- `eth_estimateUserOperationGas`
- `eth_sendUserOperation`
- `eth_getUserOperationReceipt`
- `eth_getUserOperationByHash` where available

The client must separately verify chain ID and supported EntryPoint. A bundler
response is not trusted receipt evidence; the final transaction and EntryPoint
event must be reconciled through an independently configured Ethereum RPC.

## Provider-Neutral Boundary

PhilCore provides a restricted interface for capability checks, estimation,
exact-operation submission, lookup, and receipt polling. It exposes no generic
JSON-RPC or arbitrary UserOperation submission API to applications or the
renderer.

Configuration uses references:

- `PHILCORE_SEPOLIA_BUNDLER_URL`
- `PHILCORE_SEPOLIA_RPC_URL`

Credentials remain external. Logs must omit URL secrets, request headers,
signed payloads, and unrestricted response bodies.

## Selection Review

Before approval, record:

- supported EntryPoint and chain;
- authentication and credential custody;
- request/operation logging and retention;
- rate and size limits;
- simulation implementation;
- timeout, retry, and replacement behavior;
- sponsorship coupling;
- availability and vendor lock-in;
- privacy implications of sender, calldata, and timing.

Paymaster sponsorship must not be required. Automatic blind retry after an
ambiguous submission is prohibited. Reconcile by UserOperation hash,
transaction hash, nonce, bundler lookup, RPC receipt, and EntryPoint event.

## Current Status

No bundler is approved. No endpoint is stored. No capability check or public
submission occurred in O.17.

