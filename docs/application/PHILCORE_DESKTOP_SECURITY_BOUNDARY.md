# PhilCore Desktop Security Boundary

Status: local Alpha security boundary implemented.

Phase: O.5

## Boundary

```text
Renderer
  -> narrow preload bridge
  -> Electron main Runtime host
  -> encrypted local identity / Device Vault boundary
  -> existing Runtime / local fixture infrastructure
```

The renderer is display state only. The Runtime host remains the source of truth for session, vault, approval, capability, proof, recovery, and execution status.

O.2 stores local identity and Device Vault records only through the Electron main process. The renderer never receives filesystem paths, decrypted registry plaintext, raw vault keys, raw private keys, recovery private keys, unrestricted signer objects, or vault handles.

O.3 adds a narrow `platformAuth` bridge group. It exposes availability, status, policy, enrollment, unlock, disablement, and fresh-authentication requests only. It does not expose generic Keychain CRUD, service names, account names, raw wrapping keys, or protected blobs.

O.4 adds a narrow `approval` bridge group. It exposes Runtime-generated presentation creation, presentation lookup, approve/deny/cancel responses, status, history, and bounded consumption checks. It does not expose digest-generation parameters, signer methods, arbitrary recovery calls, or reusable authority.

O.5 adds narrow `authorization` workflow commands for one selected local authorization path: start workflow, inspect sanitized workflow, request fresh auth for the exact signing digest, approve/deny/cancel signing, and inspect the sanitized result. It does not expose the STWO prover, protected witness provider, Device Vault signer, generic contract-call builder, generic ERC-4337 builder, EntryPoint handle, RPC provider, raw signed UserOperation, or public submitter.

## Electron Controls

The local Alpha shell is pinned through `package-lock.json` to Electron 39.8.10.

O.2 requires:

- `contextIsolation: true`;
- `nodeIntegration: false`;
- sandboxed renderer;
- strict preload bridge;
- no arbitrary IPC;
- no raw filesystem API in renderer;
- no shell command execution from renderer;
- no generic Runtime object exposure;
- no private key, vault key, vault handle, recovery private key, or decrypted registry transfer to renderer;
- no wrapping-key or generic Keychain transfer to renderer;
- Content Security Policy;
- navigation restrictions;
- external-link restrictions;
- no remote module;
- no unsafe `eval`;
- development tools only when explicitly enabled by local development mode.

## Bridge Surface

Bridge groups:

- `identity`;
- `session`;
- `runtime`;
- `authorization`;
- `recovery`;
- `approval`;
- `audit`;
- `settings`;
- `diagnostics`.

The bridge does not expose:

- filesystem paths;
- subprocess commands;
- generic RPC;
- raw signer objects;
- vault backends;
- arbitrary contract calls;
- unrestricted JSON execution;
- public transaction submission.
- public bundler submission;
- generic proof generation;
- raw UserOperation signing.

Every bridge request is validated against an allowlisted channel and payload shape.

The normal session path uses local Alpha passphrase authentication and encrypted local records. The legacy fixture-authentication channel remains present only as an unsupported compatibility result; it is not the normal unlock path.

When platform unlock is enrolled, the user chooses platform unlock or passphrase fallback explicitly. Failed platform unlock does not silently fall back to passphrase.

## Renderer Restrictions

The renderer must not contain or receive:

- root secret material;
- raw private keys;
- vault keys;
- wrapping keys;
- recovery private keys;
- signing sessions;
- raw proof witnesses;
- unrestricted signed payloads;
- generic Runtime internals.

Renderer security tests enforce no Node imports, CSP presence, narrow preload exposure, and no secret-shaped tokens in renderer files.

## Developer Mode

Developer mode may show local stage names and sanitized artifacts. It cannot:

- expose private keys;
- expose witnesses;
- enable public network mutation;
- skip approval;
- generate replacement presentation digests;
- mutate approved action fields;
- reuse approval artifacts;
- skip Runtime validation;
- generate arbitrary execution calls.

## Public Network Controls

O.2 continues to register no public submitters and exposes no public RPC mutation configuration. Base Sepolia and mainnet remain disabled.

O.5 local EntryPoint execution is Hardhat/local only. Starknet publication, Ethereum L1 anchoring, L1-to-Base relay, public Base execution, paymasters, and public bundlers remain disabled.
