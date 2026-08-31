# Phil V1 Step 4 Composed Account Gate

Status: corrective local candidate pending independent review

This isolated Cairo project demonstrates one synthetic exceptional account
confirmation that succeeds only when all of the following agree in one call:

- the exact accepted Step 3 UltraKeccakZKHonk root proof;
- the complete authorization envelope and all 13 returned proof inputs;
- a separate, canonical low-S P-256 device approval;
- the configured network, account, adapter, action, policy, presentation, and
  proof descriptor;
- current scope, capability, device, recovery, and validator epochs;
- time, value, fee, revocation, emergency-stop, and replay state.

Success consumes the envelope digest, root nullifier, and approval nonce,
advances one nonce and one receipt sequence, and writes only a synthetic local
receipt. The contract has no arbitrary call, transfer, upgrade, signer, RPC,
deployment, transaction, or production-runtime surface.

## Reproduce locally

Use the exact offline toolchain identified in `.tool-versions` and
`artifacts/reference-manifest.json`:

```text
npm run generate:phil-v1-step4-artifacts
npm run test:phil-v1-step4-composed-account
npm run build:phil-v1-step4-cairo
npm run test:phil-v1-step4-cairo
npm run verify:phil-v1-step4-artifacts
```

The Cairo commands require Scarb 2.14.0, Starknet Foundry 0.53.0, and USC
2.10.0 on `PATH`. Scarb is invoked offline. The generated fixture discloses
its synthetic P-256 private scalar and inherits only the already-disclosed
synthetic Step 3 proof fixture.

## Security boundary

This is not a production account, proof-backend selection, deployment, audit,
formal proof, or authorization to start Step 5. It uses no physical device,
real Phil secret, external prover, RPC, funds, or network. The isolated receipt
has `productionAuthority: false` and `networkActivity: false` and is not wired
to any product runtime.

The controlling gate and threat model are:

- `docs/reference/PHIL_V1_STEP4_COMPOSED_ACCOUNT_AUTHORIZATION_GATE.md`
- `docs/security/PHIL_V1_STEP4_COMPOSED_ACCOUNT_THREAT_MODEL.md`

The first exact candidate, `895320f4060ab809b9dab564fcedc1118dfb5780`,
was independently rejected. The corrective candidate remains unaccepted until
a separate reviewer accepts its frozen exact commit with no unresolved finding.
