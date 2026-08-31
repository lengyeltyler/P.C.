# PhilCore ERC-4337 Consumer Trust Requirements

Status: requirements only.

## Principle

`PhilBaseActionGate` verifies authorization and consumes the nullifier, but the authorized consumer remains a trusted execution module. Proof validation does not make arbitrary consumer code safe.

## Approved Consumer Requirements

- callable only through the configured ActionGate;
- exact consumer-data schema;
- bounded value policy;
- no unbounded arbitrary target unless explicitly intended and reviewed;
- reentrancy behavior reviewed;
- atomic revert behavior tested;
- events sufficient for Runtime receipt verification;
- deployment address and code hash bound in Runtime configuration;
- explicit security review before meaningful assets;
- no hidden signer, delegatecall, upgrade, or generic wallet authority unless separately approved.

## Classification

Consumers are trusted modules. Runtime capabilities must bind to specific reviewed consumer identities and consumer-data schemas.

## Current N.2 Status

Local consumers and adversarial consumers are test fixtures. Production consumer approval is not complete.
