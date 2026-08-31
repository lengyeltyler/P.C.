# Phil V1 Step 6C-1 Implementation Blocker: Nonce-Bound Frozen Catalog

Date: 2026-08-22

## Outcome

The separately authorized Step 6C-1 implementation was started against exact
definition candidate `227bd48d92c84672c50f2d19f47b9a24e5b17786`, tree
`cd5a734c5ca1ce486d55024befa85424aefefb42`, and stopped before an
implementation candidate was frozen.

Verdict:

```text
STEP_6C_1_IMPLEMENTATION_BLOCKED_BY_ACCEPTED_DEFINITION_CONTRADICTION
```

No implementation source was retained or committed. No iPhone, external RPC,
public network, deployment, real identity material, recovery material,
meaningful asset, or production authority was used.

## Reproduced Contradiction

The accepted packet requires all of the following:

1. `PhilEvmSingleCallV1.actionHash` signs `nonceSequence` and the packed
   EntryPoint nonce.
2. The catalog parameters entry has both `entryId = parametersHash` and
   `boundValueHash = parametersHash`.
3. The envelope requires `parametersHash = actionHash`.
4. The capability policy contains `catalogHash`.
5. The account constructor permanently stores both `catalogHash` and
   `capabilityPolicyHash`, with no setter.
6. After a target failure at official EntryPoint nonce `n`, a fresh request at
   nonce `n+1` must succeed through the same account.

Items 1 through 5 make item 6 impossible. Changing only the official nonce
changes `actionHash`. That changes the parameters catalog entry, then
`catalogHash`, then `capabilityPolicyHash`. The account is required to reject
those changed hashes because its constructor permanently stored the values for
nonce `n`.

The conflict exists even if the target calldata and every other field are
unchanged. The required `shouldRevert=true` operation followed by
`shouldRevert=false` changes the action hash again independently.

## Mechanical Witness

Using the packet's literal ABI types with identical synthetic fields except
for `nonceSequence` and packed nonce produced:

```text
actionHash(n=0) = 0x3c139e7db3f3f491e904e8dc9308124ef382272d2e7e8986ecf985573b629505
actionHash(n=1) = 0x80827494846d48289aea44f68a1693f6354e4405451a855ab2eb9abfa0d5bd6b

parametersEntryHash(n=0) = 0x4f2219d69669df1097e5ab6844e3782884aa36e3feae10f75daf30c1fb2a730f
parametersEntryHash(n=1) = 0x18d509452453dc82cdf08cc16c623c51f20527451601403ea38319b6b7e043db
```

The hashes are unequal. Therefore the frozen constructor catalog cannot admit
the required next EntryPoint nonce without violating an exact packet rule.

## Security Meaning

Silently omitting the constructor catalog/policy comparison would make the
required liveness test pass, but it would not implement the accepted security
contract. Keeping the comparison would make the disposable account
single-operation and fail the mandatory official-nonce liveness property.
Neither result is an acceptable Step 6C-1 candidate.

This does not change Phil's device-first identity goal, the accepted Steps 1
through 5, Step 6A, Step 6B, the Step 5 registry, or the decision to use the
official EntryPoint nonce as the sole sequence. It is a defect in the Step 6C
request-display catalog binding.

## Smallest Corrective Direction

The smallest coherent correction is to keep the account's catalog immutable
but make catalog kind 6 bind a stable parameter-schema identity rather than the
per-operation `actionHash`. The request must still sign the complete action
hash through the presentation, envelope, authorization core, approval digest,
request ID, and device signature. The iPhone must still derive the displayed
parameter summary from the raw action and verify it against the stable schema.

An exact correction must freeze:

- a new `parameterSchemaId` derivation and its ABI types;
- the revised catalog kind-6 `entryId` and `boundValueHash` rules;
- the equality map proving `presentation.parametersHash = actionHash` remains
  signed and separately proving the parameter summary uses the admitted schema;
- Solidity and SDK reconstruction rules; and
- a literal test showing the catalog and policy hashes remain stable while
  nonce `n` and nonce `n+1` produce distinct signed action hashes.

This is a definition change and requires a bounded corrective definition plus
independent read-only review before Step 6C-1 implementation resumes.

## Current Gate

This record remains the historical reason candidate `227bd48` could not be
implemented. The bounded correction in
[the third corrective definition](./PHIL_V1_STEP6C_THIRD_CORRECTIVE_DEFINITION.md)
was independently accepted. Step 6C-1 candidates `a158688`, `aea7359`,
`591f6b6`, and `5ab4650` were independently rejected and are superseded. Corrective source
commit `6f048eb`, tree `a9032b2`, is frozen under that correction. Exact
candidate `22b5cf3`, tree `2b0ff7f`, is independently accepted for Step 6C-1.
Step 6C remains incomplete; Step 6C-2 and physical-device
work remain unauthorized.
