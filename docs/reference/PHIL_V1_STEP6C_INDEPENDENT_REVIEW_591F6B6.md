# Phil V1 Step 6C-1 Independent Review Of Candidate 591F6B6

Status: Rejected and superseded

Date: 2026-08-22

## Reviewed Identity

```text
candidate commit: 591f6b6eefab2bd187868bcf47c9b77568e4c68f
candidate tree:   107ed0fe98092e518b6a9b26de311f28dba58286
source commit:    c5fda8ac490b1ef8fc667a60e9e122f8c34ca4cb
source tree:      782b71b0450146391faeb7329557c41573ca4380
```

The review was independent and read-only. It used no device, secret, signing
ceremony, external RPC, transaction, deployment, publication, or production
mutation.

## Findings

The exact candidate was rejected for these material gaps:

- restart accepted a modified or stale journal head because restore recomputed
  and discarded the supplied record hash and did not authenticate the complete
  hash chain or generation sequence;
- a receipt nonce pair was required to be internally consistent but was not
  bound to the operation nonce in the durable submission commit;
- the 29-test, 20-category claim exceeded literal coverage of every core-field
  and record substitution, the transition and crash matrix, lifecycle races,
  wrong-event/reentry behavior, and sanitized status output; and
- the constructor-storage inventory omitted `accountRuntimeCodeHash`, while the
  ABI inventory omitted the local V2 routine-signature registry record.

The review confirmed that all 29 focused cases and all 43 inherited focused
cases passed, all five artifact verifiers passed, each compiled artifact
compared all 75 compiler-input sources, and the candidate materially improved
durable flush ordering, raw-event verification, byte-exact logs, and
verifier-controlled outcome transitions. Those improvements were insufficient
for acceptance.

## Verdict

```text
REJECT_STEP_6C_1_DURABLE_EVIDENCE_SYNTHETIC_LOCAL_COMPOSITION_EXACT_CANDIDATE
```

Corrective source `13a7859e0c343df607885feffac605742c87b04f`, tree
`a1374c9e4b5e6f089b92400fcebae723a8dbe306`, supersedes this candidate and
requires a fresh independent exact-candidate review after its documentation
and artifacts are frozen.
