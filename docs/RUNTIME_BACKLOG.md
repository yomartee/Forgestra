# Production-runtime implementation backlog

The production factory remains unfinished. The experimental CLI/stdio candidate is
an intermediate option, not a substitute for the original approved-change workflow.
These workstreams are NOT_IMPLEMENTED; no permanent server is assumed.

## R1 — trusted approval boundary

Next bounded task: design and implement one local operator-owned approval authority
outside model/target control, for the authored one-file Python repair workflow only.
Bind target identity, input source SHA, complete diff/plan hash, policy version,
required checks, expiry and cancellation. Material changes invalidate approval.
Test unauthorized actors, replays, expiry, cancellation, protected files and changed
bytes. Keep CLI repair blocked: R1 alone cannot enable execution or publication.
No editable boolean, target file, JSON receipt or model output substitutes for trust.

## R2 — one OS-isolated execution backend

After separate scope approval, choose one supported backend with enforceable
filesystem/process/network/resource boundaries, zero publisher credentials and
adversarial escape, timeout, cancellation and cleanup tests. Do not fall back to
arbitrary host subprocess execution. Record actual enforcement and recovery limits.

## R3 — separate remote publisher

Consume authenticated, immutable approved/tested receipts; verify target, full
commit/tree/diff, expiry and policy. Use least privilege, idempotency, bounded writes,
reconciliation for uncertain outcomes and tested PR check triggering. Offline tests
are not live acceptance. Keep publisher and auto-merge disabled until authorized.

## R4 — factory-driven live acceptance

Only after R1–R3 and explicit disposable-target authorization: request -> inspection
-> trusted approval -> isolated change/tests -> one real PR -> checks at intended SHA
-> human review, including denial/duplicate/failure/cancellation/recovery cases.
A manual human PR does not prove factory acceptance. Generated Hasura/OIDC/container
and fleet operations need separately scoped later acceptance. No task here deploys,
pushes, publishes, creates resources, calls providers or enables legacy automation.
