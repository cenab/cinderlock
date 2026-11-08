# Cinderlock implementation

Build the open-source Go release engine described by the product design, with
customer-controlled offline delivery, target-bound plans, application acceptance,
and explicit recovery. Cinderlock owns these contracts; Zarf is a comparison
baseline, not the executor. The current request authorizes implementation of the
whole feature set. It does not establish a customer pilot or hardware support.

## Next Agent Prompt

Continue the incomplete mechanisms listed in the
[feature audit](../../docs/features.md); a passing reference workflow isn't
completion of the broader product. The current native-streaming CPU lab passed
install, model and fixture verification, schema upgrade, persistence, actual
missing-document failure, and separate synthetic restore. It also exercised
configuration ownership, storage budgets, custody-head replay rejection, signed
policy updates, server admission dry-runs, and the patched Helm toolchain.
See the [qualification record](../../docs/qualification.md) for the evidence
boundary. Local receipts remain private under `.local/qualification-004/`.

Published core at `7d81f2e` passed hosted Go and real Kubernetes install, upgrade,
failure and recovery CI. Numeric observations, script/entitlement contracts, inventory/ownership, policy
packs, runtime evidence and GitOps image staging/source proposals are now merged
locally. Requalify the combined tree; the published baseline does not cover
these changes. Endpoint preflight, CPU observation integration tests and a bounded
Argo controller observer are in progress. Authored worker resource budgets and
GitOps model preparation/check execution follow.
Keep new slices separate from the recorded baseline. Experimental journals
without original worker/volume identities cannot serve as resume evidence.

The user will supply NVIDIA test hardware later. Keep GPU qualification open;
continue all CPU, artifact, permission, security, catalog, and distribution work.

Use explicit kubeconfig/context paths on every Kubernetes/Helm invocation.
Never use the workstation's default production context. Temporary credentials,
clusters, registry data, prompts, and test receipts belong in ignored `.local/`.
Do not publish them. Shared contracts live in `internal/spec`; change their
producers, verifiers, CLI, tests, and docs together. Update this handoff before
ending an implementation pass or context handoff.

## Slice graph and global work

Each slice owns a verifiable contract. Most implementation is already present;
the remaining unchecked work is a release gate, not permission to stop.

| Slice | Seam and runnable evidence | State |
| --- | --- | --- |
| 01: trusted input | `internal/spec`; strict contracts, canonical bytes, exact field names, required application checks | Merged strict script/prerequisite and observation contracts pass local checks |
| 02: artifact delivery | `internal/bundle`, `internal/transfer`; signed closure, OCI, multipart, differential, inventory and cache references | Core delivery passes; new GitOps image-staging/proposal package checks pass |
| 03: target and plans | `internal/engine`; identity/configuration bindings, permission, admission, and unsupported-state findings | Unit/fault and real CLI integration pass for the recorded CPU profile |
| 04: controlled execution | `internal/state`, `internal/engine`; intent, coordination, reconciliation, upgrades/recovery | Unit/fault tests and live synthetic upgrade/recovery pass; broader interruption/storage qualification remains |
| 05: reference transition | `examples/document-qa`; synthetic HTTP/SQLite ingestion, persistence, migration and restore | App/chart tests and real kind transition pass |
| 06: local evidence/catalog | `internal/report`, `internal/support`, `internal/catalog`; scoped evidence and organization service | SQLite/PostgreSQL, OIDC, scope, CLI/API, and visual checks pass; remaining policy/integration scope is explicit |
| 07: extensions | CLI/API seams for GPU probes, GitOps, retirement, groups, source admission and CI | Implemented subsets have tests; remaining mechanisms and profile qualification stay open |
| 08: release quality | Docs, notices, shape, offline build, scanning, distribution and whole-tree checks | Published core and hosted CI pass; combined new feature qualification remains |

Follow dependency order: 01 → 02 → 03 → 04 → 05; 06 can progress independently
after 01. Complete 07 against the established seams, then 08 against the complete
tree. Re-slice a failing contract before broadening an implementation patch.

- [x] Run the real baseline/install → upgrade → required workflows → recovery.
- [ ] Wire and test every implemented extension through its public CLI/API.
- [x] Reconcile every original feature with code, proof, and qualification limits.
- [x] Review shape, diff, tests, performance, decisions, and user-visible reports.
- [x] Inspect real screenshots; retain honest comparison/critique evidence.
- [ ] Finish documentation, dependency notices, CI and clean offline builds.
- [ ] Inspect the final tracked tree; no local secrets or disposable artifacts.
- [ ] Commit clean passes and publish only the intended source/distribution.
- [ ] Close/archive this spec only when no implementation or applicable gate remains.

## Invariants

A bundle key cannot authorize itself. A release signature cannot grant customer
execution approval. A plan binds the signed recipe, policy, site source bytes,
target and starting state; edits require a new plan. A timeout is not proof that
a migration did not commit. Lease expiry is not fencing. Missing required
workflows never pass. Recovery of a previous state is not success of the failed
upgrade. Resource retention is not proof of data recovery or secure erasure.

The reference application is deliberately synthetic. CPU/kind checks cannot
qualify NVIDIA inference, GPU sharing, physical isolation, or a customer's
production data. Preserve those distinctions in code, reports, and documentation.
Unimplemented operations must fail explicitly; do not add no-op success paths.

## Verification and visual gates

Run focused behavior tests first, then the merged tree's unit/race/vet and live
integration gates. Pin failing behavior before a fix and retain the regression.
Never weaken a gate merely to obtain green output. Use real CLI/HTTP entry points
where possible; adapters/fake clients isolate uncertainty rather than simulate
a successful deployment.

For report/catalog visual work, inspect the actual rendered route with synthetic
data. Run screenshot-critique after the final screenshot. When changing an
existing visual surface, save its real baseline first, run compare-screenshots
on matched framing, and explain any intentional difference. A generated concept
or nonblank screenshot is not proof of a working application or accessibility.

The decisions ledger belongs in [decisions.md](decisions.md). Keep technical
choices and unresolved customer-specific defaults separate from test receipts.
No user, operator, or customer approval is implied by a recorded recommendation.
