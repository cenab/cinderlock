# Cinderlock implementation

Build the open-source Go release engine described by the product design, with
customer-controlled offline delivery, target-bound plans, application acceptance,
and explicit recovery. Cinderlock owns these contracts; Zarf is a comparison
baseline, not the executor. The current request authorizes implementation of the
whole feature set. It does not establish a customer pilot or hardware support.

## Next Agent Prompt

Finish F39's incomplete mechanisms in the [feature audit](../../docs/features.md)
using the normal intent, worker, coordination, approval and recovery owners:

1. Complete native fresh-volume preparation and separately authorized
   accepted-source checks. Before landing, pin/fix effective read-only mount
   semantics, queued writers without Pods, and source freshness after dependency
   reads. Preserve same-run fixture proof and original cross-run model evidence.
2. Implement mutable data procedures before and after independent source
   adoption, plus separately authorized restoration. Describe the durable gate
   and exact predecessor transfer before coding this slice. Model preparation
   and healthy controller status cannot substitute for these mechanisms.
3. Exercise the resulting public CLI in the owned lab, finish the combined
   release gates and feature documentation, then publish. Keep failed upgrade
   acceptance separate from successful recovery and retain original identities.

| Source | Completed evidence and boundary | Private records |
| --- | --- | --- |
| `0a73b09` | Hosted core Go and CPU transition/recovery baseline passed. | `.local/hosted-ci-42455956767/` |
| `8db0077` | Native CPU install, explicitly resumed upgrade, actual document loss and separate restore passed; endpoint/numeric Jobs included. All 18 original upgrade Jobs and eight volume/manifest bindings survived resume. | `.local/qualification-005/` |
| `f8bf623` | Real Argo v3.6.1 source/resource/SSA observation, five denial controls and restored original UIDs passed. Application acceptance remains unestablished. | `.local/argocd-profile/` |
| `34937f5` | Fresh unit/race/vet, actual PostgreSQL, source scan, static Linux builds, full source/toolchain/Helm/legal export and offline compilation passed. Binaries were not run by build checks. | `.local/distribution-34937f5/` |
| Published `edee42d` | Same Go code plus documentation. Hosted run 42468205931 passed its Go job; CPU Kubernetes job remains in progress. | `.local/hosted-ci-42468205931/` |

The [qualification record](../../docs/qualification.md) owns detailed limits.
Prerequisite duplication was removed while retaining actual-start, post-wait
and final guards; no matched live speedup is claimed. Source size audit lists
zero files over 8,000 tokens, without a hook or added dependency.

The private q007 persistent input draft retains every original procedure and
has no live effects. It awaits the actual data contracts. An optional model
mount in the existing stateless Argo chart can qualify the earlier preparation
slice separately. Recheck the frozen `8db0077` helper protocol against the final
execution CLI before reuse; original q006 and native005 artifacts stay unchanged.
The user will supply NVIDIA hardware later; keep that qualification open.

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
