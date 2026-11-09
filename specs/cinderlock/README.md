# Cinderlock implementation

Cinderlock is the Go release engine for customer-operated offline delivery,
application acceptance, upgrades, and explicit recovery. The bounded mechanisms
in the [feature audit](../../docs/features.md) are implemented. Qualification
applies only to the source, environment, and workflows named in the
[qualification record](../../docs/qualification.md).

## Next Agent Prompt

Check the current publication's [Check workflow](../../.github/workflows/check.yml)
through completion and address any failure before expanding support. Local
checks and the persistent GitOps workflow for `1587928` passed. If publication
checks are green, the next qualification is the user's deferred NVIDIA cluster;
do not ask for that hardware again, rent an instance, or substitute CPU results.

Use the existing separately authorized GPU probe, pinned artifacts, target-bound
plan, application workflows, and recovery path when that cluster is available.
Keep real inference, GPU allocation, and production restore unqualified until
actual receipts establish their scope. The current synthetic app is a lexical
retriever with SQLite, not an LLM.

The private retained records for the latest work are:

| Source and scope | Private records |
| --- | --- |
| `cac2e73`: GitOps persistent install, upgrade, and actual document-loss failure | `.local/argocd-workflow/q011/`, `.local/gitops-qualified-cac2e73/` |
| `1587928`: separately authorized same-source restore; original result, worker/receiver/claim readback, current authority, and accepted-floor checks | `.local/argocd-workflow/q011/`, `.local/gitops-recovery-qualified-1587928/` |
| `ff656b5`: actual-journal CLI and catalog HTTP comparisons, policy controls, and local waiting notice | `.local/catalog-qualified-ff656b5/` |
| `91b3ca5`: completed hosted native CPU install/upgrade/failure/recovery and verified artifact | `.local/hosted-ci-42612272505/` |

Earlier native, model/stateless, controller-denial, interrupted-run and rejected
input records stay unchanged. Detailed results and limits belong in the
qualification record rather than another handoff timeline. A frozen earlier
binary never qualifies a later source automatically.

The next contributor must preserve original workers, receiver Pods, volume and
manifest identities, source contracts, failed result bytes, and all rejected
attempts. Short-lived credentials can rotate only through fresh current bindings,
plans, and authorization; historical evidence never grants current permission.
Never rerun a completed private harness blindly or edit its signed inputs to
force a pass.

Every Kubernetes/Helm invocation must select its kubeconfig and context explicitly.
Use only the independently owned disposable lab; never the workstation's default
production context. Local credentials, keys, state, images, scripts, and receipts
stay in ignored `.local/`. Do not publish them.

## Delivery status

The implementation includes trusted input and artifact delivery, target inspection,
controlled execution and recovery, the reference transition, local evidence and
catalog, and the listed bounded extensions. Source and licenses remain in their
existing owners; no second deployment engine or shadow schema is introduced.

- [x] Verify native CPU install, upgrade, required workflows, actual failure, and recovery.
- [x] Verify GitOps staging, model preparation, independent source adoption, persistent upgrade, failure, and separate restore through the public CLI.
- [x] Exercise recorded GitOps subjects, comparisons, restrictive policy, and local notices through CLI/HTTP entry points.
- [x] Reconcile the original feature list with code, tests, and explicit qualification limits.
- [x] Review shape, error/retry boundaries, decisions, reports, and source hygiene.
- [x] Verify source/vendor/Go/Helm/legal distribution and offline compilation for the named source.
- [ ] Qualify NVIDIA inference and allocation when the user provides the cluster.
- [ ] Close/archive the qualification work after the remaining applicable profile gates are resolved.

Hosted checks remain authoritative for their exact commit. Follow the current
run after publication; an older green run cannot establish that a changed tree
passed. Preserve failures, skips, and unavailable capabilities as evidence.

## Invariants

A bundle key cannot authorize itself. A release signature cannot grant customer
execution approval. Plans bind signed recipes, policy, Site source bytes, target,
and starting state. New work rechecks current authority at its actual boundary.
A timeout is not proof that a migration did not commit. Lease expiry is not
fencing, and a canceled read cannot establish changed target facts.

Missing required workflows never pass. Waiting for customer source adoption
retains the active application gate. A successor uses an exact recorded handoff;
unknown consumers or lost original identities require reconciliation. Recovery
of a prior state is distinct from acceptance of the failed attempt. Retaining
an object UID does not prove intact data, secure erasure, or storage isolation.

The external controller owns desired state. Cinderlock stages artifacts, proposes
inert source changes, and executes separately authorized procedures and tests.
It does not silently commit, sync, or become a second Helm writer. Read-only
model provenance and mutable-data procedures retain their separate contracts.

Shared contracts live in `internal/spec`; producers, verifiers, CLI, tests, and
docs change together. The [mutable-data rationale](mutable-gitops.md) and
[decisions ledger](decisions.md) retain the choices behind those boundaries.
