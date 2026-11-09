# Authorized GitOps preparation and application checks

The [GitOps delivery profile](gitops.md) keeps Argo CD as the sole application
resource owner. Two optional plans use the normal authorization, journal,
coordination and worker paths to prepare fresh model volumes and run authored
application checks. Neither plan writes Git, syncs Argo, invokes a Helm writer,
or adopts resources from another owner.

This profile implements stateless applications with optional prepared model
claims. Mutable application data, pre-adoption quiesce/backup/migration,
post-adoption resume-writes and synthetic restore remain unimplemented. Releases
containing those procedures are rejected by this profile; retaining their
declarations does not make them executable here. Source-file reversion evidence
does not supply application or data recovery.

## Select the signed recipes

Use a signed GitOps release with an Argo owner, a full expected base commit A,
and the exact tracked YAML path. The bounded `argocd-directory-v1` source,
resource, ownership and health contract remains required for application
checks. Flux and alternate generators need another qualified profile.

The release may contain image imports, a GitOps source marker and empty-command
native seeds. Seeds referenced by `Check.fixtures` are dedicated acceptance
material. Other seeds prepare application model artifacts. Each selected seed
needs a distinct fresh revision PVC, locked non-image file manifest, positive
storage capacity and a supported mount/subpath. Authored seed commands and
other application operations are rejected. Dependencies must be covered by the
selected phase or the exact completed staging/preparation receipts.

Dedicated acceptance fixtures are seeded in the application-check run. They
cannot reuse the earlier model preparation as same-run fixture provenance and
cannot be referenced by the reviewed application inventory. Both models and
fixtures reject pending unknown native controller/Job consumers, including Jobs
that have not created a Pod. The bounded census covers Deployment, StatefulSet,
DaemonSet, ReplicaSet, Job, CronJob, ReplicationController and PodTemplate in the
target namespace. It is a current observation, not a future-writer exclusion or
general discovery of custom controllers.

## Prepare fresh model revisions at A

First complete the separately authorized image-only staging plan. Keep the
local checkout at the clean signed base A while preparing models. Store the
reviewed manifest, bundle cache, state, temporary files, Site, policy, outputs
and executable renderer outside the source repository.

```sh
cinderlock --state /private/state gitops prepare-plan release.cinder \
  --site /private/site.yaml --repository /customer/source \
  --manifest /private/reviewed-desired.yaml \
  --approved-manifest-digest "$REVIEWED_MANIFEST_SHA256" \
  --staging-run "$STAGING_RUN_ID" --out /private/prepare-plan.json
cinderlock --state /private/state run authorize /private/prepare-plan.json \
  --key /private/customer-approval.key --key-id customer-approval \
  --out /private/prepare-authorization.json
cinderlock --state /private/state run apply /private/prepare-plan.json \
  --authorization /private/prepare-authorization.json
```

Both Site and its independently admitted trust policy must allow `seed` and
`gitops-prepare`.
The fixed helper image must be locked in the bundle and selected by its exact
digest in the Site. Existing native storage, capacity, authorization and worker
budgets apply. This materialization phase runs no authored checks or entitlement
Job; declared endpoint and entitlement prerequisites run in the later application
check phase. The profile does not infer licensing or distribution permission.

Preparation uses the reviewed frozen install render and checks selected Helm
history absence before rendering. It never reads active Helm values. Only a
recorded active exact-plan run can explain a destination PVC that appeared
after planning. The native receiver transfers the signed regular files, then
the existing read-only verifier checks them. Completion binds the original seed
intent, receiver Job and Pod, verifier Job, PVC UID and immutable manifest UID.
Annotations alone cannot supply provenance. A fresh execution boundary runs
after a transfer and immediately before creating its verifier. If authority or
source changed during the transfer, the seed retains its unresolved gate until
the original receiver and a newly authorized verification can be reconciled.

`gitops_prepared` is terminal and inactive, with application acceptance
`not_established`. It does not advance the accepted-release floor. A definite
preparation failure ends as `gitops_prepare_failed`; uncertain worker outcomes
retain the active gate and require reconciliation. Normal `run resume` retains
original workers and does not create a duplicate from a missing name or UID.
`run status --check` returns a nonzero result for preparation-only completion.

## Adopt C independently, then authorize application checks

Create an inert proposal through `gitops propose`, review it and adopt it through
the customer's source-control procedure. This produces accepted commit C,
which may differ from A without rebuilding the vendor bundle. Supply C, the
exact reviewed manifest digest, original Application UID, source URL and
original reconcile/operation time bounds in a private observation contract.
No saved `ready` boolean authorizes execution.

```sh
cinderlock --state /private/state gitops checks-plan release.cinder \
  --site /private/site.yaml --manifest /private/reviewed-desired.yaml \
  --contract /private/controller-contract.json \
  --staging-run "$STAGING_RUN_ID" \
  --preparation-run "$PREPARATION_RUN_ID" --out /private/checks-plan.json
cinderlock --state /private/state run authorize /private/checks-plan.json \
  --key /private/customer-approval.key --key-id customer-approval \
  --out /private/checks-authorization.json
cinderlock --state /private/state run apply /private/checks-plan.json \
  --authorization /private/checks-authorization.json
```

Omit `--preparation-run` only when the signed release has no application model
seeds and the reviewed application has no PVC dependency. Both Site and policy
must allow `gitops-check`, `gitops-observe`, `job`, any dedicated fixture `seed`,
and the ordinary endpoint capabilities. Each phase needs a fresh exact-plan
authorization with independently admitted approval authority and nonce. The
displayed and signed action scope uses the same capability derivation as
execution. Authorizing a saved phase rechecks its current bindings. The accepted
release-sequence floor is checked during planning and at execution boundaries;
older checks cannot establish a new acceptance after a newer release passed.

The optional `Plan.gitops` body retains the reviewed manifest path, exact staging
reference and, when needed, preparation reference. Each reference contains
`runID`, `planDigest` and `resultDigest`; the CLI resolves those digests from
the original local journal. Preparation retains the base repository. Checks
retain the accepted-source contract. Historical receipts must match this exact
bundle, target, Site and policy. This harmless preparation profile deliberately
does not carry receipts across bundle, Site or policy changes.

An application model volume must map to a declared prepared asset and exact
native subpath. Empty subpath means the prepared PVC root. Every container
mount must explicitly be read-only; omission of the PVC source's `readOnly`
flag does not override an explicit read-only container mount. Devices, init or
ephemeral consumers, shadowed mounts and unknown writable consumers block.
Original preparation workers remain distinguishable from current reviewed
Deployment/ReplicaSet/Pod ownership. The original writer must remain terminal.
This does not make the storage immutable against administrators, other nodes
or future writers.

Checks perform one fixed read-only model verification before authored workflows
and one after the last workflow, with separate durable original worker
identities. They do not rehash large models for every authored check. Those
scans establish bytes at observed points, with intervening live read-only mount,
identity and consumer guards; they are not a promise of future content
immutability. Dedicated fixtures keep their existing fresh per-check verifier
and same-run provenance contract.

Each execution boundary rechecks current authority, exact target, selected
Secrets, source/controller readiness, stable resource UIDs, model provenance
and current consumers. Fixed verifier creation has its own fresh boundary after
preparation reads. A final strong source/resource observation follows
dependency reads, and the full boundary runs after the final workflow/model
verification before release acceptance. Controller resourceVersion or status
bookkeeping alone does not change the stable identity binding. Original Argo
timestamps must still be fresh; local read time cannot refresh them.

Reviewed ConfigMaps remain part of exact controller inventory. External
ConfigMaps and unsupported volume dependencies block. Critical Secret uses need
explicit Site name/key or whole-Secret scope and are bound through private
keyed fingerprints over UID, type and selected data. Reports never retain the
values. Workload ServiceAccount/token settings are disclosed; their API grants
remain advisory unless an authored workflow declares and checks that access.

The original staging receipt proves the completed graph copy and verification
then. Every phase checks current addressed root/closure availability and
metadata; initial apply also performs a full current graph byte verification.
Subsequent boundaries do not stream every image again. Live workload and worker
images must retain exact locked digests. Controller status does not prove fresh
source reachability, the controller's network route, a cache miss or a new-node
pull. Required endpoint prerequisites attest only their own selected worker
route, credentials and CA under current authority.

The public Go constructors and CLI use the existing plan and run APIs. Tests
exercise a real loopback registry, temporary Git A-to-C adoption, native file
transfer/verifiers, durable SQLite journal and fake Kubernetes/Argo clients.
They establish the tested safety contracts, not live controller reconciliation,
Pod attachment, model storage performance or full application/data recovery.
Live qualification requires explicit disposable inputs and separate receipts.
