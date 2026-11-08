# GitOps delivery

The GitOps adapter keeps the external controller as the application owner.
Cinderlock can stage signed image graphs under a separately authorized plan.
Image staging doesn't reconcile application resources, execute application
scripts, run acceptance checks, or establish controller and data recovery.

Signed license declarations remain in the bundle. This technical image-copy
phase doesn't validate operational entitlement or infer distribution rights;
separate customer distribution policy remains explicit.

## Stage signed images

Use a verified release with `deployment.type: gitops` and a declared Flux or
Argo CD owner. Both the private Site and its independently admitted trust policy
must allow `gitops-stage` and `import`. Plain HTTP registries additionally need
the existing `registry-http` capability in both. Registry credentials and routes
remain customer-selected Site inputs.

Create and review the exact image-only plan, then use the normal authorization
and execution commands:

```sh
cinderlock gitops artifacts-plan release.cinder \
  --site /private/site.yaml --out artifacts-plan.json
cinderlock run authorize artifacts-plan.json \
  --key /private/customer-approval.key --key-id customer-approval \
  --out artifacts-authorization.json
cinderlock run apply artifacts-plan.json \
  --authorization artifacts-authorization.json
```

The plan derives its complete import list from the signed locked image assets.
Additional commands, checks, empty asset selectors, or application operations
cannot be added to it. Planning doesn't invoke Helm or inspect controller-owned
application resources. It binds the namespace/target identity, exact Site and
policy, and the relevant registry credential contents through a private keyed
fingerprint. Unrelated application Secrets and image-pull credentials aren't
used by the operator-side import.

Execution uses the existing durable intent journal, coordination, authorization
nonce, and OCI importer. Completion requires copying and verifying the complete
destination image graph. `artifacts_staged` ends this phase with application
acceptance `not_established`; it doesn't advance the accepted-release floor.
Reports and support summaries retain this distinction. `run status --check`
continues to require application acceptance and returns a nonzero result for a
staging-only run.

An interrupted transfer can require reconciliation. `run resume` repeats only
the exact digest-addressed import and verifies its destination graph before
recording completion. It doesn't infer success from upload metadata. A definite
stop ends as `artifacts_failed`; uncertain transfers retain the active gate.
Changed Site, policy, target, or credential bindings require investigation and a
fresh authorized plan where applicable.

The phase stages images only. GitOps model/data preparation isn't implemented;
it doesn't prepare model PVCs. Application workflows, controller hooks, resource
rollback, and data recovery require their own supported mechanisms and
qualification. The controller's ready status alone never supplies application
acceptance.

## Propose a local source change

You can prepare a private review artifact for an existing customer-controlled
Git repository. The proposal contains an inert patch and binds the exact bundle,
Site, trust policy, repository HEAD, original file, and reviewed desired-state
bytes. It doesn't apply the patch, create a commit, contact a remote, or claim
that images have already been staged.

For this bounded proposal profile, the signed `deployment.gitops.revision` must
be the exact expected base commit, and `deployment.gitops.path` must select the
existing tracked YAML file. The controller's revision labels remain valid for
the separate export and observation commands. Review the exported desired state
before passing its digest to the proposal command:

```sh
cinderlock gitops export release.cinder \
  --site /private/site.yaml --out /private/reviewed-desired.yaml
cinderlock --state /private/cinderlock-state gitops propose release.cinder \
  --site /private/site.yaml --repository /customer/configuration \
  --head "$REVIEWED_BASE_COMMIT" --path application.yaml \
  --manifest /private/reviewed-desired.yaml \
  --approved-manifest-digest "$REVIEWED_MANIFEST_SHA256" \
  --out /private/gitops-proposal.json
```

The selected file must match HEAD, index, and working bytes without executable
mode changes. Unrelated working files can remain dirty. The local Git executable
must support isolated read commands, SHA-1 or SHA-256 commits, and attribute
checks against a commit. Executable Git helpers, inherited Git configuration,
automatic object fetching, and external diff tools are disabled. The adapter
generates a complete-file text patch directly.

This profile accepts an embedded real `.git` directory and bounded UTF-8 YAML
files. It rejects symlinked paths, linked worktrees, alternate object stores,
configuration includes, and target attribute/filter/diff rules. The source and
desired file limits live in the [Git proposal adapter](../internal/engine/gitops_propose.go).
Preparation state, temporary files, and proposal output must remain outside the
repository; output parents must already exist. Proposal files are private and
cannot overwrite existing review artifacts.

Review and submit the patch through your normal source-control process. If HEAD
or the selected file changes, create and review a new proposal. Source review
doesn't authorize application execution or establish controller reconciliation,
workflow acceptance, hook behavior, or data recovery.

## Observe the controller and selected resources

The optional `argocd-directory-v1` profile reads an exact Argo CD Application,
its accepted source, and the reviewed live resources. It produces a private
`GitOpsProfileObservation` with original controller timestamps, source and target
identities, match facts, and blockers. `ready: true` establishes this bounded
observation contract; application acceptance remains `not_established`.

Use a customer-selected local repository at the accepted full commit. Its
selected file must match HEAD, index, working bytes, and the reviewed export.
Both Site and policy must allow `gitops-observe`. Select the existing
Application's namespace, name, and UID, the credential-free source URL, the
accepted commit and manifest digest, and an original reconcile/operation time
window in a private contract. The [contract type](../internal/spec/gitops.go)
owns its exact fields and limits.

The signed GitOps revision remains the proposal's expected base commit. Applying
the reviewed source change through customer procedure creates a separate
accepted commit, selected explicitly in the observation contract. Observation
binds that commit to the exact signed path and reviewed render without rebuilding
the vendor bundle. The raw observer's explicit revision argument keeps its
controller-label semantics; it doesn't supply this stronger source binding.

```sh
cinderlock --state /private/cinderlock-state gitops observe-profile \
  release.cinder --site /private/site.yaml \
  --contract /private/controller-contract.json \
  --manifest /private/reviewed-desired.yaml \
  --out /private/controller-observation.json
```

Argo's source path is a directory. This profile requires explicit directory
mode, an exact include for the signed YAML filename, and the reported effective
source type `Directory`. It rejects alternate generators, recursion, exclusions,
multi-source configuration, ignore rules, and repository source-override YAML.
Those overrides are read before the directory include filter. Source URLs are
compared without fetching and appear in the observation only as a digest.

The destination is the controller's in-cluster server and the selected Site
namespace. The Application object must reside in its observed controller's own
namespace; additional Application namespaces are unsupported. This preserves
the controller's plain-name tracking identity without aliasing an Application
of the same name in another namespace. Workloads still use the Site namespace.
The profile supports Deployment, ClusterIP Service, and ConfigMap
resources. It reads only the exact names in the reviewed manifest and requires
the controller's resource and completed-operation inventories to agree. It
checks supplied fields, known API defaults, Deployment rollout, Argo tracking
annotations and server-side-apply ownership, and unresolved hooks or competing
writers. Other managers' spec, data, or immutability claims block even when the
reviewed file omitted that defaulted field. Ordinary API defaults without those
claims remain supported. Unknown kinds, opaque lifecycle hooks, force
operations, and ambiguous facts stay blocked. This isn't a general proof that
no drift or other writer exists.

Deployment-controller status updates may also retain its revision annotation.
The profile admits that exact controller/path bookkeeping while continuing to
reject status claims over spec, data, tracking, or other metadata fields.

For Argo's explicit `appTree` health format, the observer requires aggregate
Application health and directly checks the live Deployment rollout. It keeps
missing inline resource health absent; it doesn't fetch or claim to read the
separate application tree. Inline health, when supplied, must still be healthy.
Unknown health formats block. The [pinned controller's health handling](https://github.com/argoproj/argo-cd/blob/94037c4d4e1af4bd0651d37a179fbd9e347e668c/controller/health.go)
defines that distinction.

An ordinary resource's apply result can retain `hookPhase: Running` after a
completed sync. That field alone isn't a hook: the profile still rejects hook
types, requires the overall operation to have succeeded, and reads actual live
resource readiness. Argo's [result-code mapping](https://github.com/argoproj/argo-cd/blob/94037c4d4e1af4bd0651d37a179fbd9e347e668c/gitops-engine/pkg/sync/sync_context.go)
defines this representation.

The pinned Helm tool reads the selected release's history before and after
observation. Active or uncertain history blocks this profile. Rendering uses a
frozen install context through the shared renderer and never reads active Helm
values. A templated `managed-by: Helm` label doesn't create Helm ownership;
release annotations, actual writer claims, and history remain relevant. The
explicit Argo/resource client makes GET requests only; Helm's selected history
read can use a storage list. No application mutation, hook, sync request, or
workflow check runs. Original controller times must still be fresh after the
final reads; a new local receipt time never refreshes them.

An optional reversion reference compares selected historical commits with the
accepted clean file. It can observe an exact reset or a later commit restoring
the reviewed bytes while unrelated files remain changed. This establishes one
tracked file's bytes, without applying a patch or establishing whole-tree
reversion, controller rollback, application-data recovery, or workflow success.

The adapter is grounded in the pinned Argo
[API definitions](https://github.com/argoproj/argo-cd/blob/94037c4d4e1af4bd0651d37a179fbd9e347e668c/pkg/apis/application/v1alpha1/types.go),
[source generation](https://github.com/argoproj/argo-cd/blob/94037c4d4e1af4bd0651d37a179fbd9e347e668c/reposerver/repository/repository.go),
and [resource tracking](https://github.com/argoproj/argo-cd/blob/94037c4d4e1af4bd0651d37a179fbd9e347e668c/docs/user-guide/resource_tracking.md).
Fake API fixtures verify inspection, denial, and redaction behavior; temporary
Git repositories verify file and history handling. The
[qualification record](qualification.md) separately records the completed
bounded Argo v3.6.1 live observation. Use the
[Argo directory input guide](argocd-qualification.md) to prepare a fresh lab.
Model/data preparation, independently authorized application workflows, and
broader controller/version qualification remain open.
