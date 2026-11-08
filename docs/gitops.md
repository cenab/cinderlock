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

The phase stages images only. Bundled models, data volumes, controller hooks,
application workflows, source reversion, and data recovery require their own
supported delivery and qualification procedures. The controller's ready status
alone never supplies application acceptance.

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
