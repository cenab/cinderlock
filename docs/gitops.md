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
