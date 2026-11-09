# Mutable data across GitOps adoption

The data profile runs signed application procedures on either side of a
customer-controlled source change. Argo CD retains ownership of application
resources. Cinderlock owns the procedure journal and acceptance gate; it never
writes Git, syncs Argo, or runs a second Helm deployment.

This is a preview profile. The model/stateless live qualification does not
qualify mutable data. See the [qualification record](qualification.md) for
actual execution evidence and its limits.

## Declare application procedures

The signed release names the mutable claim and the existing operation IDs
that stop writes, take a backup, and resume writes. For example, this fragment
belongs under `spec.deployment`:

```yaml
type: gitops
gitOps:
  owner: argocd
  revision: <full expected base commit>
  path: application.yaml
  data:
    pvc: application-data
    quiesce: stop-writes
    backup: backup-data
    resume: resume-writes
```

The named operations remain normal signed scripts with their existing
timeouts, resources, idempotency declarations, and capability requirements.
Their names do not prove database semantics. The vendor must implement and
test the write barrier, backup validation, schema preconditions, and restore.

The selected transition must place `stop-writes` before `backup-data`, other
pre-adoption mutations after that backup, and `resume-writes` after its single
`gitops` marker. Every authored operation must have an unambiguous dependency
path to that marker. Imports and fresh model preparation remain separate;
dedicated acceptance fixtures belong to the post-adoption run. Native Helm
and restart operations cannot serve as another application resource writer.
Use explicit application-owned procedures for supported operational effects.

An upgrade declares both `fromDataRevision` and `toDataRevision`. The
pre-adoption Site asserts the former; the post-adoption Site asserts the
latter. These are declared schema identifiers, not database measurements.
Both Sites retain the same selected backup reference.

## Bind the old source and the future release separately

Complete image staging and, when declared, fresh native model preparation for
the target bundle. Keep state, manifests, policies, keys, and output files
outside the source checkout. Preserve the previous accepted run and its exact
reviewed old manifest; a render of the new bundle cannot represent that old
source.

The pre-adoption plan observes the old accepted source using current authority
and independently checks the new reviewed render. Select the original external
data PVC UID explicitly:

```sh
cinderlock --state /private/state --cache /private/cache gitops data-plan release.cinder \
  --site /private/source-site.yaml --contract /private/old-source.json \
  --manifest /private/target.yaml --approved-manifest-digest "$TARGET_SHA256" \
  --previous-run "$ACCEPTED_RUN" --previous-manifest /private/old.yaml \
  --staging-run "$STAGING_RUN" --preparation-run "$PREPARATION_RUN" \
  --data-uid "$ORIGINAL_DATA_UID" --out /private/data-plan.json
```

Omit the preparation flag only when no application models are declared. Use
normal `run authorize` and `run apply` for the resulting exact plan. The Site
and independently admitted current policy must permit `gitops-data`,
`gitops-observe`, and the actual selected operation/check capabilities. A
release signature does not grant customer execution approval.

Successful preparation returns `awaiting_adoption` with application acceptance
`not_established`. It retains the active application gate and cluster journal.
It releases the request Lease so a later authorized successor can proceed.
Approval expiry, waiting, or a healthy controller cannot release that gate.
`run status --check` therefore does not report application success.

## Adopt the target, then run application acceptance

Adopt the reviewed target through the customer's source process. Supply a
fresh observation contract for the resulting accepted commit and the original
Application identity. Its observation window must cover reconciliation after
the data preparation completed. Update the Site's declared data revision to
the signed target revision, retaining the same data and backup identity.

```sh
cinderlock --state /private/state --cache /private/cache gitops data-checks-plan release.cinder \
  --site /private/target-site.yaml --contract /private/adopted-source.json \
  --manifest /private/target.yaml --predecessor-run "$DATA_RUN" \
  --out /private/data-checks-plan.json
```

Authorize and apply this new plan separately. The predecessor supplies exact
staging/preparation receipts and the original mutable claim. Completed facts
retain their bundle, target, namespace, worker, and result identities; their
old approvals and Secret bytes do not grant current authority. You may rotate
policy, approval keys, or credentials between phases, provided the new plan
satisfies current policy and dependency observations. Moving a registry route
does not establish a copy at its new address.

Before any successor worker starts, Cinderlock rechecks original terminal
workers and transfers the gate through its local transaction and cluster
journals under the application Lease. Resume repairs only that recorded exact
handoff. Missing original worker identities or predecessor history require
reconciliation; a name alone cannot establish completion.

The successor runs signed post-adoption procedures, fresh same-run fixtures,
model verification, and required application workflows. Only final successful
acceptance advances the release floor. Keep original Jobs, receiver Pods,
manifests, and PVCs available through subsequent handoffs.

An interrupted validation or unavailable original-worker read cannot establish
a changed deployment recipe. It blocks continuation as unverified evidence
with exit code `13`; fixture findings use `CHECK_FIXTURE_UNVERIFIED`. Inspect
the recorded workers and reconcile the same run before retrying. This does
not turn an interrupted attempt into a safe stop or establish acceptance.

For a first installation, use `data-checks-plan --initial-data` instead of a
predecessor. It requires explicit staging, applicable model preparation, and
the independently selected `--data-uid`. It cannot bypass an accepted release
on that target, including one accepted on another channel.

## Restore after a failed acceptance

A failed post-adoption attempt retains the gate. Select a separately signed
recovery with `gitOpsData` roles naming its quiesce and resume operations on
the same PVC. This profile preserves the original backup and requires a
same-source restore: the recovery's `toRelease` equals the selected bundle's
version and its declared data revision matches the recovery Site.

```sh
cinderlock --state /private/state --cache /private/cache gitops data-recovery-plan release.cinder \
  --site /private/recovery-site.yaml --contract /private/current-source.json \
  --manifest /private/target.yaml --source-run "$FAILED_RUN" \
  --recovery restore-data --out /private/data-recovery-plan.json
```

Authorize and execute recovery as its own run. It must include actual restore
procedures and required application checks. A successful `recovered` result can
be the next operational baseline; it leaves the original failed attempt and
its unaccepted result unchanged. A failed recovery retains the gate for
another explicitly authorized supported recovery or reconciliation.

Failure before source adoption, customer source reversion, and cross-source
restoration require separate reconciliation/profiles. Do not delete a journal
or recreate a worker to force the supported same-source path.

## Storage and observation limits

The supported data claim is externally provisioned, bound, filesystem-backed,
and ReadWriteOnce, without clone/restore data sources. Its original UID and
backing volume name, class, mode, and access settings remain pinned. This is
identity evidence, not a storage-content hash or backup certification.

The controller must remain healthy through application quiescence. Bounded
native-controller and Pod inventories reject unknown consumers, including
queued Jobs with no Pod. Reviewed Deployment ownership and volume mappings
must match; current application Pods retain their controller's container and
security recipe, apart from recognized scheduling defaults. Earlier recorded
data workers must be terminal. A current authorized worker keeps its original
UID and recipe.

These observations do not fence storage, exclude future writers, discover
arbitrary custom controllers, or qualify a production backup backend. The
profile does not establish NVIDIA compatibility, physical isolation, or
customer data recovery. The [model profile](gitops-execution.md) defines the
separate read-only model and dedicated fixture contracts.
