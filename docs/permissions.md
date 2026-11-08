# Permission planning

Cinderlock checks the selected Kubernetes identity before execution. A plan's
permission findings identify the API group, resource, verb, namespace, and known
object name. They help an operator correct a missing grant without giving the
tool cluster administrator access.

## Authorization boundary

The preflight uses Kubernetes
[SelfSubjectAccessReview](https://kubernetes.io/docs/reference/kubernetes-api/definitions/self-subject-access-review-v1-authorization/).
These are nonpersistent authorization requests. Planning sends them with `POST`
because that is the Kubernetes API contract; it does not create application
resources or reserve capacity. The optional admission check below is separate.

A denial, an unavailable API, no authorizer opinion, or an evaluation error blocks
the plan. Raw server diagnostic text does not enter the findings. An allowed
result records permission at the time of the query. Execution must still handle
later denial and reconcile any effect whose outcome becomes uncertain.

The identity is the one in the explicit Site kubeconfig, shared by the Kubernetes
client and the pinned Helm executable. This is not a check of an application's
service account. Cinderlock operation Jobs have automatic API token mounting
disabled. Applications that require Kubernetes API access need their own
deployment profile and functional checks.

## Scope

The requirement model lives in
[permissions.go](../internal/engine/permissions.go). It combines the fixed
observer and coordination requests with requests needed by the chosen
operations and acceptance Jobs. Named resources use their names where they are
known. Creation and generated run objects require namespace resource access;
their final names are unavailable while the plan is being prepared.

Helm requirements come from the rendered namespaced object inventory. Upgrades
also inspect the installed Helm manifest so permission to delete a removed
object is checked. Retained data objects do not request deletion. The Helm
envelope includes creation, patching, status reads, watches, and release-history
storage as appropriate to the transition. It is conservative across the
supported Helm execution path; it is not a generated minimal RBAC role.

Malformed inventories, unknown API versions, cluster resource kinds, and
cross-namespace object references block permission planning. The normal
namespace identity lookup and a GPU profile's named node lookup are explicit
read-only exceptions to namespaced application requests.

## Limits

Authorization checks cannot prove that admission policies, resource quotas,
schedulers, storage provisioners, image pull credentials, or future permission
changes will permit the operation. RBAC role escalation and binding restrictions
are admission-time constraints beyond this tuple preflight. A service account's
future access and an application's external dependencies are also outside this
check.

An allowed authorization result is not an accepted deployment. Required
application workflows remain the acceptance gate.

## Optional server admission check

Set `Site.spec.admissionDryRun: true` and allow `admission-dry-run` in both the
Site and its independently admitted TrustPolicy. Planning then submits the
bounded Helm resource inventory with `dryRun=All`. Configured admission webhooks
can execute, so this capability must be deliberately enabled. No submitted
application object is persisted by the preflight.

New objects use create dry-run. Existing objects must belong to the selected
Helm release and have an original manifest for a three-way update dry-run.
Ambiguous identities, unsupported resource kinds, rejection, unavailable
responses, and interruption block the plan. Findings retain categorical results
without copying raw server diagnostics or submitted values.

This checks the submitted Helm objects at one point in time. It does not cover
controller-created Pods, helper Jobs, workload service-account access, future
admission decisions, or allocation of real resources. Disabled admission checks
produce an explicit untested finding. The execution API still enforces its own
authorization and admission decisions.

Native model streaming additionally requires namespaced Pod reads and
`create` on `pods/attach`; it does not request `pods/exec`. See
[native model staging](native-model-staging.md) for its recipient trust boundary.
