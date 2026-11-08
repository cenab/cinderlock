# Kubernetes and state implementation sources

The engine uses the official Kubernetes Go client and the existing Helm command
interface. The local journal uses `database/sql` and the CGo-free SQLite driver.
Dependency versions and checksums are pinned in `go.mod` and `go.sum`.

| Source | Reused API or example pattern | License |
| --- | --- | --- |
| [client-go out-of-cluster example](https://github.com/kubernetes/client-go/blob/v0.35.0/examples/out-of-cluster-client-configuration/main.go) | Explicit kubeconfig loading, REST configuration, typed clients | Apache-2.0 |
| [client-go configuration helpers](https://github.com/kubernetes/client-go/blob/v0.35.0/tools/clientcmd/api/helpers.go) and [configuration loader](https://github.com/kubernetes/client-go/blob/v0.35.0/tools/clientcmd/loader.go) | `MinifyConfig`, `FlattenConfig`, `Load`, and `Write` for a selected self-contained Kubernetes configuration; implementations imported as dependencies | Apache-2.0 |
| [client-go fake client example](https://github.com/kubernetes/client-go/tree/v0.35.0/examples/fake-client) | Fake typed clients for failure and no-mutation tests | Apache-2.0 |
| [client-go remotecommand SPDY executor](https://github.com/kubernetes/client-go/blob/v0.35.0/tools/remotecommand/spdy.go) and [SPDY transport](https://github.com/kubernetes/client-go/blob/v0.35.0/transport/spdy/spdy.go) | Native model stdin attachment with `RoundTripperFor`, `NewSPDYExecutorRejectRedirects`, and `StreamWithContext`; official implementations imported as dependencies, not copied | Apache-2.0 |
| [Kubernetes Job API](https://github.com/kubernetes/api/blob/v0.35.0/batch/v1/types.go) | Bounded Jobs, terminal conditions, labels and deadlines | Apache-2.0 |
| [NVIDIA System Management Interface](https://docs.nvidia.com/deploy/nvidia-smi/index.html) | Fixed read-only GPU CSV query for UUID, model, physical memory, driver and MIG mode | NVIDIA documentation; executable remains a declared image dependency |
| [Go database/sql](https://pkg.go.dev/database/sql) | Parameterized SQL and transactional journal updates | BSD-3-Clause |
| [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite@v1.36.3) | SQLite driver implementation | See dependency license in the source distribution |

The engine adds release-specific policy, exact recipe binding, data-scope
authorization, dual intent records, checkpoint drift detection, and conservative
uncertainty handling around these APIs. Neither a Kubernetes Lease nor a Job is
treated as an exactly-once data transaction.

## Current execution boundary

The mutating adapter executes supported namespaced Helm operations and staged
Jobs on an explicitly selected cluster. GPU model/memory/driver requirements
need a separately authorized probe plan, a locked image containing
`/usr/bin/nvidia-smi`, and explicitly selected node and GPU capacity. Planning
does not create a probe Job. Its evidence binds the target, original Job/Pod and
node identities, bundle/profile, server completion time and bounded original
logs; subsequent planning revalidates those observations. MIG and known shared
device modes are outside the initial full-GPU profile. Physical memory is not
free memory or proof of exclusive allocation; actual inference and platform
qualification remain required. Probe scheduling needs available GPU capacity.

Each Kubernetes client captures one selected configuration at construction.
Client-go and Helm consume the same minified, flattened snapshot, including the
approved CA, client certificate, key, and token bytes. Later changes to the
original kubeconfig or referenced files cannot redirect Helm or introduce a
credential plugin. The original context name, explicit namespace, TLS server
name, and compression setting remain bound. Helm receives a new private mode
0600 copy for each subprocess; that working directory is removed afterward.

Configuration and referenced credentials must be bounded regular files without
group or world writes. Leaf symlinks, pipes, devices, and oversized inputs are
rejected. Token files become static captured tokens; combining an inline token
with a rotating token file is unsupported. Credential rotation requires a new
client construction and the usual plan and target checks. System certificate
roots remain the host trust source when no explicit CA is configured. This
capture does not qualify host administrators or the system trust store.

The supported API route is direct. Client-go ignores environment proxy settings,
matching Helm's controlled subprocess environment. Explicit kubeconfig proxy
routes remain unsupported without a separately qualified profile.

A generic Helm downgrade is blocked
until its prior chart and values have a supported adapter; declared Job-based
forward repair and restoration procedures have separate recovery plans.

At each safe boundary the engine rereads the admitted policy and original Site
file, checks their exact bindings, and verifies the expected semantic state.
Own confirmed resource changes advance a durable checkpoint; ordinary resource
status changes do not count as drift. Required secret references must be
available, and raw credential values are not written into the run journal.

Missing or conflicting journals, unknown in-flight operations, active competing
GitOps ownership, expired leases, and unobservable prior workers prevent new
mutations. An expired lease is not automatically taken over. A customer must
establish quiescence before manually releasing a stranded coordination Lease.
Application tests and recovery data semantics remain supplied by the release
author and must be qualified for the selected application.

## Model materialization and retirement

Model publication uses a separate PVC for each declared revision. A vendor copy
command remains supported. An empty seed `command` selects
[native model staging](native-model-staging.md), which streams signed bundle
files through the Kubernetes API without a model carrier image. Neither receiver
nor vendor copy Job completion completes the seed operation. A second fixed Cinderlock
helper Job mounts that PVC read-only and checks every regular file against the
signed manifest's SHA-256 and size. Missing files, additional files or directories,
and symlinks fail verification. The manifest is an immutable ConfigMap created
from verified bundle records. The supported manifest size is 512 KiB; larger
manifests block planning. The helper image must be a locked asset containing the
matching Cinderlock executable. Native staging additionally requires the customer
Site to admit its exact manifest digest independently of the vendor release key.
This assumes a trusted cluster and helper image,
and a quiescent publisher; it is not storage-snapshot consistency or malicious
vendor attestation. Actual model verification on a live PVC still needs an
integration run; fake-client tests do not qualify storage or API transport.

An optional confined `modelSubPath` selects an application-owned directory inside
the PVC. This supports filesystems with housekeeping directories outside the
model tree. The release's copy command and application mount must use the same
directory explicitly; the verifier never silently excludes unlisted files.

The retirement adapter generates a separately approved `RetirementPlan` from
the installed Helm manifest. PVCs, Secrets and ConfigMaps need explicit Helm
retention annotations. StatefulSet volume deletion policies, garbage-collection
owners, kept workloads and opaque Pod lifecycle hooks can block retirement.
Execution disables Helm hooks, keeps Helm history, waits for foreground deletion,
and checks that retained objects still have their reviewed UIDs. This preserves
object identity, not a claim about stored data contents or successful reinstall.
There is no generic purge adapter.

## Durable admission and events

Run creation, optional recovery gate transfer and authorization nonce consumption
commit in one SQLite transaction. Reusing a nonce cannot leave a new active run
or release the source recovery gate. Intent, outcome, checkpoint and run-state
events commit with the journal transitions they describe. These events are local
durable history; they do not establish a remote streaming progress service.

Each Job receives its own durable worker record containing the server UID and a
digest of the fixed image, command, environment, mounts, security settings and
resources. Observation verifies that identity before accepting completion. A
replacement with the same name cannot complete the original intent. Ambiguous
creation responses remain uncertain. Workflow checks have the same intent and
worker records as migration Jobs, since checks can also write application data.
Recovery checks their termination before starting a restoration procedure.

SQLite schema version 2 adds worker identities and a run-protocol marker without
resetting existing history. Older active journals do not gain invented worker
identities during migration; automatic resume and recovery refuse those runs.
An application commit query cannot establish that an unobservable worker has
stopped, so a declared reconciliation command alone does not lift this gate.
Cluster observations remain dependent on the customer's trusted control plane;
they are not physical node fencing.

Planning performs nonpersistent SelfSubjectAccessReview requests for the
selected kubeconfig identity and the supported resource operations. Denied,
unavailable and inconclusive answers block execution. This is distinct from
admission, quota and workload-identity validation. See [permission planning](permissions.md).

Declared check fixtures currently block planning and execution because their
mounting adapter is not qualified. They are never silently ignored.
