# Cinderlock implementation decisions

These choices describe the bounded alpha implementation. They are not customer
commitments or evidence that another deployment profile works. Qualification
belongs in the qualification record; this ledger explains the choices future
work inherits.

Review the provisional full-node GPU profile first. The medium-confidence
choices also constrain chart support, script resources, controller integration,
and the optional catalog. No unsound choice remains accepted below.

## Needs-user: provisional hardware profile

### Probe the selected node's advertised full GPUs

**Verdict:** needs-user · **Confidence:** medium. **When:** hardware evidence.

A release needs particular NVIDIA devices, drivers, and memory. The probe asks
Kubernetes for the selected node's advertised full GPUs so a second, different
device is not silently omitted. It rejects known sharing and enabled MIG,
NVIDIA's device-partitioning mode, and the application selects that observed
node. The design did not choose a sharing or multi-node allocation policy.
The provisional recommendation is to retain this full-node profile until
hardware qualification establishes another one. It can require free capacity
and a maintenance window; physical memory totals do not prove free memory or
exclusive access. Reverse the choice by adding and qualifying a separately
named sharing or multi-node profile, preserving the existing result's scope.
The user has deferred supplying hardware; no hardware result is implied.

## Sound choices: medium confidence

### Keep the catalog optional and locally controlled

**Verdict:** sound · **Confidence:** medium. **When:** catalog implementation.

A disconnected customer can deploy using its local CLI and journal without a
portal. If it operates the catalog, explicitly admitted records organize
release and site observations under project roles. A recent imported result
still does not mean the application is healthy now. The design left connected
management breadth open. This choice requires controlled metadata exchange
instead of a universal live agent, and prevents a catalog decision from
becoming permission to mutate an isolated cluster.

### Require signed script declarations rather than inferred safety

**Verdict:** sound · **Confidence:** medium. **When:** script contracts.

A migration commits a database change just before its caller times out. Its
signed recipe declares inputs, permissions, possible effects, success evidence,
and retry classification. Cinderlock does not infer safety from a script name
or convert those declarations into permissions. The design left this schema
open. A manual recipe can execute once under exact approval, but an uncertain
outcome requires application evidence, reconciliation, or recovery. Preview
recipes need new declarations and locks rather than a guessed translation.

### Keep intermediate releases and entitlement checks explicit

**Verdict:** sound · **Confidence:** medium. **When:** prerequisite contracts.

A vendor supports upgrading through an intermediate release only. Planning
shows the ordered route and rejects a direct jump; it does not choose or fetch
another bundle. An offline entitlement recipe similarly uses its original
worker's completion time for freshness. Reading it today cannot renew it.
The design did not choose a version solver or license-validation protocol.
Future adapters must retain independently admitted transitions, a trustworthy
local clock, and vendor renewal procedures instead of manufacturing support.

### Support deterministic root charts before general Helm execution

**Verdict:** sound · **Confidence:** medium. **When:** chart intake.

A chart can hide a random generator or cluster lookup inside an unused template.
Intake inspects its syntax without executing it, and execution uses the frozen
reviewed objects. The initial profile rejects dynamic evaluation and bundled
subcharts. The design left the intake boundary open. Applications needing those
features require an expanded tested profile; a permissive fallback would make
one reviewed render an unreliable description of the later deployment.

### Use one signed allocation as each authored worker's request and limit

**Verdict:** sound · **Confidence:** medium. **When:** worker budgets.

A browser test or migration declares CPU, memory, temporary storage, and a
deadline. Kubernetes receives the same signed amount as its scheduling request
and execution limit. This avoids two tuning contracts that the design had not
specified, but can throttle CPU and cannot guarantee scheduling or prevent
all evictions. Fixed helpers keep their separate budgets. Authored GPU Jobs
remain unsupported until a qualified allocation profile exists; probe and
application-chart GPU paths retain their own contracts.

### Keep endpoint prerequisites narrow and independently admitted

**Verdict:** sound · **Confidence:** medium. **When:** endpoint preflight.

Before writing application state, a release can require an internal route to
return an expected HTTP status from a worker. The fixed admitted helper uses
verified TLS and explicit Secret roles; plain HTTP needs separate permission.
It follows no redirect, ambient proxy, or arbitrary runner code and captures no
response body. The design left transport breadth open. Passing proves this
response from this worker, not future node image pulls or license entitlement.
New transport features need their own credential and authority checks.

### Let application tests own numeric measurements

**Verdict:** sound · **Confidence:** medium. **When:** numeric observations.

An inference test reports samples under a named test revision and conditions.
Every sample must meet its signed bounds, and the report retains the method's
limitations. Cinderlock checks the declaration without claiming that a short
sample measures overall model quality or GPU memory. The design left collection
open. Application-owned instrumentation avoids a runtime-specific collector;
independent instrumentation remains a separately qualified adapter.

### Start with a bounded plain-directory Argo profile

**Verdict:** sound · **Confidence:** medium. **When:** controller observation.

A customer selects reviewed Deployment, Service, and ConfigMap objects from
one YAML file. The observer requires Argo's effective plain-directory source
and an Application in its controller's own namespace, while workloads can use
a separate Site namespace. Other generators, hooks, object kinds, and extra
Application namespaces are rejected. The design left the first controller
profile open. These limits avoid guessing tracking identities or generator
behavior; supporting another mode requires a distinct tested contract.

### Follow the pinned controller's actual field semantics

**Verdict:** sound · **Confidence:** medium. **When:** controller ownership.

Argo is healthy, but another manager owns an omitted defaulted replica field.
The observer uses the pinned Kubernetes schema and field-set APIs to reject
that competing ownership, including fields omitted from the reviewed file.
Ordinary defaults and the Deployment controller's exact status/revision
bookkeeping remain allowed. With Argo's separate application-tree health
format, aggregate health and actual rollout are checked without inventing
inline child health. A completed normal apply's `hookPhase: Running` is not
an actual hook by itself. The design did not define these representations.
Future controller upgrades must qualify their semantics rather than widening
these exceptions into permission for competing writers or unfinished syncs.

### Separate current registry availability from full byte verification

**Verdict:** sound · **Confidence:** medium. **When:** GitOps dependencies.

A completed staging run copied and verified the signed image graph. Later,
a bounded metadata read checks its descriptors remain available without
redownloading every layer at each boundary. Full graph hashing runs where the
phase requires a new byte audit. The design left repeat-read costs open.
Metadata availability does not detect altered bytes behind a descriptor,
replace the original copy evidence, or prove a future image pull.

### Prepare models separately from acceptance fixtures

**Verdict:** sound · **Confidence:** medium. **When:** GitOps model execution.

A vendor prepares a fresh model volume while the customer still uses the old
source. That run retains original transfer workers and volume identities but
cannot accept the application. After source adoption, a separately approved
run verifies that preparation and creates its own acceptance fixtures. Models
mount read-only; current consumer inventories reject unknown writers, including
queued Jobs. The design left the cross-run boundary open. Full model reads at
check start and finish, with identity checks between, do not promise continuous
integrity or exclusion of future writers.

### Retain the active data gate across independent source adoption

**Verdict:** sound · **Confidence:** medium. **When:** mutable GitOps phases.

After signed procedures stop application writes and prepare data, customer source review can
take hours. `awaiting_adoption` retains the application's active safety gate
and cluster journal while releasing only the request Lease, Kubernetes' timed
coordination claim. A new phase needs exact predecessor evidence and current
approval. The design left the waiting state open. Treating preparation as
ordinary completion would allow unrelated mutations of prepared data. The
initial profile requires the controller to remain healthy through quiescence;
it does not patch the Deployment to imitate a storage fence.

### Repair only the exact recorded predecessor-to-successor handoff

**Verdict:** sound · **Confidence:** medium. **When:** recovery coordination.

Local storage transfers a run's gate to a recovery, then a cluster journal write
loses its response. Resume validates both saved plans and the exact recorded
edge under the application Lease before repairing only the missing writes.
A missing successor journal is repairable only before any successor work exists,
and predecessor history must remain available. The design left this split
commit boundary open. Reusing the existing transaction avoids another workflow
store without ignoring arbitrary unresolved runs or fencing external writers.

### Use declared data procedures and same-source restoration

**Verdict:** sound · **Confidence:** medium. **When:** mutable GitOps recovery.

The signed operation graph names write-barrier, backup, mutation, source-adoption,
and resume roles. If post-adoption workflows fail, a separate authorized run
can restore data at that same adopted source and run its own required checks.
The failed attempt remains failed. The design left initial recovery breadth
open. This profile supports one external filesystem claim limited to one node at a time and
bounded native consumer inventories; vendor scripts own database semantics.
Failure before adoption and cross-source restore require another explicit
procedure, not a guessed source/storage ordering or a Job-completion claim
that a production backup is sound.

### Make fixture maintenance and restart behavior explicit

**Verdict:** sound · **Confidence:** medium. **When:** persistent fixture.

The synthetic old server would otherwise become unhealthy between database
migration and new-source adoption. Its opt-in maintenance mode keeps only the
known quiesced schema transition ready while document operations stay blocked.
Ordinary mismatch remains unhealthy. A signed restart Job replaces an original
controlled Pod using original server identity/version preconditions and narrow short-lived access;
it cannot edit Deployment, Git, Helm, or Argo desired state. The design did not
choose a sample application for this interval. These are explicit fixture
behaviors, not relaxed engine checks or production maintenance guarantees.

### Limit release groups to ordered native application plans

**Verdict:** sound · **Confidence:** medium. **When:** release groups.

A group contains several applications with exact target-version dependencies.
The runner validates native Plan membership and the dependency graph before
starting, then executes each plan under its own guards. It preserves partial
and unstarted outcomes when one fails.
It does not include recovery Plans or GitOps source-adoption phases. The design
left their different lifecycle and atomicity rules open. This keeps group
failure from pretending that several independent application changes rolled
back together. Widening this boundary requires an explicit persistent group
journal and tests for those phase handoffs, rather than adding another kind
to an allowlist and assuming its approval and waiting semantics are equivalent.

## Sound choices: high confidence

### Keep release, customer approval, and catalog keys in separate domains

**Verdict:** sound · **Confidence:** high. **When:** trust foundations.

A vendor's key signs the archive; a customer key authorizes the exact local
plan. Separate signed message domains stop either signature from substituting
for the other. A new policy or key remains a candidate until independently
admitted under retained epoch and release floors. The design left concrete
signing and admission mechanics open. Losing local history does not preserve
replay protection, and a key included beside an archive cannot trust itself.

### Use a pinned Helm executable as the native execution boundary

**Verdict:** sound · **Confidence:** high. **When:** native adapter.

Two machines have different programs named `helm` on their search paths. The
Site selects an admitted executable by exact digest and controlled arguments
and environment instead. The design left SDK versus process integration open.
Replacing this boundary with an SDK requires its own cancellation, hook, and
lifecycle evidence; the Go language choice does not establish that equivalence.

### Retain uncertainty instead of replaying possibly committed work

**Verdict:** sound · **Confidence:** high. **When:** execution and diagnostics.

A migration commits but its response is lost. Durable intent and cluster
records preserve what was requested without claiming an atomic database commit.
Original worker and application evidence determine whether continuation is
safe. A timeout, canceled inventory, or unavailable original-Job read cannot
prove a changed recipe or a safe stop. Unavailable fixture evidence is explicitly
unverified and requires reconciliation. The design left these interruption
classifications open. A fresh run can stop before its first effect, but resume
cannot assume no work occurred. Existing original-worker checks remain required.

### Preserve historical facts while rechecking current authority

**Verdict:** sound · **Confidence:** high. **When:** phased execution.

An operator rotates credentials after copying images or models. The original
copy remains a fact; the old policy and Secret bytes grant no new permission.
Completed evidence keeps its exact target, bundle, plan, result, worker, and
volume identities. Every new phase satisfies current policy, dependency,
credential, and approval checks. The design left rotation across phases open.
Old accepted manifests remain separate from future renders, and typed model
identity is retained beside its digest so later releases can verify old
consumers without carrying old credentials as authority.

### Separate absent, denied, unavailable, and stale target observations

**Verdict:** sound · **Confidence:** high. **When:** target inspection.

A successful empty inventory can establish absence; a denied list cannot.
Required incomplete facts block planning or continuation, while optional CPU
node/version observations remain advisory. Original controller operation times
and selected freshness windows are rechecked rather than refreshed by a new
receipt. The design left partial reads and freshness representation open.
This prevents invented fresh installations and makes old successful controller
state remain old evidence.

### Bind relevant Secret content privately and ownership separately

**Verdict:** sound · **Confidence:** high. **When:** configuration inspection.

Changing a monitoring annotation need not invalidate a plan, but changing a
selected password must. A retained private fingerprint key binds relevant
Secret identity, type, and content through separate keyed-hash domains; public hashes
cannot serve as password guesses. Managed/pull Secrets bind all keys, explicit
external aliases bind their selected keys, and ownership binds separately.
The design left this distinction open. Retain the journal key; relevant content,
identity, or ownership changes require fresh inspection and authorization.

### Treat retained volume identity as evidence rather than authority

**Verdict:** sound · **Confidence:** high. **When:** storage ownership.

A StatefulSet leaves a data volume without Helm ownership markers. Cinderlock
can record and retain it without adopting it based on its name. Exact qualified
ownership is needed for a direct Helm mutation. The design left orphaned
volume representation open. Object retention does not prove intact data,
secure erasure, tested application service-account access, or a successful
restore; these require their own procedures and evidence.

### Preserve original bounded measurement results

**Verdict:** sound · **Confidence:** high. **When:** numeric evidence/resume.

A test must emit one strict bounded numeric document from its original Job and
Pod, without mixed banners. An optional budget failure remains visible after
resume and is not rerun for better numbers. Complete samples stay in the local
journal; cluster records carry counts plus their exact digest and size rather
than truncating data to fit. The design left transport and storage boundaries
open. Missing local history cannot be reconstructed from that digest, and an
oversized unrelated result must not destroy the previous readable record.

### Keep inventories and external observations within their producer's scope

**Verdict:** sound · **Confidence:** high. **When:** inventory and evidence.

A signed artifact inventory lists hashes, origins, and declared licenses; it
does not run a vulnerability scanner or establish distribution rights. A signed
DNS/TCP/UDP capture retains its producer, timing, confidence, dropped events,
and protocol/attribution gaps. An empty capture does not prove no dependency.
The design left scanner and collector integrations open. External evidence can
be retained without silently strengthening native application acceptance or
claiming physical isolation or legal clearance.

### Keep GitOps preparation, source acceptance, and application acceptance distinct

**Verdict:** sound · **Confidence:** high. **When:** GitOps ownership.

Images are copied under their own approval without advancing application
acceptance. A proposal is an inert patch based on the vendor's signed base;
the customer's accepted commit is independently selected after review. Requiring
that new commit inside the original bundle would create a rebundling loop.
The design left repository integration open. Cinderlock does not commit, push,
or request controller sync. File-reversion evidence proves only that file's
history/bytes, not whole-source rollback, restored data, or passing workflows.

### Keep source reads inert and refuse a second application owner

**Verdict:** sound · **Confidence:** high. **When:** source observation.

An Argo source override can change generation before include filters run.
The observer rejects it and disables executable Git helpers and fetching.
State and outputs stay outside the repository. Shared rendering uses an
install context only after proving Helm history absent or uninstalled, and
checks history again afterward. The design left source-read and rendering
mechanics open. Another active owner blocks instead of contributing values
or being silently replaced; additional source modes need explicit contracts.

### Reuse normalization and completed evidence without removing guards

**Verdict:** sound · **Confidence:** high. **When:** worker/consumer validation.

Kubernetes adds defaults and scheduling fields to a Pod. Application consumers
and fixed workers reuse the existing normalization while retaining separate
ownership and recipe checks. Completed prerequisites need original identity,
terminal state, and freshness, not a duplicate adjacent full sweep. New work,
post-wait boundaries, and final acceptance retain their full guards. The design
left these comparison and repeat-read mechanics open. This preserves worker
protocols and authority without a parallel list of ignored fields or a claim
that removing duplicate reads establishes a measured speedup.

### Let catalog restrictions and comparisons preserve phase context

**Verdict:** sound · **Confidence:** high. **When:** catalog integration.

An operator records a check-only GitOps phase and a waiting data phase. Their
plan kinds, predecessor identities, required tests, and acceptance remain
separate in comparison; zero authored operations does not bypass required
checks. Catalog policy records become binding only when independent configuration
admits their exact scoped digests. Restrictions intersect, and waiting notices
stay in the local outbox. The design left phase handling and policy admission
open. None of these records grants engine authorization, releases an active
gate, sends a message, or establishes current application health.

### Keep historical model readers across data-phase handoffs

**Verdict:** sound · **Confidence:** high. **When:** model-bearing data recovery.

A failed application run leaves a completed model-verification worker behind.
Recovery recognizes that reader through the existing data-phase proof: its
local Plan, application, target, mutable claim, original worker identity, and
recipe must match, and historical work must be terminal. Model mounts stay
read-only. The design left this history boundary open. This avoids deleting
useful evidence, admitting every completed Job, or building a second history
format. It permits retention of a known reader without turning the original
failed workflow into acceptance or authorizing another write.
