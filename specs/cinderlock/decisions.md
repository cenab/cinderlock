# Cinderlock implementation decisions

These are current implementation choices, not customer commitments. Update the
ledger against the final code before closing the implementation spec.

## Provisional choices to qualify

### Hardware evidence reserves a full node's advertised GPU set

**Verdict:** needs-user · **Confidence:** medium.

When a release needs a particular NVIDIA device/driver/memory profile, a probe
asks Kubernetes for the selected node's advertised full GPUs and records the
actual device query. Probing one device could miss a different second device.
The provisional profile rejects known sharing and enabled MIG and constrains
the application to the observed node. This can require a maintenance window
with free capacity. A later shared or multi-node profile needs separate
qualification; no claim of free memory or exclusive allocation follows merely
from total physical memory. The final workload must still pass inference.

### Optional catalog stores customer-approved metadata

**Verdict:** sound · **Confidence:** medium.

An isolated customer can operate without a portal. If a catalog is installed,
its project/site roles and signed exchange packets organize permitted metadata;
they cannot reach an isolated cluster or turn a portal decision into a local
execution signature. This preserves local authority but requires explicit
import/export and last-observed freshness instead of a universal live status.

## Foundational choices

### Reuse the Helm executable before changing the adapter

**Verdict:** sound · **Confidence:** high.

The Go core calls an admitted Helm executable using exact arguments and a
controlled environment. It verifies the binary's digest rather than accepting
whatever `helm` appears on the host PATH. Using the Go SDK later is feasible,
but its cancellation, chart hooks, and lifecycle semantics need their own tests.
The language change alone does not justify replacing a tested external boundary.

### Uncertain writes stop for reconciliation

**Verdict:** sound · **Confidence:** high.

If a migration commits but its caller loses the response, retrying can duplicate
work. Local SQLite and a cluster record preserve intent, but cannot atomically
commit the database change. The next invocation checks the application's own
operation evidence before continuing. Where that evidence is inconclusive,
the run stays unresolved rather than manufacturing a successful receipt.

A local wait ending must not turn canceled reads into invented target or
credential changes. A freshly admitted run can establish a stop before its
first operation; resume cannot assume that absence of prior work. The private
execution entry point carries that distinction, preserving definite stops while
later interrupted observations retain their active reconciliation claim.

### Keys and approvals have different purposes

**Verdict:** sound · **Confidence:** high.

The vendor signs a release; the customer separately decides whether an exact
plan may run at its target. Bundle and authorization messages have different
signed domains. Candidate policy updates are written separately for local
admission. A new key carried beside an archive does not grant itself trust.

### Artifact inventory is not a vulnerability scan

**Verdict:** sound · **Confidence:** high.

A signed CycloneDX inventory names the locked images, model files, origins,
hashes, and declared licenses. It explicitly records incomplete package
composition and scanners not run. Otherwise a release could look scanned
merely because an inventory file exists. External scanner/evaluation results
remain evidence with their own producer, object identity, date, and coverage.

## Numeric observation pass

### The application measures; Cinderlock checks the declared bounds

**Verdict:** sound · **Confidence:** medium. **When:** numeric observation pass.

When an inference test reports latency or allocation, Cinderlock retains its
test revision, conditions, limitations and every numeric sample. Each sample
must meet the vendor's signed bounds; the engine does not turn a small test into
a general quality score. The design required application assertions but left
their transport and assessment open. Application-owned measurements avoid a
new runtime-specific collector, at the cost of trusting the test's measurement
method. Independent GPU instrumentation needs a separately qualified adapter.

### A completed test emits one bounded numeric document

**Verdict:** sound · **Confidence:** high. **When:** numeric observation pass.

If a test prints a banner and then apparently passing numbers, the whole capture
is blocked. The accepted profile requires one strict JSON document with fixed
integer units and no extra log text. The original Job and Pod identities are
bound before collection, so a replacement worker cannot supply new passing
evidence on resume. The design did not select an output format. This keeps raw
answers and diagnostics out of numeric reports; verbose test runners must use a
wrapper that emits only the declared document.

### Full samples live locally; cluster records identify the local result

**Verdict:** sound · **Confidence:** high. **When:** numeric observation pass.

When many valid tests finish, copying all samples into a Kubernetes metadata
object can exceed its size limit and prevent finalization. The cluster record
therefore stores status, counts, and the exact digest and byte length of the
complete local result. Release validation bounds the aggregate numeric evidence
while reserving room for other run data. The design left this storage boundary
open. Samples are not truncated, but a cluster record cannot reconstruct a lost
operator journal. An oversized unrelated result must preserve the previous
readable journal state rather than silently expanding the supported reader.

## Contract, inspection and delivery integration

### Require script declarations instead of inferring safety

**Verdict:** sound · **Confidence:** medium. **When:** contract integration.

A vendor-supplied migration can change a database even when its caller times
out. Each authored script now names its inputs, needed access, possible effects,
success checks and retry classification. Those are signed declarations, not
permissions or proof that retrying is safe. The design left the concrete schema
open. A manual script may run once under the exact authorized plan; uncertainty
requires reconciliation or recovery. Existing preview recipes must be relocked
and replanned rather than translated into guessed safety statements.

### Intermediate releases and entitlement checks remain explicit prerequisites

**Verdict:** sound · **Confidence:** medium. **When:** prerequisite integration.

If a customer must install an intermediate release before the target, the plan
names the ordered path and blocks the unsupported direct jump. It does not
choose or download another release. Likewise, an offline license check runs the
vendor's locked recipe and its original completion time defines freshness;
reading the result later cannot renew it. The design did not specify a version
solver or freshness clock. Operators must have a trustworthy local clock and
vendor renewal instructions, and independently authorize each transition.

### Support deterministic root charts before widening Helm intake

**Verdict:** sound · **Confidence:** medium. **When:** chart-intake integration.

When a chart invokes a random generator or looks up live cluster state, reviewing
one render cannot establish the original template's later behavior. Intake
inspects syntax without running it, including unused definitions, then execution
uses the frozen reviewed objects. This profile accepts canonical root charts
and rejects bundled subcharts and dynamic evaluation. The design left the
inspection boundary open. Applications using those chart features need an
explicitly expanded, tested profile; a permissive fallback would hide the gap.

### Failed reads remain different from empty inventories

**Verdict:** sound · **Confidence:** high. **When:** inspection integration.

A successful empty resource list can establish absence; an unavailable API or
denied list cannot. Inspection retains those distinct facts, and planning and
execution block when required inventory is incomplete. Optional node/version
facts remain advisory for a CPU release, while a GPU release still needs its
separate probe. The design left partial-read behavior open. This gives operators
useful restricted-access diagnostics without inventing a target or fresh install.

### Bind relevant secret content privately and keep ownership separate

**Verdict:** sound · **Confidence:** high. **When:** inspection integration.

A monitoring annotation should not require another upgrade approval, but changed
credentials must. The existing private fingerprint key binds Secret identity,
type and relevant bytes using separate HMAC domains, so exported digests do not
permit ordinary public hash guessing. Managed and image-pull Secrets bind all
keys; explicit external aliases bind their combined selected keys. Ownership has
its own binding. The design left this distinction open. The operator journal's
key must be retained, and replacement or relevant data/ownership changes require
fresh inspection and authorization.

### Retained volume inventory grants no ownership

**Verdict:** sound · **Confidence:** high. **When:** ownership integration.

A StatefulSet can leave a data volume without Helm markers or controller links.
Cinderlock may record and retain it, but only exact qualified ownership allows
a direct Helm mutation. A name prefix cannot establish that authority. Needed
API caller permissions and declared service accounts are shown per step without
claiming their grants were tested. The design left the representation open.
Customers can inspect existing releases without silently adopting unrelated
storage or treating retained object identity as restored application data.

### Catalog packs restrict observations without granting execution

**Verdict:** sound · **Confidence:** high. **When:** catalog-policy integration.

Registering a policy-pack record does not make it binding. An independent
catalog configuration admits its exact record digest and project/site scope;
applicable restrictions intersect and are rechecked when review is retried.
The design left policy representation open. This provides reusable restrictions
without a policy language or another execution authority. Customer plan signatures
and local trust remain required even after catalog review succeeds.

### Runtime capture claims keep their producer and gaps

**Verdict:** sound · **Confidence:** high. **When:** runtime-evidence integration.

A collector can miss packets or identify only part of a process. Imported signed
DNS/TCP/UDP observations therefore retain producer confidence, capture timing,
unsupported protocols, attribution gaps and lost events. An empty capture is not
proof of no network dependence. The design did not require a particular collector.
External producers can integrate now; qualifying them or adding a native collector
cannot silently strengthen an application's original acceptance result.

### GitOps preparation remains separate from a controller's application result

**Verdict:** sound · **Confidence:** high. **When:** GitOps delivery integration.

A completed image copy says the internal registry has the selected signed graph,
not that a controller installed a healthy application. Image staging uses its own
exact authorized plan and cannot advance the accepted application release floor.
A source proposal is an inert whole-file patch for one clean tracked YAML file;
it never commits, pushes or fetches. The design left repository integration open.
Customers retain their source review process. Native model preparation and
application checks use separate authorized execution paths. Mutable data
procedures and recovery require their own contracts.


### Optional numeric failures can finish a resumed run without being retried

**Verdict:** sound · **Confidence:** high. **When:** optional observation resume.

If a test process exits successfully but exceeds an optional numeric budget,
its failure remains visible while required application checks can still pass.
After interruption, continuation requires the same completed Job and original
successful Pod, signed check intent and retained samples. A replaced or running
source blocks continuation. The design left this interruption distinction open.
This avoids turning an optional bound into a required failure or rerunning the
test to obtain better numbers; failed application workers retain their separate
reconciliation requirements.


### Endpoint prerequisites use a fixed, narrow transport

**Verdict:** sound · **Confidence:** medium. **When:** endpoint integration.

Before an application write, a customer can require a named internal route to
return an expected status from the worker network. A fixed independently admitted
helper uses verified TLS and explicit Secret roles; anonymous HTTP requires its
own permission. Redirects, proxies, response bodies and arbitrary runner code are
outside this profile. The design left transport scope open. This keeps credentials
out of artifacts and status evidence, but does not validate a node's future pull
credentials or establish license validity. Each prerequisite rechecks authority
before starting; approved dollar signs remain literal through Kubernetes argv.

### Authored workers declare one allocation for both request and limit

**Verdict:** sound · **Confidence:** medium. **When:** worker-budget integration.

A browser test or migration must say what CPU, memory, temporary storage and time
it needs. Those amounts are signed with its script and become the worker's
requests and limits; the temporary-directory bound stays within ephemeral storage.
Equal requests/limits avoid a second tuning contract for the initial profile.
The design left the schema and caps open. This can throttle CPU and cannot promise
capacity, scheduling or eviction behavior. Fixed helper budgets stay separate.
Authored GPU requests are rejected until a safely qualified allocation profile
exists; existing probe and application-chart hardware paths remain distinct.
Older preview scripts need new declarations, locks, bundles and plans.

## Exact Argo CD observations

### Start with a plain directory and a bounded resource graph

**Verdict:** sound · **Confidence:** medium. **When:** controller observation.

When a customer selects one reviewed YAML file, the observer compares its
Deployment, Service, and ConfigMap objects with the actual cluster objects.
Other generators, hooks, and object kinds block this profile. A Helm chart label
alone is formatting metadata; active Helm history, ownership annotations, or
competing field claims block. The design left the first controller profile open.
This permits a useful first adapter without claiming that every Argo application
is supported or that current ownership excludes future writers.

Applications must reside in the controller's own observed namespace. For
example, Argo tracks `team/payments` differently from `argocd/payments`; treating
both as plain `payments` could associate the wrong application's resources.
The first profile rejects that additional-namespace mode instead of guessing
its tracking identity. Workloads may still use a separate Site namespace.

### Use Kubernetes field semantics for current ownership

**Verdict:** sound · **Confidence:** medium. **When:** controller observation.

A field manager can own a map without owning its individual keys. The observer
uses the already pinned Kubernetes schema and field-set APIs to require exact
reviewed leaf ownership, including defaulted list keys. Unknown field encodings
and overlapping foreign claims block. The design required competing writers to
block but did not specify the comparison algorithm. This avoids a second parser
and preserves normal API defaults without treating a parent claim as proof of
child ownership. The existing dependency becomes direct; its version is unchanged.
An omitted default such as one replica still changes application behavior, so
foreign spec/data/immutability claims block even outside the supplied field set.
Ordinary defaults and controller status/revision bookkeeping remain supported.
A Deployment controller can record its revision annotation in the same managed
entry as status. Only that built-in manager's Update claim over the exact
revision path is admitted; spec/data/tracking and unrelated metadata claims
remain blocked. The live API representation requires this narrow exception,
not a general grant of metadata ownership to status writers.
When Argo stores child health in its separate application tree, the observer
retains absent inline child health and combines aggregate application health
with the actual Deployment rollout. It does not infer a tree read or synthesize
child health; unknown or contradictory representations remain blocked.
Similarly, a normal successful apply can retain `Running` in the resource
record's misleadingly named `hookPhase`. The observer distinguishes that known
representation from an actual hook using its type, completed overall operation,
reviewed metadata, and live resource checks. A running operation or real hook
still blocks; changing that rule back would reject ordinary pinned-controller
results without adding safety.

### Separate the vendor's proposal base from the customer's accepted commit

**Verdict:** sound · **Confidence:** high. **When:** controller observation.

A customer applies a proposed change and creates a new commit. The signed bundle
continues to name the original proposal base; a separately selected full accepted
commit binds the observation. The exact signed file and reviewed render still
must match. Requiring that new commit inside the original bundle would force
another bundle and another source change. The design left these revision roles
open. Future execution must retain both identities rather than rebundle after
every customer commit or accept a moving branch label.

### Preserve original time and independently bound inputs

**Verdict:** sound · **Confidence:** high. **When:** controller observation.

Reading an old successful controller result today cannot make it fresh. The
customer chooses a lower time bound and maximum age for the original reconcile
and completed operation. The observer rechecks that window and its source,
namespace, Site, policy, and selected Helm history after reading resources.
Resolved private Site paths share the CLI's resolver, while original source
bytes remain separately bound. The design left this binding protocol open.
Observation time is only a receipt; changed or unavailable inputs block instead
of silently changing the reviewed environment.

### Keep source inspection inert and generation explicit

**Verdict:** sound · **Confidence:** high. **When:** controller observation.

An Argo source-override file can change generation before a directory filter
runs. The observer therefore rejects those committed overrides and requires the
reported plain-directory source. Local Git reads use a provisioned executable
outside the repository with executable helpers disabled. State and output stay
outside the source tree. The design left these source details open. Preparing
or observing a release cannot execute a repository-supplied Git program, apply a
patch, fetch, commit, or push; additional source modes need their own contract.

### Share rendering while refusing an active Helm owner

**Verdict:** sound · **Confidence:** high. **When:** controller observation.

An externally owned application must not inherit a live Helm release's values.
After proving the selected Helm history absent or uninstalled, this profile
freezes an install rendering context and rechecks history afterward. Native Helm
upgrades still derive their own upgrade context through the same renderer. The
design prohibited a second writer but left rendering context open. A new active
Helm record blocks observation instead of triggering another values read or
silently changing the source proposal.

### File restoration and application recovery remain separate evidence

**Verdict:** sound · **Confidence:** high. **When:** controller observation.

A later commit or explicit reset may restore one reviewed file while other files
remain different. Optional reversion evidence checks that exact file's local
history and bytes. It does not establish a whole-tree rollback, controller
transition, restored application data, or passing workflows. Reports retain
validated identities, digests, times, and match facts rather than source/config
values or raw controller errors. The design separated recovery domains but left
the first evidence format open. A ready observation remains point-in-time
evidence with application acceptance not established, never execution authority.

### Reuse completed evidence while guarding every new worker

**Verdict:** sound · **Confidence:** high. **When:** check execution and resume.

An already completed prerequisite still needs its original recipe, Job identity,
terminal state, and freshness checks; it does not need another immediately
adjacent full target sweep. The new-intent branch receives the current execution
guard instead. Intervening fixture-verifier waits require another guard before
the next worker, because approval or policy can expire during that wait. Final
acceptance repeats the complete guard, including coordination and checkpoint
facts. A failed guard retains completed evidence without inventing an authored
worker identity or starting a replacement. The timing audit supports removing
duplicate reads; a live speedup has not yet been measured.

### Separate current registry availability from a byte audit

**Verdict:** sound · **Confidence:** medium. **When:** GitOps dependency evidence.

Image staging proves the addressed copy completed at that time. A later bounded
metadata read can check that every descriptor in the signed closure is still
available, without downloading all layers before each application check. A
separate verifier reads and hashes the full graph when the execution phase
requires a fresh byte audit. Neither reader writes tags or content. Metadata
availability alone cannot detect changed bytes behind an unchanged descriptor,
prove a future pull, or replace the original completed-copy evidence.

### Separate model preparation from same-run acceptance material

**Verdict:** sound · **Confidence:** medium. **When:** authorized GitOps model and
application-check phases.

A vendor can prepare a fresh model volume while the customer's checkout still
contains the old source. That run records its original receiver, verifier and
volume identities but cannot accept an application release. After the customer
adopts the reviewed source, a separately authorized check run references that
exact preparation. It seeds its own test fixtures, so an old model-copy receipt
cannot masquerade as this run's test data. The plan did not specify this
cross-run boundary. Application model mounts must be read-only; current worker
and controller inventories reject unknown writers, including queued Jobs with
no Pod. Full model reads occur at check start and finish, with identity, manifest
and consumer checks between them. This bounds repeated work without promising
exclusive future writers, continuous byte integrity or mutable-data safety.

### Resume only an already committed recovery handoff

**Verdict:** sound · **Confidence:** medium. **When:** recovery journal handoff.

If local storage has transferred the active safety gate to a recovery but a
cluster journal write loses its response, the operator resumes that same run.
The existing local transaction records exactly which predecessor gave the gate
to which successor. Resume validates that edge and both saved plans, holds the
application Lease, and completes only the missing journal writes before any
worker. It never ignores an arbitrary unresolved run. A missing successor
journal is repairable only while no successor intent or worker exists; the
original predecessor journal must still be available. The plan did not specify
how to recover this split between local storage and Kubernetes. Reusing the
existing transaction and journal format avoids another workflow database or
new admission protocol. This does not reconstruct lost predecessor history or
fence application writes outside Cinderlock.

### Keep the data gate while the customer adopts source

**Verdict:** sound · **Confidence:** medium. **When:** mutable GitOps procedures.

After the vendor's signed procedures stop writes and prepare the database,
the customer may take hours to approve and adopt the new source. Cinderlock
records `awaiting_adoption` and retains the active application gate, while
releasing only the request Lease. A later plan receives that gate only from
the exact completed predecessor and runs under new approval. The plan left
the waiting boundary unspecified. Treating preparation as ordinary successful
completion would allow an unrelated mutation while the database is prepared
for another release. Initial installation is explicit and cannot bypass a
previously accepted application. The first profile requires a healthy
controller through application-level quiescence; it does not scale or patch
the customer's Deployment to imitate a storage fence.

### Keep historical facts independent of current authority

**Verdict:** sound · **Confidence:** medium. **When:** mutable GitOps history.

An operator rotates credentials after preparing a model or image. The original
copy still happened; the old credentials do not authorize another action.
Completed records retain exact bundle, target, worker, volume, Plan, and result
identities. Every new phase independently satisfies current policy, selected
Secrets, source observation, and approval. The old accepted manifest remains
separate from the future bundle's render. The plan did not define how history
survives rotation. Reusing the old policy as authority would be unsafe; forcing
all historical policy bytes to stay current would make normal rotation break
upgrade preparation. Historical model identity is stored as typed metadata
beside its digest, without Secret values, so old read-only consumers remain
verifiable even when a later release removes that model.

### Start with explicit procedures and same-source data restore

**Verdict:** sound · **Confidence:** medium. **When:** mutable GitOps recovery.

A release declares which signed Jobs quiesce, back up, and resume its mutable
claim. Dependencies determine which procedures run before or after the
customer's source change; names and script prose do not. If required checks
then fail, a separately approved recovery restores data at that same adopted
source and runs its own required workflows. The original failed result stays
failed, while the recovered result may become the next operational baseline.
The plan left the initial data adapter's recovery breadth open. This keeps
cross-source recovery and failures before adoption in explicit reconciliation
scope instead of guessing a safe source/storage ordering. The first adapter
supports one external ReadWriteOnce filesystem claim and bounded native
consumer inventory. Scripts own actual database and backup semantics; neither
Job completion nor claim identity certifies a production restore backend.

### Share Pod recipe normalization without changing worker identity

**Verdict:** sound · **Confidence:** high. **When:** data consumer review.

A Kubernetes scheduler adds a node assignment and standard defaults to an
application Pod. Those changes must not disguise altered commands, images,
mounts, or security settings. Application consumer validation and fixed workers
reuse the existing Pod default/scheduling normalization, with their respective
ownership checks and recipe digests. The plan did not specify the comparison
mechanism. Passing a Pod body to a whole-resource comparison would crash or
misinterpret resource fields; another independent list of ignored defaults
would drift. The fixed worker's digest envelope and normalization remain
unchanged, preserving the existing helper protocol.

### Model maintenance compatibility explicitly in the GitOps fixture

**Verdict:** sound · **Confidence:** medium. **When:** persistent rehearsal inputs.

The native fixture's old server becomes unhealthy when its database migrates,
before the new server is installed. The bounded GitOps data profile requires
the controller to stay healthy across that interval. Its new synthetic fixture
explicitly opts into maintenance readiness for only the known schema-1 server
observing a quiesced schema-2 database. Document/query operations remain blocked
and ordinary schema mismatch remains unhealthy. The default native behavior
and frozen receipts remain unchanged. The plan did not specify how the sample
application demonstrates this compatibility requirement. Changing the fixture
explicitly is preferable to weakening the engine's source/readiness checks;
the new image and live run need independent evidence.

The same rehearsal replaces native desired-state restart operations with
signed operational Jobs. An explicit short-lived token permits Pod operations
only in the fixture namespace. The script pins Deployment/ReplicaSet ownership,
deletes one original Pod with UID/resourceVersion preconditions, and waits for
a new ready controlled Pod. It cannot patch a Deployment or sync a controller.
This preserves actual restart/persistence testing without introducing another
desired-state writer. Its credentials and narrow lab API grants are separate
operator prerequisites, not authority granted by the bundle. V1/v2 retain
restart-based repair with an explicit write barrier, read-only integrity check,
and resume procedure. They do not restore missing data. The live failure/recovery
rehearsal selects v3's actual backup restoration.

### Carry GitOps phases through recorded catalog policy and comparisons

**Verdict:** sound · **Confidence:** high. **When:** catalog integration.

A customer records a GitOps application-check or data-recovery result and
expects the catalog to compare it and apply the same organizational rules as
an ordinary deployment. The catalog recognizes these application plan kinds
through one shared classifier. A checks-only phase can have no authored
operations, but its declared checks, identity bindings, and required-workflow
rules remain mandatory. Artifact-only preparation remains outside application
comparisons when it has no check contract. The plan did not specify the
catalog's phase handling. Rejecting every new kind would leave the CLI and
catalog disconnected; treating a phase as ordinary deployment would hide its
coverage and predecessor context. Recorded run and plan predecessor fields
must agree. A waiting-state local notice preserves unestablished acceptance
and never releases the active engine gate or sends a message.
