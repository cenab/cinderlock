# Peak storage planning

Storage in one location cannot compensate for exhaustion somewhere else. The
`peaks-v1` profile keeps domain budgets separate and combines them only when you
explicitly identify a shared backing pool. Its calculation and supported domain
names live in [`internal/storageplan`](../internal/storageplan/).

## Separate known sizes from declarations

Verified bundle descriptors provide logical payload sizes. Selected model file
manifests provide incoming bytes and the largest staging file. Registry planning
counts each destination repository's encoded OCI closure without assuming that
the backend deduplicates layers across repositories. These are content-size
facts, not measurements of expanded runtime layers or filesystem allocation.

Runtime expansion, workspace overhead, indexes, migration scratch space, and
backup growth need signed vendor budgets. Positive declared budgets reserve
their domain even when the tool cannot infer an arbitrary Job's writes.
Missing budgets remain unknown. A declared zero is a budget assertion, not a
measurement proving that the operation writes nothing.

Target free space, retained data, backing bindings, provenance, and observation
time come from explicit Site assertions. The profile refuses to relabel these
as measured target facts. Both Site and TrustPolicy must grant
`storage-assertions` before those declarations can satisfy prerequisites.
Expired or incomplete assertions block the plan. An independently qualified
target probe remains a separate capability; planning creates no storage Job.

## Retain data without double charging free space

An upgrade can keep the prior model while publishing its replacement. The
model peak includes retained content, incoming files, a conservative allowance
for the largest staging file, and declared extras. Existing retained data is
already reflected in available free space, so the free-space check charges only
the additional and temporary requirement.

When several domains share a binding, their additions must fit the same free
space together. Passing several individual checks against the same capacity is
insufficient. Conflicting facts for a shared binding block qualification.

## Recheck the actual operator filesystem

The engine adapter observes local available space using `Statfs`. This initial
profile requires the configured operator probe, actual workspace/state,
verified cache, and bundle file to share an observed filesystem. Unsupported
layouts block rather than borrow capacity from an unrelated path.

Verification has already opened the bundle before this assessment runs. The
existing archive and extracted payload footprints are reported separately from
future workspace requirements. This profile does not establish that initial
bundle ingestion would fit on a clean machine. Native model delivery streams
from verified blobs instead of creating a second full local model tree.

The approved plan binds its requirements, sources, policy, and storage bindings.
Initial execution remeasures operator free space and recomputes the assessment.
Ordinary free-space movement does not change the requirement identity, but
insufficient current capacity stops execution. These checks do not reserve
space or establish future CSI, quota, scheduling, or filesystem behavior.

The legacy `capacityBytes` field remains an explicitly unqualified scalar check
when no storage profile is selected. It does not certify per-domain readiness.
The adapter and plan-binding checks live in
[`internal/engine/storage.go`](../internal/engine/storage.go).
