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
