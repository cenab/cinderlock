# Application-owned numeric observations

An optional `observationContract` on a Job check binds application-authored
numeric assertions and latency/resource budgets to the signed release, plan,
and durable check intent. A successful Job exit is necessary; every declared
metric in every ordered sample must also meet its inclusive bounds. Checks
without this opt-in keep their exit-code behavior.

> **Note:** This is a preview feature currently under active development.

The author declares the exact test and assertion revisions, supported profile,
sample count, numeric sampling settings, nondeterminism, and sample limitations.
Each named metric has an explicit assertion, kind, fixed unit, minimum, and
maximum. Assertion, latency, and resource bounds are all required. Use integer
fixed units, such as milliseconds, bytes, and basis points; there is no unit
conversion or floating-point evaluation. The accepted units, bounded metadata,
and size/count ceilings live in the [observation contract](../internal/spec/observations.go).
Declare synthetic inputs through the existing check/fixture contract.

The original acceptance Job emits exactly one `ObservationReport` JSON object
to stdout. **Stdout must be clean.** The current Kubernetes adapter reads combined
stdout/stderr logs, so stderr must also remain empty. Separate stderr diagnostics
require a stream-aware adapter; this adapter does not provide one. Banners,
progress messages, prompts, raw answers, and attachments cannot accompany the
document. Unknown fields, duplicate keys/metrics, missing or extra metrics,
changed units, missing/extra samples, unsafe integers, and malformed or oversized
output block acceptance. Parse diagnostics never include the output.

The report echoes the version, declared profile, and `contractDigest`: SHA-256
of the RFC 8785 canonical contract JSON, using the restricted safe-integer
profile in [spec I/O](../internal/spec/io.go). Prepare that digest with the
application's test recipe. The report records application-observed runtime
version, device, device mode, warm/cold state, concurrency, and samples indexed
consecutively from one. Every sample lists metric names, units, and integer
values in contract order. The [focused CPU fixtures](../internal/engine/observations_test.go)
show a fixture assertion, latency budget, and allocation budget.
Use `mixed` or `unknown` when the application cache state cannot be described as
warm or cold. Those labels retain the gap and do not qualify a cache condition.

These are **application-reported** values. The application must observe its
actual serving runtime and resource conditions; this pass neither assigns its
devices nor independently instruments GPU memory. A metric's meaning and
measurement method belong to its declared assertion revision. The local
JSON/HTML/Markdown reports retain the declaration, limitations, and all valid
samples, including failed bounds. JSON and HTML also retain the source Job/Pod
identities and output digest. Support summaries remain allowlisted projections.

Complete results stay in the operator's SQLite journal. The cluster run record
keeps a bounded `RunJournalSummary` with status, domains, check counts, and a
SHA-256 digest and byte count of the complete compact JSON result. That digest
refers to the bytes retained locally. The cluster record cannot reconstruct the
samples or replace a lost operator journal; adding valid reports must not exceed
the cluster metadata size limit during finalization.

Release validation limits aggregate retained observation evidence before any
execution, including recovery checks. Split an oversized check profile rather
than discarding samples or increasing the reader's document limit. The bound
reserves room for other run evidence; unusually large unrelated diagnostics can
still exceed the local result limit and must not replace the last readable result.

Collection first confirms the admitted Job UID and recipe and a unique completed
Pod with its original controller owner and recipe. It durably binds the Pod UID
before reading logs and rechecks identity afterward. Resume collects only from
that original Pod, or retains a finalized result without rereading logs or
rerunning the check. Missing evidence and transport/identity uncertainty remain
blocked. An observed failed bound remains failed; changed previously captured
output cannot replace the original evidence. Trusted cluster administration is
still required: log requests and UID checks are not one atomic API operation.

A failed optional numeric bound stays failed after interruption. It need not
block required application acceptance when resume can confirm the original
successful Job and completed Pod, and retain the original samples without
rerunning the test. Missing, replaced, or still-running sources block continuation.
This does not permit blind retries of a failed application worker.

The engine evaluates the whole declared sample set without averaging away a
failure or retrying until a sample passes. The author must disclose any internal
sampling/retries in the test revision and limitations. Seeds do not establish
determinism across hardware, kernels, or runtimes. A small synthetic sample set
does not establish production capacity, general AI quality or safety, or a
qualified GPU/runtime profile. Warm/cold metadata describes application state;
declare image, registry, and node-cache scope in the limitations when relevant.
