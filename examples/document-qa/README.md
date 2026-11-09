# Synthetic document-QA delivery fixture

This example exercises Cinderlock's delivery mechanics with a deterministic
Python-standard-library service, SQLite persistence, and local JSON model and
tokenizer assets. It is **not an LLM, GPU inference, or AI quality qualification**.
The scorer ranks documents by token overlap; there are no model downloads,
runtime package installs, external APIs, or pip dependencies.

The container runs as UID/GID 10001, matching the executor's Job identity. The
Helm chart uses one replica, a retained data PVC, a non-root read-only root
filesystem, no service-account token, and a temporary directory mount. Its full
image binding is `.Values.image`. Change the chart metadata and `appVersion`
values deliberately when preparing the target release.

## Workflows

| Command or endpoint | Purpose |
| --- | --- |
| `serve` | Initialize only an empty fixture database, load local assets, and serve port 8080 |
| `POST /documents` | Store a bounded synthetic `{id,text}` document |
| `GET /documents/{id}` | Read the exact persisted fixture |
| `GET /query?q=redwood` | Run deterministic lexical retrieval |
| `GET /health` | Resource readiness: model loads and schema matches; maintenance is reported separately |
| `GET /version` | Report application/schema/model identities and the explicit synthetic-workload label |
| `probe --base-url URL --check ingestion` | Store and read a named synthetic fixture |
| `probe --base-url URL --check query` | Verify retrieval of that previously stored fixture |
| `probe --base-url URL --check persistence` | Verify the fixture remains without reinserting it |
| `observe --base-url URL --fixture PATH` | Report ordered persistence assertions, client latency, and client traced allocation as numeric observations |
| `quiesce`, `resume-writes` | Set the database-backed maintenance gate |
| `backup --out PATH` | Create an instance/operation-bound SQLite backup and digest manifest; no overwrite |
| `migrate --to 2 --operation-id schema-v1-v2` | Perform schema 1 → 2 under a write lock, then commit the ledger and schema together |
| `reconcile --operation-id ID` | Check the application-side committed operation and current schema |
| `restore --backup PATH --authorize-test-restore` | Restore an approved fixture copy; retains maintenance until explicitly resumed |
| `seed --destination /models` | Materialize and hash-check immutable local model/tokenizer files and publication marker |

The executable is `python /app/app.py` inside the image. Commands default to
`/data/app.sqlite`; a custom `--database PATH` goes before the subcommand.
`FIXTURE_DATABASE`, `MODEL_DIR`, `APP_VERSION`, and `SCHEMA_TARGET` can configure
the intended container profile. CLI flags take explicit precedence.

Pass `--fixture PATH` to a probe to read the exact synthetic document from a
staged JSON file. [fixtures/document.json](fixtures/document.json) contains the
default synthetic document. The probe rejects unknown fields, invalid document
IDs, duplicate keys, and invalid or oversized text. Ingestion writes that
document; persistence reads it without recreating it. Keep the same file for
checks before and after a restart or recovery.

The numeric runner uses the fixed application-owned contract returned by
`observation_contract()` in [app.py](app.py). Each sample reads the previously
stored fixture once; failed assertions remain in the same report, and no sample
is retried. Timing includes the client probe and fixture decoding. Allocation
means peak Python memory traced in that test-client process during each probe;
it excludes the serving process, native/RSS memory, and GPU memory. Cache warmth
remains unknown. These three synthetic reads do not qualify production capacity
or an AI profile.

Numeric Jobs emit only the bounded report, with no document text or response
bodies. A completed measurement exits zero; Cinderlock evaluates every sample
against the signed bounds. The integration workflow also uses
`--memory-limit-bytes 0` for an explicitly optional negative control: actual
traced allocation must exceed that bound while independent required checks pass.
The [observation guide](../../docs/observations.md) defines the evidence and
acceptance boundaries.

## Upgrade and recovery order

Prepare baseline schema 1 and a synthetic document. The supported reference
transition is: quiesce → backup → migrate → deploy schema-2 application →
resume-writes → restart → persistence → remaining required checks. Resource readiness
can pass while maintenance is set, so Helm can finish without unquiescing data
early. Functional checks still fail until writes/read workflows are resumed.

The migration takes a SQLite write lock and records its durable completion in
the same transaction as the schema/data change. Repeating the same declared
transition validates the target state and ledger. An absent or conflicting
commit does not reconcile successfully.

The GitOps data rehearsal has a stricter continuity requirement: the old
Deployment must stay healthy after migration while the customer adopts its
successor. For that synthetic profile only, `serve --maintenance-ready` or
`MAINTENANCE_READY=1` keeps the quiesced schema-1 server's `/health` response
healthy after the known schema-2 migration. Normal document and query operations
still return unavailable until maintenance ends and the serving schema matches.
The default profile is unchanged. This opt-in models application compatibility
during maintenance; it does not relax the engine's controller readiness checks
or establish a general compatibility guarantee.

The persistent GitOps [fixture recipes](../../tests/integration/gitops_data_inputs.py)
retain the native quiesce, backup, migration, resume, actual document deletion,
and v3 restore commands. Their operational restart is a signed Job that deletes
one exact original Pod and waits for its ready controlled replacement, using
an explicitly injected short-lived token and namespace-scoped API permissions.
It does not alter the Deployment, Helm history, or Git/Argo source. V1/v2 retain
their restart-based repair, surrounded by quiesce, read-only database integrity
validation, and resume procedures. Those repairs do not restore missing data.
The rehearsal's actual backup restoration is the separate v3 procedure.

Backups require quiescence and preserve the database instance identity, schema,
content digest, and operation ID. An existing path from another operation is
rejected. New Cinderlock runs need a new backup path when prior backups remain.
Restoration requires the explicit test-restore flag and a matching backup
manifest; it is a data restore, not an image rollback. Keep this procedure on
approved synthetic/test data. A successful fixture restore does not qualify a
production database or another backup backend.

## Model staging

The image includes tiny declared assets under `/app/models` for a self-contained
default. To exercise separate per-revision model storage, run the image's `seed`
command on a new PVC and set `.Values.models.existingClaim` to that PVC. The app
mounts it read-only at `/models`. The helper refuses mismatched partial content
and publishes the marker only after both files match. Matching hashes here
identify fixture assets; they do not establish real model compatibility.

## Validation

Run `python3 -m unittest discover -s examples/document-qa -p test_app.py` and
`helm lint examples/document-qa/chart`. Tests cover actual HTTP ingestion,
retrieval, persistence across server restart, quiescence, concurrent migration
retries, commit reconciliation, corrupt-backup refusal, test-copy restore,
concurrent seeding, missing model assets, duplicate input keys, and prohibited
probe redirects. Numeric runner cases check each actual HTTP read, failed
assertions and allocation bounds, and output privacy. These tests use no GPU and
no external network.

Python's standard-library `http.server`, `sqlite3`, `urllib`, and file APIs supply
the underlying implementation. Their published examples and APIs are available
in the [CPython repository](https://github.com/python/cpython/tree/v3.12.0/Lib).
This fixture is for delivery testing, not a production web-server template.
