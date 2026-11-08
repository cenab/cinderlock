# Catalog, reporting, and support implementation

The optional catalog is a local metadata service. It does not execute Kubernetes
operations or turn imported observations into execution authorization. The CLI
and run journal remain usable without it.

## Reused libraries and examples

| Source | Reused behavior | License |
| --- | --- | --- |
| [Go `html/template` examples](https://github.com/golang/go/blob/go1.27.1/src/html/template/doc.go) | Contextual escaping for both reports and the server-rendered catalog; untrusted values never use `template.HTML` | BSD-3-Clause |
| [Go `net/http`](https://github.com/golang/go/tree/go1.27.1/src/net/http) | HTTP handlers, timeouts, TLS, request-body bounds, and response headers | BSD-3-Clause |
| [go-oidc ID-token example](https://github.com/coreos/go-oidc/blob/v3.14.1/example/idtoken/app.go) | Provider discovery and verified issuer/audience/expiry/signature; explicit local subject-role bindings | Apache-2.0 |
| [pgx `database/sql` example](https://github.com/jackc/pgx/blob/v5.7.5/stdlib/sql.go) | PostgreSQL driver registration and `database/sql` access | MIT |
| [modernc SQLite](https://pkg.go.dev/modernc.org/sqlite@v1.36.3) | CGo-free local transactional storage | BSD-3-Clause |

Dependency versions are pinned in `go.mod` and `go.sum`. Common signing and
strict canonical JSON behavior reuse `internal/spec`; there is no separate
report or catalog implementation of the release contracts.

## Local catalog

Create a random token in a private file, obtain its hash using
`cinderlock catalog hash-token FILE`, and put the hash into a private catalog
configuration. Do not pass the token through process arguments or check it into
the repository. The file must be a regular file with no group/other access.

The following is a configuration template; replace the token hash before use.

```yaml
apiVersion: cinderlock.dev/v1alpha1
kind: CatalogConfig
origin: http://127.0.0.1:8088
actors:
  - id: release-operator
    tokenHash: REPLACE_WITH_THE_64_CHARACTER_LOWERCASE_SHA256_HASH
    projects:
      demo: [publisher, operator]
    sites: [lab]
packetKeys: []
```

Start the catalog with the existing binary:

```text
cinderlock catalog serve --config private/catalog.yaml --database private/catalog.db
```

The listener defaults to loopback. Non-loopback binding requires explicit
`--allow-remote`, a TLS certificate, and a TLS key. PostgreSQL uses
`--driver pgx --dsn-file private/postgres-dsn`; credentials are read from the
private file, not accepted as a DSN command argument.

The browser can use HTTP Basic authentication with the local token as its
password. API callers use a bearer token. No cookies or browser session token
are created. Mutation requests additionally require `Content-Type:
application/json`, `X-Cinderlock-Request: 1`, and an `Idempotency-Key`; a supplied
Origin must match the configured origin. Do not expose the loopback HTTP mode
through an unencrypted remote proxy.

## Roles and API

Roles are explicit per project: `administrator`, `publisher`, `operator`,
`approver`, `policy`, `support`, and `auditor`. Administrator does not implicitly
receive publishing, policy, or approval authority. Optional site bindings further
limit access. Support-only readers get allowlisted summaries rather than raw
record bodies.

| Endpoint | Method and behavior |
| --- | --- |
| `/` | GET: accessible, escaped, read-only catalog |
| `/api/v1/records?project=...&site=...&kind=...` | GET: scoped immutable observations |
| `/api/v1/records` | POST: role-checked record registration |
| `/api/v1/projects/{id}/releases` | GET: permitted release observations |
| `/api/v1/plan-reviews` | POST: register an original Plan for review |
| `/api/v1/policy-admissions` | POST: record customer-admitted policy observations |
| `/api/v1/site-enrollments` | POST: record site metadata; never target credentials |
| `/api/v1/approvals` | POST: exact original executable plan, current policy, target, action set, and expiry bindings |
| `/api/v1/import-previews`, `/api/v1/imports` | POST: verify a signed packet, then explicitly admit the unchanged preview |
| `/api/v1/export-previews`, `/api/v1/exports` | POST: freeze selected allowlisted projections, then produce that unchanged local export |
| `/api/v1/audit?project=...` | GET: scoped catalog admission history; site-restricted readers cannot inspect project-wide audit |

All record bodies are immutable. Repeated exact records reuse their content
identity. An idempotency key is reserved before any mutation; a different body
under the same key is rejected. If a process stops after mutation but before
recording its response, repeating that key reports a pending request. Inspect
the catalog records before choosing another request key. The service does not
claim atomicity with a cluster operation.

Catalog approval records are review metadata. They are **not** signed engine
`Authorization` objects. The local executor separately validates its own plan,
policy, credentials, state, and execution approval.

## Packet exchange and confidentiality

Read [catalog policy and observations](catalog-observations.md) for independently
admitted restrictive policy packs, recorded comparisons, the configured local
outbox, digest-reviewed notification export, and separately signed typed
evidence. These surfaces retain local execution authority and do not send
external messages.

`catalog.SignPacket` and `VerifyPacket` sign canonical `CatalogPacket` bytes
under `cinderlock.catalog-packet.v1` followed by one NUL byte. Packet keys are
independently scoped to projects/sites and optionally kinds; policy/approval
observations require explicit kind scope. Version, record kinds, sequence,
scope, exact bytes, and Ed25519 signatures are validated. Duplicate exact
packets are idempotent; reused or older sequence numbers fail closed.

Incoming packets are observations, never deployment commands. Import preview
does not create release records. The exact preview is bound to its actor,
current catalog permission policy, purpose, and expiry. Packet import publishes
records and advances replay high-water state in one database transaction.

Export previews produce allowlisted projections; they do not copy original
records wholesale. Run exports exclude target/site identities, raw errors,
logs, evidence paths, customer documents, and detailed topology. Other catalog
records export only selected identity/version/status fields. Pattern redaction
is not used as a claim that arbitrary content is safe. Review the exact bytes
and digest before moving an export through an approved process. There is no
automatic upload or return channel.

## Internal OIDC

An optional `oidc` configuration uses an explicit HTTPS issuer, client ID, and
subject-to-Actor bindings. Discovery and JWKS requests stay on that issuer's
host, reject redirects, omit ambient proxies, enforce response bounds, and use
bounded request timeouts. Local tokens can provide separately scoped emergency
access. They do not bypass role or execution approvals.

This integration verifies bearer ID tokens issued to the configured audience.
It does not implement a browser OAuth login/callback flow. Obtain tokens through
the customer's admitted identity client. Unknown subjects/roles, wrong
audiences, expired tokens, and invalid signatures are rejected. The verifier's
lazy JWKS refresh remains usable after the startup discovery context ends.

## Reports and support

`report.Render` emits standalone local HTML without external assets or scripts.
It preserves the four result domains, required checks, observations, next safe
step, and coverage gaps. It does not average away a failed required workflow.
`report.Markdown` produces a local CI summary without sending it to a service.

`support.Collect` freezes a typed summary. `support.Export` rehashes it and
requires the exact approved digest before creating a new local file. Target
topology, raw log/error content, prompts, documents, configuration and evidence
attachments are excluded by construction. Existing files are not overwritten.

## Validation and limits

Package tests cover signature tampering, packet scope/replay, cross-project
denial, request idempotency/pending outcomes, origin checks, policy-bound
approvals, HTML escaping, and support/export privacy. OIDC tests use a local TLS
issuer and exercise audience, subject, expiry, and key refresh after startup
cancellation. PostgreSQL integration runs only when
`CINDERLOCK_TEST_POSTGRES_DSN` is set; an unset variable explicitly skips it.

Back up the catalog database, replay state, configuration, and independently
managed keys together. Production backup/restore, load, internal identity
interoperability, browser accessibility, and retention qualification remain
separate operational checks. An imported or signed observation is not
independent certification or live cluster health.
