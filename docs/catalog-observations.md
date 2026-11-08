# Catalog policy and observations

The optional catalog compares admitted observations, maintains an explicitly
configured local notification outbox, evaluates restrictive policy packs, and
verifies typed external evidence. These features don't inspect live clusters,
send messages, or grant execution authority. They use the authentication, role
checks, private configuration, and
request protections described in [the catalog guide](REUSE-service.md).

## Compare recorded runs

You must admit the original `RunResult`, its exact `Plan`, and its exact `Site`
under the same catalog project and site. The run's plan hash must match the plan
body, and the plan's site hash must match the site body. Application, release
version, bundle, target, check domain, and effective required-check flags must
agree. A missing linked object blocks comparison; the catalog doesn't infer it.

Open **Compare recorded runs** from the catalog, or request the JSON endpoint:

```text
GET /api/v1/comparisons?project=plant&site=west&before=sha256:BASELINE_RECORD&after=sha256:CANDIDATE_RECORD
GET /comparisons?project=plant&site=west&before=sha256:BASELINE_RECORD&after=sha256:CANDIDATE_RECORD
```

Replace both sample hashes with complete catalog `RunResult` record digests.
These differ from the run's plan and bundle digests. Both requests are read-only.
The HTML form retains the selected digests and displays each release's profile,
bundle, test-scope identity, observation time, and recorded acceptance.

The comparison rejects another application or target. Ordinary plans and recovery
plans retain their distinct kind and source-run context. A changed plan kind,
profile, or declared test contract sets `comparable:false`, while preserving the differences
for inspection. Results identify new, missing, changed, and unchanged checks,
including declared checks without a recorded outcome. Each result domain remains
separate; there is no combined acceptance or inherited pass.

Freshness uses the recorded finish time, or start time if no finish is recorded.
The HTTP view uses a declared one-day interval and labels observations `stale`,
`recent_observation`, `future_observation`, or `time_unknown`. A recent observation
is not current health. The Go comparison API accepts an explicit positive
freshness interval of at most one year.

Linked-object lookup streams through at most the most recent thousand records
of each required kind at that project and site. Older missing dependencies need
an explicitly supported history/index extension; there is no silent fallback or
large-fleet qualification claim. Support-only identities cannot read this view.

## Admit restrictive policy packs

Policy packs add customer-controlled restrictions to catalog plan review. They
remain independent of the engine's trust policy and signed execution approval.
A satisfied pack grants no execution permission, changes no run acceptance, and
doesn't establish current health.

A policy administrator registers an immutable `PolicyPack` through the normal
authenticated record API. The [typed contract](../internal/catalog/policy.go)
accepts explicit profile names, declared operation types, and required check IDs.
For example, the body of a project-scoped record can contain:

```json
{
  "apiVersion": "cinderlock.dev/v1alpha1",
  "kind": "PolicyPack",
  "schemaVersion": 1,
  "id": "release-review",
  "expiresAt": "2027-01-01T00:00:00Z",
  "profiles": ["cpu-lab"],
  "actions": ["import", "helm"],
  "requiredChecks": ["query"]
}
```

Set your own reviewed expiry and restrictions. Supply the body inside a catalog
`Record` with its explicit project, optional site, and `kind:"PolicyPack"`.
Registration or packet import alone cannot activate restrictions. Packet imports
also require the policy role and an independently admitted packet key whose
`kinds` explicitly includes `PolicyPack`.

Independently review the resulting complete record digest, then add its exact
scope and digest to your private `CatalogConfig` and restart the catalog:

```json
{
  "policyPacks": [
    {"project":"plant", "digest":"sha256:EXACT_POLICY_PACK_RECORD"}
  ]
}
```

Replace the sample digest with the complete record digest, not the body hash.
An omitted site reuses a project-scoped pack across that project's sites. A
site-scoped admission selects a pack registered under that exact site. Neither
form reads another project or bypasses a reader's site restrictions. Multiple
applicable packs all apply; one cannot override another's denial. Omitting a
restriction field leaves that dimension unrestricted by that pack. At least
one restriction and an expiry are mandatory; unknown fields and actions fail.

Evaluate an exact admitted plan, optionally with its exact recorded run:

```text
GET /api/v1/policy-evaluations?project=plant&site=west&plan=sha256:PLAN_RECORD&run=sha256:RUN_RECORD
```

The response binds `catalogPolicyDigest`, the plan body digest, and each pack's
record digest. A check must exist and be effectively required in the plan. When
you supply a run, that same check must also have a recorded pass; missing results
fail. Profile names must match the configured allowlist, and every declared
operation must match any configured action allowlist. This action scope follows
the plan's operation list; the engine separately enforces permissions for check
execution. Unsupported plan kinds, malformed contracts, mismatched run/plan/site
identities, missing linked objects, and altered stored bytes fail closed.

If a pack applies, `/api/v1/approvals` requires the current evaluation's
`catalogPolicyDigest` alongside its existing exact-plan decision fields. Changed
configuration requires a fresh review. Pack expiry and restrictions are checked
again when recording approval and when retrying an earlier approval request.
An expired or unsatisfied pack blocks review; a historical approval remains an
observation, not a permanently valid permission. Without applicable packs, the
existing approval request remains compatible. Import previews bind the same
configuration digest and become invalid after admission configuration changes.

## Enable a local notification outbox

Notifications are disabled until your private catalog configuration declares a
matching rule. A rule has no email address, URL, connector, or sending credential:

```json
{
  "notificationRules": [
    {
      "id": "failed-upgrades",
      "project": "plant",
      "site": "west",
      "states": ["failed", "needs_reconciliation", "recovery_failed"]
    }
  ]
}
```

Merge that field into your existing `CatalogConfig`. An operator explicitly
queues a stored result; merely importing a record doesn't send or queue anything.
Use the normal authenticated JSON mutation headers and an idempotency key:

```text
POST /api/v1/notification-queues
{"project":"plant","site":"west","runDigest":"sha256:EXACT_RUN_RECORD"}

GET /api/v1/notifications?project=plant&site=west

POST /api/v1/notification-previews
{"project":"plant","site":"west","ids":["sha256:EXACT_NOTIFICATION_ID"]}

POST /api/v1/notification-exports
{"preview":"sha256:PREVIEW","approvedDigest":"sha256:PREVIEW"}
```

The queue contains immutable, deduplicated summaries of the selected observations.
It excludes raw diagnostics, evidence paths, logs, prompts, and customer documents.
Project/site labels remain local outbox metadata and appear in its reviewed
export. Automated summaries don't establish that arbitrary free text is safe to
disclose; inspect the exact preview under your policy before moving the file.

Only configured rules matching the project, optional site, and recorded run state
apply. Queueing requires an operator role; preview/export requires its export
permission. A preview binds exact pending notification identities and bytes to
the actor, current catalog configuration policy, and expiry. Changed approvals,
already exported entries, or changed pending state fail. Export marks the entries
as exported locally and returns `sent:false`; it doesn't acknowledge receipt by a
person or system. Pending list and selection size are bounded. There is no remote
notification delivery or automatic outreach capability.

An authenticated local or internal consumer can read the pending-list endpoint;
reading it does not record recipient acknowledgement.

## Verify typed external evidence

External producers can sign the versioned `catalog.ExternalEvidence` contract.
Its required fields include producer name/version, project/site, exact run,
application, plan and bundle digests, target, profile, test-scope digest, observation and
expiry timestamps, checks, claimed result, findings, coverage, and limitations.
Supported scope labels are `network-isolation`, `security-scan`,
`model-evaluation`, and `backup-restore`. These labels do not qualify a producer's
testing method. Native third-party report conversion is not implemented.

`catalog.SignExternalEvidence` signs canonical bytes with Ed25519 under the
distinct `cinderlock.external-evidence.v1` domain followed by one NUL byte.
Catalog packet, bundle, and execution-authorization signatures cannot substitute
for this signature. Bodies must use exact canonical JSON and fit the bounded
schema. Unknown fields, duplicate names, unsupported scopes, and malformed checks
are rejected.

Your private `CatalogConfig.evidenceKeys` explicitly admits each key's ID, public
key, producer, versions, projects, sites, applications, profiles, and scopes.
Optional `notAfter` and `revoked` fields restrict admission. No default producer
or public trust source is used.

Submit a signed envelope against an already admitted run:

```text
POST /api/v1/external-evidence
{
  "project":"plant",
  "site":"west",
  "runDigest":"sha256:EXACT_RUN_RECORD",
  "scope":"network-isolation",
  "evidence":{"body":{},"keyID":"ADMITTED_KEY","signature":"BASE64_SIGNATURE"}
}
```

The empty sample body is illustrative and fails validation. Supply the complete
typed canonical body and its actual signature. The verifier derives expected
subject fields from the exact linked run, plan, and site; request labels cannot
rebind them. A wrong run, bundle, profile, producer version, or key scope fails.
Expired evidence, expired key scopes, future observations, revoked keys, and
signature tampering fail.

Admission returns `integrity:"verified"` and
`acceptance:"attached_evidence_only"`. It preserves the producer's claimed result
and limits. Even an imported pass leaves a failed run unchanged. No external
evidence becomes an engine acceptance gate or authorization.

Recheck an admitted typed evidence record with:

```text
GET /api/v1/external-evidence?project=plant&site=west&digest=sha256:EVIDENCE_RECORD
```

This verifies current key admission, expiry, signature, and linked subject again.
Historical admission metadata is not permanent validity. Generic `Evidence`
records remain opaque observations and don't gain typed verification by their
name. Support-only identities cannot read raw evidence through this endpoint.

## Go APIs and validation

The service package exposes `SubjectForObservation`, `CompareObservations`, `Store.Observation`,
`Store.Compare`, `QueueNotifications`, `PendingNotifications`,
`NotificationPreview`, `ExportNotifications`, `SignExternalEvidence`,
`VerifyExternalEvidence`, and `Store.VerifyEvidence`. Lower-level store calls
require the embedding caller to enforce actor/project/site authorization and
provide its current configuration-policy digest; the HTTP handler does so.

HTTP tests cover cross-project denial, effective required checks, profile and
coverage changes, stale labels, queue enablement, immutable deduplication,
allowlisted summaries, exact export approval, producer scope, expiration,
signature domain separation, and unchanged run acceptance. An environment-gated
PostgreSQL outbox test exercises queue/preview/export with the pgx adapter.
Browser checks and these tests do not qualify production storage, GPU behavior,
customer data recovery, or external producer semantics.
