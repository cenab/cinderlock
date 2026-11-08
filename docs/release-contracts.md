# Application script and prerequisite contracts

A release declares what its application scripts may change and how their result
will be checked. The [contract validator](../internal/spec/release_contracts.go)
owns the accepted schema. Declarations remain the release author's claims;
Cinderlock cannot infer a safe migration or valid entitlement from shell text.

> **Note:** This is a preview feature currently under active development.

## Script scope and success evidence

Every authored operation Job, custom seed command, and Job check requires a
`script` contract. Its `inputs`, `permissions`, and `sideEffects` are explicit
descriptions, including the existing image, arguments, secret references, mounted
data, external application access, and destructive scope when applicable. Keep
credential values out of these portable descriptions. Native adapters and fixed
HTTP GET/HEAD checks have their own bounded contracts and reject authored script
declarations.

Descriptions never grant Kubernetes rights, change the worker's fixed security
settings, or establish network enforcement. Actual rights still come from the
customer's policy, approval, credentials, and the application itself.

An operation's `successChecks` names required application workflow or recovery
checks in that same recipe. Their images must be declared, nonoptional locked
assets. A recovery recipe cannot borrow evidence from the main release recipe.
Worker completion is retained separately from application acceptance; acceptance
still requires all required checks to pass.

A Job check may name its own ID as success evidence, including when it is
optional. This means only that the original locked check recipe completed with
its expected result. The application author must make that recipe test the
promised behavior. Optional results never replace required acceptance, and
neither a named check nor exit zero proves untested application properties.

## Retry classification

Classification does not enable automatic repetition. Every worker keeps the
existing durable intent, server identity, and conservative resume protocol.

| Classification | Operation declaration | Meaning after interruption |
| --- | --- | --- |
| `retry-safe` | `idempotent: true` | The author asserts repeat safety; the engine still establishes the original worker's fate before another attempt. |
| `reconcilable` | `idempotent: false` and explicit `reconcileCommand` | The application supplies a commit probe; it cannot fence an unobservable worker, and Cinderlock does not automatically run arbitrary reconciliation commands. |
| `manual` | `idempotent: false`, no reconciliation argv | The first exact authorized execution is supported; a failed or uncertain outcome requires original-worker reconciliation or reviewed recovery. |

Job checks support `retry-safe` and `manual` declarations. Authored check
reconciliation is unsupported. Failed or uncertain checks never start a duplicate
worker during resume, even when their declaration says repetition is safe.

## Intermediate release routes

A transition's ordered `intermediateReleases` names releases that must precede
the target. The target declaration must include a direct transition from the
final intermediate release. Selecting a route produces an actionable planning
blocker; Cinderlock does not fetch or execute a chain automatically. Admit each
intermediate bundle separately, complete its supported transition, and create a
new target plan from the actual installed state.

## Offline entitlement and renewal

An offline `license` names customer-local material through `secretRef`, a
required application workflow Job through `check`, and bundled vendor renewal
instructions through `renewalAsset`. The Job must consume that secret reference
and its own declared locked image. It cannot require staged acceptance fixtures,
because it must run before application mutation. Executable recovery recipes
must include their own required entitlement check using the same material
reference.

Approved image imports may precede validation. Every application mutation waits
for the entitlement Job, and final acceptance reuses that same durable check
intent. Secret presence alone never establishes entitlement. Failed or uncertain
validation blocks execution without an automatic rerun. After the validation
wait, the engine rechecks approval, policy, coordination, and the bound target
and secret checkpoint before following application work.

`maxAgeSeconds` limits the age of the original worker's server completion time;
it is not a license issuance date. Missing, future-dated, or stale completion
evidence blocks further application mutation and acceptance. Reconciliation does
not refresh it. Optional `expiresAt` is an additional signed upper validity
bound checked during planning and at execution boundaries. These comparisons
depend on trustworthy cluster and operator clocks.

The vendor's bundled procedure must describe its supported offline renewal,
material acquisition, customer intake, validity checks, and failure escalation.
Follow that procedure and customer policy, replace the customer-managed material,
and create an appropriately authorized plan or recovery procedure. Changed
secret metadata invalidates the old checkpoint. Resolve any original worker's
outcome before a new attempt. A new signed upper validity bound requires newly
admitted vendor release content. Cinderlock does not renew licenses, bypass
activation, or change license terms.

This preview requires explicit declarations on existing authored scripts and
Job checks. Older declarations, locks, and bundles without them must be
reauthored, relocked, rebuilt, and replanned; never edit signed metadata in place.
