# Cinderlock

Cinderlock is an open-source Go tool for preparing and operating customer-run
offline application releases, including AI application artifacts. It packages
declared images, models, charts, and tests into a signed bundle, creates a plan
against an explicit Kubernetes target, and records execution and acceptance
locally.

> **Note:** This is a preview feature currently under active development.

The current execution adapter targets an existing Kubernetes cluster, an
approved internal registry, and a digest-pinned Helm executable. NVIDIA probes
and profile checks are implemented, but real GPU inference and production
recovery are not qualified. Cinderlock does not install a cluster or drivers,
establish a physical air gap, or prove that undeclared application behavior is
offline. Existing Zarf package compatibility is not implemented.

## Try the local workflow

You need the Go version declared in [go.mod](go.mod). Dependency acquisition is
a connected preparation step; use an admitted dependency/toolchain copy for an
offline build. Build and run the package checks from the repository root:

```sh
make build
make check
./bin/cinderlock --help
./bin/cinderlock scan examples/document-qa --output json
```

The [document-QA fixture](examples/document-qa/README.md) uses Python's standard
library and SQLite. It exercises ingestion, retrieval, persistence, migration,
and test-copy restore with synthetic data. It is a lexical scorer, not an LLM.
You can run its tests without Docker, Kubernetes, or a GPU:

```sh
python3 -m unittest discover -s examples/document-qa -p test_app.py
```

## Prepare and deliver a release

A release author supplies a packaged Helm chart, explicit image bindings,
assets, supported source revisions, operation recipes, required application
checks, and recovery procedures. Start a declaration with:

```sh
./bin/cinderlock release init --out release.yaml
```

This skeleton is intentionally incomplete. Complete it for your application
before validation; the [contract types and validation](internal/spec/) define
the accepted alpha schema. Input files must stay inside the release workspace.
Keep private keys and credentials outside that workspace and source control.

For a completed declaration and a producer key admitted through your release
process, preparation uses the following sequence:

```sh
./bin/cinderlock release validate release.yaml
./bin/cinderlock release lock release.yaml --out release.lock.json
./bin/cinderlock bundle build release.lock.json \
  --key /private/producer.key --key-id vendor-release --out release.cinder
```

Locking can acquire declared sources. Building uses the populated local cache.
For private sources, `release lock --source-auth FILE` reads exact host-scoped
credentials from a private file outside the workspace. Explicitly admit any
required download/CDN redirect hosts. The credential format and transfer
boundaries are described in [bundle implementation](docs/REUSE-bundle.md).

Transfer the bundle through the customer's approved intake process. The
customer independently provisions its trust policy and verifies every payload:

```sh
./bin/cinderlock bundle verify release.cinder --trust /private/site-trust.json
./bin/cinderlock bundle sbom release.cinder \
  --trust /private/site-trust.json --out artifact-inventory.json
```

`trust keygen` creates Ed25519 keys. `trust init` and `trust propose-update`
write candidate policies for independent review; they do not enroll themselves.
The signed CycloneDX inventory describes artifacts and files. It does not run a
package or vulnerability scanner.

Sites that admit source builds can [export sources, vendor dependencies, licenses,
and an optional Go/Helm toolchain](docs/source-export.md), then verify and compile
the independently admitted distribution without Go network acquisition.

## Plan and operate an admitted target

A private Site declaration must select the kubeconfig, context, namespace,
release name, internal registry, toolchain digest, trust policy, capabilities,
and local secret references. Prepare the namespace, registry routes, storage,
image pull access, and approved helper images first. A GPU profile also requires
fresh, separately authorized hardware evidence.

With that environment and a separately admitted customer approval key, run:

```sh
./bin/cinderlock target inspect --site /private/site.yaml --out target.json
./bin/cinderlock trust admit-policy --site /private/site.yaml
```

Independently review the selected policy and the preview's exact digest, then
set `REVIEWED_POLICY_DIGEST` to that digest. Enroll it in the same local state
directory you will use for planning and execution:

```sh
./bin/cinderlock trust admit-policy --site /private/site.yaml \
  --approved-digest "$REVIEWED_POLICY_DIGEST"
./bin/cinderlock run plan release.cinder \
  --site /private/site.yaml --out plan.json
./bin/cinderlock run authorize plan.json \
  --key /private/customer-approval.key --key-id customer-approval \
  --out authorization.json
./bin/cinderlock run apply plan.json --authorization authorization.json
```

Review the plan before authorizing it. A changed site, policy, signed recipe, or
critical target state requires a new plan. Keep the same state directory for
later `run status`, `run resume`, `run recovery-plan`, and `run report` commands.
A timeout can leave remote work running; inspect and reconcile its outcome
before retrying. Recovery requires a separate plan and authorization.

For later policy changes, `trust update-sign`, `trust update-preview`, and
`trust update-admit` use a separately scoped current policy administrator and
an exact next-epoch packet. Admission prepares a new policy file; select it in
the Site explicitly after successful admission. Losing the local journal also
loses its retained policy and release replay floors.

`doctor` reports local build capabilities without choosing a Kubernetes context.
Use `doctor --site FILE` only when you intend to inspect that explicit target.

## Read the implementation boundaries

The [feature audit](docs/features.md) maps every original F01–F50 requirement to
implemented behavior, tests, and remaining gaps. It is the coverage reference;
the presence of a command does not establish a qualified deployment profile.
The [qualification record](docs/qualification.md) describes the passing CPU
workflow and the limits of the observed evidence.

- [Architecture and trust boundaries](docs/architecture.md)
- [Release scripts and offline prerequisites](docs/release-contracts.md)
- [Fixed endpoint preflight](docs/endpoint-preflight.md)
- [Kubernetes permission planning](docs/permissions.md)
- [Configuration ownership and masked review](docs/configuration.md)
- [Storage peaks and capacity assertions](docs/storage-planning.md)
- [Native offline model staging](docs/native-model-staging.md)
- [GitOps image staging and local source proposals](docs/gitops.md)
- [GitOps mutable data procedures and recovery](docs/gitops-data.md)
- [Verified acceptance fixtures](docs/fixtures.md)
- [Application-owned numeric observations](docs/observations.md)
- [Bundle intake and custody records](docs/intake.md)
- [Signed trust updates](docs/trust-updates.md)
- [Disposable Kubernetes integration lab](docs/test-lab.md)
- [Bundle, inventory, and transfer source reuse](docs/REUSE-bundle.md)
- [Execution adapter and source reuse](docs/REUSE-engine.md)
- [Reports, support exports, and optional catalog](docs/REUSE-service.md)
- [Recorded comparisons, local outbox, and external evidence](docs/catalog-observations.md)
- [Reviewable static configuration patches](docs/discovery.md)
- [Catalog development database](deploy/catalog/README.md)
- [Security boundaries](SECURITY.md)
- [Apache-2.0 license](LICENSE)
