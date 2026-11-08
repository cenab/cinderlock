# Qualification record

The initial alpha passes the synthetic CPU release workflow described below.
This is evidence for the recorded environment and tests. It doesn't qualify an
LLM, NVIDIA hardware, a physical air gap, or a customer's production recovery.
The [feature audit](features.md) separately identifies incomplete mechanisms.

## Recorded environment

Local CPU checks completed on November 7–8, 2026 UTC.
The operator CLI ran on macOS ARM64 with Go 1.27.3. Workloads ran on a disposable
single-node kind v0.33.0 cluster, Kubernetes v1.37.0, and Linux ARM64. The registry
was an explicitly admitted loopback HTTP test registry.

The toolchain used the [patched Helm preparation recipe](../tools/helm/):
`v4.3.1+cinderlock.1+gc0d08d0`, executable SHA-256
`35ce1958b1f9d3e85d92b7ad2846556be9bd400def6efed2f05690d63ac5e7d8`.
The helper and application images were locked by their OCI manifests. The
application is the [synthetic document fixture](../examples/document-qa/),
using Python, SQLite, and deterministic lexical retrieval.

## Application results

The latest completed native run used source `8db0077`, frozen operator/helper
executables, and a separately locked application image on November 8, 2026 UTC.
Later source changes require their own validation; this run does not qualify
the current branch automatically.

The [integration runner](../tests/integration/kind.py) used fresh keys, a new
namespace, a separate operator journal, and signed bundles and authorizations.
Every Kubernetes operation selected the disposable kubeconfig and context.

| Transition | Observed result |
| --- | --- |
| Initial install | Passed six required checks: internal registry HTTP response, health, ingestion, query, persistence after restart, and measured numeric observations. |
| Schema 1 → 2 upgrade | Passed native model/fixture staging, quiescence, backup, migration, deployment, restart, and six required checks after explicit resume. Persistence ran before ingestion. The optional zero-allocation-budget check retained its intended failure without failing the required workflows. |
| Deliberate document deletion | All operation steps passed; persistence, query, and numeric fixture assertions failed. The original Job log reported HTTP 404. The release remained unaccepted. |
| Separate recovery | A separately authorized run restored the synthetic backup, restarted the service, and passed all five declared checks. The failed release's original record remained unaccepted. |

The upgrade's first invocation reached its 15-minute overall CLI deadline.
Inspection confirmed all 18 original Jobs completed and the eight recorded
volume/manifest bindings remained unchanged. A fresh authorization for the same
plan allowed explicit resume with an 18-minute local wait. Completed work kept
its original identities and results; no journal or worker identities were edited.
The initial failure remains in the retained evidence. This is a completed
interrupted-run exercise, not an uninterrupted timing benchmark.

The run also exercised server admission dry-runs, configuration ownership and
masked comparison, per-check read-only fixture verification, custody-head replay
rejection, and a signed policy update invalidating the previous authorization.
Remote storage capacities were explicitly labeled synthetic assertions;
physical remote free space was not measured or reserved.

Numeric checks retained three ordered samples of fixture assertions, HTTP probe
latency, and Python test-client traced allocation. That memory measurement
excludes serving-process, native, RSS, and GPU memory. The registry probe proves
one worker-context HTTP response, without establishing fresh-node image pulls
or isolation. Private inputs and receipts remain under `.local/qualification-005/`.

## Bounded Argo controller observation

On November 8, 2026 UTC, source `f8bf623` produced `ready: true` against a real
Argo CD v3.6.1 directory deployment in the disposable Linux ARM64 cluster.
The selected accepted Git commit and reviewed bytes matched a live Deployment,
ClusterIP Service, and ConfigMap, with exact field ownership, healthy rollout,
and a completed server-side-apply sync. The preparation bundle retained its
original proposal base; the customer's accepted commit was bound separately.

An earlier manual lab sync used client-side apply and was correctly rejected.
The lab operator then explicitly requested server-side apply; Cinderlock did
not create the Application or request that sync. The resulting observation
records `applicationAcceptance: not_established`. GitOps model/data preparation,
authorized application workflows, and recovery are separate unfinished paths.
This observation does not qualify other Argo versions, Flux, or production use.
Use the [Argo input guide](argocd-qualification.md) for the preparation boundary.

## Build and protocol checks

Whole-tree unit tests, race tests, vet, and formatting checks passed. PostgreSQL
tests used an actual disposable local database. Separate fault-injection tests
cover lost responses, original worker and volume identities, replacement
objects, interrupted streams, retained files, replay, and explicit resume.
These tests don't establish crash durability or production storage behavior.

Linux AMD64 and ARM64 executables compiled with CGo disabled and were inspected
as statically linked ELF files. Cross-compilation alone doesn't qualify their
complete runtime behavior on another host.

A complete source/vendor/Go/Helm/legal export was verified and compiled from a
private snapshot with an empty module cache, vendoring, and Go network lookup
disabled. The resulting CLI was not executed by that build check. Source and
toolchain authenticity still require independent admission; an inventory cannot
authorize itself.

The final source vulnerability scan reported zero reachable findings. It also
reported two advisories in imported packages whose affected paths weren't
called. This is a dated analysis of Cinderlock, not a vulnerability scan or
security certification of supplied application images or models.

Standalone report and catalog pages received desktop/mobile browser smoke
checks, keyboard checks, and visual inspection. No external assets were
requested in those checks. This isn't a complete accessibility certification.

## Hosted core baseline

[GitHub run 42455956767](https://github.com/cenab/cinderlock/actions/runs/42455956767)
passed both Go and Kubernetes jobs for commit `0a73b09` on November 8, 2026 UTC.
Its retained synthetic receipts show successful installation and upgrade,
deliberate document-loss failure, and a separately successful recovery. The
original failed release remains unaccepted. The source distribution was also
compiled with network acquisition disabled.

This baseline includes script, inventory, policy, numeric-contract and GitOps
preparation code. Its live application fixture predates the later endpoint and
measured numeric Jobs, explicit authored worker budgets and optional-failure
resume correction. The later native run above covers those changes locally;
this hosted result does not cover later commits or the strong Argo observer.

## Reproduce and extend the evidence

Use the [lab guide](test-lab.md) for fresh local inputs. The
[Check workflow](../.github/workflows/check.yml) runs the build and Kubernetes
checks on GitHub and retains synthetic results as artifacts. Hosted results
apply to the commit and environment named by that run.

Real GPU inference, browser/login and scheduled workflows, additional runtime
and storage profiles, power-loss durability, and customer backup/restore require
their own approved test scope. Passing this fixture doesn't establish them.
