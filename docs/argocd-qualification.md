# Argo directory qualification inputs

This fixture prepares a disposable Argo directory input set.
The receipt records
`applicationAcceptance: not_established` and live qualification as pending.

The [preparation harness](../tests/integration/argocd.py) uses the existing
Cinderlock GitOps commands and the independent
[minimal chart](../examples/document-qa/argocd-chart). The chart runs the locked
Python application with its embedded `/app/models`. SQLite lives on bounded
disk `EmptyDir` storage, so Pod replacement loses its data. This profile makes
no persistence, model delivery, ingestion, recovery, or production claim.

## Prepare on the host

Run preparation only on the host with the admitted application OCI layout tar,
the actual Cinderlock binary, actual Helm, and the selected disposable lab
available. Every selection is explicit:

```sh
python3 tests/integration/argocd.py \
  --binary /private/tools/cinderlock \
  --helm /Users/batu/Developer/cinderlock/.local/tools/qualified/bin/helm \
  --application-oci /private/inputs/application.tar \
  --platform linux/arm64 \
  --workdir /private/qualification/argocd-inputs \
  --kubeconfig /Users/batu/Developer/cinderlock/.local/kubeconfig \
  --context kind-cinderlock-test \
  --registry 127.0.0.1:5005
```

Replace the tool, OCI, platform, workdir, and registry selections with your
admitted local inputs. This lab admits patched Helm `v4.3.1+cinderlock.1+gc0d08d0`
with SHA-256 `35ce1958b1f9d3e85d92b7ad2846556be9bd400def6efed2f05690d63ac5e7d8`.
The harness requires absolute executable paths, rejects a different Helm
digest before creating output, and never picks a Helm command from `PATH`.
The workdir's parent must exist without symlink
ancestors. Preparation refuses an existing workdir. It generates a fresh
`cinderlock-argocd-*` target namespace name, or accepts an explicit name under
that prefix. Create it separately with `kubectl create namespace`, or retain
its original UID receipt if the lab setup already created it. The controller namespace stays
`cinderlock-argocd-lab`.

The local OCI wrapper must be a plain tar containing only regular OCI layout
files and layout directories, at most 512 MiB and 4,096 members. Image layers
inside that layout retain their normal compression. The read-only imported
kind helper resolves platform/ref `1`; actual release locking also verifies
the selected image configuration and graph. No Docker or kubectl subprocess
runs during preparation. Export and proposal can issue the existing selected,
read-only Helm history call, so this is not a disconnected render promise.
Cinderlock passes Helm a private snapshot of the explicitly selected
kubeconfig and the same context through its existing adapter.

The workdir separates release material from keys, state, and the owned normal
Git repository. It contains test-only Ed25519 release and approval keys made
by the actual CLI. The final independent policy admits only image import,
GitOps staging, GitOps observation, and explicit plain HTTP registry access.
No Job execution capability is granted. A required authored health Job with a
timeout and worker resource declaration exists for release schema validity;
preparation never executes it.

CLI and Helm paths resolve to exact executable files and SHA-256 pins. Helm's
pin lives in the Site's normal fields. The strict baseline Site schema has no
CLI tool fields. The receipt records the preparation CLI pin, and the harness
rehashes each selected tool before invocation. The later observer can use a
separately selected exact qualification binary; preparation does not qualify it.

## Preserve the source boundary

Preparation commits a distinct inert base **A** with an explicitly synthetic
Git identity. The signed release names exactly A and `application.yaml`.
Actual `gitops export` and `gitops propose` produce the desired bytes and an
inert patch. Before applying that patch inside the owned fixture, the harness
checks its bundle/base/manifest bindings and unchanged HEAD, index, and file
bytes. It commits the accepted export as **C**, verifies a clean source, and
retains the same signed bundle. Never rebuild that bundle against C.

The receipt distinguishes Cinderlock's verified bundle-index digest from the
SHA-256 of the entire bundle file. Input records bind exact manifest,
proposal, chart, transport, and planned Application paths and bytes. No push,
customer repository, or moving source revision is involved.

The separate source transport contains only the accepted bare repository.
Empty templates, no hardlinks, removal of origin configuration, and host
`git update-server-info` prevent host configuration leakage and make dumb
HTTP Git readback possible. Its gzip is limited to 512 KiB compressed and
4 MiB expanded. The shared host/init extractor refuses links, unsafe paths,
duplicates, special files, and size violations before extraction. It restores
the empty `refs/` directory needed by a bare repository with packed refs.

The planned ConfigMap, Pod, and Service use the same imported application
image and carry no Application instance ownership label. The tokenless,
nonroot Pod extracts into bounded `EmptyDir` storage, then serves standard
Python HTTP on port 8000. This transport is outside the desired application
inventory, whose only resources are Deployment, ClusterIP Service, and
ConfigMap.

## Complete the live bindings separately

Run all live actions separately. Inspect `receipt.json` and `future-argv.json`
before running their individual argument arrays. They do not contain shell
fragments and are not an automatic executor. Create the fresh namespace,
inspect the target, and preserve the original preparation Site. Write a new
private `site-bound.yaml` with the same Site name, namespace, profile, and
explicit selections, adding `spec.clusterID` from the real snapshot's
`targetID` and `spec.namespaceUID` from its real `namespaceUID`. Verify the
snapshot's `siteID` matches the selected Site name and that the namespace UID
belongs to the newly created namespace. Preparation neither inspects a target
nor admits policy.

Review/admit that policy and use the normal image-only
`gitops artifacts-plan` → `run authorize` → `run apply` workflow. Establish
actual HTTP/Git readback of C from the source transport before creating the
planned Application. Create its explicit project first, using the recorded
project name in `cinderlock-argocd-lab`, restricted to the exact source URL,
selected namespace/in-cluster server, and Deployment/Service/ConfigMap kinds.
The core installation supplies no default project. The Application selects C, path `.`, include
`application.yaml`, the in-cluster server, and the fresh namespace. It requests
SSA explicitly and has no auto-sync, install, or operation request. The lab operator
separately requests the controller sync.

The strong observer is a separate `gitops observe-profile` command. Select its
final exact qualification binary separately from the host preparation tool.
This harness leaves live profile binding outside preparation.
Retain the original Application UID and the original RFC 3339
`notBefore` window bound before sync, then write a new private
`GitOpsProfileContract` using these exact fields:

| Field | Required source |
| --- | --- |
| `apiVersion`, `schemaVersion`, `kind` | `cinderlock.dev/v1alpha1`, `1`, `GitOpsProfileContract` |
| `profile`, `namespace` | `argocd-directory-v1`, `cinderlock-argocd-lab` |
| `name`, `uid` | Selected planned name and original real Application UID |
| `repository`, `repositoryURL` | Owned local repository and exact planned internal HTTP URL |
| `acceptedRevision` | C from the unchanged accepted repository and receipt |
| `manifestDigest` | SHA-256 of exact `desired.yaml` bytes |
| `notBefore`, `maxAgeSeconds` | Original bound window, `900` |

Check the real Application JSON against the planned source and destination,
original UID, C, and exact desired bytes. Do not invent identities or use a
local receipt timestamp to refresh freshness. The strong profile needs real
effective Directory source, completed sync inventory, health, original ordered
operation timestamps, and `argocd-controller` SSA Apply ownership. Desired
init/ephemeral containers and lifecycle hooks are unsupported; the separate
unowned source transport does not relax that boundary.

Run the merged observer with the selected tool's exact path and recorded
digest, preserving the original preparation tool pins:

```sh
/private/tools/cinderlock gitops observe-profile \
  /private/qualification/argocd-inputs/release.cinder \
  --site /private/qualification/argocd-inputs/site-bound.yaml \
  --contract /private/qualification/argocd-inputs/profile-contract.json \
  --manifest /private/qualification/argocd-inputs/desired.yaml \
  --out /private/qualification/argocd-inputs/profile-observation.json
```

Controller observation still cannot establish application acceptance or
source/data recovery. Those require separate supported, authorized workflows.

## Verify the local input pass

Run the focused tests on a host that permits loopback listeners:

```sh
CINDERLOCK_TEST_HELM=/Users/batu/Developer/cinderlock/.local/tools/qualified/bin/helm \
  python3 -m unittest discover -s tests/integration -p test_argocd_inputs.py
```

The retained HTTP/Git test must clone the advertised accepted commit and read
back the exact exported fixture bytes. A sandbox listener denial is an
unavailable capability, never a passing transport test. The other tests use
actual temporary Git repositories, real local Helm rendering, archive safety
negatives, and pre-effect target refusals. They do not substitute for the
actual CLI/Helm host preparation, image import, controller reconciliation, or
live qualification.
