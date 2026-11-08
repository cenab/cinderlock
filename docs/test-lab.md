# Disposable Kubernetes test lab

This guide prepares the explicit inputs for
[the CLI integration runner](../tests/integration/kind.py). The runner installs
a synthetic document application, upgrades its SQLite schema while preserving
data, deliberately fails persistence acceptance, and executes a separately
authorized synthetic restore. It is a workflow test, not an LLM, GPU, production
restore, or physical-air-gap test.

> **Note:** This is a preview feature currently under active development.

## Prerequisites and scope

Use a disposable Docker host with Python 3.12 or newer, Docker Buildx, kind,
kubectl, and the Go version in [go.mod](../go.mod). Prepare the digest-admitted
Helm executable with the [pinned source/dependency recipe](../tools/helm/), then
put its output directory first in this shell's `PATH`. That recipe currently
builds Helm v4.3.1 with patched dependencies and Go 1.27.3. The observed initial
lab used kind v0.33.0 and Linux arm64 node/workload images. The
[qualification record](qualification.md) includes the completed patched-Helm
workflow. Image
builds and initial image acquisition are connected preparation actions. Other
architectures or tool versions need matching inputs and their own validation.

The recipe below creates a separate `cinderlock-lab` cluster and registry on
port 5006. Choose unused names and a free loopback port. Every Kubernetes
command specifies the dedicated kubeconfig and context. Do not point this
runner at an existing customer or production cluster. The runner refuses a
context outside the `kind-cinderlock-*` prefix and a registry outside loopback;
those name checks are guards, not proof that a cluster is disposable.

From the repository root, prepare private working paths and the host binary:

```sh
umask 077
CINDERLOCK_LAB_DIR="$(pwd)/.local/test-lab"
CINDERLOCK_LAB_NAME=cinderlock-lab
CINDERLOCK_LAB_REGISTRY=cinderlock-test-registry
CINDERLOCK_LAB_PORT=5006
CINDERLOCK_LAB_ARCH=arm64
CINDERLOCK_LAB_PLATFORM="linux/${CINDERLOCK_LAB_ARCH}"
mkdir -p "$CINDERLOCK_LAB_DIR/helper"
make build
```

Keep these variables in the same shell for the following steps. The working
directory and run receipts remain local and ignored by Git.

## Prepare the cluster and registry route

Acquire the node and registry images through your approved preparation process.
These are the identities used by the observed lab; they do not certify another
cluster profile:

```sh
docker pull kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
docker pull registry@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c
kind create cluster --name "$CINDERLOCK_LAB_NAME" \
  --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5 \
  --kubeconfig "$CINDERLOCK_LAB_DIR/kubeconfig"
docker run --detach --pull never --name "$CINDERLOCK_LAB_REGISTRY" \
  --network kind --publish "127.0.0.1:${CINDERLOCK_LAB_PORT}:5000" \
  registry@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c
```

The host pushes to loopback. Nodes need a containerd route to the registry
container because their loopback is a different network namespace. This follows
the documented [kind local-registry routing pattern](https://kind.sigs.k8s.io/docs/user/local-registry/).
That guide's example is Apache-2.0, copyright The Kubernetes Authors. Current
kind node images already enable the registry configuration directory; older
images require their documented containerd configuration patch.

```sh
cat > "$CINDERLOCK_LAB_DIR/hosts.toml" <<EOF
[host."http://${CINDERLOCK_LAB_REGISTRY}:5000"]
  capabilities = ["pull", "resolve"]
EOF
for CINDERLOCK_LAB_NODE in $(kind get nodes --name "$CINDERLOCK_LAB_NAME"); do
  docker exec "$CINDERLOCK_LAB_NODE" mkdir -p "/etc/containerd/certs.d/127.0.0.1:${CINDERLOCK_LAB_PORT}"
  docker exec -i "$CINDERLOCK_LAB_NODE" cp /dev/stdin \
    "/etc/containerd/certs.d/127.0.0.1:${CINDERLOCK_LAB_PORT}/hosts.toml" \
    < "$CINDERLOCK_LAB_DIR/hosts.toml"
done
kubectl --kubeconfig "$CINDERLOCK_LAB_DIR/kubeconfig" \
  --context "kind-${CINDERLOCK_LAB_NAME}" get nodes
```

This loopback HTTP registry is an explicit test capability. A customer registry
needs its own TLS, CA, credentials, node pull access, and qualification. The
containerd mapping changes image pulls only; application Pods do not acquire
host loopback access through it.

## Build the application and fixed helper OCI archives

The runner consumes OCI-layout tar archives with reference `1`, not Docker
daemon image-save archives. Use a dedicated container builder that supports
[OCI archive exports](https://docs.docker.com/build/exporters/oci-docker/).
Creating this named builder doesn't change your selected default builder.
Build the application from the checked-in fixture:

```sh
docker buildx create --name "${CINDERLOCK_LAB_NAME}-builder" --driver docker-container \
  --driver-opt image=moby/buildkit:v0.33.0@sha256:6c2fa84a6b61ccd72899dde4239f8d5717f05f9a8ca6f3cad185fb1a95a94de3
docker buildx inspect "${CINDERLOCK_LAB_NAME}-builder" --bootstrap
docker buildx build --builder "${CINDERLOCK_LAB_NAME}-builder" --platform "$CINDERLOCK_LAB_PLATFORM" \
  --provenance=false --sbom=false --tag cinderlock/document-qa:1 \
  --output "type=oci,dest=${CINDERLOCK_LAB_DIR}/application.oci.tar,oci-mediatypes=true" \
  examples/document-qa
```

Build a static Linux helper from the same source and place it in a minimal
image. Its fixed command verifies the seeded model tree; the application image
runs the synthetic HTTP probes with Python. This helper is not a general
shell/curl test-runner image.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH="$CINDERLOCK_LAB_ARCH" \
  go build -trimpath -o "$CINDERLOCK_LAB_DIR/helper/cinderlock" ./cmd/cinderlock
cat > "$CINDERLOCK_LAB_DIR/helper/Dockerfile" <<'EOF'
FROM scratch
COPY --chmod=0555 cinderlock /usr/local/bin/cinderlock
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/cinderlock"]
EOF
docker buildx build --builder "${CINDERLOCK_LAB_NAME}-builder" --platform "$CINDERLOCK_LAB_PLATFORM" \
  --provenance=false --sbom=false --tag cinderlock/helper:1 \
  --output "type=oci,dest=${CINDERLOCK_LAB_DIR}/helper.oci.tar,oci-mediatypes=true" \
  "$CINDERLOCK_LAB_DIR/helper"
```

The fixture Dockerfile uses a base tag during preparation; the resulting image
graph is locked by digest for delivery. A bit-identical image rebuild is not
claimed. Inspect the root OCI indexes before use:

```sh
tar -xOf "$CINDERLOCK_LAB_DIR/application.oci.tar" index.json
tar -xOf "$CINDERLOCK_LAB_DIR/helper.oci.tar" index.json
```

Both must expose `org.opencontainers.image.ref.name` equal to `1` and the
selected workload platform. Their exact image bytes are imported into the test
registry by Cinderlock, then pulled by actual Kubernetes workloads.

## Run the integration workflow

Use a new run directory; the runner retains existing work and does not overwrite
an earlier run. All required flags are explicit:

```sh
python3 tests/integration/kind.py \
  --binary "$(pwd)/bin/cinderlock" \
  --kubeconfig "$CINDERLOCK_LAB_DIR/kubeconfig" \
  --context "kind-${CINDERLOCK_LAB_NAME}" \
  --registry "127.0.0.1:${CINDERLOCK_LAB_PORT}" \
  --registry-container "$CINDERLOCK_LAB_REGISTRY" \
  --workdir "$CINDERLOCK_LAB_DIR/run-01" \
  --application-oci "$CINDERLOCK_LAB_DIR/application.oci.tar" \
  --helper-oci "$CINDERLOCK_LAB_DIR/helper.oci.tar" \
  --platform "$CINDERLOCK_LAB_PLATFORM"
```

The runner creates a fresh namespace, private release/approval keys, an explicit
test policy and Site, three signed release bundles, target-bound plans, and
exact-plan authorizations. The fixed test policy includes its HTTP registry,
destructive synthetic restore, and lab observation/retirement capabilities.
It is not a production least-privilege policy template.

The registry container argument must name the running registry created above.
Before creating a namespace, the runner reads only that named container's Docker
inspection and requires its IPv4 address on the `kind` network. It retains a
typed identity/address record rather than raw Docker configuration. A selectorless
`registry-probe` Service and EndpointSlice route port 5000 to that address inside
the new namespace; their lab labels do not declare application ownership.

Every normal and recovery recipe requires the native helper to observe HTTP 200
from `http://registry-probe:5000/v2/` before non-import work. The Site and test
policy explicitly admit the host and HTTP endpoint capabilities. Public worker
events, the original Job UID/recipe, unique completed Pod and exit zero are
checked against the bounded helper JSON; `*-endpoint.json` contains the typed
proof. This is one Job-context response, not fresh node pull-credential validation,
continuous registry health, or network-isolation evidence.

The first release installs and creates the synthetic document. The second
stages a separate model PVC, quiesces writes, backs up, migrates schema 1 to 2,
deploys, restarts, and checks persistence before any check can reinsert the
document. The third deliberately deletes that document after backup. Its
required persistence Job must fail with the actual HTTP 404. A separate
recovery plan restores the synthetic backup and rechecks workflows; the failed
upgrade's acceptance remains failed.

Required numeric Jobs retain every ordered HTTP fixture assertion, client probe
latency, and test-client Python traced-allocation sample. The second release
also declares an explicitly optional zero-allocation-budget control: it must
retain a numeric failure while the independently required workflows pass.
This does not replace the third release's real missing-document failure. The
runner rereads results through `run report`, checks the original completed Job
and unique Pod identities before reading their full numeric output, then compares
the output digest and all retained samples. These resource observations exclude
serving-process and GPU memory; they do not qualify a real inference profile.

A successful final runner exit is the workflow assertion. A passing v1 or v2
receipt alone does not establish the deliberate-failure/recovery case. Inspect
`summary.json`, per-run results, private command receipts, and `recovery.html`.
Failure receipts identify the exact command; preserve the lab for inspection
rather than rerunning an uncertain mutation blindly. Never publish private
keys, kubeconfigs, state databases, or unreviewed raw receipts.

## Inspect and retire the disposable environment

The runner prints and retains its generated namespace. Use that exact name and
the dedicated configuration when inspecting it:

```sh
kubectl --kubeconfig "$CINDERLOCK_LAB_DIR/kubeconfig" \
  --context "kind-${CINDERLOCK_LAB_NAME}" -n REPLACE_WITH_PRINTED_NAMESPACE get pods,pvc,jobs
```

When finished reviewing the synthetic lab, deleting its cluster removes its
test workloads and local data. Keep receipts under your chosen retention policy:

```sh
docker buildx rm "${CINDERLOCK_LAB_NAME}-builder"
kind delete cluster --name "$CINDERLOCK_LAB_NAME" \
  --kubeconfig "$CINDERLOCK_LAB_DIR/kubeconfig"
docker stop "$CINDERLOCK_LAB_REGISTRY"
docker rm "$CINDERLOCK_LAB_REGISTRY"
```

Keep each integration receipt with its source and tool identities. The
[qualification record](qualification.md) states the scope of completed runs.
Creating this lab does not establish network isolation.
