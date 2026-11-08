# Pinned Helm preparation

This separate Go tool module builds the existing Helm CLI from its pinned
upstream source. Cinderlock continues to execute a digest-admitted Helm binary;
this is not a replacement Helm engine or a modification of the workstation's
installed tool.

## Source and dependency admission

The source is [Helm v4.3.1](https://github.com/helm/helm/releases/tag/v4.3.1),
commit `c0d08d0d6d9424d4a14febb5e8a3e51b0dd00dff`. Preparation requires its
authenticated Go module identity:

```text
helm.sh/helm/v4 v4.3.1
h1:UndCoLe9UPmNoL7IvWzaUXveL7T5t/ijoorEmgJdI9g=
go.mod: h1:Z663D/wNQG1UsG3X7svSEBPvosFVel4SIw4YIMZwmuY=
```

The Go tool directive and resolved versions live in [go.mod](go.mod) and
[go.sum](go.sum). `golang.org/x/net` is explicitly raised to v0.62.0; the
upstream graph already selects `golang.org/x/text` v0.43.0. The source checksum
is checked before building, and `go mod verify` checks the selected cache.
This recipe requires Go 1.27.3. Updating source, dependency pins, or compiler
requires a new build, scan, digest, and target qualification.

## Build into new private paths

Preparation requires Python 3 and an approved matching Go executable. Run from
the repository root, using new output paths:

```sh
./tools/helm/prepare.sh --go /approved/go/bin/go \
  --out .local/tools/qualified/bin/helm \
  --notices .local/tools/qualified/helm-notices
```

Module/vendor and vulnerability-database acquisition are connected preparation
steps. After vendoring, compilation uses an empty module cache, `-mod=vendor`,
`GOTOOLCHAIN=local`, disabled Go proxy/checksum lookup, and disabled CGo. A
native executable is built with explicit custom build metadata and upstream
commit identity. It is marked as a dependency-modified build, not an official
upstream binary.

Before publication, the recipe runs pinned `govulncheck` v1.9.0 in binary mode.
A scan failure or reachable finding stops publication. The script creates a
new `0700` executable using an exclusive link after flushing it; existing files
or notice directories are refused. It never changes global Go/Helm settings,
installs a system binary, or executes cluster operations. Failed staging stays
private for inspection, with raw preparation logs excluded from exported notices.

The notice directory contains Helm's Apache-2.0 `LICENSE`, the Go license, the
complete selected vendor source/license tree, exact tool module files, bounded
build information, source/compiler/binary hashes, and the scan result. These
are operator-supplied admission materials, not a legal completeness attestation
or permanent vulnerability clearance.

## Admit and use the result

Review the result and materials, then use that exact executable for a fresh
application qualification. To select it for the disposable runner:

```sh
PATH="$(pwd)/.local/tools/qualified/bin:$PATH" \
  python3 tests/integration/kind.py --help
```

Follow [the lab guide](../../docs/test-lab.md) with that PATH for the actual run.
The runner resolves Helm and pins its digest in the Site. Do not replace a
binary under an active plan; a changed digest requires replanning.

To include the admitted pair in a Cinderlock source distribution:

```sh
./bin/cinderlock source export . --go /approved/go/bin/go \
  --include-toolchain /approved/go \
  --helm .local/tools/qualified/bin/helm \
  --helm-notices .local/tools/qualified/helm-notices \
  --out .local/source-with-helm
```

Local preparation passed with zero reachable symbol/package findings. The
scanner also identified an unused-module-only OpenPGP advisory in the selected
`golang.org/x/crypto`; its package is not imported by this binary. The full
result is retained with the materials. Compilation and scanning do not qualify
all Helm commands, charts, Kubernetes versions, GPU workloads, or production
recovery. Hosted CI and the fresh patched-tool lab run are separate gates.
