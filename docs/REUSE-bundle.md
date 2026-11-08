# Bundle and transfer source reuse

The artifact implementation uses upstream libraries and their documented
integration examples. Dependency versions and checksums are pinned in `go.mod`
and `go.sum`; upstream implementations remain dependencies rather than copied
deployment engines.

The inspected ORAS examples are pinned to v2.6.0. The runtime uses the patched
v2.6.2 dependency; the dependency files remain authoritative for runtime versions.

| Source | Version or revision | Use | License |
| --- | --- | --- | --- |
| [ORAS Go examples](https://github.com/oras-project/oras-go/blob/v2.6.0/example_test.go) | v2.6.0 | OCI store/repository/authentication construction and graph-copy integration patterns | Apache-2.0 |
| [ORAS Go content package](https://github.com/oras-project/oras-go/tree/v2.6.0/content) | v2.6.0 | Standard OCI descriptor graph traversal; each payload is additionally rehashed by Cinderlock | Apache-2.0 |
| [JSON Canonicalization Scheme Go implementation](https://github.com/cyberphone/json-canonicalization/tree/32a48195b9b2/go) | 32a48195b9b2 | RFC 8785 encoding after strict integer-only, duplicate-key and schema validation in the shared contract package | Apache-2.0 |
| [OCI image specification](https://github.com/opencontainers/image-spec/tree/v1.1.1) | v1.1.1 | Manifest and descriptor types | Apache-2.0 |
| [OCI Go digest](https://github.com/opencontainers/go-digest/tree/v1.0.0) | v1.0.0 | OCI descriptor identifiers | Apache-2.0 |
| [Go system interfaces](https://github.com/golang/sys/tree/v0.48.0) | v0.48.0 | Unix file coordination and available-space observation | BSD-3-Clause |
| [Go standard library](https://go.dev/pkg/) | Toolchain recorded in each lock | Ed25519, SHA-256, X.509/PEM, streaming I/O, tar, TLS, HTTP, and filesystem primitives | BSD-3-Clause |

The release graph, signed Cinderlock index, site authorization boundary,
adversarial-input checks, transport formats, and retention protocol are specific
to this tool. The ORAS example flow is adapted to an explicit source/destination
and bounded context; examples' permissive defaults are not used as security
policy. Cinderlock does not invoke Zarf to build or deploy a release.

Distribution must retain the applicable upstream license files/notices, including
those in a vendored dependency tree. This list records the dependencies and
examples used by these packages; the repository's complete dependency inventory
also needs the CLI, Kubernetes, journal, and service dependencies.

## Implemented transport boundaries

`bundle.Lock` accepts declared local files/trees, pinned HTTPS files, remote OCI
images, and local OCI layouts using `oci:relative/path#reference`. Input paths
must stay within the release file's workspace. File symlinks are materialized
only when their resolved files stay within that admitted workspace. The cache
cannot be inside an input tree. Target verification/import never acquires an
upstream source, executes package installers, or runs model code.

Private source access uses `LockWithOptions` and an exact source-host map. The
CLI keeps the private authentication file outside the release workspace.
Credentials and CA paths remain acquisition inputs; they do not enter the lock
or bundle. A registry or download can redirect to a different host only when
that host is explicitly admitted. Cross-host requests permit GET/HEAD without a
body and remove authentication and cookie headers. HTTPS cannot downgrade to
HTTP. Source failures omit query-bearing redirect URLs. These rules control
every outgoing request, including bearer token realms created by the registry
authentication protocol without a redirect. Authentication hosts need a
separate `allowedAuthHosts` admission and HTTPS; a download/CDN allowlist never
grants permission to receive credentials or request bodies.

The private JSON input has the following shape. Replace the example credentials,
keep the file outside the release workspace, and restrict its permissions to
`0600` or `0400`:

```json
{"registries":{"registry.internal:443":{"username":"release-reader","password":"REPLACE_LOCALLY","allowedRedirectHosts":["artifacts.internal:443"]}}}
```

Optional per-host `caFile` and `plainHTTP` settings control the declared source
transport. Plain HTTP is explicit and unsuitable for credentials crossing an
untrusted network. These acquisition options do not alter target Site policy.
For a separate token issuer, add its exact host and port to `allowedAuthHosts`.
Do not put a registry bearer token in a portable release declaration.

`bundle.Build` emits a deterministic uncompressed `.cinder` archive of regular
GNU tar members. GNU numeric fields support large blobs beyond USTAR's file-size
limit. Verification accepts regular GNU or USTAR members only, rejects extension
records, links, device files, traversal, repeated or unindexed members, and
trailing data. Signed metadata uses the exact `cinderlock.bundle-index.v1` byte
prefix, one NUL byte, and the canonical index bytes. Public keys come from the
independent site policy, not from a key included with the archive.

`transfer.Split` and `Join` check transport bytes. Their manifest is not a new
release authorization: a joined archive still needs `bundle.Verify` under the
current site policy. A differential is a directory containing the original
signed target metadata and changed payloads. Reconstruction requires the exact
verified recipient base, checks every required object, and verifies the complete
target bundle before publishing it. It cannot become deployable merely because
the transfer manifest parses.

Cache GC serializes with lock/build operations, computes a dry-run candidate set
from retained lock/bundle references, and rejects stale plans before deletion.
Corrupt/unknown retention metadata blocks cleanup. Published lock and bundle
references are retained conservatively; automatic expiry or removal of those
references is not implemented. GC never deletes application PVCs or registries.

## Signed component inventory

Every new bundle includes a deterministic CycloneDX 1.6 inventory as a signed,
reachable payload under the `inventory.v1` capability. It lists release assets,
image/model/file identities, declared origins and licenses, and individual file
hashes. Verification regenerates that inventory from the signed release lock
and requires an exact match. The
[CycloneDX 1.6 schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json)
defines the component and composition fields used by the encoder.

The composition is explicitly incomplete: packages inside images and undeclared
runtime dependencies are not enumerated. Package and vulnerability scanners
are marked `not_run`, and license names are vendor declarations. No vulnerability
clearance, model-usage right, or functional acceptance is inferred from this
inventory. Existing external scanner reports can be separate declared assets.

## Source-build distribution and existing tools

The [source exporter](source-export.md) copies the public Go project, generates
a vendor tree with retained dependency licenses, and optionally includes a
complete matching Go distribution and a Helm binary with an admitted legal
tree. Its file manifest supports independent intake; it is not signed release
authority. No upstream package scanner or legal-completeness result is inferred.

The [separate Helm preparation module](../tools/helm/) builds the existing
Apache-2.0 Helm CLI from [v4.3.1 source](https://github.com/helm/helm/tree/v4.3.1),
commit `c0d08d0d6d9424d4a14febb5e8a3e51b0dd00dff`, with the explicitly
recorded dependency/compiler pins. It retains upstream `LICENSE` and the full
selected vendor source/license tree. This is reuse of that implementation, not
a port or a replacement Helm SDK. Source sums, build identity, legal materials,
and the dated binary scan accompany the locally prepared executable.

## Validation scope

Package tests exercise full local signed round trips, deterministic output,
materialization, hostile archives, trust scopes/revocation, invalid canonical
metadata, OCI graph completeness/corruption, multipart failures, differential
reconstruction, and GC retention/concurrency. An optional OCI registry test uses
`CINDERLOCK_TEST_REGISTRY` and explicitly skips when no test registry is supplied.
Its synthetic OCI graph verifies transport, not execution of an inference image.
No GPU, model quality, production recovery, or universal offline-readiness claim
follows from these package tests.
