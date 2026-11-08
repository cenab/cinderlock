# Verified acceptance fixtures

Job checks can read signed fixture files from a dedicated PVC at
`/cinderlock-fixtures/<assetID>`. Cinderlock stages the files with its native
receiver, verifies their complete file manifest, and mounts them read-only for
the check. HTTP checks don't consume fixtures in this profile.

## Declare a separate native seed

Declare each fixture as a locked file or file-tree asset, select one native seed
operation for it, and list its asset ID on each consuming check. For example:

```yaml
assets:
  - id: acceptance-documents
    type: file-tree
    source: ./fixtures
operations:
  - id: seed-acceptance-documents
    type: seed
    asset: acceptance-documents
    pvc: document-qa-fixtures-v2
    mountPath: /fixture-staging
    modelSubPath: artifact
    storageBytes: 1048576
checks:
  - id: document-ingestion
    type: job
    domain: workflow
    required: true
    image: application
    command:
      - /app/probe
      - --fixture
      - /cinderlock-fixtures/acceptance-documents/document.json
    fixtures:
      - acceptance-documents
```

These are release-spec members, not a complete release. The transition or
initial install must select the seed, and the release still needs its images,
deployment, required checks, and recovery definitions. Native seeding requires a
customer-admitted, exact `Site.spec.helperImage` digest. Both site and policy
must permit the `seed` and `job` actions.

The seed's optional `modelSubPath` is stripped at the fixture mount: the example
exposes the verified `artifact` directory directly under
`/cinderlock-fixtures/acceptance-documents`. Paths come from the signed file
manifest; Cinderlock doesn't interpolate them into shell commands.

## Keep fixture data dedicated

One fixture asset must map to exactly one selected native seed. Its PVC must be
separate from chart resources, application workloads, and other selected
operations. Multiple checks may read the same verified fixture. A check may
declare up to sixteen distinct assets.

Planning rejects image fixtures, vendor-command seed recipes, ambiguous seed
mappings, shared selected PVCs, unsupported charts, and known unrelated Pod
consumers. The current profile uses a bounded inventory of 256 namespace Pods;
an unavailable or larger inventory blocks qualification.

The PVC uses a filesystem with `ReadWriteOnce` access. Cinderlock binds its
server-assigned UID and the immutable manifest ConfigMap UID into the receiver
and verification Job recipes. Copied ownership annotations can't substitute a
replacement PVC or manifest. Unknown, writable, or changed Pod consumers block
fixture acceptance. The original native writer must be confirmed terminal.

Seeded data remains retained after the run. Use a distinct PVC for the next
release or recovery run. Cinderlock doesn't delete fixture data automatically
or reuse another run's volume by matching its name.

## Verify each acceptance attempt

Before starting an application check, Cinderlock requires the selected seed's
completed journal intent, original receiver identity, and independent verifier
identity. It records the asset digest, seed recipe and attempt, PVC UID,
manifest UID and digest, and verifier identity in the acceptance intent.

A new fixed read-only helper then verifies the signed manifest for that check
attempt. A missing file, changed hash or size, extra entry, or symlink prevents
the application check from starting. The application Job's recipe includes the
exact fixture bindings and read-only mounts. The journal and original workers
are rechecked before accepting completion or resuming an interrupted check.

A definite fixture-verifier failure records that no application-worker create
was attempted. Explicit recovery can proceed after all recorded workers are
confirmed terminal. An unobserved helper or a missing application-worker UID
without that durable marker remains unresolved; Cinderlock doesn't infer that
a worker never ran.

Recovery checks follow the same rules. A recovery definition that declares
fixtures must select its own native fixture seed and dedicated PVC. It doesn't
inherit acceptance evidence from the failed run.

## Understand the assurance boundary

These checks establish Kubernetes object identity, admitted worker recipes,
verified file contents at the check boundary, and read-only mounts. They don't
establish physical storage isolation or defend against a trusted node,
control-plane, namespace, or storage administrator changing the backend.
Applications must consume the mounted data in their declared workflow; a
successful Job exit doesn't establish behavior outside that workflow.

The `peaks-v1` storage profile counts fixture seeds in its model-file accounting.
Provisioning overhead, runtime image expansion, and workload-specific temporary
space still need declared budgets. Planning doesn't create Pods, PVCs, or
storage probes.

See [native model staging](native-model-staging.md) for the receiver protocol and
[storage planning](storage-planning.md) for capacity evidence. The implementation
is in [fixtures.go](../internal/engine/fixtures.go), with behavior tests in
[fixtures_test.go](../internal/engine/fixtures_test.go).
