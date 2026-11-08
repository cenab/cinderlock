# Native offline model staging

Native staging transfers models from a verified bundle to a new revision PVC
through the Kubernetes API. You do not need a second image containing the same
model weights. This profile uses an existing cluster, an internal registry, and
a customer-admitted Cinderlock helper image.

## Select the native path

Leave `command`, `image`, `args`, and `secretRefs` empty on a `seed` operation.
Declare its signed non-image asset, distinct PVC, capacity, and clean absolute
mount path. An optional confined `modelSubPath` selects the model directory;
directories outside it remain outside the model manifest, including filesystem
housekeeping directories. For example:

```yaml
operations:
  - id: seed-model
    type: seed
    asset: model
    pvc: customer-model-v2
    storageBytes: 10737418240
    mountPath: /models
    modelSubPath: payload
    timeoutSeconds: 1800
```

Set `Site.spec.helperImage` to the exact `sha256:` manifest digest of a locked
helper image. Admit that framework image digest through your own release review;
a vendor's signing key alone does not establish trust in its verifier code. The
helper must contain the matching `/usr/local/bin/cinderlock` executable. Import
it to the internal registry before staging. Floating tags and asset IDs cannot
select the native helper. An explicit nonempty seed `command` retains the vendor
carrier path and its declared image.

## Transfer and publication

The engine creates a bounded receiver Job mounting only the revision PVC, an
immutable signed-file-list ConfigMap, and temporary storage. It runs a fixed
`helper receive-model` entrypoint, without API credentials, authored commands,
or secrets. The Job and container have the normal Cinderlock deadline and
restricted security settings. The helper needs filesystem support for hard
links, exclusive creation, and directory synchronization.

Before sending bytes, the engine records the original server Job UID, recipe,
and actual controlled Pod UID and recipe. It attaches once to that Pod's stdin
using client-go's SPDY executor with redirects rejected. It never retries or
falls back to another transport after attachment. The operator needs Pod get,
list, and attach permissions. Clusters or proxies without supported SPDY attach
remain unsupported and leave an uncertain outcome to investigate.

The sender reads each raw blob directly from the verified bundle cache,
rehashing its exact signed size. It does not materialize a second model tree on
the operator machine. The receiver accepts only the signed regular files,
confined paths, sizes, and SHA-256 hashes. It rejects symlinks, duplicate records,
extra files, incomplete streams, and trailing data. Archive metadata has a bound
of 4 KiB per signed file plus 1 KiB, in addition to signed file bytes. The signed
manifest itself is limited to 512 KiB.

The receiver streams one file at a time into a private temporary file. It checks
the hash and size, synchronizes the file, and publishes with an exclusive hard
link. Existing files are never overwritten. Matching complete files are
rehashed and preserved; conflicting bytes fail the attempt. Payload storage is
one copy of each model file, with a single partial current file and filesystem
metadata overhead. Temporary and final names briefly reference the same inode.

Success requires the original receiver Job and the same recorded Pod to finish
successfully. A separate fixed helper Job then mounts the PVC read-only and
verifies the complete selected model tree against the immutable signed
manifest. Only then can the seed finish. Application inference and acceptance
tests remain separate requirements.

## Investigate and resume a lost attachment

A disconnected attachment preserves uncertainty. `run resume` never reattaches
to the original worker. It requires the original Job and the recorded Pod, with
their admitted UIDs and recipes, to be observable and terminal. A terminal Job
condition alone cannot permit retry while the actual receiver Pod is running.
Missing identities or observations keep the run blocked for external
reconciliation.

After a failed worker is known to be quiescent, explicit resume creates a new
attempt-scoped Job. The helper preserves completed files and retries the current
partial file. This version retransmits all signed file bytes, including those
already complete; completed destination files retain their modification times.
It does not yet provide missing-shard negotiation or byte-range resume.

The reserved `.cinderlock-staging` directory contains an exclusive owner record
bound to the signed manifest and deterministic partial names. A new attempt
cleans only recognized regular partial files after verifying that owner record.
Unknown entries, symlinks, and conflicting ownership require reconciliation and
are preserved. The engine admits the PVC only for the same run and signed asset;
it does not adopt an unrelated existing customer volume.

## Trust and validation limits

Kubernetes Pod attachment has no server-side UID precondition. The engine checks
the admitted Pod before and after the single attachment and when accepting its
termination; these checks are not transactional recipient fencing. This profile
trusts the cluster control plane, node, helper code, and namespace administration.
A principal able to create arbitrary Pods or mount the PVC already has access to
its data. This mechanism does not isolate confidential model data from such a
principal, attest a malicious helper, or establish physical network isolation.

Tests cover transfer corruption, path confinement, incomplete input, retained
progress, unknown temporary data, durable single-attach binding, Pod replacement,
recipe mutation, and explicit resume with worker quiescence. These filesystem
and fake-client tests do not qualify a Kubernetes transport, CSI driver, GPU,
or production recovery procedure. Use the disposable integration lab to record
separate live evidence for the exact target profile.
