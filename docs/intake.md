# Bundle intake and local custody records

An intake manifest lets an operator identify the signed release and content
supplied for intake without exporting local paths, commands, or credentials. A
custody receipt records an independently admitted customer's signed declaration
about that manifest. Neither document establishes physical transfer, human
approval, legal completeness, deployment readiness, or execution authority.

## Inspect what arrived

Create a manifest only after verifying the bundle under your current release
trust policy:

```sh
cinderlock bundle intake-manifest release.cinder \
  --trust release-trust.json --out intake.json
```

The manifest binds the signed bundle graph, release, lock, declared profile, and
content digests and sizes. Its inventory reference identifies the signed
component inventory; it doesn't turn that inventory into a package or
vulnerability scan. Payload size means unique content bytes, excluding archive
transport framing. Archive byte identity is a separate concern.

Coverage and limitation fields use versioned status identifiers so changing
explanatory prose doesn't change a manifest's identity. Changing their semantics
requires an explicit schema change.

Prerequisites come from signed declarations. The manifest doesn't inspect a
cluster or prove that its permissions, storage, GPU, driver, licensing, or local
services satisfy them. Toolchain coverage retains a declaration digest and
which fields were supplied, while omitting raw toolchain strings. It doesn't
establish a reproducible build or supply missing runtime tools.

Use `--notice-asset ID` to select existing bundled assets as notice material.
Selection and vendor-declared license labels do not establish legal completeness.
Raw source URLs, member paths, workflow endpoints, commands, and site
configuration are omitted. Release and custodian labels remain declared data;
review them under your disclosure policy.

Scanner attachments are optional hash-only references. Supply a local regular
file through `--scanner-attachment`, with `--scanner-producer` and
`--scanner-version`. Cinderlock hashes bounded file bytes and records declared
producer metadata; it doesn't run or interpret the scanner, export report
contents, or claim a clean result. Separately verified producer claims belong to
the [typed external evidence contract](catalog-observations.md#verify-typed-external-evidence).

## Admit a separate customer key

Custody keys use a separate `CustodyPolicy`, scoped to declared custodians, sites,
applications, and profiles. The selected key must be current, unrevoked, and
cover the receipt's lifetime. A public key also present in the supplied release
trust policy is rejected for custody, even if it has another key ID.

Generate a key with the existing `trust keygen` command, then independently admit
its public key in a policy such as this one. Replace the public key, scope labels,
and expiry with your approved values:

```json
{
  "apiVersion": "cinderlock.dev/v1alpha1",
  "kind": "CustodyPolicy",
  "schemaVersion": 1,
  "metadata": {},
  "keys": [{
    "id": "customer-intake",
    "publicKey": "APPROVED_BASE64_ED25519_PUBLIC_KEY",
    "custodians": ["receiving-team"],
    "sites": ["lab"],
    "applications": ["document-qa"],
    "profiles": ["nvidia-linux-kubernetes"],
    "expiresAt": "2027-01-02T00:00:00Z"
  }]
}
```

Key generation doesn't enroll an identity or grant authority. Protect your
admission policy from unauthorized changes and your PKCS8 private key with mode
`0600` or `0400`. The signing command uses bounded labels rather than inferring
personal identity or physical location.

The public-key value accepts base64 Ed25519 bytes or a complete `PUBLIC KEY` PEM
string. The policy is a customer admission input, not a self-enrolling receipt.

## Record and verify one chain edge

The following workflow signs a new local record and then verifies it. Replace
the example expiry with one covered by the current customer key:

```sh
cinderlock intake sign-receipt \
  --bundle release.cinder --trust release-trust.json --manifest intake.json \
  --keys custody-policy.json --key customer.key --key-id customer-intake \
  --custodian receiving-team --site lab --previous-head genesis \
  --expires 2027-01-01T00:00:00Z --out receipt-1.json

cinderlock intake verify-receipt receipt-1.json \
  --bundle release.cinder --trust release-trust.json --manifest intake.json \
  --keys custody-policy.json --previous-head genesis \
  --head-file private/custody-head.json
```

Both operations reverify the actual bundle and exact manifest linkage. The
receipt signs canonical bytes in its own cryptographic domain. Release,
catalog, evidence, and execution signatures cannot substitute for it. Receipt
and key expiry are checked against the currently supplied policies and local
clock; the timestamp is not independently attested.

The decision clock is sampled after bundle verification and, when anchoring,
after the head-lock wait. Long hashing or lock waits don't extend validity.

`genesis` explicitly starts a chain. For a subsequent record, use the accepted
receipt digest as `--previous-head` and advance `--sequence`. Every edge stays
bound to the same manifest and bundle. Changing selected notice or attachment
metadata changes the manifest identity and requires its own chain.

Without `--head-file`, verification is stateless and returns `anchored:false`.
It checks the predecessor you supplied; it cannot discover another accepted
child or prevent replay against an old anchor. With `--head-file`, a private
local file lock and compare-and-swap permit only one continuation of that
trusted head. Concurrent competing edges and replays against an advanced head
fail. The head directory cannot be group/world writable, and symlink heads are
rejected. New manifest and receipt output files never overwrite existing files.

Retain the head as trusted local state, outside inbound packages. Deleting,
copying, or rolling back that state changes the anchor; this is not a distributed
ledger and cannot establish global uniqueness across independent head copies.
After an I/O error, inspect the head before retrying: persistence may have
advanced even if the final sync reported an error. Filesystem crash recovery,
network-filesystem locks, and multi-machine consensus remain unqualified.

## Contracts and validation

The [intake package](../internal/intake/) owns deterministic manifest extraction,
receipt-domain signing, current key scope checks, and local head advancement.
The [CLI adapter](../internal/cli/intake.go) owns flags, bounded execution context,
exclusive output files, and the shared JSON/JSONL result contract. Use command
help for the complete option surface.

Tests use real signed artifact bundles and independent customer keys. They cover
wrong trusted bundles, manifest tampering, issuer and profile denial, expired or
revoked keys, signature-domain separation, unsupported physical-custody claims,
size bounds, private head state, concurrent forks, and replay denial. The fixture
chart is transport-only; these checks don't establish that Helm, inference,
hardware, or customer recovery ran successfully.
