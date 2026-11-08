# Configuration ownership and masked review

Declare which Helm values your customer can change in the signed release.
Cinderlock checks those rules before rendering and includes a value-free review
in the saved plan. This contract supports one packaged root chart without
subcharts or chart dependencies.

## Declare ownership

Add `configuration` beside the deployment's `imageBindings`. For example:

```yaml
spec:
  deployment:
    type: helm
    chart: ./document-qa.tgz
    values:
      - ./release-values.yaml
    imageBindings:
      - asset: application
        valuesPath: image
    configuration:
      version: 1
      fields:
        - path: image
          owner: generated
          type: string
          required: true
        - path: appVersion
          owner: vendor
          type: string
          required: true
        - path: data.capacity
          owner: site
          type: string
          required: true
        - path: data.existingClaim
          owner: vendor
          type: string
        - path: models
          owner: vendor
          type: object
```

The customer can then set only the declared site-owned values:

```yaml
spec:
  values:
    data:
      capacity: 192Mi
```

The owner controls who supplies the value:

| Owner | Behavior |
| --- | --- |
| `vendor` | Chart defaults and bundled values supply the field. Site overrides are refused. |
| `site` | The Site may override the field; packaged defaults can supply it otherwise. |
| `generated` | Cinderlock supplies the exact digest-pinned image binding. Site overrides are refused. |

Every image binding must have one exact `generated` field of type `string`.
Generated fields cannot name other kinds of configuration. Parent replacements,
such as `data: null`, cannot bypass a protected child such as
`data.existingClaim`. Unknown Site paths are refused, including dotted-key aliases
and array-index syntax.

## Understand the supported scope

The contract permits 1–256 nonoverlapping paths. A path has at most 256 bytes and
16 dot-separated object segments. Each segment starts with an ASCII letter or
underscore, followed by letters, digits, underscores, or hyphens, up to 64
characters. Wildcards, list indexes, escapes, duplicate rules, and overlapping
parent/child rules are unsupported.

The basic types are `string`, `boolean`, `integer`, `array`, and `object`.
Integers use the existing signed-document safe-integer range. A required value
must exist after resolution; an empty string still has type `string`. An
optional Site value of `null` can remove its default. A required value cannot be
removed this way.

An `object` or `array` rule owns the entire value at its path. You cannot combine
that rule with child ownership rules. This gives an explicit scope without
validating every member's shape. Use the chart's `values.schema.json` for nested
constraints, ranges, enums, and other schema rules. Cinderlock's existing Helm
rendering applies that schema; the ownership contract does not replace it.

Rules govern declared fields and admission of Site overrides. Undeclared chart
defaults remain unavailable for Site override and do not gain individual review
rows. This is not a general chart-schema inference system.

## Review the plan

Create the plan with the existing command:

```sh
cinderlock run plan release.cinder --site site.yaml --out plan.json
```

Resolution preserves the existing precedence: chart defaults, ordered bundled
values files, Site values, then generated image bindings. Maps merge; arrays and
scalars replace earlier values. Default coalescing and null handling follow
Helm's ordered values behavior within the supported root-chart profile.

The plan's `configurationReview` records:

- `ownership`: `enforced` for the declared contract or `unqualified` when absent.
- `comparisonRevision`: the exact original `snapshot.helmRevision`.
- `comparisonStatus`: `available`, `not_installed`, or `not_compared`.
- `fields`: declared paths, owners, and `added`, `changed`, `unchanged`,
  `removed`, or `not_compared` states.
- `effectiveDigest`: a keyed HMAC of the final resolved configuration when
  ownership is enforced.

The field review contains no plaintext values or unkeyed value hashes. The
whole-configuration HMAC uses the private local state key. The plan,
authorization, and existing desired-resource digest bind the review to the
configuration and rendered objects. Execution boundaries recompute ownership,
the effective HMAC, and the review; changing metadata cannot change or authorize
execution.

Comparisons read the exact pinned Helm revision, including after Cinderlock's
own Helm operations advance the current revision. Missing or unreadable pinned
history yields `not_compared` fields and a blocking finding for an enforced
contract. Cinderlock does not substitute the latest values as a baseline. A new
installation explicitly uses `not_installed` and an empty prior baseline.

Helm schema and template failures remain failures, but their raw error text is
withheld from plan findings because it can echo configuration values.

## Keep the limits visible

A release without `configuration` still runs under the existing compatibility
rules. New plans explicitly mark its ownership review `unqualified`; Cinderlock
does not claim field ownership validation. Existing saved plans without a review
remain compatible only when their release has no ownership contract. Recovery
plans create a new review pinned to their own observed starting revision.
Hardware probe and retirement plans do not apply Helm values.

The masked review does not make a raw value suitable for a portable bundle or
Site file. Keep credentials in customer-managed Secret references supported by
the chart and execution profile. Values are still supplied to Helm in private
temporary files, and the local state key is required to reproduce the keyed
configuration binding.

The focused tests cover ownership bypasses, required values, basic types,
privacy, plan admission, missing history, and a real local Helm comparison:

```sh
go test ./internal/spec ./internal/engine -run '^TestConfiguration' -count=1
```

The real Helm test reports a skip when the executable is unavailable. It renders
locally and does not contact a Kubernetes cluster.
