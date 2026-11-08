# Contributing to Cinderlock

Start with a reproducible deployment problem and its supported profile. Keep
changes small enough to explain the resulting behavior and prove the failure.
The current alpha has explicit qualification limits in
[feature coverage](docs/features.md).

## Validate changes

Run `make check`, `make race`, and the reference application tests:

```sh
python3 -m unittest discover -s examples/document-qa -p test_app.py
helm lint examples/document-qa/chart
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

For a bug, retain a regression that fails before the fix and passes afterward.
Exercise the public command when the defect crosses CLI and engine boundaries.
Use fake clients for controlled fault injection and report live integration
results separately. The [Kubernetes integration runner](tests/integration/kind.py)
requires an explicitly prepared disposable lab; it never selects your default
Kubernetes context.

## Preserve execution safety

A bundle cannot grant its own trust or customer approval. A reviewed plan binds
the source recipe, desired resources, target, policy, and starting state. Record
intent before an external effect. Preserve uncertainty after a lost response;
do not retry a stateful operation until its outcome is reconciled. Never treat
a successful restore as acceptance of the failed upgrade.

Keep credentials, kubeconfigs, databases, generated bundles, and local receipts
outside the tracked source. Use synthetic data in fixtures. Preserve third-party
licenses and document copied or adapted source in the appropriate
[reuse notes](docs/REUSE-bundle.md). Do not import code without a compatible
license and required notices.

## Describe the evidence

Explain the problem, resulting behavior, compatibility effects, and exact
checks run. Name skipped capabilities and baseline failures. A compile, mock,
or CPU fixture cannot qualify NVIDIA inference, physical isolation, or a
customer's production recovery procedure.
