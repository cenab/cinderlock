# Security reporting and boundaries

Cinderlock is experimental release software. Use a disposable environment and
synthetic data before qualifying an application transition. A successful test
applies only to its recorded release, profile, workflows, and recovery scope.

Report a suspected vulnerability privately through the repository's configured
security reporting channel. If private reporting has not been enabled, avoid
placing secrets or exploit details in a public issue; contact the repository
owner through an available private channel.

The release signer, customer approval authority, local trust administrator,
operator, and data owner have distinct responsibilities. A signed bundle does
not grant Kubernetes permissions. Keep signing keys, kubeconfigs, database
credentials, and raw customer data outside source control and portable releases.

The threat model excludes a malicious cluster administrator, compromised host
kernel, and an attacker controlling the operator account. Kubernetes Leases and
local SQLite records do not provide distributed transactions or exactly-once
database migrations. An uncertain operation requires reconciliation.

The optional catalog authenticates and scopes metadata access. Imported results
are observations; catalog approval metadata does not replace a customer-signed
engine authorization. Strict-gap installations have no implied remote access.
