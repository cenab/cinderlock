# Optional catalog database

This Compose profile supplies a local development PostgreSQL database for the
native `cinderlock catalog serve` command. It is separate from the application
cluster. It binds only loopback, uses an externally supplied password file, and
retains its data volume on ordinary shutdown.

Preload the approved `postgres:17-alpine` image during connected preparation.
`pull_policy: never` prevents a missing image from silently downloading. Set
`CINDERLOCK_POSTGRES_PASSWORD_FILE` to a private file outside the repository;
then start this profile using Docker Compose. The optional port variable is
`CINDERLOCK_POSTGRES_PORT` (default `55432`).

Place the matching DSN in a private regular file and use
`cinderlock catalog serve --driver pgx --dsn-file FILE --config FILE`. Never put
the password directly into the command line or commit the password/configuration.
The [catalog guide](../../docs/REUSE-service.md) documents roles and API requests.

For production, use the customer's admitted PostgreSQL deployment and a role
restricted to the catalog schema. This development profile's initialization
role owns its dedicated database; it is not a production privilege template.
Production TLS, backups, restore, retention, and upgrade procedures require their
own qualification. Do not delete the Compose data volume as part of routine
shutdown or an application rollback.
