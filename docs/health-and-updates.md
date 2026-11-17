# Health and version reporting

Agents expose authenticated `/health` (liveness), `/ready` (read-only readiness)
and `/version` routes. Existing health responses remain compatible. Readiness
uses bounded native DHCP/Bind configuration validation, RADIUS file availability,
and the private CA controller's managed-issuer process state. It does not prove
every client operation succeeds; use service diagnostics for that.

Agent container probes also check the TCP listener. They do not disable mTLS or
require additional client/private signing keys. The CA runtime probes its private
Unix socket with the existing management scope. No agent gains a Docker mount.

Published app/agent/runtime images embed `NETADMIN_BUILD_VERSION` from the release
build. Development and older images report **unknown**, never an assumed match.
The dashboard shows app and agent versions, readiness and mismatches, including
when the Home Assistant app has not been upgraded with its service agents.
`NETADMIN_VERSION` remains the Compose image-selection variable; it does not
override reported build identity. Do not set `NETADMIN_BUILD_VERSION` in runtime
environment files. Images without embedded metadata report **unknown**.

Image changes must pass container smoke tests before release. Deployments needing
availability during first-time setup should not interpret an unconfigured CA or
missing service configuration as ready. Health does not automatically authorize
rollback of migrated persistent data.

A CA with no configured managed issuers returns HTTP 503 and `ready: false`.
Every configured issuer must be running. Fresh-host installation permits only
the authenticated `key_ready`/empty-authority state for onboarding, verified from
both runtime and agent; this is not operational readiness and does not relax
health checks for configured CAs or coordinated upgrades.
