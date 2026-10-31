# NetAdmin setup

## Requirements

NetAdmin is an administration interface. This add-on does not run Bind, a DHCP
server, FreeRADIUS or the restricted service agents. Deploy those separately;
the project's [deployment guide](https://github.com/timlaing/net-admin#configure-and-run)
includes Docker Compose stacks for ISC DHCPD and Kea.

Before making changes through NetAdmin, configure:

- Bind 9 with AXFR access and RFC 2136 update permissions for NetAdmin's TSIG key.
- The DHCP and RADIUS agents with server certificates, a trusted client
  certificate and the same bearer token used by NetAdmin.
- FreeRADIUS with a client entry and shared secret for NetAdmin authentication.

## First start

1. Install and start NetAdmin, then open its interface through Home Assistant over HTTPS.
2. Create an emergency `root` password of at least 12 characters.
3. Restart NetAdmin from Home Assistant and sign in as `root`.
4. Open **Settings**. Enable DNS, DHCP and/or RADIUS and enter their connection details.
5. Expand **Agent security** for your existing agent token and TLS certificate paths.
6. Save to apply connection changes immediately, then use **Test active connections**.

New installations start with all three services disabled. No external service is
needed for root login. Disabling a service only disables its administration and,
for RADIUS, its login path; it does not stop the external server.

The account and connection settings are written to `/config/netadmin.env` with mode
`0640`, using an atomic write. The root password is hashed with Argon2id. Service
secrets never enter the wizard's browser session. Password fields on the Settings
page stay empty: leaving one blank preserves its existing value. To remove a
stored secret, disable the service and set its assignment to an empty string in the
environment file as a trusted administrator, then reload saved connections. Keep the file private and include it in backups.

## Configuration options

| Option | Default | Purpose |
| --- | --- | --- |
| `dhcp_backend` | `isc` | Choose `isc` or `kea` to match the deployed DHCP agent. This does not migrate or reconfigure the DHCP server. |
| `dns_server` | `dns.internal` | Reachable hostname or IP address of Bind. |
| `dns_zones` | empty | Comma-separated authoritative zones, for example `example.net,2.0.192.in-addr.arpa`. Set these explicitly for this add-on unless you separately configure a readable Bind configuration for discovery. |
| `dhcp_agent_url` | `https://dhcp.internal:8081` | DHCP agent HTTPS URL. The hostname must match its TLS certificate. |
| `radius_agent_url` | `https://radius.internal:8082` | RADIUS agent HTTPS URL. The hostname must match its TLS certificate. |

The Home Assistant options above are legacy startup fallbacks, retained for existing
installations. **NetAdmin Settings is authoritative:** values saved there override
these fallbacks on every start, including saved blank values. Do not maintain two
copies. Existing installations retain their enabled services until explicitly disabled.

## Service credentials and certificates

Settings groups everyday connection fields by service. Advanced sections contain:

- **Agent security:** enter the bearer token already shared with both agents.
  Provision a CA, client certificate and private key under `/config/pki/`, then
  enter their paths inside NetAdmin. A blank CA uses system trust; certificate
  verification is never disabled. Both agents must trust the client certificate.
- **RADIUS:** enter both the administration agent URL and the authentication host,
  plus the existing shared secret configured in FreeRADIUS's client entry.
- **Advanced DNS:** set the TSIG name/algorithm if they differ from your existing
  key. Explicit zone names are recommended. Optional local discovery reads a
  Bind configuration file mounted inside NetAdmin; it cannot discover remote files.

Each diagnostic tests the **active** settings. Saving validates and applies connection
changes immediately without a process restart. **Reload saved connections** applies
manual file edits; invalid configuration leaves active connections unchanged. Both
actions preserve accounts and sessions. Application upgrades and first-run account
creation still require a full restart. Agent tests validate
hostname resolution, TLS and bearer authentication via the protected health endpoint;
they do not establish daemon health or write/reload permissions. DNS tests perform
an AXFR read of the first configured zone only; they do not test updates or other zones.
Failures are summarized without exposing remote response bodies or credentials.

Standalone deployments show a read-only Settings page and offer the same tests.
They continue to use `NETADMIN_*` environment variables, documented in the project's
[environment template](https://github.com/timlaing/net-admin/blob/main/.env.example).
Set `NETADMIN_DNS_ENABLED`, `NETADMIN_DHCP_ENABLED` and `NETADMIN_RADIUS_ENABLED` to
`true` or `false`. They default to `true` for compatibility with existing deployments.

## Access and troubleshooting

Open NetAdmin through Home Assistant ingress over HTTPS. Session cookies are
always Secure, so plain HTTP is unsuitable for login. NetAdmin has its own login:
Home Assistant ingress does not replace its account permissions. RADIUS users
with `Filter-Id` set to `netadmin-admin` can administer services; users with
`netadmin-standard` can change only their own password.

If the interface displays an HTTPS notice, open Home Assistant using its HTTPS
address. When HTTPS terminates at a reverse proxy, ensure it forwards the original
protocol in `X-Forwarded-Proto`. Do not disable Secure cookies to work around this.
Ingress navigation, form actions and session cookies stay under NetAdmin's own
Home Assistant ingress path.

- **Wizard still appears:** create the root account and restart the add-on so
  it loads `/config/netadmin.env`.
- **Agent connection fails:** check name resolution, the HTTPS URL, certificate
  hostname, CA and client certificate paths, and the shared agent token.
- **No DNS zones or updates fail:** set `dns_zones`, check AXFR permissions and
  confirm the TSIG key has update permission for the relevant zone.
- **RADIUS login fails:** check `NETADMIN_RADIUS_HOST`, the shared secret,
  server client entry and role attribute. Use the emergency root account to
  regain access while investigating.

Check the add-on logs for errors. Remove passwords, tokens, keys and private
network details before sharing diagnostics.

## Help and license

[Project documentation](https://github.com/timlaing/net-admin#readme) ·
[Report an issue](https://github.com/timlaing/net-admin/issues)

NetAdmin is released under the [MIT license](https://github.com/timlaing/net-admin/blob/main/LICENSE).
