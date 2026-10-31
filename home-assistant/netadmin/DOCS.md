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
always Secure, so plain HTTP is unsuitable for login. NetAdmin requires its own login by default. The optional ingress login policy
below can delegate administrator authentication to Home Assistant. RADIUS users
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

## Ingress login policy

**Require NetAdmin login through ingress** is a Home Assistant Configuration option,
separate from connection settings. It is **on by default**, retaining root/RADIUS
login inside Home Assistant. Turn it **off** to use your existing Home Assistant
administrator session without a second login. Restart NetAdmin after changing it.
Connection save/reload does not change this policy.

The panel remains available to users who sign in with root/RADIUS. Delegated access requires a
request from Supervisor (`172.30.32.2`), its ingress path and a user identity whose
forwarded groups contain `system-admin`, plus Supervisor 2026.10.5 or newer. The
version is detected at startup through Bashio; unknown/older versions retain login.
Other source addresses with forged ingress
headers are denied. Missing identity/group headers (for example, an older Supervisor)
fall back to NetAdmin login. A non-administrator identity is denied.

Delegated access does not issue a reusable NetAdmin administrator session cookie.
Audit records identify the Home Assistant user by stable user ID. Sign-out and
password changes belong to Home Assistant when using this mode. CSRF protection and
Secure cookies remain enabled: continue using HTTPS for the Home Assistant frontend.

Standalone containers and direct requests always retain NetAdmin login, regardless
of this option. The app does not publish an additional direct port automatically.

## DNS agent and automatic zone discovery

Deploy the DNS agent alongside Bind, then enter its HTTPS URL under NetAdmin
**Settings → DNS**. It uses the shared agent token and client mTLS credentials.
When configured, its inventory replaces the manual zone list; zones need not be
specified up front. Record reads and updates still use Bind's AXFR/RFC 2136 interface.

Zone creation takes a zone name and complete zone file (SOA and NS included).
Zone removal stops serving that zone but retains the zone file and journal.
The first mutation expands includes with `named-checkconf -p`, saves the original
main configuration as `named.conf.before-netadmin`, and installs the canonical
configuration in `netadmin.conf`. The original included files are retained.
Bind validates all zone files with `named-checkconf -z` before `rndc reconfig`;
a failed validation or reload restores the preceding configuration.

Bind views and duplicate zone names are deliberately rejected. Review these
configurations before migration. TLS certificates must be provisioned separately.
For Compose, opt in with `-f docker-compose.yml -f docker-compose.dns-agent.yml`
(or use the Kea base file). The DNS agent certificate must include `dns` in its
SAN, and its CA/client trust and bearer token must match NetAdmin. The override
shares Bind's network namespace for local RNDC and its configuration directory;
it does not mount the Docker socket. No changes are made merely by discovering zones.

## DHCP subnet and pool management

The DHCP page discovers subnets across the agent's main configuration and included
files. Use **Create subnet** with an IPv4 CIDR, then edit its allocation pools and
options under **Subnets, pools and options**. Each pool is a start-end address pair;
remove a line to remove a pool, or leave the field blank to remove all pools.
New networks must not overlap an existing subnet. Ranges must be ordered,
non-overlapping, contained in their subnet and exclude network/broadcast addresses.

**Remove subnet** removes its definition and nested configuration after confirmation,
while retaining the lease database. Before the first subnet creation/removal in a
source file, the agent saves `<filename>.before-netadmin-subnets`. Changes go through
the native ISC/Kea validator and existing transactional reload/rollback mechanism.
Existing subnets remain in their original files: no duplicate registry or mandatory
rewriting of unrelated configuration is needed. New ISC definitions are appended to
the main configuration; Kea requires exactly one `subnet4` array in the main file
for creation. More complex layouts can still be discovered and existing definitions
edited/removed, subject to the daemon's own validation.

DNS agent deployment support currently targets the supplied Alpine 3.24 image and
Bind container. Its `named-checkconf` executable is `/usr/bin/named-checkconf`;
other distributions may require adapting that path. Declare the TSIG update key
in Bind's configuration (not only in its separate RNDC key file). The agent uses
`DNS_UPDATE_KEY`, falling back to `NETADMIN_DNS_TSIG_NAME` and then `rndc-key`, and
rejects creation if that key is not declared. Custom non-root/AppArmor deployments
must provision `DNS_ZONE_DIR` with daemon write access for dynamic-update journals;
the bundled container test verifies authenticated updates in the supplied image.
