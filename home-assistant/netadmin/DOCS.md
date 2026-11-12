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

1. Install and start NetAdmin, then open its interface through Home Assistant ingress.
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

Home Assistant Configuration contains only **Require NetAdmin login through ingress**
(`ingress_require_login`, on by default). Restart the add-on after changing this
Home Assistant authentication policy.

Manage all DNS, DHCP and RADIUS connection details in **NetAdmin → Settings**,
including the DHCP backend, DNS server and zones, agent URLs, credentials and TLS
paths. Save there to apply changes without restarting.

When upgrading from an older release, startup imports the retired Home Assistant
connection options into `/config/netadmin.env` only for assignments that are not
already saved there. Existing saved values, including empty strings, win. Once
that import succeeds, startup removes the retired options from Home Assistant.
If import or cleanup fails, startup stops rather than discard your configuration;
check the add-on logs and configuration file permissions before restarting.

## Service credentials and certificates

Settings groups everyday connection fields by service. Advanced sections contain:

- **Agent security:** enter the bearer token already shared with both agents.
  Provision a CA, client certificate and private key under `/config/pki/`, then
  enter their paths inside NetAdmin. A blank CA uses system trust; certificate
  verification is never disabled. Both agents must trust the client certificate.
- **RADIUS:** enter both the administration agent URL and the authentication host,
  plus the existing shared secret configured in FreeRADIUS's client entry.
- **DNS connection mode:** turn **Use DNS agent** on for an agent URL and shared
  agent security. Turn it off for **Direct Bind**, including server, zones and TSIG
  settings. Only the selected mode is used; switching preserves the other values.

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

Open NetAdmin through Home Assistant ingress using HTTP or HTTPS. Ingress cookies
follow the frontend's scheme and remain scoped to NetAdmin's ingress path.
NetAdmin requires its own login by default. The optional ingress login policy
below can delegate administrator authentication to Home Assistant. RADIUS users
with `Filter-Id` set to `netadmin-admin` can administer services; users with
`netadmin-standard` can change only their own password.

The HTTPS requirement applies to direct access, whose cookies remain Secure.
When HTTPS terminates at a reverse proxy, ensure it forwards the original protocol.
Ingress navigation, form actions and session cookies stay under NetAdmin's own
Home Assistant ingress path.

- **Wizard still appears:** create the root account and restart the add-on so
  it loads `/config/netadmin.env`.
- **Agent connection fails:** check name resolution, the HTTPS URL, certificate
  hostname, CA and client certificate paths, and the shared agent token.
- **No DNS zones or updates fail:** configure DNS discovery or zones in Settings, check AXFR permissions and
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
password changes belong to Home Assistant when using this mode. CSRF protection
remains enabled over both HTTP and HTTPS ingress. HTTPS ingress cookies remain Secure.

Standalone containers and direct requests always retain NetAdmin login, regardless
of this option. The app does not publish an additional direct port automatically.

## DNS agent and automatic zone discovery

Deploy the DNS agent alongside Bind, turn on **Settings → DNS → Use DNS agent**
and enter its HTTPS URL. It uses the shared agent token and client mTLS credentials.
Agent mode discovers zones and routes all zone and record operations through the
agent. The web app does not need a Bind address, zone list, TSIG secret or local
Bind configuration path in this mode.

The agent connects locally to Bind (`DNS_SERVER=127.0.0.1`, `DNS_PORT=53`) and reads
the selected TSIG key and algorithm from Bind's expanded configuration. The key
must permit AXFR and RFC 2136 updates for each managed zone. Neither its secret
nor the expanded configuration is returned by the API. Keep these settings on the
Bind/agent deployment. Record writes are limited to discovered authoritative zones;
SOA/NS and protocol control record types are protected.

Turn **Use DNS agent** off to use direct Bind access. The retained agent URL is
ignored, and the Direct Bind section appears. Agent mode ignores retained direct
Bind settings. Existing deployments infer agent mode from a configured agent URL
until the toggle is explicitly saved.

Upgrade the DNS agent to **0.6.0 or newer before updating the web app** in agent
mode. Agents from 0.5.x lack the record API; there is no silent direct-Bind fallback.

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

### Read-only agents and zone snapshots (0.6.1)

Set `NETADMIN_AGENT_READ_ONLY=true` on each service agent for inventory-only access.
Agents reject write requests even if a caller bypasses the interface. NetAdmin
reads `/capabilities` and hides service mutation forms and action buttons.
The overview displays **Read-only**, **Writable** or **Unknown** separately from
connection status. Older agents without capability reporting display **Unknown**. Keep configuration
mounts read-only and omit reload/PID access for these deployments. Older agents
without the capability endpoint retain their existing behavior.

When **Load live zone** fails, the DNS page remains available and explains the
zone-transfer requirement. With DNS agent 0.6.1 or newer, **Read local zone
snapshot** reads the configured zone file plus its journal through Bind's native
compiler. This does not reload Bind or change its transfer policy. Snapshots can
lag unpersisted in-memory changes. Mount the zone files, journals and any included
files at the paths declared in Bind's configuration. Direct Bind mode still
requires authenticated AXFR for live record reads.

RADIUS agent 0.6.1 reports each client's source and supports updating or deleting
simple client definitions in the configured main clients file or managed include.
Use **Edit** to populate the form. Leave the shared secret blank to preserve it;
new clients require a secret of at least 16 characters. Updates preserve unrelated
attributes. Duplicate client names and nested client blocks require native editing.
The agent must have the complete validation configuration, a writable directory
mount for the target file and working reload access before enabling changes.
Individual file mounts can prevent atomic replacement; read-only deployments
remain inventory-only. Existing EAP settings, certificates and passwords do not
need migration for client management.

The overview checks agent connectivity automatically and refreshes every 30 seconds
while the page is visible. Status checks require an administrator session and use
short HTTP timeouts with a 30-second server-side cache. A connected DNS agent does
not imply that Bind allows AXFR, and a connected RADIUS agent does not verify a
RADIUS user's login. Use the Settings diagnostics to check those service operations.
Direct Bind mode is labelled separately because no DNS agent is configured.

### In-place deletion and multiple selection

DNS records, DHCP reservations/subnets and RADIUS users/clients use the same
deletion controls. With JavaScript enabled, deleting a row keeps the current
search, sort order, page size and page instead of reloading the browser. Select
individual rows or all deletable rows on the current page, then **Delete selected**.
Selections remain across pages and filters; the count and confirmation include
hidden selections. Protected records and unmanaged/read-only items have no delete
selection control.

Bulk deletion is sequential, not an atomic transaction. Each item uses its existing
CSRF-protected, administrator-only endpoint and the agent's normal validation and
rollback. Only acknowledged deletions disappear. An unconfirmed result stops the
batch, leaves remaining rows and selections in place, and is never automatically
retried. Refresh and check authoritative state before retrying an uncertain write.

Whole-zone/subnet and CA-authority deletion forms also update content without a
browser reload, preserving table state and scroll position where applicable.
Authority deletion retains its typed confirmation, separate management scope and
operation ID. Without JavaScript, the existing form submissions and redirects
remain available. Viewing leases, audit records and other read-only tables does
not grant deletion rights.

### Subnet table and editor (0.6.2)

The DHCP page lists subnets in a searchable, paginated table. Select **Edit subnet**
to change its allocation pools and DHCP options, or **View subnet** for a read-only
agent. The detail page shows the network, netmask, configuration source and Kea
subnet ID when reported. Subnet identity cannot be changed through this editor.

Enter pools as `start-end`, one per line, and options as `name=value`, one per
line, using the backend's native option syntax. ISC text values need quotes;
upgrade the DHCP agent to 0.6.2 so those quotes are preserved when reading options.
Blank fields remove subnet pools or options, while inherited options and other
subnet directives remain unchanged. Invalid input stays on the page for correction;
the agent still validates the complete candidate before installation and reload.

## RADIUS password formats

The updated RADIUS agent stores both SHA-512 `Crypt-Password` and `NT-Password`
for new passwords and password resets. This supports PAP and EAP-MSCHAPv2
without storing cleartext passwords. Both hashes stay on the agent; the UI
shows only their format names. Treat the NT hash as sensitive password material.

Upgrade the RADIUS agent alongside the web app. **Migrate users** converts
legacy cleartext credentials to both hashes and preserves native check and
reply attributes, including pool and fixed-address assignments. Existing
crypt-only or NT-only records remain usable for their supported methods.
Reset their passwords to generate the missing hash; it cannot be derived
from the other hash. Editing a role without supplying a password preserves
existing credentials. Passwords must fit within 256 UTF-8 bytes to avoid
OpenSSL input truncation. Ambiguous native configuration is rejected before changes.

## RADIUS authentication modes

Use **RADIUS → Authentication modes** to enable EAP-MSCHAPv2, PEAP with MSCHAPv2,
or EAP-TLS. Multiple methods can coexist during migration; the preferred mode is
offered first. Device connection profiles must be updated separately.
Certificates are shown only when configured EAP methods use TLS. Selecting PEAP
or EAP-TLS reveals **Prepare certificates** before applying, so expired
certificates can be renewed first. Unknown agent status retains certificate access.

Upgrade the RADIUS agent and enable `RADIUS_AUTH_MANAGEMENT=true`, share the EAP
and inner-tunnel configuration directories with it, and configure acknowledged
restart support. See `docs/radius-authentication.md` for mounts and migration
steps. Changes are validated and restarted with rollback; PAP is unchanged.
