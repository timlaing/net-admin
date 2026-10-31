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

1. Install the add-on and open **Configuration**.
2. Enter the DNS server, DNS zone names and HTTPS URLs of your agents. Select
   the backend that your DHCP agent actually uses, then save.
3. Start the add-on and select **Open Web UI** through Home Assistant ingress.
4. Complete the wizard: create an emergency `root` password of at least 12
   characters, enter the service details and matching secrets, then apply.
5. Restart the add-on to load the generated configuration, then sign in as `root`.
6. Complete the external service authentication and certificate configuration
   before using the administration pages.

The wizard writes `/config/netadmin.env` in the add-on's persistent configuration
directory with mode `0640`. It stores the root password as an Argon2id hash and
generates the session secret and agent token. The wizard locks once configured.
Keep this file private and include it in your backup plan.

## Configuration options

| Option | Default | Purpose |
| --- | --- | --- |
| `dhcp_backend` | `isc` | Choose `isc` or `kea` to match the deployed DHCP agent. This does not migrate or reconfigure the DHCP server. |
| `dns_server` | `dns.internal` | Reachable hostname or IP address of Bind. |
| `dns_zones` | empty | Comma-separated authoritative zones, for example `example.net,2.0.192.in-addr.arpa`. Set these explicitly for this add-on unless you separately configure a readable Bind configuration for discovery. |
| `dhcp_agent_url` | `https://dhcp.internal:8081` | DHCP agent HTTPS URL. The hostname must match its TLS certificate. |
| `radius_agent_url` | `https://radius.internal:8082` | RADIUS agent HTTPS URL. The hostname must match its TLS certificate. |

These addresses are placeholders: replace them with names reachable from the
add-on. The Configuration options override the corresponding addresses saved
by the wizard on each start. Keep both sets consistent and restart after changes.

## Service credentials and certificates

Advanced settings belong in `/config/netadmin.env`, using shell-compatible
`NETADMIN_*=...` assignments. This file is sourced at startup; edit it only as a
trusted administrator. See the project's
[environment template](https://github.com/timlaing/net-admin/blob/main/.env.example)
for all supported settings.

- Set `NETADMIN_AGENT_CA`, `NETADMIN_AGENT_CERT` and `NETADMIN_AGENT_KEY` to the
  paths of your CA, client certificate and private key inside the add-on, for
  example under `/config/pki/`. Provision these files separately.
- Configure both agents with the generated `NETADMIN_AGENT_TOKEN` value and
  trust the client certificate. The wizard does not configure remote agents.
- Set `NETADMIN_RADIUS_HOST` to the FreeRADIUS authentication server and use the
  same `NETADMIN_RADIUS_SECRET` in its client entry. The RADIUS agent URL is a
  separate endpoint used for administration.
- Set `NETADMIN_DNS_TSIG_SECRET` to the existing Bind key's secret. Adjust
  `NETADMIN_DNS_TSIG_NAME` and `NETADMIN_DNS_TSIG_ALGORITHM` if your key differs
  from the defaults (`rndc-key` and `hmac-sha256`).

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

- **Wizard still appears:** confirm setup completed and restart the add-on so
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
