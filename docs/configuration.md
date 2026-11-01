# Configuration

All configuration comes from environment variables — there is no configuration
file. `.env.example` is the template; docker-compose injects it into the
containers.

!!! info "Two variable families"
`NETADMIN_*` configures the **web application**. The agents use their own
`DHCP_*` / `RADIUS_*` variables, set in `docker-compose.yml` (rarely
edited).

## Required variables

| Variable                      | Purpose                                           |
| ----------------------------- | ------------------------------------------------- |
| `NETADMIN_SECRET_KEY`         | Flask session signing key (any long random value) |
| `NETADMIN_ROOT_PASSWORD_HASH` | Argon2id hash of the emergency `root` password    |

`Settings.from_env()` refuses to start when either is missing.

## Web application

| Variable                                                           | Default                    | Purpose                                                                  |
| ------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------ |
| `NETADMIN_DATA_DIR`                                                | `/data`                    | SQLite data and application state                                        |
| `NETADMIN_SESSION_MINUTES`                                         | `60`                       | Session lifetime in minutes                                              |
| `NETADMIN_AGENT_TOKEN`                                             | _(empty)_                  | Bearer token shared with both agents (set in compose)                    |
| `NETADMIN_AGENT_CA` / `NETADMIN_AGENT_CERT` / `NETADMIN_AGENT_KEY` | _(unset)_                  | Client mTLS material for agent calls (compose: `/pki/*.crt`)             |
| `NETADMIN_DHCP_AGENT_URL`                                          | `https://dhcp-agent:8081`   | DHCP agent endpoint (compose: `https://…`)                               |
| `NETADMIN_RADIUS_AGENT_URL`                                        | `https://radius-agent:8082` | RADIUS agent endpoint (compose: `https://…`)                             |
| `NETADMIN_DHCP_BACKEND`                                            | `isc`                      | Backend label shown by the web UI and the add-on toggle (`isc` \| `kea`) |

## DNS

| Variable                      | Default       | Purpose                                                                |
| ----------------------------- | ------------- | ---------------------------------------------------------------------- |
| `NETADMIN_DNS_USE_AGENT` | inferred from agent URL if unset | Select agent (`true`) or direct Bind (`false`); only the selected transport is used |
| `NETADMIN_DNS_AGENT_URL` | _(empty)_ | Agent HTTPS URL, using shared agent TLS and token settings |
| `NETADMIN_DNS_SERVER`         | `dns`         | Bind service host                                                      |
| `NETADMIN_DNS_CONFIG_PATH`    | _(unset)_     | `named.conf` path (compose: `/bind-config/named.conf`)                 |
| `NETADMIN_DNS_ZONES`          | _(empty)_     | Comma-separated zone list carried from setup                           |
| `NETADMIN_DNS_TSIG_NAME`      | `rndc-key`    | TSIG key name                                                          |
| `NETADMIN_DNS_TSIG_SECRET`    | _(empty)_     | Base64 TSIG secret; the DNS container seeds or generates it when empty |
| `NETADMIN_DNS_TSIG_ALGORITHM` | `hmac-sha256` | TSIG algorithm                                                         |

Agent mode requires a matching 0.6.0+ DNS agent and shared agent security. Direct
Bind fields above are unused in agent mode. The agent reads its TSIG key from
local Bind configuration and uses `DNS_SERVER`/`DNS_PORT` (defaults `127.0.0.1`/`53`).
Set `DNS_UPDATE_KEY` only when the declared key name differs from `rndc-key`
(or its `NETADMIN_DNS_TSIG_NAME` fallback). Upgrade the agent before the web app.

## RADIUS authentication

| Variable                         | Default             | Purpose                                                     |
| -------------------------------- | ------------------- | ----------------------------------------------------------- |
| `NETADMIN_RADIUS_HOST`           | `radius`            | RADIUS server for `radclient`                               |
| `NETADMIN_RADIUS_SECRET`         | _(empty)_           | Shared secret — **empty disables RADIUS login** (root only) |
| `NETADMIN_RADIUS_NAS_IP`         | `127.0.0.1`         | NAS-IP sent in access requests                              |
| `NETADMIN_RADIUS_ROLE_ATTRIBUTE` | `Filter-Id`         | Reply attribute mapped to roles                             |
| `NETADMIN_RADIUS_ADMIN_VALUE`    | `netadmin-admin`    | Attribute value granting the admin role                     |
| `NETADMIN_RADIUS_STANDARD_VALUE` | `netadmin-standard` | Attribute value granting the standard role                  |

Optional `NETADMIN_RADIUS_TLS_*` seeds keep an existing RADIUS CA serving — see
README → _Key material_.

## DHCP agent (`docker-compose.yml`)

| Variable              | Default                                | Purpose                                                                      |
| --------------------- | -------------------------------------- | ---------------------------------------------------------------------------- |
| `DHCP_SERVER`         | `isc`                                  | Backend dispatch: `isc` validates with `dhcpd -t`, `kea` with `kea-dhcp4 -t` |
| `DHCP_MAIN_CONFIG`    | `/etc/dhcp/dhcpd.conf`                 | Main configuration the agent edits                                           |
| `DHCP_MANAGED_FILE`   | `/etc/dhcp/netadmin-reservations.conf` | Agent-owned reservations include                                             |
| `DHCP_LEASES_FILE`    | `/var/lib/dhcp/dhcpd.leases`           | Leases file                                                                  |
| `DHCP_RELOAD_COMMAND` | `kill -HUP 1`                          | Reload action (Kea mode reloads over `/run/kea/kea4-ctrl.sock` instead)      |

The Kea stack (`docker-compose.kea.yml`) sets `DHCP_SERVER: kea` for you.

## RADIUS agent (`docker-compose.yml`)

| Variable                      | Default                                  | Purpose                              |
| ----------------------------- | ---------------------------------------- | ------------------------------------ |
| `RADIUS_MANAGED_FILE`         | `/etc/raddb/mods-config/files/netadmin`  | Agent-owned users file               |
| `RADIUS_AUTHORIZE_FILE`       | `/etc/raddb/mods-config/files/authorize` | Included authorize file              |
| `RADIUS_CLIENTS_FILE`         | `/etc/raddb/clients.conf`                | RADIUS clients config                |
| `RADIUS_MANAGED_CLIENTS_FILE` | `/etc/raddb/netadmin-clients.conf`       | Agent-owned clients include          |
| `RADIUS_ADMIN_POOLS`          | `pool-parent`                            | Parent pool for managed files        |
| `RADIUS_RELOAD_COMMAND`       | `kill -HUP 1`                            | Reload action (shared PID namespace) |

## Home Assistant add-on options

| Option | Schema | Purpose |
| --- | --- | --- |
| `ingress_require_login` | `bool` | Require NetAdmin login through ingress (default `true`) |

All service connection details are managed in **NetAdmin → Settings**, including
DHCP backend, DNS server/zones and agent URLs. Changes saved there apply without a
restart. Retired Home Assistant connection options are imported on upgrade only
when their assignments are missing from `/config/netadmin.env`; existing values
and saved blanks are preserved. After a successful import, the retired options
are removed from Home Assistant.

Secrets are **not** part of the options schema: the ingress-only wizard writes
`/config/netadmin.env` (mode 0640) on first run.

DNS, DHCP and RADIUS can each be disabled with `NETADMIN_DNS_ENABLED`,
`NETADMIN_DHCP_ENABLED` and `NETADMIN_RADIUS_ENABLED` (`true`/`false`; default `true`).
The Home Assistant app manages these and connection details on its **Settings** page.
Agent diagnostics require the same HTTPS, client certificate and bearer token as
the supported production Compose deployment. A health check does not test write permissions.

`NETADMIN_INGRESS_REQUIRE_LOGIN` defaults to `true`. In the Home Assistant app it
is managed by the **Require NetAdmin login through ingress** option. Setting it
to `false` delegates trusted ingress administrator access to Home Assistant; it
never disables direct or standalone authentication. Connection reloads preserve it.
