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
DNS server/zones and agent URLs. DHCP agents report their own ISC/Kea backend;
there is no separate backend selector for agent connections. Changes saved there apply without a
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


## RADIUS certificates

Open **RADIUS → Certificates** to see the current CA and server subjects, serials,
SHA-256 fingerprints, validity dates and revocation-list expiry. Downloads contain
public certificates or the CRL only; private keys never leave the agent.

The supported stack shares `radius-certs:/etc/raddb/certs` between RADIUS and its
agent. Upgrade both images together. The service image runs a small PID 1 wrapper
which keeps the PID namespace stable and restarts the RADIUS daemon when the agent
activates a certificate transaction. Existing ordinary configuration reloads still
use HUP. Certificate changes interrupt authentication and require a writable agent,
its `RADIUS_CERT_MANAGEMENT=true` setting, and a matching local RSA or EC CA key.
Self-signed local roots are supported; externally signed or offline authorities must
be managed through their issuing CA. Missing keys, older agents/services, or invalid
material produce an unavailable/disabled state, never invented certificate details.

Agent settings:

| Variable | Default | Meaning |
| --- | --- | --- |
| `RADIUS_CERT_DIR` | `/etc/raddb/certs` | Shared service certificate directory. |
| `RADIUS_CERT_MANAGEMENT` | `false` | Enable mutations; the provided Compose files set this to true. |
| `RADIUS_CERT_KEY_PASSWORD` | packaged bootstrap password | Password for existing CA keys and generated server keys; must match the EAP private-key password. Set through deployment secrets. |
| `RADIUS_CERT_RESTART_MODE` | `signal` | Use the packaged wrapper, or explicitly choose `command` for an existing acknowledged restart helper. |
| `RADIUS_CERT_RESTART_COMMAND` | `kill -USR1 1` | Signal the supported service wrapper. The agent waits for an acknowledgement before reporting success. |

For deployments with a restricted host restart service and no shared PID namespace,
set `RADIUS_CERT_RESTART_MODE=command` and explicitly set
`RADIUS_CERT_RESTART_COMMAND` to the existing fixed helper. It must wait for a full
RADIUS restart and a successful health check before returning zero. Nonzero status
or timeout triggers rollback and another helper call to activate the restored files.
Do not use a fire-and-forget signal command in this mode. This preserves existing
socket-based integrations without giving the agent access to the Docker socket.

Keep the native EAP configuration on the packaged `server.pem` and `ca.pem` paths.
Custom configurations must be mounted into the agent too, so its `radiusd -XC`
validation checks the same service configuration. Do not point the editor at a
different certificate directory than the service actually uses.

- **Renew server certificate:** new key and serial, same subject and extensions
  including SANs, validity up to one year capped by CA expiry. The old certificate
  is retained as a public historical file and is not automatically revoked.
- **Revoke and replace server certificate:** sign a CRL containing the old serial,
  retain previous revocations, and install a replacement key and certificate.
  Distribute the CRL to devices configured to check server revocation. Existing
  sessions can continue until they reconnect; devices that do not check the CRL
  will not reject the old identity solely because this button was used.
- **Renew CA certificate:** retain its signing key/subject and issue a new ten-year
  certificate. Existing issued certificates remain in place. Distribute the renewed
  CA; devices' installed CA expiry is not automatically extended.
- **Retire and replace CA:** an explicit immediate cutover to a new CA key and server
  identity. Install the new CA and remove the old root from every device trust store.
  Replace EAP-TLS client certificates issued by the old CA. A CRL cannot remotely
  remove a root from devices. Old public CA/CRL files remain on the agent for recovery
  and distribution; the former CA signing key is replaced.
- **Refresh revocation list:** keep all entries, sign a fresh CRL with a 30-day
  next-update date, and distribute it before clients' current CRL expires.

Operations require confirmation and use certificate fingerprints to reject stale
browser submissions. The agent validates candidate files, preserves the service
file ownership, and restarts RADIUS. Failed validation restores the files; failed
activation also attempts to restart the original identity. Check service status if
a failure is reported. These operations do not modify the management agents' mTLS
certificates in `/pki`, device trust stores, or client-certificate validation policy.
