# Installation

NetAdmin ships as pre-built multi-arch container images (recommended) or as a
Home Assistant add-on. Running from source is intended for development.

## Prerequisites

- Docker Engine with the Compose plugin (or a Kubernetes-flavoured equivalent
  of your choosing for the images themselves).
- A reverse proxy that terminates **HTTPS** — the session cookie is always
  `Secure`, so plain HTTP logins are intentionally unsuitable.
- For running from source: Python 3.12+.

## Container images

Every `vX.Y.Z` release publishes amd64 **and** arm64 manifests for:

| Image                                    | Role                                                |
| ---------------------------------------- | --------------------------------------------------- |
| `ghcr.io/timlaing/netadmin`              | Web application (port 8099)                         |
| `ghcr.io/timlaing/netadmin-dhcp-agent`   | Restricted DHCP agent (8081, mTLS + bearer token)   |
| `ghcr.io/timlaing/netadmin-dns-agent`    | Optional Bind zone agent (8083, mTLS + bearer token; from 0.5.0) |
| `ghcr.io/timlaing/netadmin-radius-agent` | Restricted RADIUS agent (8082, mTLS + bearer token) |
| `ghcr.io/timlaing/netadmin-dns`          | Bind 9 DNS service                                  |
| `ghcr.io/timlaing/netadmin-dhcp`         | ISC DHCPD service                                   |
| `ghcr.io/timlaing/netadmin-radius`       | FreeRADIUS service                                  |
| `ghcr.io/<arch>-addon-netadmin`          | Home Assistant add-on                               |

Tags per image: `X.Y.Z` (release), `latest`, and `sha-<commit>`. Release tags
must match the add-on version in `home-assistant/netadmin/config.yaml`.
All images can equally be built locally from this repository's Dockerfiles.

## Docker Compose

1. Clone and enter the repository:

   ```sh
   git clone https://github.com/timlaing/net-admin.git
   cd net-admin
   ```

2. Copy `.env.example` to `.env` and replace every placeholder — see
   [Configuration](configuration.md) for what each variable does.

3. Create a private CA plus separate server certificates for both agents and a
   NetAdmin client certificate under `pki/`. Certificate SANs must match
   `dhcp-agent` and `radius-agent`. Restrict private keys to the container user
   (`0600`) and configuration files containing hashes/secrets to `0640`.

4. Add a matching RADIUS client and a restricted TSIG update permission for the
   DNS service.

5. Build and start:

   ```sh
   docker compose up --build -d
   ```

6. Put the application behind HTTPS and open port 8099 through the reverse
   proxy.

!!! note "Key material"
TSIG and RADIUS TLS material is seeded or generated on first start — nothing
is baked into images. Rotation and seeding procedures are documented on the
repository home page (README → _Key material_).

For a migration from an existing pre-NetAdmin stack, run `scripts/cutover.sh`
from a repository checkout on the server.

## Home Assistant add-on

- Install the add-on and open it through its **ingress** (sidebar) panel.
- The first-run setup wizard generates the secrets, hashes the emergency root
  password and writes `/config/netadmin.env` (mode 0640). Restart the add-on to
  load it. The wizard is only reachable through ingress and locks itself once
  configured.
- Configure service connections and diagnostics in the application's Settings page.
  The add-on's `ingress_require_login` option controls whether trusted Home Assistant
  administrator identity can replace the application login through ingress.
- For the 0.5.0 upgrade, optional DNS agent and rollback preparation, see
  [Deployment guide](deployment-0.5.0.md).

## Running from source

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

Console entry points after installation: `netadmin` (web application, port
8099), `netadmin-dhcp-agent` (8081), `netadmin-dns-agent` (8083) and
`netadmin-radius-agent` (8082). In
containers they run under gunicorn. See [Development](AGENTS.md) for the
full check commands.
