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

## Fresh-host installer

The bootstrap is served from the repository's main branch. It selects the latest
stable release with uploaded installer assets and an `installer-ready.json`
completion marker, written only after image and asset publication succeeds. A
newer release that is still publishing or has failed does not displace the last
verified installer. Before the first verified release, it exits with a clear error.

The first download needs `curl` and a working system CA trust store. If these
are missing, install them first using the command for your distribution (omit
`sudo` when already running as root):

```sh
# Debian, Ubuntu and 64-bit Raspberry Pi OS
sudo apt-get update && sudo apt-get install -y curl ca-certificates

# Fedora and RHEL
sudo dnf install -y curl ca-certificates
```

Then download and run the installer:

```sh
curl -fsSL --connect-timeout 10 --max-time 120 https://raw.githubusercontent.com/timlaing/net-admin/main/scripts/install.sh -o install.sh && bash install.sh
```

The download must succeed before Bash runs, so a failed download cannot report a
successful installation. The script reads prompts from the terminal and requests
sudo when needed. It offers these independent choices:

- Bind DNS, or no DNS.
- ISC DHCPD, Kea DHCP, or no DHCP.
- FreeRADIUS, or no RADIUS.
- Managed certificate authority, or no CA.

Any non-empty combination is supported, including CA-only, RADIUS-only and
DHCP-only. The small private **transport CA** generated to authenticate agents
is separate from the optional managed CA service; omitting that service never
disables mTLS. No standalone web app is deployed: install the Home Assistant
NetAdmin app separately.

Automatic host setup supports Debian, Ubuntu, 64-bit Raspberry Pi OS, Fedora and
RHEL on amd64/arm64. It uses Docker's official apt/dnf repositories, installs
missing dependencies and enables a newly installed Docker daemon. Existing
Docker is reused; conflicting Podman/distribution Docker/containerd packages
are reported for manual resolution rather than removed. RHEL hosts with an old
system Python receive Python 3.11. The installer requires a local rootful Engine
and a fixed IPv4 address already assigned to the selected host. macOS and Docker
Desktop are not supported by this installer; DHCP needs native Linux LAN access.

Download the script first to inspect it or pass options:

```sh
curl -fsSL --connect-timeout 10 --max-time 120 https://raw.githubusercontent.com/timlaing/net-admin/main/scripts/install.sh -o install.sh && bash install.sh --help
```

After a successful download, preview a selection:

```sh
bash install.sh --yes --dry-run --address 192.0.2.10 --interface eth0 \
  --dns yes --dhcp kea --radius yes --ca yes
```

Replace the documentation address/interface with your host's fixed LAN address
and interface. Remove `--dry-run` to install. `--yes` accepts defaults and package
installation without further prompts. Pass options to the downloaded `install.sh`;
the bootstrap and repository-key transfers have connection and total time limits.

For example, a **CA-only** deployment:

```sh
bash install.sh --yes --address 192.0.2.10 \
  --dns no --dhcp none --radius no --ca yes
```

A **RADIUS-only** deployment:

```sh
bash install.sh --yes --address 192.0.2.10 \
  --dns no --dhcp none --radius yes --ca no
```

The default directory is `/opt/netadmin`; override it with `--directory`.
`--version X.Y.Z` selects an explicit release. By default the installer resolves
the latest verified stable GitHub release once and downloads the Compose
template and bootstrap scripts from that exact tag. Every selected image uses the same
release version; containers are started with `--no-build`.

The installer checks the selected address/interface, conflicting Compose project
and listener ports, creates private transport credentials, pulls selected images,
and validates initial files with the native daemon parsers before startup. It
then checks each agent using a real mTLS connection and bearer token. It also
requires the selected containers to be running and verifies native Bind/Kea
control responses, the RADIUS process, and ISC's serving or intentional waiting
state. Failed pulls/startups retain state and never report success. To retry
unchanged:

```sh
bash install.sh --directory /opt/netadmin --resume --yes
```

An existing deployment directory is never overwritten. `--resume` uses its saved
service selection, image versions and keys; it does not change services or perform
an upgrade. Use `--prepare-only` to generate and validate Compose files without
pulling images or starting containers, then resume later. This option may still
install missing host dependencies. `--dry-run` makes no downloads or changes.

### Connect the app

Open the Home Assistant app, complete its root-account wizard and restart it.
The installer prints the selected agent HTTPS URLs and credential file paths,
without displaying secrets. Securely copy `transport/client/ca.crt`, `client.crt`
and `client.key` into `/config/pki/` in Home Assistant. Enter their new paths and
the token from `agents.env` under **Settings → Agent security**. Enable only the
installed services and enter their agent URLs. For DNS choose **Use DNS agent**;
for DHCP enter the agent URL and check its reported ISC/Kea backend. The backend
is configured on the agent, not selected in the app. For CA, enter the separate
token from `secrets/management-token`. Use **Test active connections**.

### One-time pairing

Use `bash install.sh --pair` with your service choices to offer enrollment after
startup. Pairing requires a release that includes this feature. For an installation
created by such a release, use `bash install.sh --resume --pair
--directory /opt/netadmin --yes`. Instead, you can run the pairing command printed
by the installer (also available as `sudo python3 /opt/netadmin/bootstrap/pairing.py
--directory /opt/netadmin`). Keep that terminal open. In the Home Assistant app,
open **Settings → Pair installation**, paste the `netadmin-pair://...` code and
choose **Pair installation**. This replaces the current agent connections with
this host's selected services. Test the active connections afterward.

The code contains a random single-use secret and a certificate fingerprint.
It expires after ten minutes; TCP port 8085 must be reachable from the app during
that window only. The app pins the host certificate before sending the secret.
The host closes enrollment after one claim, including an interrupted transfer;
run the command again to recover. No transport authority or managed CA private
keys are transferred. Codes and credentials must not be pasted into logs or chat.

RADIUS administration and login are independent. Pairing enables administration
for installed RADIUS services and imports their agent URL, while preserving your
existing login host, shared secret and login enablement. Add the app as a RADIUS
client through administration before configuring or enabling new RADIUS logins.
`NETADMIN_RADIUS_ADMIN_ENABLED` controls administration; if unset, it follows the
legacy `NETADMIN_RADIUS_ENABLED` flag. Both have separate switches in Settings.
Manual credential setup above remains supported. QR scanning is not required.

Keep the deployment directory and Docker volumes in protected backups. Transport
identities expire after one year; reissue them using the retained transport CA
before expiry. Pairing transfers the existing client identity; it does not rotate
keys or extend certificate validity. Superseded app-owned paired credentials
are removed after successful activation once in-flight requests have released
them. Manually provisioned credentials are left alone.

### Configure the network

Create user zones, DHCP subnets/pools, RADIUS clients/users and managed CAs through
NetAdmin. DNS starts authoritative-only, without user-defined zones; it is not a
recursive internet resolver. ISC remains in a waiting state until a matching
subnet is created, and returns to waiting when the last subnet is removed. Kea
starts with an empty subnet list. Neither allocates addresses until a pool is
configured. ISC restart failures are acknowledged to the agent for rollback.

RADIUS starts from packaged defaults, without network clients or users. Add the
Home Assistant host as a RADIUS client with a shared secret before enabling
RADIUS authentication for app login; root login works without it. RADIUS TLS
material is generated by its existing first-start bootstrap, independently of
the optional managed CA. Managed root/issuing authorities are created later in
the [CA UI](ca-setup.md).

Only selected services are started. Agent listeners are bound/published on the
chosen address, DNS also listens on loopback, and DHCP uses the chosen LAN
interface. The installer does not change firewall rules, router DHCP, device
trust or existing containers. Ensure the app and intended network clients can
reach the required service ports. Verify real DNS queries, DHCP leasing and/or
RADIUS authentication before relying on the installation; agent connectivity
checks do not establish those end-to-end operations.

For local development, the launcher supports
`--source-directory /path/to/net-admin --version X.Y.Z`; it uses that checkout's
deployment files instead of downloading them. Image tags still refer to that
version and must exist in GHCR before a real installation can start.

## Existing configurations with Docker Compose

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

5. Pull and start the published images (set `NETADMIN_VERSION` in `.env` to pin
   a release; the default is `latest`):

   ```sh
   docker compose pull
   docker compose up -d --no-build
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
  Legacy service options are imported on upgrade and removed from Home Assistant.
  The add-on's only option, `ingress_require_login`, controls whether trusted Home Assistant
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
