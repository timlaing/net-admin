# NetAdmin

[![CI](https://github.com/timlaing/net-admin/actions/workflows/ci.yml/badge.svg)](https://github.com/timlaing/net-admin/actions/workflows/ci.yml)
[![Lint](https://github.com/timlaing/net-admin/actions/workflows/lint.yml/badge.svg)](https://github.com/timlaing/net-admin/actions/workflows/lint.yml)
[![CodeQL](https://github.com/timlaing/net-admin/actions/workflows/codeql.yml/badge.svg)](https://github.com/timlaing/net-admin/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/timlaing/net-admin)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-4c8eda)](https://timlaing.github.io/net-admin/)

[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=coverage)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)

[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=vulnerabilities)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=sqale_rating)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=reliability_rating)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=bugs)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=timlaing_NetAdmin&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=timlaing_NetAdmin)

NetAdmin is a Flask and Bootstrap application for administering Bind 9, ISC DHCPD (or
Kea DHCP) and FreeRADIUS while leaving each service as the source of truth. Bind uses
AXFR and RFC 2136. Restricted DHCP and RADIUS agents validate and atomically install
file-backed changes.

[![Open your Home Assistant instance and show the add add-on repository dialog with a specific repository URL pre-filled.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Ftimlaing%2Fnet-admin)

## Security model

- RADIUS authentication with `Filter-Id` mapped to `netadmin-admin` or `netadmin-standard`.
- Emergency `root` authentication uses an Argon2id hash from the environment.
- Standard users can only change their own password.
- Global CSRF protection, server-side one-hour sessions, strict cookies and audit records.
- Agents do not mount the Docker socket.
- Passwords and service configuration are never stored in NetAdmin's SQLite database.

## Configure and run

1. Copy `.env.example` to `.env` and replace every placeholder.
2. Add a matching RADIUS client and restricted TSIG update permission.
3. Create a private CA plus separate server certificates for both agents and a NetAdmin
   client certificate under `pki/`. Certificate SANs must match `dhcp-agent` and
   `radius-agent`.
4. Restrict private keys to the container user (`0600`) and configuration files containing
   hashes/secrets to `0640`.
5. Run `docker compose up --build -d`.
6. Put the application behind HTTPS and open port 8099 through the reverse proxy.

Direct-access cookies are always `Secure`, so direct HTTP is unsuitable for login.
Verified Home Assistant ingress supports its frontend's HTTP or HTTPS connection;
ingress cookies stay scoped to the app's ingress path.

### Key material

- **DNS/DHCP TSIG key** (`rndc-key`, name fixed by `named.conf` and `dhcpd.conf`):
  on first start the `dns` container seeds it from `NETADMIN_DNS_TSIG_SECRET`
  (base64) or generates it if that is unset, prints the **full key to the console
  on every start**, and shares it with `dhcp` through the `rndc-shared` volume.
  Existing key material is never regenerated: later edits or removal of the env
  value do not rotate it. To rotate, stop both services, delete the key and start
  again:

  ```sh
  docker compose stop dhcp dns
  docker compose run --rm --entrypoint rm dns /run/rndc/rndc.key
  docker compose up -d dns dhcp
  ```

- **RADIUS TLS material**: generated at first start by the packaged bootstrap
  into the `radius-certs` volume — nothing is baked into the image. To keep
  serving an existing CA (so supplicants keep trusting it), base64 the current
  material into `NETADMIN_RADIUS_TLS_SERVER_PEM` and `NETADMIN_RADIUS_TLS_CA_PEM`
  (plus optionally `NETADMIN_RADIUS_TLS_CA_KEY` and
  `NETADMIN_RADIUS_TLS_CLIENT_PEM`), e.g. `base64 -w0 server.pem`. Seeds are
  validated before install; a corrupt seed fails the container loudly instead of
  silently rotating the CA. Logs show fingerprints and subjects only — private
  keys are never printed. `scripts/cutover.sh` extracts this material from the
  old stack automatically.

For Home Assistant, open the add-on through its ingress (sidebar) panel on first run: a
setup wizard generates the secrets, hashes the emergency root password and writes
`/config/netadmin.env` (mode 0640). Restart the add-on to load it. The wizard is only
reachable through ingress and locks itself once configured; the file is never included in
the repository or options schema. To migrate an existing pre-NetAdmin stack, run
`scripts/cutover.sh` from a repo checkout on the server.

### DNS connection modes

DNS supports two exclusive connection modes in Settings: **Use DNS agent** uses
the agent URL and shared mTLS/token settings for zones and records; turning it off
reveals direct Bind/TSIG settings. Upgrade the DNS agent to 0.6.0 before the app
when using agent mode.

### Kea DHCP backend

`docker-compose.kea.yml` is a complete standalone alternative stack running Kea DHCP;
`docker-compose.yml` (ISC dhcpd) is unchanged:

```sh
docker compose -f docker-compose.kea.yml up -d --build
```

The DHCP agent selects its backend with `DHCP_SERVER=isc|kea` (default `isc`) and
validates candidate files with the matching daemon parser (`dhcpd -t` /
`kea-dhcp4 -t`); in Kea mode it reloads the daemon over `/run/kea/kea4-ctrl.sock`.
In the Home Assistant add-on, choose the matching DHCP backend in NetAdmin
**Settings → DHCP**. All service connections are managed there; Home Assistant
Configuration contains only the ingress login policy.

#### Migrating an existing ISC configuration

`scripts/migrate-to-kea.sh` converts a live dhcpd tree (the main config plus every
`include`) into the layout the NetAdmin agent manages:

```sh
scripts/migrate-to-kea.sh \
  --config dhcp/config/dhcpd.conf \
  --out-dir /tmp/kea-migration \
  --leases dhcp/dhcpd.leases        # optional: keep live bindings
```

It writes `kea4.conf`, one folded `netadmin-reservations.json` holding every host
declaration from every file (the agent owns it at runtime), and — with `--leases` — a
Kea memfile containing only live bindings, then checks the result with the real
`kea-dhcp4 -t`. Every value is a flag (`--interfaces`, `--include-path`, `--lease-db`,
`--lifetime`, `--socket-name`, `--dry-run`, …) with no network baked in; conflicting
reservations and missing includes fail loudly before anything is written. See
`scripts/migrate-to-kea.sh --help` for the full list, and [MIGRATION.md](MIGRATION.md)
for the step-by-step migration-day runbook (prepare, cutover, verify, rollback).

## Development

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
ruff check .
ruff format --check .
mypy
pylint netadmin
pytest
```

## CI and published containers

GitHub Actions runs the same checks plus container smoke tests on every push and
pull request (`.github/workflows/ci.yml`, `lint.yml`, `pre-commit.yml`, `codeql.yml`).
The smoke tests boot each image and verify real behaviour: login and Secure
cookies for the app, mTLS plus bearer-token enforcement for the agents,
ingress-only access plus wizard locking for the add-on, TSIG key precedence and
real dynamic updates for the dns service, the shared-volume key wait and install
flow for dhcp, and runtime TLS generation, reuse, seeded-material validation and
fingerprint-only logging for radius (`Tools/smoke_*.sh`). Every image is built and
smoke-tested on both amd64 and aarch64 (native runners).

Publishing a `vX.Y.Z` GitHub Release publishes multi-arch images to GHCR after
verify and lint gates pass (`.github/workflows/publish.yml` triggers on
`release: published`, so a stray `git push --tags` publishes nothing):

- `ghcr.io/timlaing/netadmin` — web application
- `ghcr.io/timlaing/netadmin-dns-agent` — restricted Bind zone-management agent (optional)
- `ghcr.io/timlaing/netadmin-dhcp-agent` — restricted DHCP agent
- `ghcr.io/timlaing/netadmin-radius-agent` — restricted RADIUS agent
- `ghcr.io/timlaing/netadmin-dns` — Bind 9 service
- `ghcr.io/timlaing/netadmin-dhcp` — ISC DHCPD service
- `ghcr.io/timlaing/netadmin-radius` — FreeRADIUS service
- `ghcr.io/timlaing/<arch>-addon-netadmin` — Home Assistant add-on

The release's tag must match `home-assistant/netadmin/config.yaml`'s `version`.
Release notes are drafted automatically from conventional commits by
release-drafter; the tag is created when the release is published.

### Certificate authority and renewal

See [Certificate management](docs/certificates.md) for configurable local RADIUS
certificates and the optional Docker step-ca service, CSR issuance, revocation/CRLs,
and automatic RADIUS certificate renewal.
