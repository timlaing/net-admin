# AGENTS.md

Single-package Python repo (not a monorepo). Python >= 3.12, Flask 3, setuptools.

## Commands

```sh
. .venv/bin/activate          # venv already exists; deps: pip install -e '.[dev]'
uv lock                       # after changing [project] deps; CI installs via `uv sync --locked`
ruff check .                  # lint (includes bandit-style "S" rules)
ruff format --check .         # formatting, line-length 100
mypy                          # strict; checks only the netadmin package, not tests
pylint netadmin
pytest                        # full suite with coverage gate
```

Run these in that order before considering work done. `pre-commit install` hooks run
ruff --fix, ruff-format and mypy automatically.

- Single test: `pytest tests/test_dhcp_agent.py::test_name --no-cov -q`.
  `addopts` forces `--cov=netadmin --cov-fail-under=80`, so any partial run fails the
  coverage gate unless you pass `--no-cov`. (`-p no:cov` does NOT work — it unloads the
  plugin that parses the `--cov` args.)
- Tests are self-contained: they build `Settings(...)` directly with `tmp_path`; no
  `.env` or live services needed. Agent endpoint tests set `NETADMIN_AGENT_TOKEN` via
  `monkeypatch`.

## Architecture

Three deployables from one package, wired in `docker-compose.yml`:

- `netadmin/` — web app (`netadmin` script → `netadmin.wsgi:main`, port 8099).
  Factory: `netadmin/app.py::create_app`; routes in the `web` blueprint.
- `netadmin/agents/dhcp.py` and `netadmin/agents/radius.py` — restricted sidecar agents
  (ports 8081/8082). Each is a separate Flask app behind mTLS + bearer token.
- `netadmin/services/` — shared logic: `dns.py` talks to Bind via AXFR + RFC 2136
  (dnspython), `dhcp_files.py`/`radius_files.py` parse/render service configs,
  `agents.py` is the web app's mTLS HTTP client.
- `netadmin/setup.py` — first-run wizard for the HA add-on. `wsgi.py::build_app`
  falls back to it only when `NETADMIN_ADDON=1` and required env is missing;
  routes 404 unless the request carries HA's `X-Ingress-Path` header. It writes
  `/config/netadmin.env` (override: `NETADMIN_ENV_FILE`) with mode 0640.
- `scripts/cutover.sh` — one-shot migration from the pre-NetAdmin stack; builds
  first while old services still run, then stops old, syncs leases/zones (incl.
  `.jnl`), and starts the new stack with health checks. Keeps old containers for
  rollback. Run it on the server from a repo checkout, not locally.
- `scripts/migrate-to-kea.sh` + `netadmin/services/kea_migrate.py` — generic
  ISC→Kea migration: folds every host file into one agent-owned
  `netadmin-reservations.json`, renders `kea4.conf` (globals inherited into every
  subnet), optionally converts live leases to a Kea memfile, then validates with
  `kea-dhcp4 -t`. Flag-driven with no network baked in (`--config/--out-dir/
--interfaces/--lease-db/...`); `NETADMIN_PYTHON` overrides interpreter selection.
  Strict on purpose: missing config/include or conflicting reservations abort
  before writing. Migration-day procedure: `MIGRATION.md`. `cutover.sh` above is
  the separate pre-NetAdmin path.
- Service images: `docker/Dockerfile.{bind,dhcpd,freeradius}` with
  `docker/entrypoint-*.sh`; compose tags them `ghcr.io/timlaing/netadmin-{dns,dhcp,radius}`.
  `docker-compose.kea.yml` is the Kea-backend variant of the same stack
  (`docker compose -f docker-compose.kea.yml up -d`); the dhcp agent selects its
  backend with `DHCP_SERVER=isc|kea` (default isc), validates with the matching
  daemon parser, and in kea mode reloads over the `/run/kea/kea4-ctrl.sock`
  control socket (`python3 -m netadmin.agents.kea_ctrl`). Migration tooling is
  separate from both compose files.
  Entrypoints own key material at runtime — never baked into images: dns seeds or
  generates `rndc-key` into the `rndc-shared` volume and prints the full key on
  every start, dhcp waits for that volume and copies the key to
  `/etc/dhcp/rndc.key`, radius generates or seeds TLS into `radius-certs` and logs
  fingerprints only (never keys). Existing material is never silently replaced.

Flow: web app never writes service config itself; it calls the agents, which validate a
candidate file (e.g. `dhcpd -t`, `freeradius -C`), atomically install it, and roll back
on reload failure (`netadmin/agents/common.py::validated_transaction`). Preserve this
boundary — do not move privileged file writes into the web app.

Security invariants (deliberate, tested — do not weaken):

- Passwords and service configuration are never stored in SQLite; `netadmin/store.py`
  holds only sessions, audit records and rate limits.
- Agents do not mount the Docker socket.
- Standard RADIUS users can change only their own password; mutating routes are
  `@admin_required`.
- Direct-access session cookies are always `Secure`; direct plain HTTP login is
  intentionally broken. Verified Supervisor ingress cookies follow the external
  HTTP/HTTPS scheme and are scoped to the app's ingress path. Never trust ingress
  headers from other peers or disable CSRF protection.
- Ruff `S` (security) rules are enabled; `noqa: S603/S104` and `# nosec` comments on
  subprocess/bind code are deliberate — follow the same pattern, don't remove them.

## Environment

Config comes only from `NETADMIN_*` env vars (`netadmin/config.py::from_env`, template
in `.env.example`). `NETADMIN_SECRET_KEY` and `NETADMIN_ROOT_PASSWORD_HASH` are
required — `Settings.from_env()` raises at import if missing. Agents use `DHCP_*` /
`RADIUS_*` vars (see docker-compose). Production agents run under gunicorn with TLS
certs from `/pki` and share the service container's PID namespace so the reload command
is `kill -HUP 1`.

## Traps

- `dns/`, `dhcp/`, `freeradius/`, `watchtower/`, `pki/` are gitignored but present
  locally: live service configs containing real credentials, TSIG keys and leases.
  Mount them in compose, never commit or copy their contents into tracked files.
- `home-assistant/` is an HA add-on wrapper; its `run.sh` sources `/config/netadmin.env`
  (never committed) before starting gunicorn.
- No CI workflows existed before `.github/workflows/`; the local check sequence above is
  still the fast gate. CI additionally builds every image and runs the `Tools/smoke_*.sh`
  smoke tests, so container-affecting changes (Dockerfiles, env handling, `wsgi.py`,
  `setup.py`) must pass those before the release that publishes them to GHCR
  (`publish.yml` triggers on `release: published`, not on tag pushes).
- Commit messages follow conventional commits (`feat:`, `fix:`, `test:`) — release-drafter
  and the autolabeler depend on them.
