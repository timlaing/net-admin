#!/usr/bin/env bash
# Prepare an isolated CA deployment using independent, existing agent mTLS trust.
set -euo pipefail
usage() {
  echo 'Usage: install-ca.sh --directory PATH --pki-dir PATH --agent-env FILE --version VERSION --bind IP [--dry-run]'
}
deployment='' transport='' agent_env='' version='' bind='' dry_run=false
while (($#)); do
  case "$1" in
    --directory) deployment="${2:?}"; shift 2 ;;
    --pki-dir) transport="${2:?}"; shift 2 ;;
    --agent-env) agent_env="${2:?}"; shift 2 ;;
    --version) version="${2:?}"; shift 2 ;;
    --bind) bind="${2:?}"; shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$deployment" && -n "$transport" && -n "$agent_env" && -n "$version" && -n "$bind" ]] || { usage >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]] || { echo 'Specify an explicit release version.' >&2; exit 2; }
command -v python3 >/dev/null
command -v docker >/dev/null
docker compose version >/dev/null
for file in server.crt server.key ca.crt; do
  [[ -r "$transport/$file" ]] || { echo "Missing readable transport/$file" >&2; exit 2; }
done
[[ -r "$agent_env" ]] || { echo 'Agent environment file is not readable.' >&2; exit 2; }
script_root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$deployment/installation.json" ]]; then
  docker compose -p netadmin-ca --project-directory "$deployment" -f "$deployment/compose.yml" config --quiet
  echo "Existing CA deployment found in $deployment; state preserved. Use its Compose project for explicit upgrades."
  exit 0
fi
if [[ "$dry_run" == true ]]; then
  echo "Would prepare isolated CA containers in $deployment, release $version, bind $bind."
  echo 'No keys, configuration or containers changed. Root key generation happens inside the runtime.'
  exit 0
fi
if [[ -n "$(docker ps -aq --filter label=com.docker.compose.project=netadmin-ca)" ]]; then
  echo "A netadmin-ca Compose project already exists. Inspect it before installing another authority." >&2
  exit 2
fi
# Never source operator env as shell code, and never print or copy unrelated service secrets.
python3 - "$deployment" "$transport" "$agent_env" "$version" "$bind" "$script_root" <<'PY'
import ipaddress, json, os, secrets, shlex, shutil, sys
from pathlib import Path
out, transport, source, version, bind, repo = sys.argv[1:]
ipaddress.IPv4Address(bind)
p=Path(out).resolve()
if p.exists():
    raise SystemExit('Deployment directory already exists. Inspect/update its existing Compose project; no files overwritten.')
values={}
for line in Path(source).read_text().splitlines():
    if line.startswith('NETADMIN_AGENT_TOKEN='):
        parts=shlex.split(line.split('=',1)[1])
        if len(parts)!=1: raise SystemExit('Invalid agent bearer token')
        values['NETADMIN_AGENT_TOKEN']=parts[0]
if not values.get('NETADMIN_AGENT_TOKEN') or any(c in values['NETADMIN_AGENT_TOKEN'] for c in '\r\n\x00'):
    raise SystemExit('NETADMIN_AGENT_TOKEN is required in the supplied agent environment file')
if "'" in values['NETADMIN_AGENT_TOKEN']: raise SystemExit('Token must not contain single quotes')
os.umask(0o077)
p.mkdir(parents=True,mode=0o700)
(p/'transport').mkdir();(p/'secrets').mkdir()
for name in ('server.crt','server.key','ca.crt'):
    shutil.copyfile(Path(transport)/name,p/'transport'/name)
    (p/'transport'/name).chmod(0o400)
(p/'secrets/management-token').write_text(secrets.token_urlsafe(48))
# Compose env_file literal format: single quoted values do not interpolate dollars.
(p/'runtime.env').write_text("NETADMIN_AGENT_TOKEN='"+values['NETADMIN_AGENT_TOKEN']+"'\n")
(p/'.env').write_text(f'NETADMIN_VERSION={version}\nCA_BIND_ADDRESS={bind}\n')
shutil.copyfile(Path(repo)/'docker-compose.ca.yml',p/'compose.yml')
(p/'installation.json').write_text(json.dumps({'version':version,'bind':bind,'project':'netadmin-ca'},indent=2)+'\n')
print('Prepared CA deployment:',p)
PY
docker compose -p netadmin-ca --project-directory "$deployment" -f "$deployment/compose.yml" config --quiet
docker compose -p netadmin-ca --project-directory "$deployment" -f "$deployment/compose.yml" pull
docker compose -p netadmin-ca --project-directory "$deployment" -f "$deployment/compose.yml" up -d --no-build
ready=false
for _ in {1..30}; do
  if docker compose -p netadmin-ca --project-directory "$deployment" -f "$deployment/compose.yml" exec -T ca-runtime python -c \
    'import os,httpx; from pathlib import Path; token=Path(os.environ["CA_MANAGEMENT_TOKEN_FILE"]).read_text().strip(); client=httpx.Client(transport=httpx.HTTPTransport(uds="/control/ca.sock")); response=client.get("http://controller/authorities",headers={"X-CA-Management-Token":token}); response.raise_for_status()' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
[[ "$ready" == true ]] || { echo "Runtime is not ready. Inspect its Compose logs; state and credentials are preserved." >&2; exit 1; }
echo "Open NetAdmin Settings: CA URL https://$bind:8084."
echo "Enter the separate management token from $deployment/secrets/management-token."
echo 'Use the existing agent bearer token and matching client certificate. Then open Certificates.'
echo 'Keep secrets and persistent volumes. Re-running never replaces an existing installation.'
