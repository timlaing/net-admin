#!/usr/bin/env bash
# Download a release-pinned, service-only NetAdmin stack and prepare a fresh host.
set -euo pipefail
# Parse options, prepare host dependencies and launch a pinned installer.
install_main() {
original_arguments=("$@")
# Print supported options without changing the host.
usage() {
  cat <<'EOF'
Usage: install.sh [options]
  --directory PATH         Deployment directory (Linux: /opt/netadmin; macOS: ~/Library/Application Support/NetAdmin)
  --address IPV4           Fixed LAN address of this host
  --interface NAME         LAN interface for DHCP (for example eth0)
  --dhcp isc|kea|none       DHCP backend (Linux default kea; macOS default none)
  --dns yes|no             Include Bind DNS (default yes)
  --radius yes|no          Include FreeRADIUS (default yes)
  --ca yes|no              Include the managed CA (default yes)
  --version latest|X.Y.Z    Default: latest stable GitHub release
  --yes                    Accept defaults without interactive prompts
  --dry-run                Describe actions without downloads or changes
  --prepare-only           Prepare and validate, but do not start containers
  --pair                   Offer a ten-minute one-time pairing code after startup
  --resume                 Resume an existing installer deployment unchanged
  --source-directory PATH  Use local deployment assets for development

Run on Linux or macOS (DNS, RADIUS and CA only on macOS); sudo is requested when needed. Supports
installation: Debian, Ubuntu, 64-bit Raspberry Pi OS, Fedora and RHEL.
Existing Docker installations are reused; conflicting packages are not removed.
EOF
}
platform=linux
[[ "$(uname -s)" != Darwin ]] || platform=macos
directory=/opt/netadmin
[[ "$platform" != macos ]] || directory="$HOME/Library/Application Support/NetAdmin"
address='' interface='' dns='' dhcp='' radius='' ca=''
pair=false
version=latest yes=false dry_run=false prepare_only=false resume=false source_directory=''
while (($#)); do
  case "$1" in
    --directory) directory="${2:?Missing directory}"; shift 2 ;;
    --address) address="${2:?Missing address}"; shift 2 ;;
    --interface) interface="${2:?Missing interface}"; shift 2 ;;
    --dhcp) dhcp="${2:?Missing DHCP backend}"; shift 2 ;;
    --dns) dns="${2:?Missing DNS choice}"; shift 2 ;;
    --radius) radius="${2:?Missing radius choice}"; shift 2 ;;
    --ca) ca="${2:?Missing CA choice}"; shift 2 ;;
    --version) version="${2:?Missing version}"; shift 2 ;;
    --source-directory) source_directory="${2:?Missing source directory}"; shift 2 ;;
    --yes) yes=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    --prepare-only) prepare_only=true; shift ;;
    --pair) pair=true; shift ;;
    --resume) resume=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
# Report an unrecoverable installer error and stop.
fail() { echo "$*" >&2; exit 1; }
# Read a terminal answer or return the noninteractive default.
ask() {
  local answer
  if [[ "$yes" == true ]]; then
    printf '%s' "$2"
  else
    if ! { true < /dev/tty; } 2>/dev/null; then
      fail 'Use --yes and explicit options for non-interactive installation.'
    fi
    read -r -p "$1 [$2]: " answer < /dev/tty
    printf '%s' "${answer:-$2}"
  fi
}
if [[ "$resume" == false ]]; then
  [[ -n "$dns" ]] || dns="$(ask 'Include Bind DNS: yes or no' yes)"
  if [[ "$platform" == macos ]]; then
    [[ -n "$dhcp" ]] || dhcp=none
  else
    [[ -n "$dhcp" ]] || dhcp="$(ask 'DHCP backend: isc, kea or none' kea)"
  fi
  [[ -n "$radius" ]] || radius="$(ask 'Include FreeRADIUS: yes or no' yes)"
  [[ -n "$ca" ]] || ca="$(ask 'Include managed certificate authority: yes or no' yes)"
  [[ -n "$address" ]] || address="$(ask 'Fixed IPv4 address of this host' '')"
  if [[ "$dhcp" != none && -z "$interface" ]]; then
    interface="$(ask 'LAN interface for DHCP' eth0)"
  fi
  [[ "$dhcp" =~ ^(isc|kea|none)$ ]] || fail 'DHCP must be isc, kea or none.'
  [[ "$dns" =~ ^(yes|no)$ && "$radius" =~ ^(yes|no)$ && "$ca" =~ ^(yes|no)$ ]] || fail 'DNS, CA and RADIUS choices must be yes or no.'
  [[ "$dns" == yes || "$dhcp" != none || "$radius" == yes || "$ca" == yes ]] || fail 'Select at least one service.'
  [[ "$address" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Specify --address with the fixed LAN IPv4 address.'
  [[ "$dhcp" == none || "$interface" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail 'Invalid LAN interface.'
fi
[[ "$version" == latest || "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || fail 'Invalid release version.'
[[ "$directory" == /* && "$directory" != / && "$directory" != *$'\n'* ]] || fail 'Specify an absolute deployment directory other than /.'
if [[ "$resume" == false && -e "$directory" ]]; then
  fail 'Deployment directory exists. Use --resume for an installer deployment; no files overwritten.'
fi
if [[ "$platform" == macos && "$dhcp" != none && "$resume" == false ]]; then
  fail "DHCP requires Linux; use --dhcp none on macOS."
fi
if [[ "$dry_run" == true ]]; then
  if [[ "$platform" == macos ]]; then
    echo "Would reuse or install Docker Desktop through Homebrew, start it and publish selected service ports."
  else
    echo "Would reuse Docker Engine/Compose, or install missing components from Docker's official repository."
  fi
  if [[ "$resume" == true ]]; then
    echo "Would resume the saved deployment in $directory."
    echo 'Would reuse saved configuration, service selection, image versions and credentials.'
    echo 'Would validate native configurations, pull saved images and start saved services.'
  else
    echo "Would download release $version to $directory; DNS=$dns, DHCP=$dhcp, RADIUS=$radius, CA=$ca."
    echo "Host address: $address; interface: ${interface:-none}. Transport credentials generated locally."
    if [[ "$prepare_only" == true ]]; then
      echo 'Would prepare files and validate Compose without pulling images or starting containers.'
    else
      echo 'Would validate native configurations, pull selected images and start only selected services.'
    fi
  fi
  echo 'No packages, downloads, files or containers changed.'
  exit 0
fi
[[ "$(uname -s)" =~ ^(Linux|Darwin)$ ]] || fail 'Install on Linux or macOS.'
[[ "$(uname -m)" =~ ^(x86_64|aarch64|arm64)$ ]] || fail 'Published images require amd64 or arm64 (use 64-bit Raspberry Pi OS).'
if [[ "$platform" == macos ]]; then
  [[ "$EUID" != 0 ]] || fail 'Run the macOS installer as your desktop user, without sudo.'
  export PATH="$PATH:$HOME/.docker/bin:/Applications/Docker.app/Contents/Resources/bin"
  if [[ "$yes" == false ]]; then
    [[ "$(ask 'Install missing desktop dependencies and start selected services: yes or no' no)" == yes ]] || exit 0
  fi
  if ! command -v docker >/dev/null || { [[ ! -d /Applications/Docker.app ]] && [[ ! -d "$HOME/Applications/Docker.app" ]]; }; then
    command -v brew >/dev/null || fail 'Install Homebrew from https://brew.sh, then rerun to install Docker Desktop.'
    brew install --cask docker-desktop
  fi
  # Homebrew OpenSSL provides the certificate-generation flags used on Linux too.
  if ! command -v brew >/dev/null; then
    fail 'Install Homebrew from https://brew.sh for Python and OpenSSL 3, then rerun.'
  fi
  if ! brew list --versions python@3.13 >/dev/null 2>&1; then brew install python@3.13; fi
  if ! brew list --versions openssl@3 >/dev/null 2>&1; then brew install openssl@3; fi
  openssl_prefix="$(brew --prefix openssl@3)"
  python_prefix="$(brew --prefix python@3.13)"
  export PATH="$openssl_prefix/bin:$python_prefix/libexec/bin:$PATH"
  python_command=python3
  open -a Docker
  echo 'Waiting for Docker Desktop. Complete its first-run setup in the app if prompted.'
  deadline=$((SECONDS + 180))
  until docker info >/dev/null 2>&1; do
    (( SECONDS < deadline )) || fail 'Start Docker Desktop, complete its setup, then rerun the installer.'
    sleep 3
  done
  docker compose version >/dev/null
else
if [[ "$EUID" != 0 ]]; then
  command -v sudo >/dev/null || fail 'sudo is required to install host packages and service files.'
  # A piped installer has no reusable source filename. Save the fully parsed
  # function before elevating; never try to read the remaining pipeline as code.
  elevated_script="$(mktemp)"
  chmod 0600 "$elevated_script"
  {
    printf '#!/usr/bin/env bash\nset -euo pipefail\n'
    declare -f install_main
    printf '\ninstall_main "$@"\n'
  } > "$elevated_script"
  elevation_args=("${original_arguments[@]}")
  if [[ "$resume" == false ]]; then
    elevation_args+=(--dns "$dns" --dhcp "$dhcp" --radius "$radius" --ca "$ca" --address "$address")
    [[ -z "$interface" ]] || elevation_args+=(--interface "$interface")
  fi
  result=0
  sudo /bin/bash "$elevated_script" "${elevation_args[@]}" || result=$?
  rm -f "$elevated_script"
  exit "$result"
fi
# os-release is a root-owned operating-system file, never a downloaded env file.
# shellcheck source=/dev/null
. /etc/os-release
case "$ID" in
  debian|raspbian|ubuntu) family=apt ;;
  fedora|rhel) family=dnf ;;
  *) fail 'Automatic setup supports Debian, Ubuntu, Raspberry Pi OS, Fedora and RHEL.' ;;
esac
if [[ "$yes" == false ]]; then
  [[ "$(ask 'Install missing host dependencies and start the selected NetAdmin services: yes or no' no)" == yes ]] || exit 0
fi
missing=false
for dependency in curl python3 openssl ip; do
  command -v "$dependency" >/dev/null || missing=true
done
if [[ "$family" == apt ]]; then
  trust_store=/etc/ssl/certs/ca-certificates.crt
else
  trust_store=/etc/pki/tls/certs/ca-bundle.crt
fi
[[ -s "$trust_store" ]] || missing=true
if [[ "$missing" == true ]]; then
  if [[ "$family" == apt ]]; then
    apt-get update
    apt-get install -y ca-certificates curl python3 openssl iproute2
  else
    dnf install -y ca-certificates curl python3 openssl iproute
  fi
fi
if [[ ! -s "$trust_store" ]]; then
  if [[ "$family" == apt ]]; then update-ca-certificates; else update-ca-trust extract; fi
  [[ -s "$trust_store" ]] || fail 'System CA trust store is missing or empty after certificate setup.'
fi
python_command=python3
if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 9))'; then
  [[ "$ID" == rhel ]] || fail 'Python 3.9 or newer is required.'
  dnf install -y python3.11
  python_command=python3.11
fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  if ! command -v docker >/dev/null; then
    # Do not remove an operator's container runtime to make installation work.
    if [[ "$family" == apt ]]; then
      for package in docker.io docker-compose podman-docker containerd runc; do
        if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'install ok installed'; then
          fail "Conflicting package $package is installed. Resolve it manually; nothing was removed."
        fi
      done
    else
      for package in podman podman-docker runc docker docker-engine; do
        if rpm -q "$package" >/dev/null 2>&1; then
          fail "Conflicting package $package is installed. Resolve it manually; nothing was removed."
        fi
      done
    fi
    packages=(docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin)
  else
    packages=(docker-compose-plugin)
  fi
  if [[ "$family" == apt ]]; then
    distro="$ID"
    [[ "$distro" != raspbian ]] || distro=debian
    codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
    [[ "$codename" =~ ^[a-z]+$ ]] || fail 'Cannot determine distribution codename.'
    if [[ ! -e /etc/apt/sources.list.d/docker.sources && ! -e /etc/apt/sources.list.d/docker.list ]]; then
      install -d -m 0755 /etc/apt/keyrings
      curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        --connect-timeout 10 --max-time 120 \
        "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc
      chmod 0644 /etc/apt/keyrings/docker.asc
      cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$distro
Suites: $codename
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
    fi
    apt-get update
    apt-get install -y "${packages[@]}"
  else
    if [[ ! -e /etc/yum.repos.d/docker-ce.repo ]]; then
      if [[ "$ID" == fedora ]]; then
        dnf install -y dnf5-plugins
        dnf config-manager addrepo --from-repofile https://download.docker.com/linux/fedora/docker-ce.repo
      else
        dnf install -y dnf-plugins-core
        dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
      fi
    fi
    dnf install -y "${packages[@]}"
  fi
  systemctl enable --now docker
fi
docker info >/dev/null || fail 'Docker is installed but unavailable. Start/fix its daemon and rerun.'
docker compose version >/dev/null
fi
# Saved helpers may predate platform checks, so enforce them in the bootstrap too.
"$python_command" - "$directory" "$platform" "$resume" <<'PREFLIGHT'
import json
import os
import subprocess
import sys
from pathlib import Path

directory, platform, resume = sys.argv[1:]
if resume == 'true':
    manifest = Path(directory) / 'installation.json'
    if not manifest.is_file():
        raise SystemExit('No installer deployment found to resume.')
    try:
        state = json.loads(manifest.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise SystemExit('Invalid installer deployment manifest') from None
    if not isinstance(state, dict):
        raise SystemExit('Invalid installer deployment manifest')
    if state.get('schema') != 1 or state.get('project') != 'netadmin-services':
        raise SystemExit('Unrecognized installer deployment')
    if state.get('platform', 'linux') != platform:
        raise SystemExit('Saved deployment platform does not match this host')
    if platform == 'macos' and state.get('dhcp') != 'none':
        raise SystemExit('Saved macOS deployment cannot enable DHCP')
context = json.loads(subprocess.run(['docker', 'context', 'inspect'], check=True,
                                  capture_output=True, timeout=10).stdout)
endpoint = context[0]['Endpoints']['docker']['Host']
if not os.environ.get('DOCKER_CONTEXT'):
    endpoint = os.environ.get('DOCKER_HOST') or endpoint
if not endpoint.startswith('unix://'):
    raise SystemExit('Remote Docker contexts are not supported')
PREFLIGHT
if [[ "$resume" == true ]]; then
  [[ -f "$directory/bootstrap/install_services.py" ]] || fail 'No installer deployment found to resume.'
  resume_args=(--directory "$directory" --resume)
  if [[ "$pair" == true ]]; then
    "$python_command" "$directory/bootstrap/install_services.py" --help | grep -q -- --pair || fail "This saved installer predates pairing. Use manual credentials or a new deployment from a pairing-capable release."
    resume_args+=(--pair)
  fi
  if [[ "$platform" == macos ]]; then
    "$python_command" "$directory/bootstrap/install_services.py" --help | grep -q -- --platform || fail 'The saved helper does not support macOS.'
    resume_args+=(--platform macos)
  fi
  exec "$python_command" "$directory/bootstrap/install_services.py" "${resume_args[@]}"
fi
# Ignore newer releases whose images/assets have not finished publication.
if [[ "$version" == latest ]]; then
  version="$("$python_command" - <<'PY'
import json
import re
import urllib.request

def latest_installer_release():
    """Find the newest stable release with completed image and asset publication."""
    required = {'install.sh', 'install.sh.sha256', 'compose.yml', 'installer-ready.json'}
    for page in range(1, 11):
        request = urllib.request.Request(
            'https://api.github.com/repos/timlaing/net-admin/releases'
            f'?per_page=100&page={page}',
            headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'NetAdmin-installer'},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            releases = json.load(response)
        if not isinstance(releases, list):
            raise SystemExit('Invalid GitHub releases response')
        for release in releases:
            if not isinstance(release, dict) or release.get('draft') or release.get('prerelease'):
                continue
            tag = release.get('tag_name', '')
            if not isinstance(tag, str) or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', tag):
                continue
            uploaded = {asset.get('name') for asset in release.get('assets', [])
                        if asset.get('state') == 'uploaded' and asset.get('size', 0) > 0}
            if required <= uploaded:
                return tag[1:]
        if len(releases) < 100:
            break
    raise SystemExit('No verified stable NetAdmin installer release is available yet')

if __name__ == '__main__':
    print(latest_installer_release())
PY
)"
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || fail 'Invalid published release tag.'
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
if [[ -n "$source_directory" ]]; then
  cp "$source_directory/scripts/install_services.py" "$temporary/install_services.py"
else
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --connect-timeout 10 --max-time 120 \
    "https://raw.githubusercontent.com/timlaing/net-admin/v$version/scripts/install_services.py" \
    -o "$temporary/install_services.py"
fi
args=(--directory "$directory" --address "$address" --interface "$interface" --dns "$dns" --dhcp "$dhcp" --radius "$radius" --ca "$ca" --version "$version")
if [[ "$platform" == macos ]]; then
  "$python_command" "$temporary/install_services.py" --help | grep -q -- --platform || fail 'This release predates macOS support. Select a macOS-capable release.'
  args+=(--platform macos)
fi
[[ "$prepare_only" == false ]] || args+=(--prepare-only)
if [[ "$pair" == true ]]; then
  "$python_command" "$temporary/install_services.py" --help | grep -q -- --pair || fail 'The selected release predates pairing. Select a pairing-capable release or use manual credentials.'
  args+=(--pair)
fi
[[ -z "$source_directory" ]] || args+=(--source-directory "$source_directory")
"$python_command" "$temporary/install_services.py" "${args[@]}"
}
# Parse the complete body before reading interactive input from /dev/tty. This
# also permits the same file to be executed via curl ... | bash.
install_main "$@"
