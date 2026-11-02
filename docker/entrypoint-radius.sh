#!/usr/bin/env bash
# Provide the FreeRADIUS TLS material, then exec radiusd.
#
# Existing material in /etc/raddb/certs (a named volume) is never silently
# replaced. Precedence:
#   1. server.pem and ca.pem both exist      -> reuse unchanged
#   2. neither exists and a seed var is set  -> install from environment
#   3. neither exists, no seed vars          -> generate via packaged bootstrap
#   4. exactly one exists                    -> refuse to start (partial state)
# Seed variables accept PEM (literal newlines or \n escapes) or base64:
#   NETADMIN_RADIUS_TLS_SERVER_PEM  server key + certificate (required to seed)
#   NETADMIN_RADIUS_TLS_CA_PEM      CA certificate (required to seed)
#   NETADMIN_RADIUS_TLS_CA_KEY      CA private key (optional, enables re-issue)
#   NETADMIN_RADIUS_TLS_CLIENT_PEM  client key + certificate (optional)
# Seeded material is validated before it is installed: a corrupt or mismatched
# seed fails the container loudly rather than rotating the CA silently.
# Only fingerprints and subjects are ever logged; private keys never are.
set -euo pipefail

CERT_DIR="/etc/raddb/certs"
SERVER_PEM="$CERT_DIR/server.pem"
CA_PEM="$CERT_DIR/ca.pem"
# Password used by the packaged bootstrap (server.cnf/ca.cnf output_password);
# seeded material produced by the same bootstrap decrypts with it.
BOOTSTRAP_PASS="whatever"

say() { printf '[entrypoint-radius] %s\n' "$*"; }
die() { printf '[entrypoint-radius] ERROR: %s\n' "$*" >&2; exit 1; }

decode_var() { # $1 = variable value; prints decoded PEM
  local value="$1"
  case "$value" in
    *-----BEGIN*) printf '%b\n' "$value" ;;
    *)
      printf '%s' "$value" | base64 -d 2>/dev/null \
        || die "TLS seed variable is neither PEM nor valid base64"
      ;;
  esac
}

extract_cert() { # $1 = PEM file; prints the first certificate block
  local pem="$1"
  awk '$0 == "-----BEGIN CERTIFICATE-----" { p = 1 } p { print } \
       $0 == "-----END CERTIFICATE-----" { exit }' "$pem"
}

extract_key() { # $1 = PEM file; prints the first private key block
  local pem="$1"
  awk '/^-----BEGIN .*PRIVATE KEY-----$/ { p = 1 } p { print } \
       /^-----END .*PRIVATE KEY-----$/ { exit }' "$pem"
}

key_pubkey() { # $1 = key PEM file; prints the public key, or fails
  local pem="$1"
  openssl pkey -in "$pem" -pubout -passin "pass:$BOOTSTRAP_PASS" 2>/dev/null \
    || openssl pkey -in "$pem" -pubout 2>/dev/null
}

validate_pair() { # $1 = cert+key file, $2 = CA file, $3 = label
  local cert_file="$1" ca_file="$2" label="$3"
  local tmp cert_pem key_pem cert_pub key_pub
  tmp="$(mktemp -d)"
  cert_pem="$tmp/cert.pem"
  key_pem="$tmp/key.pem"
  extract_cert "$cert_file" > "$cert_pem"
  extract_key "$cert_file" > "$key_pem"
  grep -q "BEGIN CERTIFICATE" "$cert_pem" \
    || { rm -rf "$tmp"; die "$label: no X.509 certificate found"; }
  grep -q "PRIVATE KEY" "$key_pem" \
    || { rm -rf "$tmp"; die "$label: no private key found"; }
  openssl x509 -in "$cert_pem" -noout 2>/dev/null \
    || { rm -rf "$tmp"; die "$label: certificate does not parse"; }
  key_pub="$(key_pubkey "$key_pem")" \
    || { rm -rf "$tmp"; die "$label: private key unreadable (encrypted with an unexpected password?)"; }
  cert_pub="$(openssl x509 -in "$cert_pem" -noout -pubkey 2>/dev/null)" \
    || { rm -rf "$tmp"; die "$label: cannot read certificate public key"; }
  [[ "$cert_pub" = "$key_pub" ]] \
    || { rm -rf "$tmp"; die "$label: certificate and private key do not match"; }
  openssl verify -CAfile "$ca_file" -untrusted "$cert_file" "$cert_pem" >/dev/null 2>&1 \
    || { rm -rf "$tmp"; die "$label: certificate does not verify against the provided CA"; }
  rm -rf "$tmp"
}

validate_ca() { # $1 = CA certificate file
  local ca_file="$1"
  openssl x509 -in "$ca_file" -noout 2>/dev/null || die "CA_PEM: certificate does not parse"
}

validate_ca_key() { # $1 = CA key file, $2 = CA certificate file
  local key_file="$1" ca_file="$2"
  local tmp key_pub cert_pub
  tmp="$(mktemp -d)"
  extract_key "$key_file" > "$tmp/ca.key"
  grep -q "PRIVATE KEY" "$tmp/ca.key" \
    || { rm -rf "$tmp"; die "CA_KEY: no private key found"; }
  key_pub="$(key_pubkey "$tmp/ca.key")" \
    || { rm -rf "$tmp"; die "CA_KEY: private key unreadable (encrypted with an unexpected password?)"; }
  cert_pub="$(openssl x509 -in "$ca_file" -noout -pubkey 2>/dev/null)" \
    || { rm -rf "$tmp"; die "CA_KEY: cannot read CA certificate public key"; }
  [[ "$key_pub" = "$cert_pub" ]] \
    || { rm -rf "$tmp"; die "CA_KEY: does not match the provided CA certificate"; }
  rm -rf "$tmp"
}

fingerprint_file() { # $1 = certificate-bearing file; prints sha256 + subject
  local pem="$1"
  local fp subject
  fp="$(openssl x509 -in "$pem" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2-)" \
    || return 1
  [[ -n "$fp" ]] || return 1
  subject="$(openssl x509 -in "$pem" -noout -subject -serial 2>/dev/null | tr '\n' ' ')"
  printf '    %-11s sha256 %s\n    %s\n' "$(basename "$pem")" "$fp" "$subject"
}

fix_permissions() {
  local f
  for f in "$CERT_DIR"/*; do
    [[ -f "$f" ]] || continue
    chown root:radius "$f"
    case "$(basename "$f")" in
      # radiusd instantiates eap as its runtime (non-root) user, which must be
      # able to read the server identity and CA - the packaged defaults are
      # 0640 root:radius for exactly this reason.
      server.pem | ca.pem) chmod 640 "$f" ;;
      *)
        if grep -q -- "PRIVATE KEY" "$f" 2>/dev/null; then
          chmod 600 "$f"
        else
          chmod 640 "$f"
        fi
        ;;
    esac
  done
}

has_server=false
has_ca=false
[[ -s "$SERVER_PEM" ]] && has_server=true
[[ -s "$CA_PEM" ]] && has_ca=true

if [[ "$has_server" == true && "$has_ca" == true ]]; then
  state="reusing existing TLS material from $CERT_DIR"
elif [[ "$has_server" == false && "$has_ca" == false ]]; then
  if [[ -n "${NETADMIN_RADIUS_TLS_SERVER_PEM:-}" || -n "${NETADMIN_RADIUS_TLS_CA_PEM:-}" ]]; then
    [[ -n "${NETADMIN_RADIUS_TLS_SERVER_PEM:-}" ]] \
      || die "seed requested but NETADMIN_RADIUS_TLS_SERVER_PEM is empty"
    [[ -n "${NETADMIN_RADIUS_TLS_CA_PEM:-}" ]] \
      || die "seed requested but NETADMIN_RADIUS_TLS_CA_PEM is empty"
    tmp="$(mktemp -d)"
    decode_var "$NETADMIN_RADIUS_TLS_SERVER_PEM" > "$tmp/server.pem"
    decode_var "$NETADMIN_RADIUS_TLS_CA_PEM" > "$tmp/ca.pem"
    [[ -z "${NETADMIN_RADIUS_TLS_CA_KEY:-}" ]] \
      || decode_var "$NETADMIN_RADIUS_TLS_CA_KEY" > "$tmp/ca.key"
    [[ -z "${NETADMIN_RADIUS_TLS_CLIENT_PEM:-}" ]] \
      || decode_var "$NETADMIN_RADIUS_TLS_CLIENT_PEM" > "$tmp/client.pem"
    # Validate before touching the volume: a corrupt seed fails the container
    # and leaves nothing half-installed behind.
    validate_ca "$tmp/ca.pem"
    validate_pair "$tmp/server.pem" "$tmp/ca.pem" "SERVER_PEM"
    [[ ! -f "$tmp/ca.key" ]] || validate_ca_key "$tmp/ca.key" "$tmp/ca.pem"
    [[ ! -f "$tmp/client.pem" ]] || validate_pair "$tmp/client.pem" "$tmp/ca.pem" "CLIENT_PEM"
    install -m 644 "$tmp/ca.pem" "$CA_PEM"
    install -m 600 "$tmp/server.pem" "$SERVER_PEM"
    [[ ! -f "$tmp/ca.key" ]] || install -m 600 "$tmp/ca.key" "$CERT_DIR/ca.key"
    [[ ! -f "$tmp/client.pem" ]] || install -m 600 "$tmp/client.pem" "$CERT_DIR/client.pem"
    rm -rf "$tmp"
    state="seeded TLS material from environment"
  else
    [[ -x "$CERT_DIR/bootstrap" ]] \
      || die "no TLS material and no packaged bootstrap to generate it"
    if ! boot_log="$("$CERT_DIR/bootstrap" 2>&1)"; then
      printf '%s\n' "$boot_log" >&2
      die "packaged TLS bootstrap failed"
    fi
    [[ -s "$SERVER_PEM" && -s "$CA_PEM" ]] \
      || die "bootstrap finished without creating server.pem and ca.pem"
    state="generated fresh TLS material via packaged bootstrap"
  fi
else
  present=""
  [[ "$has_server" == false ]] || present="server.pem"
  [[ "$has_ca" == false ]] || present="$present ca.pem"
  die "partial TLS material in $CERT_DIR ($present present, the other missing); restore both files or delete both to allow regeneration"
fi

fix_permissions

say "$state"
say "TLS material fingerprints (private keys are never logged):"
fingerprint_file "$SERVER_PEM" || die "server.pem has no readable certificate"
fingerprint_file "$CA_PEM" || die "ca.pem is not a readable certificate"

# The packaged configuration links mods-enabled/eap itself; keep this as a
# safety net so the module is always present regardless of package defaults.
if [[ ! -e /etc/raddb/mods-enabled/eap ]]; then
  ln -sf ../mods-available/eap /etc/raddb/mods-enabled/eap
  say "enabled the packaged eap module"
fi

exec /usr/local/bin/radius-supervisor.sh "$@"
