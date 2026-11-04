# Certificate management

For container-generated root keys, UI initialization, subordinate issuing CAs and
the optional installer, see [Create a root and issuing CAs](ca-setup.md). The
[design notes](ca-bootstrap-design.md) also describe longer-term extensions.
The procedures below cover the existing local and externally initialized step-ca backends.

NetAdmin supports two RADIUS certificate backends. The default `local` backend
uses the existing RADIUS CA. The optional `step-ca` backend delegates issuance to
Smallstep and runs a separate renewal worker. Both install certificates through
the RADIUS agent's configuration validation, acknowledged restart, and rollback.
No agent mounts the Docker socket. In local mode, the RADIUS agent reads its CA
signing key from `ca.key`. With step-ca, the signing key stays in the authority
container; NetAdmin and its agents receive no authority signing key.

## Local certificates

Open **RADIUS → Certificates**. **Renew server certificate** lets you set the CN,
DNS/IP SANs, and validity in whole days (1–3650). Enter **365** for one year.
The expiry is capped by the CA's expiry. Existing policy extensions are preserved.
**Create new server certificate** creates a new server key and a server-authentication
certificate with the selected CN, SANs and lifetime, replacing the active identity.
The previous public certificate is archived; it is not automatically revoked.
Renewal also creates a fresh key. Existing API clients omitting the new fields retain
the old identity and the default 365-day lifetime.

CN is limited to 64 UTF-8 bytes. SANs accept comma/whitespace-separated DNS names,
wildcards such as `*.example.test`, and IPv4/IPv6 addresses. Include the server name
configured in client Wi-Fi/VPN profiles. Changing names or a certificate pinned by
clients may require updating those profiles. Local CRLs retain the existing manual
refresh/distribution workflow.

## Deploy step-ca

Use the opt-in `docker-compose.step-ca.yml` override with either the ISC or Kea
base stack. This adds `step-ca`, `ca-agent`, and `radius-renewal`, and selects the
step-ca backend on `radius-agent`. It does not enrol or change the running RADIUS
identity until an administrator explicitly requests issuance.

### 1. Provision the authority

Create an operator-owned `step-ca/` directory and password files under
`pki/step-ca/`. These directories are gitignored. Do not put passwords in Compose,
command-line arguments, tracked files, or image layers. The CA password decrypts
the issuing key; the provisioner password authorizes enrolment. They can and should
be different. The CA agent receives only the provisioner password. Each CLI command has a
20-second deadline: token generation plus revocation and optional CRL reconciliation
fit within the web client's 60-second operation timeout.

Initialize a two-tier authority using Smallstep's documented `step ca init`
procedure, keeping the generated paths under `/home/step`, using address `:9000`,
and including `step-ca` plus the externally used CA hostname in its DNS names.
For example, after creating `pki/step-ca/ca-password` securely:

```sh
mkdir -p step-ca
# The official image runs as UID 1000; make the state directory writable by it.
sudo chown 1000:1000 step-ca
docker run --rm -it \
  -v "$PWD/step-ca:/home/step" \
  -v "$PWD/pki/step-ca/ca-password:/run/secrets/ca-password:ro" \
  smallstep/step-ca:0.30.2 step ca init \
  --deployment-type standalone --name 'Network CA' \
  --dns step-ca --dns ca.example.test --address :9000 \
  --provisioner netadmin --password-file /run/secrets/ca-password
```

Initialization uses the supplied password for its initial provisioner as well as
its CA keys. Initially copy that password securely to
`pki/step-ca/provisioner-password`; use Smallstep's provisioner management to rotate
the enrolment password independently. Give each container's runtime user read
access to only its required secrets. Take an encrypted offline backup of the root
key, then remove `step-ca/secrets/root_ca_key` from the online host. The running CA
uses only its intermediate key. Never remove the intermediate key or CA database.

Configure an explicit authority-wide name policy in `step-ca/config/ca.json`,
under `authority.policy`. Open-source step-ca does not support a `policy` field
on an individual JWK provisioner; that placement is ignored. For example:

```json
{
  "authority": {
    "policy": {
      "x509": {
        "allow": {
          "dns": ["example.test", "*.example.test"],
          "ip": ["192.0.2.0/24"]
        },
        "allowWildcardNames": false
      }
    }
  }
}
```

Merge this into the existing authority configuration, retaining its provisioners.
The IP-policy key is `ip`, not `ips`. A DNS wildcard matches exactly one label;
add deeper DNS zones explicitly. Test both allowed and rejected requests against
the actual daemon before relying on the policy.

Configure a certificate template in the `netadmin` JWK provisioner's
`options.x509`. The template must emit leaf certificates
(`CA:FALSE`), allow only intended usages, and include any CRL distribution URL.
Choose allowed DNS suffixes/IP ranges for your network. Do not enable CA issuance
or copy arbitrary CSR extensions. The CSR endpoint verifies signatures, key
strength, and rejects CA requests, but the authority is the final policy boundary.

Set provisioner lifetime claims to match the intended workflow. A useful RADIUS
starting point is a 24-hour default with automatic renewal; the enrolment form
requests one day by default. The general CSR form defaults to 365 days, which the
CA rejects unless its maximum duration permits it. These are requests, not overrides
of CA policy. Enable renewal and keep certificate-token renewal supported.

If enabling ACME, configure a separate ACME provisioner and provide the CA's HTTPS
endpoint directly to compatible clients. NetAdmin's manual CSR screen does not
install a renewal client on the requesting device.

### 2. Provision agent transport certificates

Use your existing independent agent mTLS trust hierarchy to create:

- `pki/ca-agent/server.crt`, `server.key`, `ca.crt`: server identity with SAN `ca-agent`
  and the CA that authenticates NetAdmin/RADIUS agent clients.
- `pki/ca-agent-client/client.crt`, `client.key`, `ca.crt`: a client-authentication
  identity for the RADIUS agent and the CA that verifies the CA agent server.

NetAdmin uses its existing `NETADMIN_AGENT_CA/CERT/KEY` and bearer token. The CA
agent uses the same token authentication and read-only guard as other agents. Keep
this transport PKI independent of the certificates it manages, to avoid circular
bootstrap or renewal dependencies.

### 3. Start the optional services

```sh
docker compose -f docker-compose.yml -f docker-compose.step-ca.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.step-ca.yml up -d --build
```

For Kea, replace the first Compose file with `docker-compose.kea.yml`. The CA must
have DNS SAN `step-ca` for the internal HTTPS connection. Port 9000 binds to loopback by default. Publish it on an explicitly selected
interface or configure a proxy when external renewal/ACME clients need access.
The CA agent is not published to the host. Pin root trust with
`step-ca/certs/root_ca.crt`, mounted read-only into the agents. Never replace it
with a certificate supplied in an issuance response.

Enable **CA administration** in Settings to show CA alongside the other services in the dashboard and menus. Standalone deployments use `NETADMIN_CA_ENABLED=true` and `NETADMIN_CA_AGENT_URL`. Disabling CA hides its navigation and stops dashboard polling while preserving the configured endpoint. Existing deployments with a CA URL remain enabled unless explicitly disabled.
It supports CSR issuance, public chain/root downloads, an issuance inventory
paged in groups of 100 (use Next page to continue), and
revocation with reason codes. Use **Inspect CSR** to decode the requested subject,
SANs and public key strength before approval. **Revoke a certificate by serial**
accepts the hexadecimal serial displayed on the RADIUS page, including the current
serial after direct renewal. The inventory records certificates issued through
this agent, including RADIUS enrolment. Direct renewals and certificates issued
through other provisioners are not a complete inventory here. Identical CSR/lifetime requests return the same recorded certificate by default.
The web form also supplies a stable request ID for retries; a new intentional
operation can use a new 32-character hexadecimal `request_id`. Reusing an ID with
a different CSR/lifetime is rejected. Complete staged outputs are recovered after
a crash; uncertain operations are retained and never automatically re-signed.
Inspect inventory and CA records before retrying an uncertain operation. Do not delete agent state to resolve an error.

### 4. Enrol FreeRADIUS

Distribute the new root certificate and configure the expected RADIUS server name
on clients first. In **RADIUS → Certificates**, choose **Issue server certificate
from step-ca**, specify CN/SANs and lifetime, then type `STEP CA` to confirm.

The RADIUS agent generates the private key locally and sends only its CSR to the
CA agent. It verifies the returned key, CN, SANs, server usage and chain against
the pinned root. It installs the key, leaf and intermediate chain in `server.pem`,
and installs the root in `ca.pem`, validates FreeRADIUS, then requests an
acknowledged native restart. A failed activation restores the previous identity.

**This also changes the CA trusted by RADIUS for EAP-TLS client certificates.**
Migrate those client certificates before enrolment. Password-based PEAP/MSCHAPv2
accounts remain as configured. Existing connections may be interrupted by restart.
Keep the previous root/key material securely for a planned rollback; changing the
backend variable alone does not undo a trust migration.

### Automatic renewal

`radius-renewal` uses the RADIUS agent image, shares the certificate volume and
RADIUS PID namespace, and checks every minute. At two-thirds of certificate
lifetime it stages a renewal using `step ca renew --mtls=false`, authenticated by
a signed token using the existing certificate/key. This supports serverAuth-only
certificates. It does not need the CA provisioner password or authority signing key.
The encrypted key is staged privately and its password is supplied through an
anonymous stdin pipe, never a temporary password file. The key is retained during renewal; a new enrolment generates a new key.

The worker shares the manual-operation lock, re-reads current files under that
lock, validates the replacement identity/chain, and uses the same activation and
rollback path. It retries failures at the next poll. Read-only mode or disabled
certificate management prevents activation. Run exactly one worker per RADIUS
instance; do not enable a competing external renewer that writes these files.

Watch `docker compose ... logs radius-renewal` and certificate expiry in the UI.
A CA outage does not replace the working certificate, but prolonged outages can
allow it to expire. Expired or revoked identities require explicit re-enrolment;
the worker does not silently fall back to an enrolment credential. CA revocation
prevents renewal; CRL checking is necessary to reject a still-unexpired certificate.

## CRLs

step-ca's open-source CRL implementation is minimal and documented as experimental.
Enable `crl.enabled` and `crl.generateOnRevoke` in its configuration, configure
refresh/cache intervals, and include a stable `crlDistributionPoints` URL in your
leaf certificate template before issuance. NetAdmin's **Download CRL** retrieves
`/1.0/crl` over pinned HTTPS from the CA; clients should use the stable CA
publication endpoint rather than an administrator-login-protected NetAdmin URL.

For clients needing an HTTP distribution point, configure step-ca's
`insecureAddress`, CRL `idpURL`, and a suitable published port/reverse proxy. The
CRL is signed; publishing it over HTTP does not expose signing keys. Test that the
actual relying clients fetch and enforce the CRL, including cached-list behaviour.
OCSP is not supplied by this integration. Pending revocations are recorded before contacting the CA. Retries reconcile
already-revoked responses or authoritative CRL entries before confirming local
state; an unconfirmed operation remains visibly pending. Local CA controls are disabled while
step-ca is selected; use the CA service for revocation.

## Backups and verification

Back up CA configuration, intermediate key, password recovery material, and CA
database together using Smallstep's supported procedure. Keep the root key offline.
Also preserve `ca-agent-data` (public request/issuance/revocation records) and
`radius-certs` (service identity and rollback material). Never restore old CA state
in a way that loses issued certificates or revocations. Test restoration separately.

Run the repository checks plus:

```sh
docker build -f docker/Dockerfile.ca-agent -t netadmin-ca-agent:test .
docker build -f docker/Dockerfile.radius-agent -t netadmin-radius-agent:test .
bash Tools/smoke_step_ca.sh netadmin-radius-agent:test
bash Tools/smoke_radius_certificates.sh netadmin-radius-agent:test
```

The step-ca smoke uses disposable synthetic PKI and verifies real CSR signing,
chain installation, certificate-token renewal, native RADIUS restart and revocation.
A representative real EAP client authentication remains a deployment acceptance
check; container validation alone does not prove client trust compatibility.

References: [step-ca setup](https://smallstep.com/docs/step-ca/getting-started/),
[authority policies](https://smallstep.com/docs/step-ca/configuration/#policy),
[renewal](https://smallstep.com/docs/step-cli/reference/ca/renew/),
[production and CRLs](https://smallstep.com/docs/step-ca/certificate-authority-server-production/).

If a CA or RADIUS certificate request times out, the audit outcome is **Unknown**, rather
than a confirmed failure. Refresh the certificate status before retrying; a
bounded status request may still report the agent unavailable while activation
finishes. A status change alone does not prove which operation succeeded.

CA audit records identify the request ID, certificate record or serial. After a
lost response (timeout, read/protocol error or uncertain server response), the
issuance screen keeps the original CSR, lifetime and request ID. **Retry same
request** reuses that identity; it does not silently start another issuance.
step-ca renewals reject CN/SAN/lifetime overrides; use explicit enrolment to
change the identity. Enrolment warns when DNS/IP-only inputs replace other SAN types.

Newly activated step-ca server certificates must permit digital signatures when a KeyUsage extension is present. This supports signed TLS handshakes, including TLS 1.3. Existing identities remain inspectable and usable as renewal credentials; configure the CA template to issue a signing-capable replacement.


### Delete authorities and start again

Open **CA** and expand **Delete intermediate CA** or **Delete root CA** on the
selected authority. Type `DELETE CA` and approve the operation. The agent must
permit writes. Delete child authorities before their parents.

Deletion stops the managed issuer and permanently removes its local keys,
certificates, issuance inventory and revocation data. It does not revoke
certificates already held by clients or remove external recovery backups.
Deleting the root generates a fresh signing key and identity, including when the
old root key was archived. Create a new root certificate and subordinate CAs,
and distribute the replacement root trust to clients before using them.
